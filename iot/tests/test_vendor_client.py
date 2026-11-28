"""The connector's vendor client against a scripted vendor (httpx.MockTransport): OAuth refresh rules, Retry-After, backoff,
which requests may be retried, and that no secret reaches an exception or a log line. No network and no Docker."""
from __future__ import annotations

import logging
import threading
from email.utils import format_datetime
from datetime import datetime, timezone
from urllib.parse import parse_qs

import httpx
import pytest

from harness import FakeClock
from iotlab.connector.crypto import CredentialVault, generate_key
from iotlab.connector.store import Store
from iotlab.connector.vendor_client import (ClientConfig, OAuthStateError, RateLimited, ReauthRequired, VendorClient, VendorError, VendorUnavailable,
                                            backoff_delay, parse_retry_after)

BASE = "http://vendor.test"


class Vendor:
    """A scripted vendor. `api` and `token` are lists of responses consumed in order (the last one repeats)."""

    def __init__(self):
        self.api: list = []
        self.token: list = []
        self.requests: list[httpx.Request] = []
        self.token_calls = 0
        self.delay = 0.0
        self._n = 0
        self.mu = threading.Lock()

    def handler(self, request: httpx.Request) -> httpx.Response:
        with self.mu:
            self.requests.append(request)
        if request.url.path == "/oauth/token":
            with self.mu:
                self.token_calls += 1
                n = self.token_calls
            if self.delay:
                threading.Event().wait(self.delay)
            return self._pick(self.token, n - 1, request)
        with self.mu:
            self._n += 1
            n = self._n
        return self._pick(self.api, n - 1, request)

    @staticmethod
    def _pick(script, i, request):
        item = script[min(i, len(script) - 1)] if script else httpx.Response(200, json={})
        if isinstance(item, Exception):
            raise item
        return item(request) if callable(item) else item

    def api_requests(self):
        return [r for r in self.requests if r.url.path != "/oauth/token"]


def ok(json=None, status=200, headers=None):
    return httpx.Response(status, json=json if json is not None else {"ok": True}, headers=headers)


def tokens(access, refresh, expires_in=100, scope="locks:read"):
    return httpx.Response(200, json={"access_token": access, "refresh_token": refresh, "expires_in": expires_in, "scope": scope, "token_type": "Bearer"})


def make(tmp_path, vendor: Vendor, clock=None, **cfg):
    clock = clock or FakeClock()
    store = Store(str(tmp_path / "c.db"))
    vault = CredentialVault(generate_key())
    sleeps: list[float] = []
    client = VendorClient(
        ClientConfig(base_url=BASE, client_id="cid", client_secret="client-secret-XYZ789", redirect_uri="http://cb/", base_delay=0.5, max_delay=30,
                     max_retry_after=60, max_attempts=5, **cfg),
        store, vault, clock=clock, sleeper=sleeps.append, rng=lambda lo, hi: hi,
        http=httpx.Client(base_url=BASE, transport=httpx.MockTransport(vendor.handler)))
    client._store_tokens({"access_token": "at_FIRST-ACCESS-1", "refresh_token": "rt_FIRST-REFRESH-1", "expires_in": 100, "scope": "locks:read"}, None)
    return client, store, sleeps, clock


def form(request: httpx.Request) -> dict:
    return {k: v[0] for k, v in parse_qs(request.content.decode()).items()}


def auth_of(request: httpx.Request) -> str:
    return request.headers["authorization"]


# ---- refresh timing -----------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("advance,refreshes", [(0, 0), (69, 0), (70, 1), (99, 1), (500, 1)])
def test_a_token_is_refreshed_exactly_when_it_is_within_the_skew_of_expiry(tmp_path, advance, refreshes):
    v = Vendor()
    v.token = [tokens("at_SECOND-ACCESS-2", "rt_SECOND-REFRESH-2")]
    c, store, _, clock = make(tmp_path, v)            # expires in 100 s, skew 30 s: due at 70 s
    clock.advance(advance)
    c.request("GET", "/v1/locks")
    assert v.token_calls == refreshes
    assert auth_of(v.api_requests()[0]) == ("Bearer at_SECOND-ACCESS-2" if refreshes else "Bearer at_FIRST-ACCESS-1")


def test_the_rotated_refresh_token_is_used_next_time_not_the_spent_one(tmp_path):
    v = Vendor()
    v.token = [tokens("at_A2-ACCESS-22", "rt_R2-REFRESH-22"), tokens("at_A3-ACCESS-33", "rt_R3-REFRESH-33")]
    c, store, _, clock = make(tmp_path, v)
    clock.advance(80)
    c.request("GET", "/v1/locks")
    clock.advance(80)
    c.request("GET", "/v1/locks")
    sent = [form(r)["refresh_token"] for r in v.requests if r.url.path == "/oauth/token"]
    assert sent == ["rt_FIRST-REFRESH-1", "rt_R2-REFRESH-22"]


def test_a_refresh_that_returns_no_new_refresh_token_keeps_the_old_one(tmp_path):
    v = Vendor()
    v.token = [httpx.Response(200, json={"access_token": "at_A2-ACCESS-22", "expires_in": 100}), tokens("at_A3-ACCESS-33", "rt_R3-REFRESH-33")]
    c, store, _, clock = make(tmp_path, v)
    clock.advance(80)
    c.request("GET", "/v1/locks")
    clock.advance(80)
    c.request("GET", "/v1/locks")
    assert [form(r)["refresh_token"] for r in v.requests if r.url.path == "/oauth/token"] == ["rt_FIRST-REFRESH-1", "rt_FIRST-REFRESH-1"]


def test_ten_callers_with_an_expired_token_cause_one_refresh(tmp_path):
    v = Vendor()
    v.delay = 0.15                                    # the refresh is slow, so every caller reaches the lock while it runs
    v.token = [tokens("at_SHARED-ACCESS-2", "rt_SHARED-REFRESH-2")]
    c, store, _, clock = make(tmp_path, v)
    clock.advance(500)
    errors, results = [], []

    def call():
        try:
            results.append(c.request("GET", "/v1/locks").status_code)
        except Exception as exc:                      # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=call) for _ in range(10)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert not errors and results == [200] * 10
    assert v.token_calls == 1, "a second refresh with the spent token would be read as a replay and kill the grant"
    assert {auth_of(r) for r in v.api_requests()} == {"Bearer at_SHARED-ACCESS-2"}


def test_a_401_refreshes_once_and_retries_with_the_new_token(tmp_path):
    v = Vendor()
    v.api = [ok(status=401, json={"error": "invalid_token"}), ok({"data": []})]
    v.token = [tokens("at_NEW-ACCESS-22", "rt_NEW-REFRESH-22")]
    c, store, sleeps, _ = make(tmp_path, v)
    assert c.request("GET", "/v1/locks").json() == {"data": []}
    assert v.token_calls == 1 and [auth_of(r) for r in v.api_requests()] == ["Bearer at_FIRST-ACCESS-1", "Bearer at_NEW-ACCESS-22"]


def test_a_second_401_after_a_fresh_refresh_ends_in_needs_reauth(tmp_path):
    v = Vendor()
    v.api = [ok(status=401, json={"error": "invalid_token"})]
    v.token = [tokens("at_NEW-ACCESS-22", "rt_NEW-REFRESH-22")]
    c, store, _, _ = make(tmp_path, v)
    with pytest.raises(ReauthRequired):
        c.request("GET", "/v1/locks")
    assert store.get_oauth()["status"] == "needs_reauth" and v.token_calls == 1


def test_invalid_grant_stops_everything_until_a_person_reauthorizes(tmp_path):
    v = Vendor()
    v.token = [httpx.Response(400, json={"error": "invalid_grant"})]
    c, store, sleeps, clock = make(tmp_path, v)
    clock.advance(500)
    with pytest.raises(ReauthRequired):
        c.request("GET", "/v1/locks")
    assert v.token_calls == 1 and not sleeps, "invalid_grant is final: no retry, no backoff"
    assert store.get_oauth()["status"] == "needs_reauth" and store.get_oauth()["last_error"] == "invalid_grant"
    before = len(v.requests)
    with pytest.raises(ReauthRequired):
        c.request("GET", "/v1/locks")
    assert len(v.requests) == before, "once the grant is dead the connector stops calling the vendor"


def test_a_vendor_outage_during_refresh_retries_then_keeps_the_grant(tmp_path):
    v = Vendor()
    v.token = [httpx.Response(503), httpx.Response(502), tokens("at_NEW-ACCESS-22", "rt_NEW-REFRESH-22")]
    c, store, sleeps, clock = make(tmp_path, v)
    clock.advance(500)
    c.request("GET", "/v1/locks")
    assert v.token_calls == 3 and sleeps == [0.5, 1.0]
    v2 = Vendor()
    v2.token = [httpx.Response(503)]
    (tmp_path / "second").mkdir()
    c2, store2, _, clock2 = make(tmp_path / "second", v2)
    clock2.advance(500)
    with pytest.raises(VendorUnavailable):
        c2.request("GET", "/v1/locks")
    row = store2.get_oauth()
    assert row["status"] == "ok" and row["last_error"].startswith("refresh_failed"), "an outage is not a revoked grant"
    assert c2.vault.decrypt(row["refresh_token_enc"]) == "rt_FIRST-REFRESH-1"


@pytest.mark.parametrize("payload", [{"access_token": "x"}, {"expires_in": 100}, {"access_token": "", "expires_in": 100, "refresh_token": "r"},
                                      {"access_token": "at_X-ACCESS-12", "expires_in": 0, "refresh_token": "r"},
                                      {"access_token": "at_X-ACCESS-12", "expires_in": -5, "refresh_token": "r"},
                                      {"access_token": "at_X-ACCESS-12", "expires_in": "soon", "refresh_token": "r"},
                                      {"access_token": "at_X-ACCESS-12", "expires_in": True, "refresh_token": "r"}, {"access_token": 5, "expires_in": 10}])
def test_a_malformed_token_answer_does_not_overwrite_the_grant(tmp_path, payload):
    v = Vendor()
    v.token = [httpx.Response(200, json=payload)]
    c, store, _, clock = make(tmp_path, v)
    before = store.get_oauth()["access_token_enc"]
    clock.advance(500)
    with pytest.raises(VendorError) as exc:
        c.request("GET", "/v1/locks")
    assert exc.value.code == "malformed_token_response"
    assert store.get_oauth()["access_token_enc"] == before


def test_a_token_answer_that_is_not_json_is_refused(tmp_path):
    v = Vendor()
    v.token = [httpx.Response(200, content=b"<html>maintenance</html>")]
    c, store, _, clock = make(tmp_path, v)
    clock.advance(500)
    with pytest.raises(VendorError):
        c.request("GET", "/v1/locks")


def test_an_unauthorized_client_on_refresh_needs_reauth(tmp_path):
    v = Vendor()
    v.token = [httpx.Response(401, json={"error": "invalid_client"})]
    c, store, _, clock = make(tmp_path, v)
    clock.advance(500)
    with pytest.raises(ReauthRequired):
        c.request("GET", "/v1/locks")
    assert store.get_oauth()["last_error"] == "invalid_client"


def test_a_connector_that_was_never_authorized_says_so(tmp_path):
    v = Vendor()
    store = Store(str(tmp_path / "x.db"))
    c = VendorClient(ClientConfig(base_url=BASE, client_id="c", client_secret="s", redirect_uri="r"), store, CredentialVault(generate_key()),
                     http=httpx.Client(base_url=BASE, transport=httpx.MockTransport(v.handler)))
    with pytest.raises(ReauthRequired):
        c.request("GET", "/v1/locks")
    assert not v.requests


# ---- Retry-After -----------------------------------------------------------------------------------------------------------------------
NOW = 1_800_000_000.0


@pytest.mark.parametrize("value,want", [("5", 5.0), ("0", 0.0), ("  7 ", 7.0), ("120", 120.0), (None, None), ("", None), ("-3", None), ("1.5", None),
                                         ("soon", None), (format_datetime(datetime.fromtimestamp(NOW + 30, tz=timezone.utc), usegmt=True), 30.0),
                                         (format_datetime(datetime.fromtimestamp(NOW - 30, tz=timezone.utc), usegmt=True), 0.0)])
def test_retry_after_is_whole_seconds_or_an_http_date(value, want):
    assert parse_retry_after(value, NOW) == want


def test_a_429_waits_exactly_retry_after_then_succeeds(tmp_path):
    v = Vendor()
    v.api = [ok(status=429, headers={"Retry-After": "7"}, json={"error": "rate_limited"}), ok({"data": 1})]
    c, store, sleeps, _ = make(tmp_path, v)
    assert c.request("GET", "/v1/locks").json() == {"data": 1}
    assert sleeps == [7.0]


def test_a_429_with_an_http_date_waits_that_long(tmp_path):
    clock = FakeClock(NOW)
    date = format_datetime(datetime.fromtimestamp(NOW + 12, tz=timezone.utc), usegmt=True)
    v = Vendor()
    v.api = [ok(status=429, headers={"Retry-After": date}), ok()]
    c, store, sleeps, _ = make(tmp_path, v, clock=clock)
    c.request("GET", "/v1/locks")
    assert sleeps == [12.0]


def test_a_retry_after_longer_than_the_cap_is_raised_not_slept(tmp_path):
    v = Vendor()
    v.api = [ok(status=429, headers={"Retry-After": "3600"})]
    c, store, sleeps, _ = make(tmp_path, v)
    with pytest.raises(RateLimited) as exc:
        c.request("GET", "/v1/locks")
    assert exc.value.retry_after == 3600 and not sleeps and len(v.api_requests()) == 1


def test_a_429_without_retry_after_falls_back_to_backoff_and_gives_up_after_the_attempts(tmp_path):
    v = Vendor()
    v.api = [ok(status=429)]
    c, store, sleeps, _ = make(tmp_path, v)
    with pytest.raises(RateLimited):
        c.request("GET", "/v1/locks")
    assert len(v.api_requests()) == 5 and sleeps == [0.5, 1.0, 2.0, 4.0]


def test_a_429_is_retried_even_for_a_post_because_nothing_was_executed(tmp_path):
    v = Vendor()
    v.api = [ok(status=429, headers={"Retry-After": "1"}), ok(status=202, json={"id": "cmd_1"})]
    c, store, sleeps, _ = make(tmp_path, v)
    assert c.request("POST", "/v1/locks/x/unlock").status_code == 202


# ---- backoff and what may be retried ---------------------------------------------------------------------------------------------------
def test_backoff_doubles_and_is_capped():
    assert [backoff_delay(n, 0.5, 4.0, rng=lambda lo, hi: hi) for n in range(1, 7)] == [0.5, 1.0, 2.0, 4.0, 4.0, 4.0]
    assert [backoff_delay(n, 0.5, 4.0, rng=lambda lo, hi: lo) for n in range(1, 4)] == [0.25, 0.5, 1.0]


def test_a_5xx_get_is_retried_with_growing_waits_until_it_works(tmp_path):
    v = Vendor()
    v.api = [ok(status=503), ok(status=500), ok(status=502), ok({"fine": 1})]
    c, store, sleeps, _ = make(tmp_path, v)
    assert c.request("GET", "/v1/locks").json() == {"fine": 1}
    assert sleeps == [0.5, 1.0, 2.0]


def test_a_5xx_that_never_clears_raises_after_the_attempts(tmp_path):
    v = Vendor()
    v.api = [ok(status=503)]
    c, store, sleeps, _ = make(tmp_path, v)
    with pytest.raises(VendorUnavailable):
        c.request("GET", "/v1/locks")
    assert len(v.api_requests()) == 5


def test_a_post_without_an_idempotency_key_is_never_retried_after_a_5xx(tmp_path):
    v = Vendor()
    v.api = [ok(status=503), ok(status=201)]
    c, store, sleeps, _ = make(tmp_path, v)
    with pytest.raises(VendorUnavailable):
        c.request("POST", "/v1/locks/x/codes", json={"name": "g"})
    assert len(v.api_requests()) == 1, "a retry could create a second code"


def test_a_post_with_an_idempotency_key_is_retried_and_carries_the_same_key(tmp_path):
    v = Vendor()
    v.api = [ok(status=503), ok(status=201, json={"id": "ac_1"})]
    c, store, sleeps, _ = make(tmp_path, v)
    assert c.request("POST", "/v1/locks/x/codes", json={"name": "g"}, idempotency_key="key-1").status_code == 201
    assert [r.headers["idempotency-key"] for r in v.api_requests()] == ["key-1", "key-1"]


def test_a_network_error_is_retried_for_a_get_and_not_for_an_unkeyed_post(tmp_path):
    v = Vendor()
    v.api = [httpx.ConnectError("refused"), ok({"fine": 1})]
    c, store, sleeps, _ = make(tmp_path, v)
    assert c.request("GET", "/v1/locks").json() == {"fine": 1}
    v2 = Vendor()
    v2.api = [httpx.ReadTimeout("slow"), ok(status=201)]
    c2, store2, _, _ = make(tmp_path, v2)
    with pytest.raises(VendorUnavailable):
        c2.request("POST", "/v1/locks/x/codes", json={})
    assert len(v2.api_requests()) == 1


def test_a_4xx_is_raised_with_its_code_and_never_retried(tmp_path):
    for status, code in ((404, "not_found"), (409, "lock_offline"), (400, "invalid_window")):
        v = Vendor()
        v.api = [ok(status=status, json={"error": code, "error_description": "why"})]
        c, store, sleeps, _ = make(tmp_path, v)
        with pytest.raises(VendorError) as exc:
            c.request("GET", "/v1/locks")
        assert (exc.value.status, exc.value.code) == (status, code) and len(v.api_requests()) == 1 and not sleeps


def test_a_403_names_the_missing_scope_in_the_record_without_ending_the_grant(tmp_path):
    v = Vendor()
    v.api = [ok(status=403, json={"error": "insufficient_scope", "required_scope": "codes:write"})]
    c, store, _, _ = make(tmp_path, v)
    with pytest.raises(VendorError) as exc:
        c.request("POST", "/v1/locks/x/codes", json={})
    assert exc.value.code == "insufficient_scope"
    row = store.get_oauth()
    assert row["status"] == "ok" and row["last_error"] == "insufficient_scope:codes:write"


def test_max_attempts_one_makes_exactly_one_try(tmp_path):
    v = Vendor()
    v.api = [ok(status=503)]
    c, store, sleeps, _ = make(tmp_path, v)
    with pytest.raises(VendorUnavailable):
        c.request("GET", "/v1/locks", max_attempts=1)
    assert len(v.api_requests()) == 1 and not sleeps


# ---- the authorization code flow --------------------------------------------------------------------------------------------------------
def test_the_state_parameter_must_be_one_we_issued(tmp_path):
    v = Vendor()
    c, store, _, _ = make(tmp_path, v)
    v.token = [tokens("at_X-ACCESS-123", "rt_X-REFRESH-123")]
    with pytest.raises(OAuthStateError):
        c.complete_authorization("code_abcdef123456", "state-we-never-issued")
    assert v.token_calls == 0, "the code must not even be exchanged"
    url = c.authorization_url()
    state = parse_qs(httpx.URL(url).query.decode())["state"][0]
    c.complete_authorization("code_abcdef123456", state)
    assert v.token_calls == 1
    with pytest.raises(OAuthStateError):
        c.complete_authorization("code_abcdef123456", state)          # a state is good once


def test_an_old_state_is_refused(tmp_path):
    v = Vendor()
    v.token = [tokens("at_X-ACCESS-123", "rt_X-REFRESH-123")]
    c, store, _, clock = make(tmp_path, v)
    state = parse_qs(httpx.URL(c.authorization_url()).query.decode())["state"][0]
    clock.advance(601)
    with pytest.raises(OAuthStateError):
        c.complete_authorization("code_abcdef123456", state)


def test_the_authorization_url_and_the_code_exchange_carry_what_the_contract_says(tmp_path):
    v = Vendor()
    v.token = [tokens("at_X-ACCESS-123", "rt_X-REFRESH-123")]
    c, store, _, _ = make(tmp_path, v)
    q = parse_qs(httpx.URL(c.authorization_url()).query.decode())
    assert q["response_type"] == ["code"] and q["client_id"] == ["cid"] and q["redirect_uri"] == ["http://cb/"] and "locks:read" in q["scope"][0]
    c.complete_authorization("code_abcdef123456", q["state"][0])
    sent = [r for r in v.requests if r.url.path == "/oauth/token"][-1]
    assert form(sent) == {"grant_type": "authorization_code", "code": "code_abcdef123456", "redirect_uri": "http://cb/"}
    assert sent.headers["authorization"].startswith("Basic ")          # the client secret travels in the header, not the form


# ---- nothing secret leaks ---------------------------------------------------------------------------------------------------------------
def test_no_token_or_secret_reaches_an_exception_message_or_a_log_line(tmp_path, caplog):
    secrets_in_play = ["at_FIRST-ACCESS-1", "rt_FIRST-REFRESH-1", "client-secret-XYZ789", "at_NEW-ACCESS-22", "rt_NEW-REFRESH-22"]
    caplog.set_level(logging.DEBUG)
    messages = []
    scripts = [
        ([ok(status=401), ok(status=401)], [tokens("at_NEW-ACCESS-22", "rt_NEW-REFRESH-22")]),
        ([ok(status=503)], [httpx.Response(400, json={"error": "invalid_grant"})]),
        ([ok(status=429, headers={"Retry-After": "9999"})], []),
        ([ok(status=403, json={"error": "insufficient_scope", "required_scope": "codes:write"})], []),
        ([httpx.ConnectError("refused")], [tokens("at_NEW-ACCESS-22", "rt_NEW-REFRESH-22")]),
    ]
    for api, token in scripts:
        v = Vendor()
        v.api, v.token = api, token
        c, store, _, clock = make(tmp_path, v)
        clock.advance(500 if token and token[0].status_code == 400 else 0)
        try:
            c.request("GET", "/v1/locks")
        except Exception as exc:                                      # noqa: BLE001
            messages.append(f"{exc!s} {exc!r}")
    blob = caplog.text + " ".join(messages)
    for secret in secrets_in_play:
        assert secret not in blob
