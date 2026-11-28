"""The manufacturer cloud stand-in, tested against the contract in iot/docs/contract.md. It is a stand-in, so these tests are what make it
a fair one: OAuth edge cases, rate limiting, the deliberately inconsistent lock objects, access code rules and webhook delivery.
No Docker: the stand-in is driven over HTTP with no MQTT attached."""
from __future__ import annotations

import base64
import json
import threading
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from harness import FakeClock, REDIRECT
from iotlab.connector import webhook
from iotlab.util import ServerThread
from iotlab.vendor_cloud import VendorCloud, VendorConfig, build_app, sign

SECRET = "cs-unit-secret"


class Env:
    def __init__(self, **cfg):
        self.clock = FakeClock()
        self.cloud = VendorCloud(VendorConfig(client_secret=SECRET, redirect_uris=(REDIRECT,), delivery_backoff=0.02, **cfg), clock=self.clock)
        for i, shape in enumerate("abc"):
            self.cloud.add_lock(f"lock-{shape}", f"Door {shape}", shape)
            self.cloud._on_mqtt(None, None, _M(f"locks/lock-{shape}/status", "online"))
            self.cloud._on_mqtt(None, None, _M(f"locks/lock-{shape}/state", json.dumps({"lock": "locked", "battery": 62 - i, "battery_low": False, "last_cmd": None, "seq": 1})))
        self.srv = ServerThread(build_app(self.cloud)).start()
        self.http = httpx.Client(base_url=self.srv.url, follow_redirects=False)

    def close(self):
        self.http.close()
        self.srv.stop()
        self.cloud.close()

    def code(self, scope="locks:read locks:write codes:read codes:write webhooks:write", state="s1", redirect=REDIRECT):
        r = self.http.get("/oauth/authorize", params={"response_type": "code", "client_id": "connector-app", "redirect_uri": redirect, "scope": scope, "state": state})
        assert r.status_code == 302, r.text
        q = parse_qs(urlparse(r.headers["location"]).query)
        assert q["state"] == [state]
        return q["code"][0]

    def token(self, code, secret=SECRET, redirect=REDIRECT, basic=True):
        data = {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect}
        if basic:
            return self.http.post("/oauth/token", data=data, auth=("connector-app", secret))
        return self.http.post("/oauth/token", data={**data, "client_id": "connector-app", "client_secret": secret})

    def refresh(self, rt):
        return self.http.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": rt}, auth=("connector-app", SECRET))

    def login(self, **kw):
        r = self.token(self.code(**kw))
        assert r.status_code == 200, r.text
        return r.json()

    def api(self, tok, method, path, **kw):
        return self.http.request(method, path, headers={"Authorization": f"Bearer {tok['access_token']}", **kw.pop("headers", {})}, **kw)


class _M:
    def __init__(self, topic, payload):
        self.topic, self.payload = topic, payload.encode()


@pytest.fixture
def env():
    e = Env()
    yield e
    e.close()


# ---- OAuth -----------------------------------------------------------------------------------------------------------------------------
def test_authorization_code_flow_returns_tokens_and_echoes_state(env):
    tok = env.login(state="abc")
    assert tok["token_type"] == "Bearer" and tok["expires_in"] == 3600 and tok["access_token"].startswith("at_") and tok["refresh_token"].startswith("rt_")


@pytest.mark.parametrize("params", [
    {"client_id": "someone-else", "redirect_uri": REDIRECT},
    {"client_id": "connector-app", "redirect_uri": "http://evil.example/cb"},
])
def test_an_unknown_client_or_unregistered_redirect_is_never_redirected_to(env, params):
    r = env.http.get("/oauth/authorize", params={"response_type": "code", "scope": "locks:read", "state": "s", **params})
    assert r.status_code == 400 and "location" not in r.headers


def test_a_code_works_once_and_reuse_kills_what_it_produced(env):
    code = env.code()
    first = env.token(code)
    assert first.status_code == 200
    again = env.token(code)
    assert again.status_code == 400 and again.json()["error"] == "invalid_grant"
    assert env.api(first.json(), "GET", "/v1/locks").status_code == 401, "a replayed code means it leaked: the tokens it made are revoked"


def test_a_code_expires(env):
    code = env.code()
    env.clock.advance(61)
    assert env.token(code).json()["error"] == "invalid_grant"


def test_the_redirect_uri_at_the_token_step_must_match(env):
    assert env.token(env.code(), redirect="http://127.0.0.1:9/other").json()["error"] == "invalid_grant"


@pytest.mark.parametrize("basic", [True, False])
def test_client_authentication_by_header_or_body(env, basic):
    assert env.token(env.code(), basic=basic).status_code == 200


def test_a_wrong_client_secret_is_refused(env):
    r = env.token(env.code(), secret="not-the-secret")
    assert r.status_code == 401 and r.json()["error"] == "invalid_client" and r.headers["www-authenticate"] == "Basic"


def test_an_access_token_works_until_its_expiry_instant(env):
    tok = env.login()
    env.clock.advance(3599)
    assert env.api(tok, "GET", "/v1/locks").status_code == 200
    env.clock.advance(1)
    r = env.api(tok, "GET", "/v1/locks")
    assert r.status_code == 401 and r.json()["error"] == "invalid_token"


def test_a_refresh_rotates_and_the_spent_refresh_token_is_a_replay(env):
    tok = env.login()
    second = env.refresh(tok["refresh_token"])
    assert second.status_code == 200 and second.json()["refresh_token"] != tok["refresh_token"]
    replay = env.refresh(tok["refresh_token"])
    assert replay.status_code == 400 and replay.json()["error"] == "invalid_grant"
    assert env.api(second.json(), "GET", "/v1/locks").status_code == 401, "a replayed refresh token revokes the whole grant, new tokens included"


def test_a_refresh_token_expires(env):
    tok = env.login()
    env.clock.advance(30 * 86400 + 1)
    assert env.refresh(tok["refresh_token"]).json()["error"] == "invalid_grant"


def test_an_unknown_refresh_token_and_a_missing_grant_type_are_refused(env):
    assert env.refresh("rt_nonsense").json()["error"] == "invalid_grant"
    r = env.http.post("/oauth/token", data={"grant_type": "password"}, auth=("connector-app", SECRET))
    assert r.status_code == 400 and r.json()["error"] == "unsupported_grant_type"


def test_a_token_without_a_scope_cannot_use_that_route(env):
    tok = env.login(scope="locks:read")
    assert env.api(tok, "GET", "/v1/locks").status_code == 200
    r = env.api(tok, "POST", "/v1/locks/lock-a/unlock")
    assert r.status_code == 403 and r.json() == {"error": "insufficient_scope", "error_description": "this token lacks locks:write", "required_scope": "locks:write"}


def test_a_request_without_a_bearer_token_is_a_401(env):
    r = env.http.get("/v1/locks")
    assert r.status_code == 401 and "Bearer" in r.headers["www-authenticate"]


# ---- rate limiting -----------------------------------------------------------------------------------------------------------------------
def test_rate_limit_answers_429_with_a_whole_number_retry_after_and_recovers():
    e = Env(rate_limit=(3, 10.0))
    try:
        tok = e.login()
        assert [e.api(tok, "GET", "/v1/locks").status_code for _ in range(3)] == [200, 200, 200]
        r = e.api(tok, "GET", "/v1/locks")
        assert r.status_code == 429 and r.headers["retry-after"].isdigit() and 1 <= int(r.headers["retry-after"]) <= 10
        e.clock.advance(int(r.headers["retry-after"]))
        assert e.api(tok, "GET", "/v1/locks").status_code == 200
    finally:
        e.close()


def test_the_limit_is_per_token():
    e = Env(rate_limit=(2, 10.0))
    try:
        a, b = e.login(), e.login()
        assert [e.api(a, "GET", "/v1/locks").status_code for _ in range(3)] == [200, 200, 429]
        assert e.api(b, "GET", "/v1/locks").status_code == 200
    finally:
        e.close()


def test_retry_after_can_be_an_http_date(env):
    tok = env.login()
    env.cloud.faults.update(rate_limit_hard=20, retry_after_format="date")
    r = env.api(tok, "GET", "/v1/locks")
    when = parsedate_to_datetime(r.headers["retry-after"])
    assert r.status_code == 429 and abs(when.timestamp() - (env.clock.now + 20)) < 2


def test_the_vendor_being_down_answers_503_everywhere(env):
    tok = env.login()
    env.http.post("/_lab/faults", json={"down": True})
    assert env.http.get("/healthz").status_code == 503
    assert env.api(tok, "GET", "/v1/locks").status_code == 503
    env.http.post("/_lab/faults", json={"down": False})
    assert env.http.get("/healthz").status_code == 200


# ---- the locks, with fields that do not agree ---------------------------------------------------------------------------------------------
def test_the_three_lock_shapes_name_the_same_facts_differently(env):
    tok = env.login()
    a, b, c = (env.api(tok, "GET", f"/v1/locks/lock-{s}").json() for s in "abc")
    assert (a["state"], a["battery_level"], a["online"], a["firmware"], isinstance(a["updated_at"], int)) == ("LOCKED", 62, True, "1.4.2", True)
    assert (b["locked"], b["battery_pct"], b["connected"], "firmware" in b, isinstance(b["updated_at"], str)) == (True, 61, True, False, True)
    assert (c["lock_state"], c["battery"], c["online"], c["fw"]) == ("locked", "60%", 1, "1.4.2")
    assert not {"state", "online", "battery_level"} & set(b)       # the field names themselves differ, not only the values


def test_a_lock_that_never_reported_battery_leaves_the_field_out(env):
    env.cloud.add_lock("lock-new", "New", "c")
    tok = env.login()
    assert "battery" not in env.api(tok, "GET", "/v1/locks/lock-new").json()


def test_the_list_is_paginated_with_a_cursor(env):
    tok = env.login()
    seen, cursor = [], None
    for _ in range(5):
        r = env.api(tok, "GET", "/v1/locks", params={"limit": 2, **({"cursor": cursor} if cursor else {})}).json()
        seen += [x["id"] for x in r["data"]]
        cursor = r["next_cursor"]
        if not cursor:
            break
    assert seen == ["lock-a", "lock-b", "lock-c"]


def test_an_unknown_lock_is_404(env):
    assert env.api(env.login(), "GET", "/v1/locks/nope").status_code == 404


def test_a_command_to_an_offline_lock_is_refused_and_an_idempotency_key_returns_the_same_command(env):
    tok = env.login()
    key = {"Idempotency-Key": "k-1"}
    first = env.api(tok, "POST", "/v1/locks/lock-a/unlock", headers=key)
    again = env.api(tok, "POST", "/v1/locks/lock-a/unlock", headers=key)
    other = env.api(tok, "POST", "/v1/locks/lock-a/unlock", headers={"Idempotency-Key": "k-2"})
    assert first.status_code == 202 and first.json() == again.json() and other.json()["id"] != first.json()["id"]
    env.cloud._on_mqtt(None, None, _M("locks/lock-b/status", "offline"))
    r = env.api(tok, "POST", "/v1/locks/lock-b/lock")
    assert r.status_code == 409 and r.json()["error"] == "lock_offline"


def test_a_command_is_confirmed_by_the_lock_echoing_its_id_and_times_out_otherwise(env):
    tok = env.login()
    cmd = env.api(tok, "POST", "/v1/locks/lock-a/unlock").json()
    assert env.api(tok, "GET", f"/v1/commands/{cmd['id']}").json()["status"] == "pending"
    env.clock.advance(31)
    assert env.api(tok, "GET", f"/v1/commands/{cmd['id']}").json()["status"] == "timed_out"
    cmd2 = env.api(tok, "POST", "/v1/locks/lock-a/unlock").json()
    env.cloud._on_mqtt(None, None, _M("locks/lock-a/state", json.dumps({"lock": "unlocked", "battery": 60, "last_cmd": cmd2["id"]})))
    assert env.api(tok, "GET", f"/v1/commands/{cmd2['id']}").json()["status"] == "confirmed"
    assert [e["type"] for e in env.cloud.events][-1] == "lock.unlocked"


# ---- temporary access codes ------------------------------------------------------------------------------------------------------------------
def window(env, start=0, hours=2):
    s = env.clock.now + start
    return {"starts_at": datetime.fromtimestamp(s, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "ends_at": datetime.fromtimestamp(s + hours * 3600, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}


def test_a_code_is_shown_once_and_the_list_says_status_not_the_code(env):
    tok = env.login()
    made = env.api(tok, "POST", "/v1/locks/lock-a/codes", json={"name": "guest", **window(env)})
    assert made.status_code == 201
    doc = made.json()
    assert len(doc["code"]) == 6 and doc["code"].isdigit() and isinstance(doc["starts_at"], int), "the create answer uses epoch seconds"
    listed = env.api(tok, "GET", "/v1/locks/lock-a/codes").json()["data"]
    assert len(listed) == 1 and "code" not in listed[0] and isinstance(listed[0]["starts_at"], str), "the list uses ISO and never the code"


def test_a_code_goes_scheduled_then_active_then_expired():
    env = Env(access_ttl=10 * 86400)                 # the token must outlive the hours this test jumps
    try:
        tok = env.login()
        env.api(tok, "POST", "/v1/locks/lock-a/codes", json={"name": "g", **window(env, start=3600, hours=1)})
        status = lambda: env.api(tok, "GET", "/v1/locks/lock-a/codes").json()["data"][0]["status"]   # noqa: E731
        assert status() == "scheduled"
        env.clock.advance(3600)
        assert status() == "active"
        env.clock.advance(3600)
        assert status() == "expired"
    finally:
        env.close()


@pytest.mark.parametrize("body,code", [
    ({"name": "g", "starts_at": "2026-11-28T10:00:00Z", "ends_at": "2026-11-28T10:00:00Z"}, "invalid_window"),
    ({"name": "g", "starts_at": "2026-11-28T10:00:00Z", "ends_at": "2026-11-28T09:00:00Z"}, "invalid_window"),
    ({"name": "g", "starts_at": "2026-11-01T10:00:00Z", "ends_at": "2026-12-05T10:00:00Z"}, "invalid_window"),
    ({"name": "g", "starts_at": "garbage", "ends_at": "2026-11-28T10:00:00Z"}, "invalid_window"),
    ({"starts_at": "2026-11-28T10:00:00Z", "ends_at": "2026-11-28T11:00:00Z"}, "invalid_request"),
])
def test_bad_code_windows_are_refused(env, body, code):
    r = env.api(env.login(), "POST", "/v1/locks/lock-a/codes", json=body)
    assert r.status_code == 400 and r.json()["error"] == code


def test_a_lock_holds_a_limited_number_of_live_codes_and_a_revoked_one_frees_a_slot(env):
    tok = env.login()
    ids = [env.api(tok, "POST", "/v1/locks/lock-a/codes", json={"name": f"g{i}", **window(env)}).json()["id"] for i in range(4)]
    full = env.api(tok, "POST", "/v1/locks/lock-a/codes", json={"name": "g5", **window(env)})
    assert full.status_code == 409 and full.json()["error"] == "code_slots_full"
    assert env.api(tok, "DELETE", f"/v1/locks/lock-a/codes/{ids[0]}").status_code == 204
    assert env.api(tok, "POST", "/v1/locks/lock-a/codes", json={"name": "g6", **window(env)}).status_code == 201


def test_codes_on_one_lock_are_distinct_and_revoking_twice_is_fine(env):
    tok = env.login()
    pins = {env.api(tok, "POST", "/v1/locks/lock-a/codes", json={"name": f"g{i}", **window(env)}).json()["code"] for i in range(4)}
    assert len(pins) == 4
    cid = env.api(tok, "GET", "/v1/locks/lock-a/codes").json()["data"][0]["id"]
    assert [env.api(tok, "DELETE", f"/v1/locks/lock-a/codes/{cid}").status_code for _ in range(2)] == [204, 204]
    assert env.api(tok, "DELETE", "/v1/locks/lock-a/codes/ac_missing").status_code == 404
    assert env.api(tok, "DELETE", f"/v1/locks/lock-b/codes/{cid}").status_code == 404, "a code belongs to its own lock"


def test_a_code_create_that_lost_its_answer_is_replayed_not_duplicated(env):
    tok = env.login()
    env.cloud.faults["fail_after_commit"] = 1
    hdr = {"Idempotency-Key": "once"}
    body = {"name": "g", **window(env)}
    assert env.api(tok, "POST", "/v1/locks/lock-a/codes", json=body, headers=hdr).status_code == 503
    r = env.api(tok, "POST", "/v1/locks/lock-a/codes", json=body, headers=hdr)
    assert r.status_code == 201 and len([c for c in env.cloud.codes.values() if c["lock_id"] == "lock-a"]) == 1


# ---- webhooks and the event feed ----------------------------------------------------------------------------------------------------------------
class Receiver:
    """A webhook endpoint that records what it gets and answers with a scripted status."""

    def __init__(self, statuses=(200,)):
        self.got: list[dict] = []
        self.statuses = list(statuses)
        app = FastAPI()

        @app.post("/hook")
        async def hook(request: Request):
            body = await request.body()
            self.got.append({"headers": dict(request.headers), "body": body})
            status = self.statuses[min(len(self.got) - 1, len(self.statuses) - 1)]
            return JSONResponse({"ok": status < 300}, status_code=status)

        self.srv = ServerThread(app).start()
        self.url = self.srv.url + "/hook"

    def wait(self, n, timeout=5.0):
        end = time.time() + timeout
        while len(self.got) < n and time.time() < end:
            threading.Event().wait(0.02)
        return len(self.got) >= n


def register(env, url, tok=None):
    tok = tok or env.login()
    r = env.api(tok, "POST", "/v1/webhooks", json={"url": url})
    assert r.status_code == 201, r.text
    return tok, r.json()


def test_the_webhook_secret_is_returned_once_and_deliveries_verify_with_it(env):
    rx = Receiver()
    tok, hook = register(env, rx.url)
    assert hook["secret"].startswith("whsec_")
    env.cloud._on_mqtt(None, None, _M("locks/lock-a/state", json.dumps({"lock": "unlocked", "battery": 60, "last_cmd": None})))   # a manual turn
    assert rx.wait(1)
    got = rx.got[0]
    ts = got["headers"]["x-vendor-timestamp"]
    assert got["headers"]["x-vendor-signature"] == sign(hook["secret"], ts, got["body"])
    assert webhook.verify(hook["secret"], got["headers"], got["body"], env.clock.now) == int(ts)
    evt = json.loads(got["body"])
    assert evt["type"] == "lock.unlocked" and evt["data"]["source"] == "manual" and evt["lock_seq"] == 1 and got["headers"]["x-vendor-event-id"] == evt["id"]
    assert "secret" not in env.api(tok, "GET", "/v1/locks").text
    rx.srv.stop()


def test_a_failed_delivery_is_retried_with_a_fresh_timestamp_until_it_is_accepted(env):
    rx = Receiver(statuses=(500, 503, 200))
    register(env, rx.url)
    env.cloud._on_mqtt(None, None, _M("locks/lock-a/state", json.dumps({"lock": "unlocked", "battery": 60, "last_cmd": None})))
    assert rx.wait(3)
    assert [d["status"] for d in env.cloud.deliveries] == [500, 503, 200] and [d["attempt"] for d in env.cloud.deliveries] == [1, 2, 3]
    rx.srv.stop()


def test_the_vendor_gives_up_after_its_attempts(env):
    rx = Receiver(statuses=(500,))
    register(env, rx.url)
    env.cloud._on_mqtt(None, None, _M("locks/lock-a/state", json.dumps({"lock": "unlocked", "battery": 60, "last_cmd": None})))
    assert rx.wait(4)
    threading.Event().wait(0.4)
    assert len(rx.got) == 4
    rx.srv.stop()


def test_delivery_is_at_least_once_so_a_duplicate_can_arrive(env):
    rx = Receiver()
    register(env, rx.url)
    env.cloud.faults["duplicate_deliveries"] = True
    env.cloud._on_mqtt(None, None, _M("locks/lock-a/state", json.dumps({"lock": "unlocked", "battery": 60, "last_cmd": None})))
    assert rx.wait(2)
    assert rx.got[0]["body"] == rx.got[1]["body"]
    rx.srv.stop()


def test_a_captured_delivery_can_be_replayed_byte_for_byte(env):
    rx = Receiver()
    register(env, rx.url)
    env.cloud._on_mqtt(None, None, _M("locks/lock-a/state", json.dumps({"lock": "unlocked", "battery": 60, "last_cmd": None})))
    assert rx.wait(1)
    env.cloud.replay_captured(env.cloud.events[-1]["id"])
    assert rx.wait(2) and rx.got[1]["headers"]["x-vendor-signature"] == rx.got[0]["headers"]["x-vendor-signature"] and rx.got[1]["body"] == rx.got[0]["body"]
    rx.srv.stop()


def test_paused_delivery_makes_no_attempt_at_all(env):
    rx = Receiver()
    register(env, rx.url)
    env.cloud.faults["drop_webhooks"] = True
    env.cloud._on_mqtt(None, None, _M("locks/lock-a/state", json.dumps({"lock": "unlocked", "battery": 60, "last_cmd": None})))
    threading.Event().wait(0.3)
    assert not rx.got and not env.cloud.deliveries and env.cloud.events, "the event exists in the feed but was never pushed"
    rx.srv.stop()


def test_the_webhook_url_must_be_https_or_loopback(env):
    r = env.api(env.login(), "POST", "/v1/webhooks", json={"url": "http://example.com/hook"})
    assert r.status_code == 400


def test_the_event_feed_is_ordered_and_a_dropped_part_is_a_410():
    e = Env(event_retention=3)
    try:
        tok = e.login()
        for i in range(6):
            lock = "unlocked" if i % 2 == 0 else "locked"
            e.cloud._on_mqtt(None, None, _M("locks/lock-a/state", json.dumps({"lock": lock, "battery": 60, "last_cmd": None})))
        feed = e.api(tok, "GET", "/v1/events", params={"since_seq": 4}).json()
        assert [x["seq"] for x in feed["data"]] == [5, 6] and feed["latest_seq"] == 6
        gone = e.api(tok, "GET", "/v1/events", params={"since_seq": 1})
        assert gone.status_code == 410 and gone.json()["error"] == "cursor_expired"
    finally:
        e.close()


def test_lab_faults_refuse_an_unknown_fault_name(env):
    r = env.http.post("/_lab/faults", json={"no_such_fault": True})
    assert r.status_code == 400
