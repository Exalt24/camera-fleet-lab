"""The connector's client for the vendor cloud: OAuth 2.0 authorization code with rotating refresh tokens, and a request method that
survives the failures a vendor API produces.

  - a token is refreshed shortly before it expires, and again after a 401, by ONE caller at a time (a lock plus a re-check, so
    ten threads that see an expired token cause one refresh, not ten. Refresh tokens rotate, so a second refresh with the old
    token would be read by the vendor as a replay and would kill the whole grant)
  - the rotated refresh token and the new access token are written in one statement before anything else uses them
  - invalid_grant ends in status needs_reauth, not in a retry loop
  - 429 waits for Retry-After (seconds or an HTTP date) and gives up, raising RateLimited, when the wait is longer than a cap
  - 5xx and network errors are retried with exponential backoff and jitter, but a POST is retried only when it carries an
    Idempotency-Key, so a retry cannot create a second code or send a second unlock
  - no token or secret is ever put in an exception message or a log line
"""
from __future__ import annotations

import random
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlencode

import httpx

from .crypto import CredentialVault
from .safelog import SafeLogger, register_secret
from .store import Store

log = SafeLogger("lockbridge.vendor")

DEFAULT_SCOPE = "locks:read locks:write codes:read codes:write webhooks:write"


class VendorError(Exception):
    def __init__(self, status: int, code: str, description: str = ""):
        super().__init__(f"{status} {code}")
        self.status, self.code, self.description = status, code, description


class ReauthRequired(VendorError):
    """The grant is gone (revoked, expired or replayed). Only a person can approve a new one."""

    def __init__(self, reason: str):
        super().__init__(401, "reauth_required", reason)


class RateLimited(VendorError):
    def __init__(self, retry_after: float):
        super().__init__(429, "rate_limited", f"retry after {retry_after:g}s")
        self.retry_after = retry_after


class VendorUnavailable(Exception):
    """A network error or a 5xx that did not clear within the attempts allowed."""


class OAuthStateError(Exception):
    pass


@dataclass
class ClientConfig:
    base_url: str
    client_id: str
    client_secret: str
    redirect_uri: str
    scope: str = DEFAULT_SCOPE
    refresh_skew: float = 30.0
    max_attempts: int = 5
    base_delay: float = 0.5
    max_delay: float = 30.0
    max_retry_after: float = 60.0
    timeout: float = 10.0
    state_ttl: float = 600.0


def parse_retry_after(value: str | None, now: float) -> float | None:
    """Retry-After is whole seconds or an HTTP date. Anything else, or a negative number, is unknown (None)."""
    if value is None:
        return None
    text = value.strip()
    if text.isdigit():
        return float(text)
    try:
        when = parsedate_to_datetime(text)
    except (TypeError, ValueError):
        return None
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0.0, when.timestamp() - now)


def backoff_delay(attempt: int, base: float, cap: float, rng=random.uniform) -> float:
    """Exponential with equal jitter: between half and all of min(cap, base * 2^(attempt-1))."""
    ceiling = min(cap, base * 2 ** (attempt - 1))
    return rng(ceiling / 2, ceiling)


class VendorClient:
    def __init__(self, cfg: ClientConfig, store: Store, vault: CredentialVault, clock=time.time, sleeper=time.sleep,
                 rng=random.uniform, http: httpx.Client | None = None):
        self.cfg, self.store, self.vault = cfg, store, vault
        self.clock, self.sleep, self.rng = clock, sleeper, rng
        self.http = http or httpx.Client(base_url=cfg.base_url, timeout=cfg.timeout)
        self._refresh_lock = threading.Lock()
        self._states: dict[str, float] = {}
        self._states_mu = threading.Lock()
        self.refreshes = 0
        register_secret(cfg.client_secret)

    # -- authorization code flow ------------------------------------------------------------------------------------------
    def authorization_url(self) -> str:
        state = secrets.token_urlsafe(18)
        with self._states_mu:
            self._states[state] = self.clock()
        query = urlencode({"response_type": "code", "client_id": self.cfg.client_id, "redirect_uri": self.cfg.redirect_uri,
                           "scope": self.cfg.scope, "state": state})
        return f"{self.cfg.base_url}/oauth/authorize?{query}"

    def complete_authorization(self, code: str, state: str) -> None:
        """Called with what the vendor put on the redirect. A state we did not issue (or issued too long ago, or already used)
        means the redirect did not come from our own request, so the code is not exchanged."""
        with self._states_mu:
            issued = self._states.pop(state, None)
        if issued is None or self.clock() - issued > self.cfg.state_ttl:
            raise OAuthStateError("the state parameter does not match a pending authorization")
        register_secret(code)
        payload = self._token_request({"grant_type": "authorization_code", "code": code, "redirect_uri": self.cfg.redirect_uri})
        self._store_tokens(payload, fallback_refresh=None)

    # -- tokens ---------------------------------------------------------------------------------------------------------------
    def is_connected(self) -> bool:
        st = self.store.get_oauth()
        return bool(st and st["refresh_token_enc"] and st["status"] == "ok")

    def _require_connected(self, st: dict | None) -> dict:
        if not st or not st["refresh_token_enc"]:
            raise ReauthRequired("no grant: the connector has not been authorized")
        if st["status"] != "ok":
            raise ReauthRequired(f"the grant needs a new authorization ({st['status']})")
        return st

    def _store_tokens(self, payload: dict, fallback_refresh: str | None) -> None:
        access = payload.get("access_token")
        expires_in = payload.get("expires_in")
        refresh = payload.get("refresh_token") or fallback_refresh
        if not (isinstance(access, str) and access and isinstance(expires_in, (int, float)) and not isinstance(expires_in, bool)
                and expires_in > 0 and isinstance(refresh, str) and refresh):
            raise VendorError(502, "malformed_token_response", "the token answer is missing a field")
        register_secret(access)
        register_secret(refresh)
        now = self.clock()
        self.store.set_oauth(self.vault.encrypt(access), self.vault.encrypt(refresh), now + float(expires_in),
                             str(payload.get("scope") or self.cfg.scope), now)

    def _token_request(self, data: dict) -> dict:
        attempt = 0
        while True:
            attempt += 1
            try:
                resp = self.http.post("/oauth/token", data=data, auth=(self.cfg.client_id, self.cfg.client_secret))
            except httpx.TransportError as exc:
                self._retry_or_raise(attempt, None, f"network error: {exc.__class__.__name__}")
                continue
            if resp.status_code == 200:
                try:
                    return resp.json()
                except ValueError:
                    raise VendorError(502, "malformed_token_response", "the token answer is not JSON")
            if resp.status_code == 429 or resp.status_code >= 500:
                self._retry_or_raise(attempt, resp, f"token endpoint answered {resp.status_code}")
                continue
            error = _error_code(resp)
            if resp.status_code in (400, 401) and error in ("invalid_grant", "invalid_client"):
                self.store.set_oauth_status("needs_reauth", error)
                raise ReauthRequired(error)
            raise VendorError(resp.status_code, error or "token_error")

    def _retry_or_raise(self, attempt: int, resp: httpx.Response | None, what: str) -> None:
        wait = parse_retry_after(resp.headers.get("retry-after"), self.clock()) if resp is not None and resp.status_code == 429 else None
        if resp is not None and resp.status_code == 429 and wait is not None and wait > self.cfg.max_retry_after:
            raise RateLimited(wait)
        if attempt >= self.cfg.max_attempts:
            self.store.set_oauth_status(None, f"refresh_failed: {what}")
            if resp is not None and resp.status_code == 429:
                raise RateLimited(wait or 0)
            raise VendorUnavailable(what)
        self.sleep(wait if wait is not None else backoff_delay(attempt, self.cfg.base_delay, self.cfg.max_delay, self.rng))

    def refresh(self, rejected: str | None = None) -> None:
        """Refresh the access token. `rejected` is a token the vendor just refused with a 401: if the stored token is already a
        different one, someone else refreshed while this caller waited for the lock, and nothing more is needed."""
        with self._refresh_lock:
            st = self._require_connected(self.store.get_oauth())
            current = self.vault.decrypt(st["access_token_enc"])
            needed = (current == rejected) if rejected is not None else (st["expires_at"] - self.cfg.refresh_skew <= self.clock())
            if not needed:
                return
            old_refresh = self.vault.decrypt(st["refresh_token_enc"])
            payload = self._token_request({"grant_type": "refresh_token", "refresh_token": old_refresh})
            self._store_tokens(payload, fallback_refresh=old_refresh)
            self.refreshes += 1
            log.info("access token refreshed")

    def access_token(self) -> str:
        st = self._require_connected(self.store.get_oauth())
        if st["expires_at"] - self.cfg.refresh_skew <= self.clock():
            self.refresh()
            st = self._require_connected(self.store.get_oauth())
        return self.vault.decrypt(st["access_token_enc"])

    # -- requests ---------------------------------------------------------------------------------------------------------------
    def request(self, method: str, path: str, *, params: dict | None = None, json: dict | None = None,
                idempotency_key: str | None = None, max_attempts: int | None = None) -> httpx.Response:
        limit = max_attempts or self.cfg.max_attempts
        replay_safe = method.upper() in ("GET", "HEAD", "DELETE", "PUT") or bool(idempotency_key)
        refreshed = False
        attempt = 0
        while True:
            attempt += 1
            token = self.access_token()
            headers = {"Authorization": f"Bearer {token}"}
            if idempotency_key:
                headers["Idempotency-Key"] = idempotency_key
            try:
                resp = self.http.request(method, path, params=params, json=json, headers=headers)
            except httpx.TransportError as exc:
                if not replay_safe or attempt >= limit:
                    raise VendorUnavailable(f"network error: {exc.__class__.__name__}") from None
                self.sleep(backoff_delay(attempt, self.cfg.base_delay, self.cfg.max_delay, self.rng))
                continue
            status = resp.status_code
            if status < 400:
                return resp
            if status == 401:
                if refreshed:
                    self.store.set_oauth_status("needs_reauth", "token_rejected_after_refresh")
                    raise ReauthRequired("the vendor rejected a freshly refreshed token")
                refreshed = True
                attempt -= 1
                self.refresh(rejected=token)
                continue
            if status == 429:
                wait = parse_retry_after(resp.headers.get("retry-after"), self.clock())
                if wait is not None and wait > self.cfg.max_retry_after:
                    raise RateLimited(wait)
                if attempt >= limit:
                    raise RateLimited(wait if wait is not None else 0.0)
                self.sleep(wait if wait is not None else backoff_delay(attempt, self.cfg.base_delay, self.cfg.max_delay, self.rng))
                continue
            if status >= 500:
                if not replay_safe or attempt >= limit:
                    raise VendorUnavailable(f"vendor answered {status}")
                self.sleep(backoff_delay(attempt, self.cfg.base_delay, self.cfg.max_delay, self.rng))
                continue
            code = _error_code(resp) or "error"
            if status == 403:
                self.store.set_oauth_status(None, f"{code}:{_field(resp, 'required_scope')}")
            raise VendorError(status, code, _field(resp, "error_description") or "")


def _json(resp: httpx.Response) -> dict:
    try:
        data = resp.json()
        return data if isinstance(data, dict) else {}
    except ValueError:
        return {}


def _error_code(resp: httpx.Response) -> str | None:
    value = _json(resp).get("error")
    return value if isinstance(value, str) else None


def _field(resp: httpx.Response, name: str) -> str | None:
    value = _json(resp).get(name)
    return value if isinstance(value, str) else None
