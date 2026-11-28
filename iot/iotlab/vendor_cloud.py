"""A stand-in for a smart lock MANUFACTURER'S cloud API, written from the contract in iot/docs/contract.md.

It is not any real vendor's API and no real vendor was contacted. It reproduces the behaviour an integration has to cope with:
OAuth 2.0 authorization code with rotating refresh tokens and short access tokens, rate limiting with Retry-After, lock objects
whose fields are named and typed differently from lock to lock, temporary access codes with a validity window, an HMAC signed
webhook that is delivered at least once, and an event feed to poll when a webhook was missed. It talks to the locks through the
same MQTT broker the locks use, so a command given here really goes out as an MQTT message.

The /_lab routes inject faults. They are for the tests and are not part of the contract.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import queue
import secrets
import threading
import time
import uuid
from dataclasses import dataclass
from email.utils import format_datetime
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlencode

import httpx
import paho.mqtt.client as mqtt
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response

from .util import iso, parse_ts

SCOPES = ("locks:read", "locks:write", "codes:read", "codes:write", "webhooks:write")
SIGNATURE_HEADER = "X-Vendor-Signature"
TIMESTAMP_HEADER = "X-Vendor-Timestamp"
EVENT_ID_HEADER = "X-Vendor-Event-Id"


def sign(secret: str, timestamp: int | str, body: bytes) -> str:
    """The signature the contract defines: v1=hex(HMAC-SHA256(secret, "<timestamp>.<raw body>"))."""
    mac = hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()
    return f"v1={mac}"


class ApiError(Exception):
    def __init__(self, status: int, code: str, description: str = "", headers: dict | None = None, extra: dict | None = None):
        self.status, self.code, self.description, self.headers, self.extra = status, code, description, headers or {}, extra or {}


@dataclass
class VendorConfig:
    client_id: str = "connector-app"
    client_secret: str = ""
    redirect_uris: tuple[str, ...] = ("http://127.0.0.1:9/callback",)
    access_ttl: float = 3600
    refresh_ttl: float = 30 * 86400
    code_ttl: float = 60
    rate_limit: tuple[int, float] = (100, 60.0)       # requests per window per access token
    delivery_attempts: int = 4
    delivery_backoff: float = 0.5
    command_timeout: float = 30
    max_codes_per_lock: int = 4
    max_code_days: int = 30
    event_retention: int = 1000
    page_size: int = 50


@dataclass
class VLock:
    id: str
    name: str
    shape: str = "a"
    firmware: str | None = "1.4.2"
    state: str | None = None
    online: bool | None = None
    battery: int | None = None
    battery_low: bool = False
    updated_at: float | None = None
    seq: int = 0


class VendorCloud:
    def __init__(self, config: VendorConfig, clock=time.time):
        self.cfg = config
        self.clock = clock
        self.mu = threading.RLock()
        self.locks: dict[str, VLock] = {}
        self.auth_codes: dict[str, dict] = {}
        self.access: dict[str, dict] = {}
        self.refresh: dict[str, dict] = {}
        self.families: dict[str, dict] = {}
        self.windows: dict[str, list] = {}
        self.commands: dict[str, dict] = {}
        self.idem: dict[tuple, dict] = {}
        self.codes: dict[str, dict] = {}
        self.events: list[dict] = []
        self.gseq = 0
        self.webhook: dict | None = None
        self.deliveries: list[dict] = []
        self.sent_log: dict[str, dict] = {}              # event id -> the exact first delivery (timestamp, body, signature)
        self.faults: dict = {"down": False, "retry_after_format": "seconds", "drop_webhooks": False, "webhook_secret_drift": False,
                             "duplicate_deliveries": False, "fail_after_commit": 0, "rate_limit_hard": 0, "api_down": False, "token_down": False}
        self.mqtt: mqtt.Client | None = None
        self._queue: "queue.Queue[dict | None]" = queue.Queue()
        self._stop = threading.Event()
        self._worker = threading.Thread(target=self._deliver_loop, daemon=True)
        self._worker.start()

    # -- setup ------------------------------------------------------------------------------------------------------------
    def add_lock(self, lock_id: str, name: str, shape: str = "a", firmware: str | None = "1.4.2") -> None:
        with self.mu:
            self.locks[lock_id] = VLock(lock_id, name, shape, firmware)

    def attach_mqtt(self, host: str, port: int, username: str, password: str) -> None:
        c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="vendor-cloud")
        c.username_pw_set(username, password)
        c.reconnect_delay_set(min_delay=1, max_delay=2)

        def on_connect(client, userdata, flags, rc, props=None):
            if rc == 0:
                for leaf in ("state", "status", "event"):
                    client.subscribe(f"locks/+/{leaf}", qos=1)

        c.on_connect = on_connect
        c.on_message = self._on_mqtt
        c.connect(host, port, keepalive=5)
        c.loop_start()
        self.mqtt = c

    def close(self) -> None:
        self._stop.set()
        self._queue.put(None)
        if self.mqtt:
            self.mqtt.disconnect()
            self.mqtt.loop_stop()
        self._worker.join(timeout=3)

    # -- mqtt side --------------------------------------------------------------------------------------------------------
    def _on_mqtt(self, client, userdata, msg) -> None:
        parts = msg.topic.split("/")
        if len(parts) != 3 or parts[0] != "locks" or parts[1] not in self.locks:
            return
        lock_id, leaf = parts[1], parts[2]
        payload = msg.payload.decode(errors="replace")
        with self.mu:
            lk = self.locks[lock_id]
            if leaf == "status":
                online = payload == "online"
                was = lk.online
                lk.online = online
                lk.updated_at = self.clock()
                if was is not None and was != online:
                    self._emit("lock.online" if online else "lock.offline", lk, {})
                elif was is None and not online:
                    self._emit("lock.offline", lk, {})
            elif leaf == "state":
                self._on_state(lk, payload)
            elif leaf == "event":
                try:
                    doc = json.loads(payload)
                except ValueError:
                    return
                if doc.get("type") == "battery_low":
                    self._emit("lock.battery_low", lk, {"battery": doc.get("battery")})

    def _on_state(self, lk: VLock, payload: str) -> None:
        try:
            doc = json.loads(payload)
            new = doc["lock"]
        except (ValueError, KeyError, TypeError):
            return
        prev = lk.state
        lk.battery = doc.get("battery") if isinstance(doc.get("battery"), int) else lk.battery
        lk.battery_low = bool(doc.get("battery_low"))
        lk.updated_at = self.clock()
        cmd = self.commands.get(doc.get("last_cmd") or "")
        if cmd and cmd["status"] == "pending" and cmd["lock_id"] == lk.id:
            cmd["status"] = "failed" if new == "jammed" else "confirmed"
            cmd["finished_at"] = self.clock()
            lk.state = new
            self._emit(f"lock.{new}", lk, {"state": new, "command_id": cmd["id"], "source": "remote"})
        elif new != prev:
            lk.state = new
            if prev is not None:                       # the first state after a restart is a sync, not a change
                self._emit(f"lock.{new}", lk, {"state": new, "source": "manual"})
        else:
            lk.state = new

    # -- events and webhook delivery ----------------------------------------------------------------------------------------
    def _emit(self, type_: str, lk: VLock, data: dict) -> dict:
        self.gseq += 1
        lk.seq += 1
        evt = {"id": f"evt_{uuid.uuid4().hex[:16]}", "type": type_, "lock_id": lk.id, "occurred_at": iso(self.clock()),
               "seq": self.gseq, "lock_seq": lk.seq, "data": data}
        self.events.append(evt)
        if len(self.events) > self.cfg.event_retention:
            del self.events[: len(self.events) - self.cfg.event_retention]
        if not self.faults["drop_webhooks"]:             # decided when the event happens, so a later change cannot revive it
            self._queue.put(evt)
        return evt

    def _deliver_loop(self) -> None:
        while not self._stop.is_set():
            evt = self._queue.get()
            if evt is None:
                return
            with self.mu:
                hook = dict(self.webhook) if self.webhook else None
            if not hook:
                continue
            if hook["events"] and evt["type"] not in hook["events"]:
                continue
            self._deliver(evt, hook)

    def _deliver(self, evt: dict, hook: dict, replay: bool = False) -> None:
        body = json.dumps(evt, separators=(",", ":")).encode()
        for attempt in range(1, self.cfg.delivery_attempts + 1):
            ts = int(self.clock())
            secret = hook["secret"] + ("-drifted" if self.faults["webhook_secret_drift"] else "")
            headers = {"Content-Type": "application/json", TIMESTAMP_HEADER: str(ts), SIGNATURE_HEADER: sign(secret, ts, body), EVENT_ID_HEADER: evt["id"]}
            self.sent_log.setdefault(evt["id"], {"timestamp": ts, "body": body, "signature": headers[SIGNATURE_HEADER]})
            record = {"event_id": evt["id"], "attempt": attempt, "at": iso(self.clock()), "status": None, "error": None}
            try:
                r = httpx.post(hook["url"], content=body, headers=headers, timeout=3)
                record["status"] = r.status_code
                ok = 200 <= r.status_code < 300
            except httpx.HTTPError as exc:
                record["error"] = exc.__class__.__name__
                ok = False
            with self.mu:
                self.deliveries.append(record)
                del self.deliveries[:-500]
            if ok:
                if self.faults["duplicate_deliveries"] and not replay:
                    self._deliver(evt, hook, replay=True)
                return
            if self._stop.wait(self.cfg.delivery_backoff * 2 ** (attempt - 1)):
                return

    def redeliver(self, event_id: str) -> None:
        """Send an event again with a fresh timestamp and signature (the vendor's own retry, so a duplicate)."""
        with self.mu:
            hook = dict(self.webhook) if self.webhook else None
            evt = next((e for e in self.events if e["id"] == event_id), None)
        if hook and evt:
            self._deliver(evt, hook, replay=True)

    def replay_captured(self, event_id: str) -> int:
        """Post the exact first delivery again: same timestamp, same signature. An attacker who captured it could do this."""
        with self.mu:
            hook = dict(self.webhook) if self.webhook else None
            sent = self.sent_log.get(event_id)
        if not hook or not sent:
            raise KeyError(event_id)
        headers = {"Content-Type": "application/json", TIMESTAMP_HEADER: str(sent["timestamp"]), SIGNATURE_HEADER: sent["signature"], EVENT_ID_HEADER: event_id}
        return httpx.post(hook["url"], content=sent["body"], headers=headers, timeout=3).status_code

    # -- auth -------------------------------------------------------------------------------------------------------------
    def _fault_down(self) -> None:
        if self.faults["down"]:
            raise ApiError(503, "service_unavailable", "the vendor cloud is down")

    def require(self, request: Request, scope: str) -> dict:
        self._fault_down()
        header = request.headers.get("authorization", "")
        if not header.lower().startswith("bearer "):
            raise ApiError(401, "invalid_token", "bearer token required", {"WWW-Authenticate": 'Bearer error="invalid_token"'})
        token = header[7:].strip()
        with self.mu:
            rec = self.access.get(token)
            now = self.clock()
            if rec is None or self.families.get(rec["family"], {}).get("revoked"):
                raise ApiError(401, "invalid_token", "unknown or revoked token", {"WWW-Authenticate": 'Bearer error="invalid_token"'})
            if rec["exp"] <= now:
                raise ApiError(401, "invalid_token", "the access token expired", {"WWW-Authenticate": 'Bearer error="invalid_token", error_description="expired"'})
            if self.faults["api_down"]:                    # the health route stays green while the API fails for everyone
                raise ApiError(503, "service_unavailable", "the API is failing")
            if scope not in self.families[rec["family"]]["scope"]:
                raise ApiError(403, "insufficient_scope", f"this token lacks {scope}", extra={"required_scope": scope})
            self._rate_limit(token, now)
            return rec

    def _rate_limit(self, token: str, now: float) -> None:
        limit, window = self.cfg.rate_limit
        hard = self.faults["rate_limit_hard"]
        win = self.windows.get(token)
        if win is None or now >= win[0] + window:
            win = self.windows[token] = [now, 0]
        win[1] += 1
        if hard or win[1] > limit:
            wait = max(1, math.ceil(win[0] + window - now))
            if hard:
                wait = int(hard)
            value = str(wait) if self.faults["retry_after_format"] == "seconds" else format_datetime(datetime.fromtimestamp(now + wait, tz=timezone.utc), usegmt=True)
            raise ApiError(429, "rate_limited", "too many requests", {"Retry-After": value})

    def issue_tokens(self, family: str, client_id: str) -> dict:
        now = self.clock()
        at, rt = "at_" + secrets.token_urlsafe(24), "rt_" + secrets.token_urlsafe(24)
        self.access[at] = {"family": family, "client": client_id, "exp": now + self.cfg.access_ttl}
        self.refresh[rt] = {"family": family, "client": client_id, "exp": now + self.cfg.refresh_ttl, "used": False}
        return {"access_token": at, "token_type": "Bearer", "expires_in": int(self.cfg.access_ttl), "refresh_token": rt,
                "scope": " ".join(sorted(self.families[family]["scope"]))}

    def revoke_family(self, family: str) -> None:
        if family in self.families:
            self.families[family]["revoked"] = True

    # -- lock rendering: the fields differ from lock to lock on purpose -------------------------------------------------------
    def render(self, lk: VLock) -> dict:
        upd = lk.updated_at
        if lk.shape == "a":
            doc = {"id": lk.id, "name": lk.name, "model": "L-100", "state": lk.state.upper() if lk.state else None, "battery_level": lk.battery,
                   "firmware": lk.firmware, "online": lk.online, "updated_at": int(upd) if upd else None}
        elif lk.shape == "b":
            doc = {"id": lk.id, "name": lk.name, "locked": None if lk.state is None else lk.state == "locked", "battery_pct": lk.battery,
                   "connected": lk.online, "updated_at": iso(upd) if upd else None}
            if lk.state == "jammed":
                doc["jammed"] = True
        else:
            doc = {"id": lk.id, "name": lk.name, "lock_state": lk.state, "online": None if lk.online is None else int(lk.online),
                   "fw": lk.firmware, "updated": iso(upd) if upd else None}
            if lk.battery is not None:
                doc["battery"] = f"{lk.battery}%"
        doc["seq"] = lk.seq
        return doc

    def code_view(self, c: dict) -> dict:
        now = self.clock()
        if c["revoked_at"] is not None:
            status = "revoked"
        elif now >= c["ends_at"]:
            status = "expired"
        elif now < c["starts_at"]:
            status = "scheduled"
        else:
            status = "active"
        return {"id": c["id"], "lock_id": c["lock_id"], "name": c["name"], "starts_at": iso(c["starts_at"]), "ends_at": iso(c["ends_at"]), "status": status}

    def command_view(self, cmd: dict) -> dict:
        status = cmd["status"]
        if status == "pending" and self.clock() - cmd["issued_at"] > self.cfg.command_timeout:
            status = "timed_out"
        return {"id": cmd["id"], "lock_id": cmd["lock_id"], "action": cmd["action"], "status": status}

    def _maybe_fail_after_commit(self) -> None:
        if self.faults["fail_after_commit"] > 0:
            self.faults["fail_after_commit"] -= 1
            raise ApiError(503, "service_unavailable", "the work was done but the answer was lost")


def _client_auth(cloud: VendorCloud, request: Request, form: dict) -> str:
    import base64
    cid = secret = None
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("basic "):
        try:
            cid, _, secret = base64.b64decode(auth[6:]).decode().partition(":")
        except ValueError:
            pass
    else:
        cid, secret = form.get("client_id"), form.get("client_secret")
    if cid != cloud.cfg.client_id or not secret or not hmac.compare_digest(secret, cloud.cfg.client_secret):
        raise ApiError(401, "invalid_client", "client authentication failed", {"WWW-Authenticate": "Basic"})
    return cid


def build_app(cloud: VendorCloud) -> FastAPI:
    app = FastAPI(title="vendor cloud stand-in", docs_url=None, redoc_url=None, openapi_url=None)

    @app.exception_handler(ApiError)
    async def _api_error(request: Request, exc: ApiError):
        body = {"error": exc.code, "error_description": exc.description, **exc.extra}
        return JSONResponse(body, status_code=exc.status, headers=exc.headers)

    # -- health and OAuth -----------------------------------------------------------------------------------------------
    @app.get("/healthz")
    def healthz():
        cloud._fault_down()
        return {"status": "ok"}

    @app.get("/oauth/authorize")
    def authorize(response_type: str = "", client_id: str = "", redirect_uri: str = "", scope: str = "", state: str = ""):
        cloud._fault_down()
        if client_id != cloud.cfg.client_id or redirect_uri not in cloud.cfg.redirect_uris:
            raise ApiError(400, "invalid_request", "unknown client or unregistered redirect_uri")   # never redirect to an unregistered address
        if response_type != "code":
            raise ApiError(400, "unsupported_response_type")
        asked = set(scope.split()) or set(SCOPES)
        granted = asked & set(SCOPES)
        if not granted:
            raise ApiError(400, "invalid_scope")
        code = "code_" + secrets.token_urlsafe(18)
        with cloud.mu:
            family = uuid.uuid4().hex
            cloud.families[family] = {"scope": set(granted), "revoked": False}
            cloud.auth_codes[code] = {"client": client_id, "redirect_uri": redirect_uri, "family": family, "exp": cloud.clock() + cloud.cfg.code_ttl, "used": False}
        sep = "&" if "?" in redirect_uri else "?"
        return RedirectResponse(redirect_uri + sep + urlencode({"code": code, "state": state}), status_code=302)

    @app.post("/oauth/token")
    async def token(request: Request):
        cloud._fault_down()
        if cloud.faults["token_down"]:
            raise ApiError(503, "service_unavailable", "the token endpoint is failing")
        form = dict(parse_qsl((await request.body()).decode(), keep_blank_values=True))   # no python-multipart needed
        cid = _client_auth(cloud, request, form)
        grant = form.get("grant_type")
        with cloud.mu:
            now = cloud.clock()
            if grant == "authorization_code":
                rec = cloud.auth_codes.get(form.get("code", ""))
                if not rec or rec["client"] != cid:
                    raise ApiError(400, "invalid_grant", "unknown authorization code")
                if rec["used"]:
                    cloud.revoke_family(rec["family"])            # a reused code means it leaked: kill what it produced
                    raise ApiError(400, "invalid_grant", "authorization code already used")
                if rec["exp"] <= now:
                    raise ApiError(400, "invalid_grant", "authorization code expired")
                if form.get("redirect_uri") != rec["redirect_uri"]:
                    raise ApiError(400, "invalid_grant", "redirect_uri does not match")
                rec["used"] = True
                return JSONResponse(cloud.issue_tokens(rec["family"], cid), headers={"Cache-Control": "no-store"})
            if grant == "refresh_token":
                rec = cloud.refresh.get(form.get("refresh_token", ""))
                if not rec or rec["client"] != cid or cloud.families.get(rec["family"], {}).get("revoked"):
                    raise ApiError(400, "invalid_grant", "unknown or revoked refresh token")
                if rec["used"]:
                    cloud.revoke_family(rec["family"])            # refresh tokens rotate: the old one coming back is a replay
                    raise ApiError(400, "invalid_grant", "refresh token already used")
                if rec["exp"] <= now:
                    raise ApiError(400, "invalid_grant", "refresh token expired")
                rec["used"] = True
                return JSONResponse(cloud.issue_tokens(rec["family"], cid), headers={"Cache-Control": "no-store"})
        raise ApiError(400, "unsupported_grant_type")

    # -- locks ------------------------------------------------------------------------------------------------------------
    @app.get("/v1/locks")
    def list_locks(request: Request, limit: int = 0, cursor: str = ""):
        cloud.require(request, "locks:read")
        size = limit or cloud.cfg.page_size
        with cloud.mu:
            ids = sorted(cloud.locks)
            start = int(cursor) if cursor.isdigit() else 0
            page = ids[start:start + size]
            nxt = str(start + size) if start + size < len(ids) else None
            return {"data": [cloud.render(cloud.locks[i]) for i in page], "next_cursor": nxt}

    def _lock(lock_id: str) -> VLock:
        lk = cloud.locks.get(lock_id)
        if lk is None:
            raise ApiError(404, "not_found", "no such lock")
        return lk

    @app.get("/v1/locks/{lock_id}")
    def get_lock(request: Request, lock_id: str):
        cloud.require(request, "locks:read")
        with cloud.mu:
            return cloud.render(_lock(lock_id))

    def _command(request: Request, lock_id: str, action: str):
        rec = cloud.require(request, "locks:write")
        key = request.headers.get("idempotency-key")
        with cloud.mu:
            lk = _lock(lock_id)
            if key and (rec["client"], key) in cloud.idem:
                return JSONResponse(cloud.idem[(rec["client"], key)], status_code=202)
            if lk.online is not True:
                raise ApiError(409, "lock_offline", "the lock is not connected")
            cmd = {"id": "cmd_" + uuid.uuid4().hex[:12], "lock_id": lock_id, "action": action, "status": "pending", "issued_at": cloud.clock()}
            cloud.commands[cmd["id"]] = cmd
            view = cloud.command_view(cmd)
            if key:
                cloud.idem[(rec["client"], key)] = view
        if cloud.mqtt:
            cloud.mqtt.publish(f"locks/{lock_id}/cmd", json.dumps({"cmd_id": cmd["id"], "action": action}), qos=1)
        cloud._maybe_fail_after_commit()
        return JSONResponse(view, status_code=202)

    @app.post("/v1/locks/{lock_id}/lock")
    def lock_it(request: Request, lock_id: str):
        return _command(request, lock_id, "lock")

    @app.post("/v1/locks/{lock_id}/unlock")
    def unlock_it(request: Request, lock_id: str):
        return _command(request, lock_id, "unlock")

    @app.get("/v1/commands/{command_id}")
    def get_command(request: Request, command_id: str):
        cloud.require(request, "locks:read")
        with cloud.mu:
            cmd = cloud.commands.get(command_id)
            if not cmd:
                raise ApiError(404, "not_found")
            return cloud.command_view(cmd)

    # -- temporary access codes -----------------------------------------------------------------------------------------------
    @app.post("/v1/locks/{lock_id}/codes")
    async def create_code(request: Request, lock_id: str):
        rec = cloud.require(request, "codes:write")
        try:
            body = await request.json()
            name = str(body["name"])[:60]
            starts, ends = parse_ts(body["starts_at"]), parse_ts(body["ends_at"])
        except (ValueError, KeyError, TypeError):
            raise ApiError(400, "invalid_request", "name, starts_at and ends_at are required")
        if starts is None or ends is None or ends <= starts:
            raise ApiError(400, "invalid_window", "ends_at must be after starts_at")
        if ends - starts > cloud.cfg.max_code_days * 86400:
            raise ApiError(400, "invalid_window", f"a code can last at most {cloud.cfg.max_code_days} days")
        key = request.headers.get("idempotency-key")
        with cloud.mu:
            _lock(lock_id)
            if key and (rec["client"], key) in cloud.idem:
                return JSONResponse(cloud.idem[(rec["client"], key)], status_code=201)
            live = [c for c in cloud.codes.values() if c["lock_id"] == lock_id and cloud.code_view(c)["status"] in ("active", "scheduled")]
            if len(live) >= cloud.cfg.max_codes_per_lock:
                raise ApiError(409, "code_slots_full", "the lock holds no more codes")
            used = {c["code"] for c in live}
            while True:
                pin = f"{secrets.randbelow(10**6):06d}"
                if pin not in used:
                    break
            code = {"id": "ac_" + uuid.uuid4().hex[:10], "lock_id": lock_id, "name": name, "code": pin, "starts_at": starts, "ends_at": ends, "revoked_at": None}
            cloud.codes[code["id"]] = code
            view = {**cloud.code_view(code), "code": pin, "starts_at": int(starts), "ends_at": int(ends)}   # the create answer uses epoch seconds, the list uses ISO
            if key:
                cloud.idem[(rec["client"], key)] = view
        cloud._maybe_fail_after_commit()
        return JSONResponse(view, status_code=201)

    @app.get("/v1/locks/{lock_id}/codes")
    def list_codes(request: Request, lock_id: str):
        cloud.require(request, "codes:read")
        with cloud.mu:
            _lock(lock_id)
            return {"data": [cloud.code_view(c) for c in cloud.codes.values() if c["lock_id"] == lock_id]}

    @app.delete("/v1/locks/{lock_id}/codes/{code_id}")
    def revoke_code(request: Request, lock_id: str, code_id: str):
        cloud.require(request, "codes:write")
        with cloud.mu:
            _lock(lock_id)
            c = cloud.codes.get(code_id)
            if not c or c["lock_id"] != lock_id:
                raise ApiError(404, "not_found", "no such code")
            if c["revoked_at"] is None:
                c["revoked_at"] = cloud.clock()
        return Response(status_code=204)

    # -- webhooks and the event feed --------------------------------------------------------------------------------------------
    @app.post("/v1/webhooks")
    async def register_webhook(request: Request):
        cloud.require(request, "webhooks:write")
        try:
            body = await request.json()
            url = str(body["url"])
        except (ValueError, KeyError, TypeError):
            raise ApiError(400, "invalid_request", "url is required")
        if not url.startswith(("http://127.0.0.1", "https://")):
            raise ApiError(400, "invalid_request", "the url must be https (loopback http is allowed in the lab)")
        with cloud.mu:
            cloud.webhook = {"id": "wh_" + uuid.uuid4().hex[:8], "url": url, "events": body.get("events") or [], "secret": "whsec_" + secrets.token_urlsafe(24)}
            return JSONResponse({"id": cloud.webhook["id"], "url": url, "secret": cloud.webhook["secret"]}, status_code=201)

    @app.get("/v1/webhooks/{webhook_id}/deliveries")
    def deliveries(request: Request, webhook_id: str):
        cloud.require(request, "webhooks:write")
        with cloud.mu:
            if not cloud.webhook or cloud.webhook["id"] != webhook_id:
                raise ApiError(404, "not_found")
            return {"data": list(cloud.deliveries[-50:])}

    @app.get("/v1/events")
    def feed(request: Request, since_seq: int = 0, limit: int = 100):
        cloud.require(request, "locks:read")
        with cloud.mu:
            if cloud.events and since_seq and since_seq < cloud.events[0]["seq"] - 1:
                raise ApiError(410, "cursor_expired", "that part of the feed was dropped; read the locks instead")
            rows = [e for e in cloud.events if e["seq"] > since_seq][:limit]
            return {"data": rows, "latest_seq": cloud.gseq}

    # -- lab controls (not part of the contract) ----------------------------------------------------------------------------------
    @app.post("/_lab/faults")
    async def set_faults(request: Request):
        body = await request.json()
        with cloud.mu:
            for k, v in body.items():
                if k not in cloud.faults:
                    raise ApiError(400, "invalid_request", f"unknown fault {k}")
                cloud.faults[k] = v
            return cloud.faults

    @app.post("/_lab/action")
    async def lab_action(request: Request):
        body = await request.json()
        with cloud.mu:
            what = body.get("action")
            if what == "revoke_tokens":
                for f in cloud.families:
                    cloud.revoke_family(f)
            elif what == "strip_scopes":
                for f in cloud.families.values():
                    f["scope"] -= set(body.get("scopes", []))
            else:
                raise ApiError(400, "invalid_request", "unknown action")
        return {"ok": True}

    return app
