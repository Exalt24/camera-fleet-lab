"""The connector: keeps the third party record in step with the vendor cloud and the locks.

Where each fact comes from, and what wins when two disagree:
  - webhook events and the polled event feed are the SAME stream. Each event has a vendor id (the dedupe key) and a per-lock
    sequence number. A projection is updated only by an event newer than the lock's sequence, so a duplicate, a replay and an
    event that arrives late change nothing.
  - the polled event cursor is advanced only by polling, never by a webhook. A webhook for event 10 arriving while events 8 and 9
    were missed must not move the cursor past them.
  - a snapshot (GET /v1/locks) cannot roll a lock back to an older sequence than a webhook already applied.
  - the lock's own MQTT messages fill separate columns (mqtt_*). The vendor view and the device view are both kept so that a
    disagreement can be seen, not averaged away.
  - a field the vendor leaves out is left as it was. It is never written as 0.
"""
from __future__ import annotations

import json
import time
import uuid

from ..util import iso, parse_ts
from . import webhook
from .crypto import CredentialVault
from .normalize import STATES, normalize_code, normalize_lock
from .safelog import SafeLogger, register_secret
from .store import Store
from .vendor_client import RateLimited, ReauthRequired, VendorClient, VendorError, VendorUnavailable
from .webhook import WebhookRejected

log = SafeLogger("lockbridge.sync")

LOW_BATTERY = 20
EVENT_STATE = {"lock.locked": "locked", "lock.unlocked": "unlocked", "lock.jammed": "jammed"}
ACTION_TARGET = {"lock": "locked", "unlock": "unlocked"}
MAX_PAGES = 1000


def _valid_event(evt) -> bool:
    return (isinstance(evt, dict) and isinstance(evt.get("id"), str) and evt["id"] and isinstance(evt.get("type"), str)
            and isinstance(evt.get("lock_id"), str) and evt["lock_id"] and isinstance(evt.get("seq"), int)
            and isinstance(evt.get("lock_seq"), int) and parse_ts(evt.get("occurred_at")) is not None)


class Connector:
    def __init__(self, store: Store, vault: CredentialVault, client: VendorClient, clock=time.time,
                 webhook_tolerance: float = webhook.DEFAULT_TOLERANCE, recent_window: float = 600.0):
        self.store, self.vault, self.client, self.clock = store, vault, client, clock
        self.tolerance = webhook_tolerance
        self.recent_window = recent_window

    # -- webhook ------------------------------------------------------------------------------------------------------------
    def register_webhook(self, public_url: str) -> str:
        resp = self.client.request("POST", "/v1/webhooks", json={"url": public_url}, idempotency_key=None)
        doc = resp.json()
        secret = doc.get("secret")
        if not isinstance(secret, str) or not secret:
            raise VendorError(502, "malformed_webhook_response", "no secret in the answer")
        register_secret(secret)
        self.store.set_secret("webhook_secret", self.vault.encrypt(secret))
        self.store.meta_set("webhook_id", doc.get("id", ""))
        return str(doc.get("id", ""))

    def receive_webhook(self, headers, body: bytes) -> dict:
        """Verify, then apply. Raises WebhookRejected(reason) for anything that is not a genuine, fresh, well formed event."""
        enc = self.store.get_secret("webhook_secret")
        if enc is None:
            self.store.meta_incr("webhook_rejected:no_secret")
            raise WebhookRejected("no_secret")
        try:
            webhook.verify(self.vault.decrypt(enc), headers, body, self.clock(), self.tolerance)
        except WebhookRejected as exc:
            self.store.meta_incr(f"webhook_rejected:{exc.reason}")
            log.warning("webhook rejected: %s", exc.reason)
            raise
        try:
            evt = json.loads(body)
        except ValueError:
            evt = None
        if not _valid_event(evt):
            self.store.meta_incr("webhook_rejected:malformed_body")
            raise WebhookRejected("malformed_body")
        self.store.meta_set("webhook_last_at", self.clock())
        self.store.meta_incr("webhook_received")
        result = self.apply_event(evt, "webhook")
        if result == "duplicate":
            self.store.meta_incr("webhook_duplicates")
        return {"result": result}

    def apply_event(self, evt: dict, source: str) -> str:
        """Returns applied, duplicate or stale. Recording the event and updating the lock happen in one transaction."""
        now = self.clock()
        data = evt.get("data") if isinstance(evt.get("data"), dict) else {}
        with self.store.transaction():
            fresh = self.store.insert_event(evt["id"], evt["lock_id"], evt["type"], parse_ts(evt["occurred_at"]), now, evt["seq"], source)
            if not fresh:
                return "duplicate"
            self.store.ensure_lock(evt["lock_id"])
            lock = self.store.get_lock(evt["lock_id"])
            cmd = data.get("command_id")
            if isinstance(cmd, str):
                self.store.settle_command(cmd, "failed" if evt["type"] == "lock.jammed" else "confirmed", source, now)
            if evt["lock_seq"] <= lock["lock_seq"]:
                return "stale"
            cols: dict = {"lock_seq": evt["lock_seq"], "synced_at": now}
            if evt["type"] in EVENT_STATE:
                cols["state"] = EVENT_STATE[evt["type"]]
            elif evt["type"] == "lock.offline":
                cols["online"] = 0
            elif evt["type"] == "lock.online":
                cols["online"] = 1
            elif evt["type"] == "lock.battery_low":
                level = data.get("battery")
                if isinstance(level, int) and not isinstance(level, bool) and 0 <= level <= 100:
                    cols["battery"] = level
                cols["battery_low"] = 1
            self.store.update_lock(evt["lock_id"], **cols)
            return "applied"

    # -- snapshot and reconcile ----------------------------------------------------------------------------------------------
    def sync_locks(self) -> int:
        cursor, pages, count = None, 0, 0
        while True:
            params = {"cursor": cursor} if cursor else {}
            doc = self.client.request("GET", "/v1/locks", params=params).json()
            for raw in doc.get("data") or []:
                lock = normalize_lock(raw)
                if lock is None:
                    self.store.meta_incr("locks_skipped_unreadable")
                    continue
                self._apply_snapshot(lock)
                count += 1
            nxt = doc.get("next_cursor")
            pages += 1
            if not nxt or nxt == cursor or pages >= MAX_PAGES:
                return count
            cursor = nxt

    def _apply_snapshot(self, lock: dict) -> None:
        self.store.ensure_lock(lock["id"])
        existing = self.store.get_lock(lock["id"])
        cols: dict = {"synced_at": self.clock()}
        if lock["name"]:
            cols["name"] = lock["name"]
        if lock["firmware"]:
            cols["firmware"] = lock["firmware"]
        seq = lock["seq"]
        if seq is None or seq >= existing["lock_seq"]:
            if lock["state"]:
                cols["state"] = lock["state"]
            if lock["online"] is not None:
                cols["online"] = int(lock["online"])
            if lock["battery"] is not None:
                cols["battery"] = lock["battery"]
                cols["battery_low"] = int(lock["battery"] <= LOW_BATTERY)
            if lock["vendor_updated_at"] is not None:
                cols["vendor_updated_at"] = lock["vendor_updated_at"]
            if seq is not None:
                cols["lock_seq"] = seq
        self.store.update_lock(lock["id"], **cols)

    def poll_events(self) -> dict:
        since = int(self.store.meta_get("event_cursor", "0"))
        counts = {"applied": 0, "duplicate": 0, "stale": 0, "expired": False}
        pages = 0
        while pages < MAX_PAGES:
            pages += 1
            try:
                doc = self.client.request("GET", "/v1/events", params={"since_seq": since}).json()
            except VendorError as exc:
                if exc.status == 410:
                    counts["expired"] = True      # the feed dropped what we missed; the snapshot that follows repairs the state
                    head = self.client.request("GET", "/v1/events", params={"since_seq": 0, "limit": 1}).json().get("latest_seq")
                    if isinstance(head, int):     # resume from the feed's head, read BEFORE the snapshot so nothing in between is skipped
                        self.store.meta_set("event_cursor", head)
                    return counts
                raise
            rows = [e for e in doc.get("data") or [] if _valid_event(e)]
            if not rows:
                break
            for evt in rows:
                counts[self.apply_event(evt, "poll")] += 1
                since = max(since, evt["seq"])
            self.store.meta_set("event_cursor", since)
            if len(rows) < 100:
                break
        return counts

    def reconcile(self) -> dict:
        """Poll the event feed, take a snapshot of the locks, then check the access codes. Records success or the error class."""
        started = self.clock()
        try:
            events = self.poll_events()
            locks = self.sync_locks()
            codes = self.sync_codes()
        except Exception as exc:
            self.store.meta_set("last_sync_error", _error_label(exc))
            raise
        self.store.meta_set("last_sync_at", self.clock())
        self.store.meta_set("last_sync_error", "")
        return {"events": events, "locks": locks, "codes": codes, "seconds": round(self.clock() - started, 3)}

    # -- commands -----------------------------------------------------------------------------------------------------------------
    def send_command(self, lock_id: str, action: str) -> dict:
        if action not in ACTION_TARGET:
            raise ValueError("action must be lock or unlock")
        resp = self.client.request("POST", f"/v1/locks/{lock_id}/{action}", idempotency_key=str(uuid.uuid4()))
        doc = resp.json()
        if not isinstance(doc.get("id"), str):
            raise VendorError(502, "malformed_command_response", "no command id")
        self.store.put_command(doc["id"], lock_id, action, "pending", self.clock())
        return self.store.get_command(doc["id"])

    def refresh_command(self, command_id: str) -> dict:
        """Ask the vendor what became of a command (the poll path for a confirmation that never arrived by webhook or MQTT)."""
        cmd = self.store.get_command(command_id)
        if cmd is None:
            raise KeyError(command_id)
        doc = self.client.request("GET", f"/v1/commands/{command_id}").json()
        status = doc.get("status")
        if status in ("confirmed", "failed", "timed_out"):
            self.store.settle_command(command_id, status, "poll", self.clock())
        return self.store.get_command(command_id)

    # -- access codes ---------------------------------------------------------------------------------------------------------------
    def create_code(self, lock_id: str, name: str, starts_at: float, ends_at: float, idempotency_key: str | None = None) -> dict:
        if ends_at <= starts_at:
            raise ValueError("ends_at must be after starts_at")
        resp = self.client.request("POST", f"/v1/locks/{lock_id}/codes", idempotency_key=idempotency_key or str(uuid.uuid4()),
                                   json={"name": name, "starts_at": iso(starts_at), "ends_at": iso(ends_at)})
        doc = resp.json()
        norm = normalize_code(doc)
        pin = doc.get("code")
        if norm is None or not isinstance(pin, str) or not pin:
            raise VendorError(502, "malformed_code_response", "the answer has no id or no code")
        register_secret(pin)
        self.store.update_lock(lock_id, synced_at=self.clock())      # a lock that has a code is a lock the code sync must visit
        self.store.put_code(norm["id"], lock_id, name, self.vault.encrypt(pin), norm["starts_at"] or starts_at, norm["ends_at"] or ends_at,
                            norm["status"] or "scheduled", "connector", self.clock())
        # The plaintext code is returned to the caller once, like the vendor returned it to us. The record keeps ciphertext only.
        return {"id": norm["id"], "lock_id": lock_id, "name": name, "code": pin, "starts_at": norm["starts_at"], "ends_at": norm["ends_at"],
                "status": norm["status"]}

    def code_plaintext(self, code_id: str) -> str | None:
        row = self.store.get_code(code_id)
        return self.vault.decrypt(row["code_enc"]) if row and row["code_enc"] else None

    def revoke_code(self, code_id: str) -> dict:
        row = self.store.get_code(code_id)
        if row is None:
            raise KeyError(code_id)
        try:
            self.client.request("DELETE", f"/v1/locks/{row['lock_id']}/codes/{code_id}")
        except VendorError as exc:
            if exc.status != 404:                 # already gone at the vendor is the state we wanted
                raise
        self.store.update_code(code_id, status="revoked", revoked_at=self.clock(), code_enc=None)
        return self.store.get_code(code_id)

    def sync_codes(self) -> dict:
        changed = healed = 0
        for lock in self.store.list_locks(managed_only=True):
            try:
                doc = self.client.request("GET", f"/v1/locks/{lock['id']}/codes").json()
            except VendorError as exc:
                if exc.status == 404:
                    continue
                raise
            seen = set()
            for raw in doc.get("data") or []:
                v = normalize_code(raw)
                if v is None or v["status"] is None:
                    self.store.meta_incr("codes_skipped_unreadable")
                    continue
                seen.add(v["id"])
                local = self.store.get_code(v["id"])
                if local is None:
                    self.store.put_code(v["id"], lock["id"], v["name"], None, v["starts_at"], v["ends_at"], v["status"], "vendor", self.clock())
                    changed += 1
                    continue
                if local["status"] == "revoked" and v["status"] in ("active", "scheduled"):
                    self.client.request("DELETE", f"/v1/locks/{lock['id']}/codes/{v['id']}")      # a revoke that did not reach the vendor
                    healed += 1
                    continue
                cols = {}
                if local["status"] != v["status"] and local["status"] != "revoked":
                    cols["status"] = v["status"]
                if v["status"] in ("expired", "revoked") and local["code_enc"]:
                    cols["code_enc"] = None            # a finished code is not kept
                if cols:
                    self.store.update_code(v["id"], **cols)
                    changed += 1
            for local in self.store.list_codes(lock["id"]):
                if local["id"] not in seen and local["status"] in ("active", "scheduled"):
                    self.store.update_code(local["id"], status="missing")
                    changed += 1
        self.store.meta_set("last_code_sync_at", self.clock())
        self.store.meta_set("last_code_sync_error", "")
        return {"changed": changed, "healed": healed}

    # -- the locks' own MQTT messages -----------------------------------------------------------------------------------------------
    def on_mqtt_state(self, lock_id: str, doc) -> None:
        if not isinstance(doc, dict) or doc.get("lock") not in STATES:
            self.store.meta_incr("mqtt_malformed")
            return
        battery = doc.get("battery")
        cols = {"mqtt_state": doc["lock"], "mqtt_seen_at": self.clock()}
        if isinstance(battery, int) and not isinstance(battery, bool) and 0 <= battery <= 100:
            cols["mqtt_battery"] = battery
        self.store.update_lock(lock_id, **cols)
        self.store.meta_set("mqtt_last_message_at", self.clock())
        cmd = self.store.get_command(doc["last_cmd"]) if isinstance(doc.get("last_cmd"), str) else None
        if cmd and cmd["lock_id"] == lock_id:
            ok = doc["lock"] == ACTION_TARGET.get(cmd["action"])
            self.store.settle_command(cmd["id"], "confirmed" if ok else "failed", "mqtt", self.clock())

    def on_mqtt_status(self, lock_id: str, payload: str) -> None:
        if payload not in ("online", "offline"):
            self.store.meta_incr("mqtt_malformed")
            return
        self.store.update_lock(lock_id, mqtt_online=int(payload == "online"), mqtt_seen_at=self.clock())
        self.store.meta_set("mqtt_last_message_at", self.clock())

    # -- diagnostics (no secret ever appears here) ------------------------------------------------------------------------------------
    def _probe(self, method: str, path: str, **kw):
        try:
            resp = self.client.request(method, path, max_attempts=1, **kw)
            return {"ok": True, "status": resp.status_code, "error": None, "retry_after": None}, resp
        except ReauthRequired as exc:
            return {"ok": False, "status": 401, "error": "reauth_required", "retry_after": None, "detail": exc.description}, None
        except RateLimited as exc:
            return {"ok": False, "status": 429, "error": "rate_limited", "retry_after": exc.retry_after}, None
        except VendorError as exc:
            return {"ok": False, "status": exc.status, "error": exc.code, "retry_after": None}, None
        except VendorUnavailable as exc:
            return {"ok": False, "status": None, "error": "unavailable", "retry_after": None, "detail": str(exc)}, None

    def _vendor_probes(self, lock_id: str | None) -> dict:
        """Live, read only calls with one attempt each, so a diagnosis never waits on a retry loop. Run first, because a probe can itself
        change the OAuth record (a 401 that cannot be refreshed ends the grant) and the record is read after."""
        vendor: dict = {"lock_view": None, "deliveries": None}
        locks_probe, resp = self._probe("GET", "/v1/locks", params={"limit": 50})
        vendor["locks"] = locks_probe
        if resp is not None and lock_id:
            for raw in resp.json().get("data") or []:
                if raw.get("id") == lock_id:
                    vendor["lock_view"] = normalize_lock(raw)
        if lock_id:
            vendor["codes"] = self._probe("GET", f"/v1/locks/{lock_id}/codes")[0]
        wid = self.store.meta_get("webhook_id")
        if wid and locks_probe["ok"]:
            probe, dresp = self._probe("GET", f"/v1/webhooks/{wid}/deliveries")
            if dresp is not None:
                rows = dresp.json().get("data") or []
                failing = [r for r in rows if not (isinstance(r.get("status"), int) and 200 <= r["status"] < 300)]
                last = rows[-1] if rows else None
                vendor["deliveries"] = {"total": len(rows), "failed": len(failing), "last_status": last and last.get("status"),
                                        "last_error": last and last.get("error")}
            else:
                vendor["deliveries"] = {"error": probe["error"]}
        if locks_probe["ok"]:
            _, fresp = self._probe("GET", "/v1/events", params={"since_seq": self.store.max_event_seq(), "limit": 1})
            if fresp is not None:
                latest = fresp.json().get("latest_seq")
                vendor["events_behind"] = (latest - self.store.max_event_seq()) if isinstance(latest, int) else None
        return vendor

    def diagnostics(self, lock_id: str | None = None) -> dict:
        vendor = self._vendor_probes(lock_id)
        now = self.clock()
        oauth = self.store.get_oauth() or {}

        def age(key: str):
            value = self.store.meta_get(key)
            return round(now - float(value), 1) if value not in (None, "") else None

        pending = [{"id": c["id"], "lock_id": c["lock_id"], "action": c["action"], "age_s": round(now - c["issued_at"], 1)} for c in self.store.pending_commands()]
        since = now - self.recent_window
        lock = None
        if lock_id:
            row = self.store.get_lock(lock_id)
            lock = row and {k: row[k] for k in ("id", "state", "online", "battery", "lock_seq", "mqtt_state", "mqtt_online", "mqtt_battery")}
        return {
            "oauth": {"connected": bool(oauth.get("refresh_token_enc")), "status": oauth.get("status", "missing"), "last_error": oauth.get("last_error"),
                      "expires_in_s": round(oauth["expires_at"] - now, 1) if oauth.get("expires_at") else None, "scope": oauth.get("scope")},
            "sync": {"last_sync_age_s": age("last_sync_at"), "last_sync_error": self.store.meta_get("last_sync_error") or None,
                     "loop_tick_age_s": age("loop_tick_at"), "last_code_sync_age_s": age("last_code_sync_at")},
            "webhook": {"registered": self.store.get_secret("webhook_secret") is not None, "last_received_age_s": age("webhook_last_at"),
                        "received": int(self.store.meta_get("webhook_received", "0")),
                        "duplicates": int(self.store.meta_get("webhook_duplicates", "0")),
                        "rejected": {k: int(v) for k, v in self.store.meta_prefix("webhook_rejected:").items()},
                        "recent_by_source": {"webhook": self.store.count_events("webhook", since), "poll": self.store.count_events("poll", since)}},
            "commands": {"pending": pending},
            "mqtt": {"connected": self.store.meta_get("mqtt_connected") == "1", "last_message_age_s": age("mqtt_last_message_at")},
            "lock": lock,
            "vendor": vendor,
        }


def _error_label(exc: Exception) -> str:
    """A class name and a short code, never the message (a message can carry a url or a header)."""
    if isinstance(exc, VendorError):
        return f"{exc.__class__.__name__}:{exc.status}:{exc.code}"
    return exc.__class__.__name__
