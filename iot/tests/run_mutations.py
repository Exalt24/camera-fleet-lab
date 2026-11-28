#!/usr/bin/env python3
"""Mutation controls for the IoT slice: every guard is broken, one at a time, and a test must go red.

For each mutant this copies the iot/ tree (code, tests, broker config) to a temp folder, changes ONE thing in ONE file of the copy, points the
tests at the copy (IOT_SRC) and runs pytest on the tests that are meant to notice. A mutant is CAUGHT when pytest fails. A mutant that leaves
those tests green means a test is missing, and this script exits 1. The broker is a real mosquitto container, started once and shared (the
three broker CONFIG mutants start their own, from the mutated config).

  offline   connector, vendor stand-in and helper guards: needs no Docker
  sim       the lock simulator: needs Docker
  diagnose  the diagnosis tool's branches: needs Docker
  broker    the mosquitto config (anonymous access, per lock topics, the connector user): needs Docker

    python iot/tests/run_mutations.py [--group offline|sim|diagnose|broker|all] [--jobs N] [--only TEXT] [--check-anchors] [--save FILE]
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
IOT = HERE.parent
sys.path.insert(0, str(IOT))

WEBHOOK = ["tests/test_webhook_verify.py"]
CLIENT = ["tests/test_vendor_client.py"]
UNITS = ["tests/test_crypto_store_normalize.py"]
FLOWS = ["tests/test_connector_flows.py", "tests/test_connector_scope.py", "tests/test_property.py"]
VENDOR = ["tests/test_vendor_cloud.py"]
LEAKS = ["tests/test_crypto_store_normalize.py", "tests/test_vendor_client.py", "tests/test_connector_flows.py"]

W = "iotlab/connector/webhook.py"
C = "iotlab/connector/vendor_client.py"
S = "iotlab/connector/sync.py"
ST = "iotlab/connector/store.py"
N = "iotlab/connector/normalize.py"
L = "iotlab/connector/safelog.py"
CR = "iotlab/connector/crypto.py"
V = "iotlab/vendor_cloud.py"
LS = "iotlab/lock_sim.py"
D = "iotlab/diagnose.py"
U = "iotlab/util.py"

# (name, file, old text, new text, tests, optional -k expression)
OFFLINE = [
    ("webhook: skip the signature check", W, "if not any(hmac.compare_digest(c, want) for c in candidates):", "if False:", WEBHOOK),
    ("webhook: skip the replay window", W, "if abs(now - int(ts_raw)) > tolerance:", "if False:", WEBHOOK),
    ("webhook: the window only looks at the past", W, "if abs(now - int(ts_raw)) > tolerance:", "if (now - int(ts_raw)) > tolerance:", WEBHOOK),
    ("webhook: the window edge is excluded", W, "if abs(now - int(ts_raw)) > tolerance:", "if abs(now - int(ts_raw)) >= tolerance:", WEBHOOK),
    ("webhook: compare the signature with ==", W, "hmac.compare_digest(c, want) for c in candidates", "c == want for c in candidates", WEBHOOK),
    ("webhook: accept any signature scheme", W, 'p.strip().startswith("v1=")', "True", WEBHOOK),
    ("webhook: only the first of several signatures", W, "any(hmac.compare_digest(c, want) for c in candidates)", "any(hmac.compare_digest(c, want) for c in candidates[:1])", WEBHOOK),
    ("webhook: no timestamp format check", W, "if not ts_raw.isdigit():", "if False:", WEBHOOK),
    ("webhook: the timestamp is not signed", W, 'f"{timestamp}.".encode() + body', "body", WEBHOOK),
    ("client: refresh even when another caller already did", C,
     'needed = (current == rejected) if rejected is not None else (st["expires_at"] - self.cfg.refresh_skew <= self.clock())', "needed = True", CLIENT),
    ("client: no lock around the refresh", C, "with self._refresh_lock:", "if True:", CLIENT),
    ("client: no skew, refresh only after expiry", C, 'if st["expires_at"] - self.cfg.refresh_skew <= self.clock():\n            self.refresh()',
     'if st["expires_at"] <= self.clock():\n            self.refresh()', CLIENT),
    ("client: keep the spent refresh token", C, 'refresh = payload.get("refresh_token") or fallback_refresh', 'refresh = fallback_refresh or payload.get("refresh_token")', CLIENT),
    ("client: invalid_grant does not end the grant", C, '                self.store.set_oauth_status("needs_reauth", error)\n                raise ReauthRequired(error)',
     "                raise ReauthRequired(error)", CLIENT),
    ("client: a 401 does not trigger a refresh", C, "self.refresh(rejected=token)\n                continue", "continue", CLIENT),
    ("client: Retry-After ignored on a 429", C,
     "self.sleep(wait if wait is not None else backoff_delay(attempt, self.cfg.base_delay, self.cfg.max_delay, self.rng))\n                continue\n            if status >= 500:",
     "self.sleep(backoff_delay(attempt, self.cfg.base_delay, self.cfg.max_delay, self.rng))\n                continue\n            if status >= 500:", CLIENT),
    ("client: no cap on a long Retry-After", C, "if wait is not None and wait > self.cfg.max_retry_after:\n                    raise RateLimited(wait)\n                if attempt >= limit:",
     "if False:\n                    raise RateLimited(wait)\n                if attempt >= limit:", CLIENT),
    ("client: backoff does not grow", C, "ceiling = min(cap, base * 2 ** (attempt - 1))", "ceiling = min(cap, base)", CLIENT),
    ("client: backoff has no jitter floor", C, "return rng(ceiling / 2, ceiling)", "return rng(0, ceiling)", CLIENT),
    ("client: retry every POST", C, 'replay_safe = method.upper() in ("GET", "HEAD", "DELETE", "PUT") or bool(idempotency_key)', "replay_safe = True", CLIENT),
    ("client: no Idempotency-Key header", C, 'if idempotency_key:\n                headers["Idempotency-Key"] = idempotency_key', 'if False:\n                headers["Idempotency-Key"] = idempotency_key', CLIENT),
    ("client: HTTP date Retry-After unsupported", C, "when = parsedate_to_datetime(text)", "return None", CLIENT),
    ("client: a negative Retry-After is accepted", C, "if text.isdigit():", 'if text.lstrip("-").isdigit():', CLIENT),
    ("client: a past HTTP date waits a negative time", C, "return max(0.0, when.timestamp() - now)", "return when.timestamp() - now", CLIENT),
    ("client: the OAuth state is not checked", C, "if issued is None or self.clock() - issued > self.cfg.state_ttl:", "if False:", CLIENT),
    ("client: the OAuth state never expires", C, "or self.clock() - issued > self.cfg.state_ttl:", "or False:", CLIENT),
    ("client: the OAuth state can be used twice", C, "issued = self._states.pop(state, None)", "issued = self._states.get(state)", CLIENT),
    ("client: a malformed token answer is stored", C, "if not (isinstance(access, str) and access and isinstance(expires_in, (int, float)) and not isinstance(expires_in, bool)",
     "if False and (isinstance(access, str) and access and isinstance(expires_in, (int, float)) and not isinstance(expires_in, bool)", CLIENT),
    ("client: a 4xx is retried", C, "if status >= 500:\n                if not replay_safe or attempt >= limit:", "if status >= 400:\n                if not replay_safe or attempt >= limit:", CLIENT),
    ("client: a missing scope is not recorded", C, "if status == 403:\n                self.store.set_oauth_status(", "if False:\n                self.store.set_oauth_status(", CLIENT),
    ("client: a rejected fresh token does not end the grant", C, 'self.store.set_oauth_status("needs_reauth", "token_rejected_after_refresh")', "pass", CLIENT),
    ("client: an outage during refresh kills the grant", C, 'self.store.set_oauth_status(None, f"refresh_failed: {what}")', 'self.store.set_oauth_status("needs_reauth", f"refresh_failed: {what}")', CLIENT),
    ("log: registered secrets are not masked", L, "text = text.replace(s, MASK)", "pass", UNITS),
    ("log: token shaped text is not masked", L, "for pat in _PATTERNS:", "for pat in []:", UNITS),
    ("log: the logger skips redaction", L, 'self._log.log(level, "%s", redact(text))', 'self._log.log(level, "%s", text)', UNITS),
    ("log: a very short value is registered as a secret", L, "if value and len(value) >= 4:", "if value:", UNITS),
    ("vault: encrypt returns the plaintext", CR, 'return self._multi.encrypt(plaintext.encode("utf-8")).decode("ascii")', "return plaintext", UNITS),
    ("vault: rotate keeps the old ciphertext", CR, 'return self._multi.rotate(token.encode("ascii")).decode("ascii")', "return token", UNITS),
    ("store: a duplicate event is accepted", ST, "INSERT OR IGNORE INTO events", "INSERT OR REPLACE INTO events", UNITS),
    ("store: a settled command can be overwritten", ST, "WHERE id = ? AND status = 'pending'", "WHERE id = ?", UNITS),
    ("store: a failed transaction commits", ST, 'self._db.execute("ROLLBACK")', 'self._db.execute("COMMIT")', UNITS),
    ("normalize: a missing battery reads as 0", N, "            return int(round(v))\n    return None", "            return int(round(v))\n    return 0", UNITS),
    ("normalize: an out of range battery is kept", N, "if isinstance(v, (int, float)) and 0 <= v <= 100:", "if isinstance(v, (int, float)):", UNITS),
    ("normalize: a bool counts as a battery", N, "if isinstance(v, bool) or v is None:", "if v is None:", UNITS),
    ("normalize: the jammed flag is ignored", N, 'if raw.get("jammed") is True:\n        return "jammed"', 'if False:\n        return "jammed"', UNITS),
    ("normalize: state spelling is case sensitive", N, "v.strip().lower() in STATES", "v.strip() in STATES", UNITS),
    ("util: an unknown time reads as 1970", U, "return float(value) if value > 0 else None", "return float(value)", UNITS),
    ("sync: a stale event overwrites a newer state", S, 'if evt["lock_seq"] <= lock["lock_seq"]:', "if False:", FLOWS),
    ("sync: a snapshot rolls a lock back", S, 'if seq is None or seq >= existing["lock_seq"]:', "if True:", FLOWS),
    ("sync: a webhook moves the poll cursor", S, 'self.store.update_lock(evt["lock_id"], **cols)\n            return "applied"',
     'self.store.update_lock(evt["lock_id"], **cols)\n            self.store.meta_set("event_cursor", evt["seq"])\n            return "applied"', FLOWS),
    ("sync: an expired feed (410) is not handled", S, "if exc.status == 410:", "if False:", FLOWS),
    ("sync: an expired feed does not move the cursor", S, 'self.store.meta_set("event_cursor", head)', "pass", FLOWS),
    ("sync: only the first page of locks", S, 'nxt = doc.get("next_cursor")', "nxt = None", FLOWS),
    ("sync: webhook verification skipped", S, "webhook.verify(self.vault.decrypt(enc), headers, body, self.clock(), self.tolerance)", "pass", FLOWS),
    ("sync: the replay window is ignored", S, "self.clock(), self.tolerance)", "self.clock(), 10**9)", FLOWS),
    ("sync: rejections are not counted", S, 'self.store.meta_incr(f"webhook_rejected:{exc.reason}")', "pass", FLOWS),
    ("sync: a lock command without an idempotency key", S, 'f"/v1/locks/{lock_id}/{action}", idempotency_key=str(uuid.uuid4()))', 'f"/v1/locks/{lock_id}/{action}")', FLOWS),
    ("sync: a code create without an idempotency key", S, "idempotency_key=idempotency_key or str(uuid.uuid4()),", "idempotency_key=idempotency_key,", FLOWS),
    ("sync: a revoked code keeps its ciphertext", S, 'self.store.update_code(code_id, status="revoked", revoked_at=self.clock(), code_enc=None)',
     'self.store.update_code(code_id, status="revoked", revoked_at=self.clock())', FLOWS),
    ("sync: revoking a code the vendor lost fails", S, "if exc.status != 404:", "if True:", FLOWS),
    ("sync: a revoke that did not reach the vendor is not repeated", S, 'if local["status"] == "revoked" and v["status"] in ("active", "scheduled"):', "if False:", FLOWS),
    ("sync: a vanished code is not flagged", S, 'self.store.update_code(local["id"], status="missing")', "pass", FLOWS),
    ("sync: codes are synced for locks the vendor never listed", S, "for lock in self.store.list_locks(managed_only=True):", "for lock in self.store.list_locks():", FLOWS),
    ("sync: an expired code keeps its ciphertext", S, 'if v["status"] in ("expired", "revoked") and local["code_enc"]:', "if False:", FLOWS),
    ("sync: codes made at the vendor are ignored", S, 'self.store.put_code(v["id"], lock["id"], v["name"], None, v["starts_at"], v["ends_at"], v["status"], "vendor", self.clock())', "pass", FLOWS),
    ("sync: malformed MQTT state is accepted", S, 'if not isinstance(doc, dict) or doc.get("lock") not in STATES:', "if not isinstance(doc, dict):", FLOWS),
    ("sync: an echo from another lock settles the command", S, 'if cmd and cmd["lock_id"] == lock_id:', "if cmd:", FLOWS),
    ("sync: a jam over MQTT counts as confirmed", S, 'ok = doc["lock"] == ACTION_TARGET.get(cmd["action"])', "ok = True", FLOWS),
    ("sync: a jam event counts as confirmed", S, '"failed" if evt["type"] == "lock.jammed" else "confirmed"', '"confirmed"', FLOWS),
    ("sync: the battery_low flag is not set", S, 'cols["battery_low"] = 1', "pass", FLOWS),
    ("sync: an offline event is ignored", S, 'elif evt["type"] == "lock.offline":\n                cols["online"] = 0', 'elif evt["type"] == "lock.offline":\n                pass', FLOWS),
    ("sync: an unreadable lock is not counted", S, 'self.store.meta_incr("locks_skipped_unreadable")', "pass", FLOWS),
    ("sync: an event with a text sequence is accepted", S, 'and isinstance(evt.get("seq"), int)', "and True", FLOWS),
    ("vendor: a replayed refresh token is accepted", V, 'raise ApiError(400, "invalid_grant", "refresh token already used")', "pass", VENDOR),
    ("vendor: a replayed code does not revoke what it made", V, "cloud.revoke_family(rec[\"family\"])            # a reused code means it leaked: kill what it produced", "pass", VENDOR),
    ("vendor: an unregistered redirect is accepted", V, "or redirect_uri not in cloud.cfg.redirect_uris", "or False", VENDOR),
    ("vendor: the redirect at the token step is not checked", V, 'if form.get("redirect_uri") != rec["redirect_uri"]:', "if False:", VENDOR),
    ("vendor: an expired access token is accepted", V, 'if rec["exp"] <= now:\n                raise ApiError(401, "invalid_token", "the access token expired"',
     'if False:\n                raise ApiError(401, "invalid_token", "the access token expired"', VENDOR),
    ("vendor: scopes are not enforced", V, 'if scope not in self.families[rec["family"]]["scope"]:', "if False:", VENDOR),
    ("vendor: the rate limit never triggers", V, "if hard or win[1] > limit:", "if hard:", VENDOR),
    ("vendor: the client secret is not checked", V, "not hmac.compare_digest(secret, cloud.cfg.client_secret)", "False", VENDOR),
    ("vendor: a command idempotency key is ignored", V, 'if key and (rec["client"], key) in cloud.idem:\n                return JSONResponse(cloud.idem[(rec["client"], key)], status_code=202)',
     'if False:\n                return JSONResponse(cloud.idem[(rec["client"], key)], status_code=202)', VENDOR),
    ("vendor: a code idempotency key is ignored", V, 'if key and (rec["client"], key) in cloud.idem:\n                return JSONResponse(cloud.idem[(rec["client"], key)], status_code=201)',
     'if False:\n                return JSONResponse(cloud.idem[(rec["client"], key)], status_code=201)', VENDOR),
    ("vendor: a backwards code window is accepted", V, "if starts is None or ends is None or ends <= starts:", "if starts is None or ends is None:", VENDOR),
    ("vendor: the code slot limit is not enforced", V, "if len(live) >= cloud.cfg.max_codes_per_lock:", "if False:", VENDOR),
    ("vendor: a failed delivery is never retried", V, "for attempt in range(1, self.cfg.delivery_attempts + 1):", "for attempt in range(1, 2):", VENDOR),
    ("vendor: the event feed never answers 410", V, 'if cloud.events and since_seq and since_seq < cloud.events[0]["seq"] - 1:', "if False:", VENDOR),
    ("vendor: a command never times out", V, 'if status == "pending" and self.clock() - cmd["issued_at"] > self.cfg.command_timeout:', "if False:", VENDOR),
]

SIM_TESTS = ["tests/test_lock_sim_broker.py"]
SIM = [
    ("lock: no command dedupe", LS, "if cmd_id in self._seen:", "if False:", SIM_TESTS),
    ("lock: no last will", LS, 'self.client.will_set(topic(lock_id, "status"), "offline", qos=1, retain=True)', "pass", SIM_TESTS),
    ("lock: the last will is not retained", LS, 'self.client.will_set(topic(lock_id, "status"), "offline", qos=1, retain=True)',
     'self.client.will_set(topic(lock_id, "status"), "offline", qos=1, retain=False)', SIM_TESTS),
    ("lock: the online status is not retained", LS, 'client.publish(topic(self.lock_id, "status"), "online", qos=1, retain=True)',
     'client.publish(topic(self.lock_id, "status"), "online", qos=1, retain=False)', SIM_TESTS),
    ("lock: the state is not retained", LS, 'json.dumps(doc), qos=1, retain=True)', 'json.dumps(doc), qos=1, retain=False)', SIM_TESTS),
    ("lock: the battery report repeats while low", LS, "fire = low and not self._low_reported", "fire = low", SIM_TESTS),
    ("lock: a hung lock still answers", LS, "if self.hung:\n            return", "if False:\n            return", SIM_TESTS),
    ("lock: a jam is ignored", LS, 'self.lock_state = "jammed" if self.jammed else "unlocked"', 'self.lock_state = "unlocked"', SIM_TESTS),
    ("lock: a report changes the door and the battery", LS, 'if action in ("lock", "unlock"):\n                self.applied += 1', "if True:\n                self.applied += 1", SIM_TESTS),
    ("lock: garbage payloads are not ignored", LS, "except (ValueError, KeyError, TypeError):\n            return", "except (ValueError, KeyError):\n            return", SIM_TESTS),
]

DIAG_TESTS = ["tests/test_diagnose.py"]


def dk(expr: str) -> list:
    return [*DIAG_TESTS, "-k", expr]


DIAGNOSE = [
    ("diagnose: an unreachable broker is not distinguished", D, 'if kind == "unreachable":', "if False:", dk("stopped_broker")),
    ("diagnose: a refused login is not distinguished", D, 'if kind == "refused":', "if False:", dk("refuses_the_diagnosis_user")),
    ("diagnose: the message round trip is not required", D, "if ms is None:", "if False:", dk("cannot_route")),
    ("diagnose: the broker password is put in the evidence", D, 'where = {"host": t.broker_host, "port": t.broker_port}', 'where = {"host": t.broker_host, "port": t.broker_port, "password": t.broker_password}', dk("never_contains")),
    ("diagnose: the device is probed with the broker down", D, 'if broker.status != "ok":\n        return Layer("device", "unknown"', 'if False:\n        return Layer("device", "unknown"', dk("stopped_broker")),
    ("diagnose: a last will is not read as offline", D, 'if status[1] != "online":', "if False:", dk("link_died")),
    ("diagnose: a lock the broker never heard of is fine", D, "if status is None:", "if False:", dk("never_heard_of")),
    ("diagnose: a missing report echo is fine", D, "if echo is None:", "if False:", dk("does_not_read_commands")),
    ("diagnose: the probe sends a real unlock", D, '"action": "report"', '"action": "unlock"', dk("read_only")),
    ("diagnose: a low battery is not noted", D, "note = f\", battery LOW at {doc.get('battery')}%\" if doc.get(\"battery_low\") else \"\"", 'note = ""', dk("low_battery")),
    ("diagnose: an unreachable vendor is ignored", D, 'if resp is None:\n        return Layer("vendor_cloud", "fail"', 'if False:\n        return Layer("vendor_cloud", "fail"', dk("does_not_answer_at_all")),
    ("diagnose: a vendor 5xx is ignored", D, 'if resp.status_code >= 500:\n        return Layer("vendor_cloud"', 'if False:\n        return Layer("vendor_cloud"', dk("vendor_outage")),
    ("diagnose: rate limiting is not recognised", D, 'if probe.get("status") == 429:', "if False:", dk("rate_limits_this_app")),
    ("diagnose: a failing API behind a green health route is ignored", D, 'if probe.get("error") == "unavailable" or (probe.get("status") or 0) >= 500:', "if False:", dk("health_route_is_green")),
    ("diagnose: a vendor view that disagrees with the broker is ignored", D, 'if view and view["online"] is False and device is not None and device.status == "ok":', "if False:", dk("shows_an_online_lock_as_offline")),
    ("diagnose: an unauthorized connector is ignored", D, 'if not o["connected"]:', "if False:", dk("never_authorized")),
    ("diagnose: a dead grant status is ignored", D, 'if o["status"] != "ok":', "if False:", dk("revoked_grant")),
    ("diagnose: a missing scope is ignored", D, 'if codes.get("status") == 403:', "if False:", dk("lost_the_codes_scope")),
    ("diagnose: an unregistered webhook is ignored", D, 'if not w["registered"]:', "if False:", dk("never_registered")),
    ("diagnose: rejected deliveries are ignored", D, 'if w["rejected"]:', "if False:", dk("secret_mismatch")),
    ("diagnose: failing delivery attempts are ignored", D, 'if d.get("failed"):', "if False:", dk("cannot_reach")),
    ("diagnose: poll only events are ignored", D, "if (poll > 0 and hook == 0) or behind > 0:", "if False:", dk("stopped_delivering")),
    ("diagnose: an unreachable connector is ignored", D, 'if diag is None:\n        return Layer("connector", "fail"', 'if False:\n        return Layer("connector", "fail"', dk("connector_that_is_down")),
    ("diagnose: a stalled loop is ignored", D, 'if s["loop_tick_age_s"] is not None and s["loop_tick_age_s"] > t.stale_s:', "if False:", dk("stalled_reconcile")),
    ("diagnose: a failing reconcile is ignored", D, 'if s["last_sync_error"]:', "if False:", dk("keeps_failing")),
    ("diagnose: an old last sync is ignored", D, 'if s["last_sync_age_s"] is not None and s["last_sync_age_s"] > t.stale_s:', "if False:", dk("long_time")),
    ("diagnose: stuck commands are ignored", D, "if stuck:", "if False:", dk("stuck_pending")),
    ("diagnose: a down MQTT subscription is ignored", D, 'if not m["connected"]:', "if False:", dk("lost_its_mqtt")),
    ("diagnose: a stale record is ignored", D, 'if lock and view and view["online"] is True and lock["online"] == 0:', "if False:", dk("still_says_offline")),
    ("diagnose: the verdict is the last failure", D, 'broken = next((layer for layer in ordered if layer.status == "fail"), None)',
     'broken = next((layer for layer in reversed(ordered) if layer.status == "fail"), None)', dk("two_faults")),
    ("diagnose: codes_not_syncing skips the OAuth layer", D, '"codes_not_syncing": ["vendor_cloud", "oauth", "connector"],', '"codes_not_syncing": ["vendor_cloud", "connector"],', dk("revoked_grant or lost_the_codes_scope")),
    ("diagnose: webhook_silence skips the webhook layer", D, '"webhook_silence": ["vendor_cloud", "oauth", "webhook", "connector"],', '"webhook_silence": ["vendor_cloud", "oauth", "connector"],', dk("secret_mismatch or stopped_delivering")),
]

# (name, file, old, new, tests): the mutated config is given to a NEW broker
BROKER_TESTS = ["tests/test_lock_sim_broker.py", "-k", "cannot_write or connector_user or anonymous"]
BROKER = [
    ("broker: anonymous clients are allowed", "mosquitto/mosquitto.conf", "allow_anonymous false", "allow_anonymous true", BROKER_TESTS),
    ("broker: a lock may write any lock's topics", "mosquitto/acl.conf", "pattern write locks/%c/state", "pattern write locks/+/state", BROKER_TESTS),
    ("broker: the connector may forge state", "mosquitto/acl.conf", "user connector\ntopic read locks/+/state", "user connector\ntopic readwrite locks/+/state", BROKER_TESTS),
]

GROUPS = {"offline": OFFLINE, "sim": SIM, "diagnose": DIAGNOSE, "broker": BROKER}


def copy_tree(dst: Path) -> None:
    shutil.copytree(IOT, dst, ignore=shutil.ignore_patterns("__pycache__", "state", ".pytest_cache", "*.pyc", "*.db*"))


LAST_FAILURE = [""]


def pytest_red(root: Path, tests: list, env_extra: dict) -> tuple[bool, str]:
    env = dict(os.environ, IOT_SRC=str(root), **env_extra)
    args = [t for t in tests]
    r = subprocess.run([sys.executable, "-m", "pytest", *args, "-q", "-x", "-p", "no:cacheprovider"], capture_output=True, text=True, encoding="utf-8",
                       errors="replace", env=env, cwd=str(root), timeout=580)
    tail = [ln for ln in r.stdout.splitlines() if ln.strip()][-1:] or [""]
    if r.returncode != 0:
        LAST_FAILURE[0] = r.stdout[-2500:]
    return r.returncode != 0, tail[0]


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


def run_group(label: str, mutants: list, jobs: int, only: str | None, check_only: bool, broker_json: Path | None, log) -> tuple[int, int]:
    selected = [m for m in mutants if not only or only in m[0]]
    if not selected:
        return 0, 0
    if check_only:
        bad = [m[0] for m in selected if m[2] not in read(IOT / m[1])]
        for name in bad:
            log(f"  FAIL  {name}: the anchor is not in the file, the mutation would not apply")
        log(f"{label}: {len(selected) - len(bad)}/{len(selected)} anchors found")
        return len(selected) - len(bad), len(selected)
    env_extra = {"IOT_BROKER_JSON": str(broker_json)} if broker_json else {}
    base_root = Path(tempfile.mkdtemp(prefix="iotmut-base-"))
    try:
        copy_tree(base_root / "iot")
        tests_union = sorted({t for m in selected for t in m[4] if t.startswith("tests/")})
        base_red, base_tail = pytest_red(base_root / "iot", tests_union, env_extra) if label != "broker" else (False, "skipped, the broker group runs its own baseline per mutant")
    finally:
        shutil.rmtree(base_root, ignore_errors=True)
    log(f"{label}: baseline, unchanged code: {'FAILED' if base_red else 'green'} ({base_tail})")
    if base_red:
        log("  the unchanged code already fails, so no mutant means anything. What pytest printed:" + chr(10) + LAST_FAILURE[0])
        return 0, -1

    def one(m) -> str:
        name, rel, old, new, tests = m
        root = Path(tempfile.mkdtemp(prefix="iotmut-"))
        broker = None
        try:
            copy_tree(root / "iot")
            target = root / "iot" / rel
            src = read(target)
            if old not in src:
                return f"  FAIL  {name}: the anchor is not in {rel}, the mutation did not apply"
            target.write_text(src.replace(old, new, 1), encoding="utf-8", newline="\n")
            extra = dict(env_extra)
            if label == "broker":
                # a broker built from the MUTATED config, started by the copy's own module in a child process (this process may already hold the real one)
                up = subprocess.run([sys.executable, "-m", "iotlab.broker", "up"], capture_output=True, text=True, encoding="utf-8", errors="replace",
                                    env=dict(os.environ, PYTHONPATH=str(root / "iot")), cwd=str(root / "iot"), timeout=120)
                if up.returncode != 0:
                    return f"  FAIL  {name}: the mutated broker did not start: {up.stderr.strip()[-200:]}"
                doc = json.loads((root / "iot" / "state" / "broker.json").read_text(encoding="utf-8"))
                broker = doc["container"]
                jf = root / "broker.json"
                jf.write_text(json.dumps({**doc, "workdir": str(root)}), encoding="utf-8")
                extra = {"IOT_BROKER_JSON": str(jf)}
            red, tail = pytest_red(root / "iot", tests, extra)
            return f"  {'CAUGHT' if red else 'MISSED'}  {name}  [{tail}]"
        finally:
            if broker:
                subprocess.run(["docker", "rm", "-f", "-v", broker], capture_output=True, timeout=60)
            shutil.rmtree(root, ignore_errors=True)

    with ThreadPoolExecutor(max_workers=jobs) as pool:
        lines = list(pool.map(one, selected))
    for line in lines:
        log(line)
    caught = sum(1 for ln in lines if ln.lstrip().startswith("CAUGHT"))
    log(f"{label}: {caught}/{len(selected)} mutants caught")
    return caught, len(selected)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--group", default="all", choices=["all", *GROUPS])
    ap.add_argument("--jobs", type=int, default=0, help="parallel mutants for the offline group (the others run serially)")
    ap.add_argument("--only")
    ap.add_argument("--check-anchors", action="store_true")
    ap.add_argument("--save")
    args = ap.parse_args()
    out: list[str] = []

    def log(line: str) -> None:
        print(line, flush=True)
        out.append(line)

    wanted = list(GROUPS) if args.group == "all" else [args.group]
    needs_broker = any(g in wanted for g in ("sim", "diagnose")) and not args.check_anchors
    shared, broker_json = None, None
    if needs_broker:
        from iotlab import broker as broker_mod
        if not broker_mod.docker_available():
            print("Docker is not running: the sim, diagnose and broker groups need it", file=sys.stderr)
            return 2
        shared = broker_mod.start_broker()
        broker_json = Path(tempfile.mkdtemp(prefix="iotmut-broker-")) / "broker.json"
        broker_json.write_text(json.dumps({"container": shared.container, "port": shared.port, "passwords": shared.passwords, "workdir": str(shared.workdir)}), encoding="utf-8")
    total_caught = total = 0
    ok = True
    try:
        for g in wanted:
            jobs = (args.jobs or 4) if g == "offline" else 1          # the groups that share a broker and induce timing faults run one at a time
            c, t = run_group(g, GROUPS[g], jobs, args.only, args.check_anchors, broker_json if g in ("sim", "diagnose") else None, log)
            if t == 0:
                continue                                         # nothing selected in this group
            total_caught += c
            total += max(t, 0)
            ok = ok and c == t and t > 0
    finally:
        if shared:
            shared.remove()
            shutil.rmtree(broker_json.parent, ignore_errors=True)
    if args.check_anchors:
        log(f"total: {total_caught}/{total} anchors found")
    else:
        log(f"total: {total_caught}/{total} mutants caught" + ("" if ok else "  (NOT ALL CAUGHT)"))
    if args.save:
        Path(args.save).parent.mkdir(parents=True, exist_ok=True)
        Path(args.save).write_text("\n".join(out) + "\n", encoding="utf-8")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
