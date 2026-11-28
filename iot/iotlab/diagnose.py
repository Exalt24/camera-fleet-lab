"""Which layer broke? The lock integration's version of the camera monitor.

Given a symptom, probe the layers that symptom can pass through, in the order the data travels, and report the FIRST one that
fails with the evidence that says so. Later layers are still probed and printed, but they are downstream of the cause and
the verdict is the first failure, exactly like the camera monitor's `tunnel -> port -> video`.

  layers (in data order):  broker -> device -> vendor_cloud -> oauth -> webhook -> connector
  symptoms:                lock_offline | unlock_unconfirmed | codes_not_syncing | webhook_silence

Every probe is read only. The device probe sends one `report` command, which makes a lock publish its state again and changes
nothing on the door. Nothing here prints a password, a token or an access code: the connector's /diag route does not carry any.

    python -m iotlab.diagnose --symptom lock_offline --lock lock-1 --broker 127.0.0.1:1883 --vendor http://127.0.0.1:8200 --connector http://127.0.0.1:8300
    (the broker user and password come from DIAG_MQTT_USER and DIAG_MQTT_PASSWORD)
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import time
from dataclasses import asdict, dataclass, field

import httpx
import paho.mqtt.client as mqtt

LAYERS_FOR = {
    "lock_offline": ["broker", "device", "vendor_cloud", "oauth", "connector"],
    "unlock_unconfirmed": ["broker", "device", "vendor_cloud", "oauth", "webhook", "connector"],
    "codes_not_syncing": ["vendor_cloud", "oauth", "connector"],
    "webhook_silence": ["vendor_cloud", "oauth", "webhook", "connector"],
}

NEXT_STEP = {
    "broker": "Check the broker container and its listener first. Every later layer depends on it.",
    "device": "Look at the lock itself: power and batteries, its link to the broker, firmware. The broker is fine, so the cause is on the device side.",
    "vendor_cloud": "The manufacturer's cloud is the problem or is refusing this app. Check the vendor status page and the rate limit. Nothing local needs fixing.",
    "oauth": "The grant is the problem. Re-authorize the connector, or fix the missing scope, then run a reconcile.",
    "webhook": "Deliveries are not arriving or are being rejected. Compare the stored webhook secret with the vendor's, check the clock, check the endpoint URL.",
    "connector": "The connector itself is the problem: restart or unstick it, then read its last sync error.",
}


@dataclass
class Targets:
    lock_id: str
    broker_host: str = "127.0.0.1"
    broker_port: int = 1883
    broker_user: str = "diag"
    broker_password: str = field(default="", repr=False)
    vendor_url: str = ""
    connector_url: str = ""
    timeout: float = 3.0
    stale_s: float = 120.0                 # a sync or a loop tick older than this is called stalled
    command_stale_s: float = 30.0          # a command pending longer than this is called unconfirmed


@dataclass
class Layer:
    name: str
    status: str                            # ok | fail | unknown
    summary: str
    evidence: dict = field(default_factory=dict)


@dataclass
class Diagnosis:
    symptom: str
    broken_layer: str | None
    summary: str
    next_step: str
    layers: list[Layer]


# -- the broker session ------------------------------------------------------------------------------------------------------
class BrokerSession:
    def __init__(self, t: Targets):
        self.t = t
        self.messages: list[tuple[str, str, float]] = []
        self.rc = None
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"diag-{secrets.token_hex(3)}")
        self.client.username_pw_set(t.broker_user, t.broker_password)
        self.client.on_connect = self._on_connect
        self.client.on_message = lambda c, u, m: self.messages.append((m.topic, m.payload.decode(errors="replace"), time.time()))

    def _on_connect(self, client, userdata, flags, reason_code, properties=None):
        self.rc = reason_code

    def connect(self) -> tuple[str, str]:
        """Returns ("ok" | "unreachable" | "refused", detail)."""
        try:
            self.client.connect(self.t.broker_host, self.t.broker_port, keepalive=10)
        except OSError as exc:
            return "unreachable", exc.__class__.__name__
        self.client.loop_start()
        end = time.time() + self.t.timeout
        while self.rc is None and time.time() < end:
            time.sleep(0.02)
        if self.rc is None:
            return "unreachable", "no CONNACK before the timeout"
        if self.rc.is_failure:
            return "refused", str(self.rc)
        return "ok", ""

    def wait_for(self, predicate, timeout: float):
        end = time.time() + timeout
        while time.time() < end:
            for m in list(self.messages):
                if predicate(m):
                    return m
            time.sleep(0.02)
        return None

    def roundtrip(self) -> float | None:
        topic = f"diag/{secrets.token_hex(4)}"
        self.client.subscribe(topic, qos=1)
        time.sleep(0.15)                                      # let the SUBACK land before publishing
        start = time.time()
        self.client.publish(topic, "ping", qos=1)
        got = self.wait_for(lambda m: m[0] == topic, self.t.timeout)
        return round((time.time() - start) * 1000, 1) if got else None

    def close(self) -> None:
        try:
            self.client.disconnect()
        finally:
            self.client.loop_stop()


# -- layer probes ------------------------------------------------------------------------------------------------------------------
def probe_broker(t: Targets, session: BrokerSession) -> Layer:
    kind, detail = session.connect()
    where = {"host": t.broker_host, "port": t.broker_port}
    if kind == "unreachable":
        return Layer("broker", "fail", f"the broker does not answer on {t.broker_host}:{t.broker_port} ({detail})", {**where, "error": detail})
    if kind == "refused":
        return Layer("broker", "fail", "the broker is up but refused the diagnosis user (authentication)", {**where, "reason": detail})
    ms = session.roundtrip()
    if ms is None:
        return Layer("broker", "fail", "the broker accepts connections but did not deliver a message published to itself", where)
    return Layer("broker", "ok", f"connected, message round trip {ms} ms", {**where, "roundtrip_ms": ms})


def probe_device(t: Targets, session: BrokerSession, broker: Layer) -> Layer:
    if broker.status != "ok":
        return Layer("device", "unknown", "not probed: the broker layer failed, so the lock cannot be reached through it", {})
    status_topic, state_topic = f"locks/{t.lock_id}/status", f"locks/{t.lock_id}/state"
    session.client.subscribe(status_topic, qos=1)
    session.client.subscribe(state_topic, qos=1)
    status = session.wait_for(lambda m: m[0] == status_topic, 1.0)
    state_msg = session.wait_for(lambda m: m[0] == state_topic, 0.6)
    state = None
    if state_msg:
        try:
            state = json.loads(state_msg[1])
        except ValueError:
            state = None
    ev: dict = {"status": status[1] if status else None, "state_age_s": round(time.time() - state["ts"], 1) if state and "ts" in state else None}
    if status is None:
        return Layer("device", "fail", f"the broker holds no status for {t.lock_id}: it never connected, or the broker lost its retained messages", ev)
    if status[1] != "online":
        return Layer("device", "fail", f"the broker holds the last will of {t.lock_id}: offline", ev)
    cmd_id = f"diag-{secrets.token_hex(4)}"
    start = time.time()
    session.client.publish(f"locks/{t.lock_id}/cmd", json.dumps({"cmd_id": cmd_id, "action": "report"}), qos=1)
    echo = session.wait_for(lambda m: m[0] == state_topic and f'"{cmd_id}"' in m[1], t.timeout)
    if echo is None:
        return Layer("device", "fail", f"{t.lock_id} says online but did not answer a report command within {t.timeout:g} s (firmware hung or not reading commands)", ev)
    doc = json.loads(echo[1])
    ev.update({"answered_ms": round((time.time() - start) * 1000, 1), "battery": doc.get("battery"), "battery_low": bool(doc.get("battery_low")),
               "lock": doc.get("lock")})
    note = f", battery LOW at {doc.get('battery')}%" if doc.get("battery_low") else ""
    return Layer("device", "ok", f"online and answered a report in {ev['answered_ms']} ms{note}", ev)


def _get(url: str, timeout: float):
    try:
        return httpx.get(url, timeout=timeout), None
    except httpx.HTTPError as exc:
        return None, exc.__class__.__name__


def probe_vendor_cloud(t: Targets, diag: dict | None, device: Layer | None) -> Layer:
    resp, err = _get(f"{t.vendor_url}/healthz", t.timeout)
    if resp is None:
        return Layer("vendor_cloud", "fail", f"the vendor cloud does not answer ({err})", {"url": t.vendor_url, "error": err})
    if resp.status_code >= 500:
        return Layer("vendor_cloud", "fail", f"the vendor cloud answers {resp.status_code} on its health route", {"status": resp.status_code})
    if diag:
        probe = diag["vendor"]["locks"]
        if probe.get("status") == 429:
            return Layer("vendor_cloud", "fail", f"the vendor is rate limiting this app (Retry-After {probe.get('retry_after'):g} s)", probe)
        if probe.get("error") == "unavailable" or (probe.get("status") or 0) >= 500:
            return Layer("vendor_cloud", "fail", f"the vendor health route is fine but its API fails for this app ({probe.get('detail') or probe.get('status')})", probe)
        view = diag["vendor"].get("lock_view")
        if view and view["online"] is False and device is not None and device.status == "ok":
            return Layer("vendor_cloud", "fail",
                         "the vendor cloud shows the lock offline while the broker shows it online and answering (the vendor lost its own link to the lock)",
                         {"vendor_online": False, "broker_status": device.evidence.get("status")})
    return Layer("vendor_cloud", "ok", "the vendor cloud answers and serves this app", {"health": resp.status_code})


def probe_oauth(t: Targets, diag: dict | None) -> Layer:
    if diag is None:
        return Layer("oauth", "unknown", "not probed: the connector's token state cannot be read while the connector is unreachable", {})
    o, v = diag["oauth"], diag["vendor"]
    if not o["connected"]:
        return Layer("oauth", "fail", "the connector holds no grant: it was never authorized", {"status": o["status"]})
    if o["status"] != "ok":
        return Layer("oauth", "fail", f"the grant is unusable ({o['status']}: {o['last_error']}): the refresh token was revoked, replayed or has expired", o)
    if v["locks"].get("error") == "reauth_required":
        return Layer("oauth", "fail", "the vendor rejects the connector's tokens even after a refresh", {"vendor": v["locks"]})
    codes = v.get("codes") or {}
    if codes.get("status") == 403:
        return Layer("oauth", "fail", f"the grant lacks a scope the access codes need ({o['last_error']})", {"scope": o["scope"], "vendor": codes})
    return Layer("oauth", "ok", f"grant valid, access token expires in {o['expires_in_s']} s", {"expires_in_s": o["expires_in_s"], "scope": o["scope"]})


def probe_webhook(t: Targets, diag: dict | None) -> Layer:
    if diag is None:
        return Layer("webhook", "unknown", "not probed: webhook counters cannot be read while the connector is unreachable", {})
    w, d = diag["webhook"], diag["vendor"].get("deliveries") or {}
    if not w["registered"]:
        return Layer("webhook", "fail", "no webhook is registered with the vendor, so no event will ever be pushed", w)
    if w["rejected"]:
        worst = max(w["rejected"], key=w["rejected"].get)
        meaning = {"bad_signature": "the signing secret does not match the vendor's (a rotated or mistyped secret)",
                   "stale_timestamp": "the timestamps fall outside the replay window (a clock skew between the two sides, or replayed requests)"}.get(worst, "the requests are malformed")
        return Layer("webhook", "fail", f"the vendor delivers but the connector rejects {w['rejected'][worst]} request(s) as {worst}: {meaning}", {"rejected": w["rejected"], "deliveries": d})
    if d.get("failed"):
        return Layer("webhook", "fail", f"the vendor's delivery attempts are failing (last status {d.get('last_status')}, last error {d.get('last_error')}): the endpoint does not take them", d)
    poll, hook = w["recent_by_source"]["poll"], w["recent_by_source"]["webhook"]
    behind = diag["vendor"].get("events_behind") or 0
    if (poll > 0 and hook == 0) or behind > 0:
        reason = "the vendor has made no delivery attempt at all" if d.get("total") == 0 else "the attempts are not reaching the connector"
        return Layer("webhook", "fail", f"{poll or behind} event(s) reached the connector only by polling and none by webhook: {reason} (delivery paused or the endpoint disabled at the vendor)",
                     {"recent_by_source": w["recent_by_source"], "events_behind": behind, "deliveries": d})
    return Layer("webhook", "ok", f"{w['received']} webhook(s) accepted, none rejected, deliveries healthy", {"received": w["received"], "deliveries": d})


def probe_connector(t: Targets, diag: dict | None, health_error: str | None) -> Layer:
    if diag is None:
        return Layer("connector", "fail", f"the connector does not answer on {t.connector_url} ({health_error or 'no diagnostics'})", {"error": health_error})
    s, m = diag["sync"], diag["mqtt"]
    if s["loop_tick_age_s"] is not None and s["loop_tick_age_s"] > t.stale_s:
        return Layer("connector", "fail", f"the reconcile loop has not run for {s['loop_tick_age_s']:g} s (stalled)", s)
    if s["last_sync_error"]:
        return Layer("connector", "fail", f"the last reconcile failed: {s['last_sync_error']}", s)
    if s["last_sync_age_s"] is not None and s["last_sync_age_s"] > t.stale_s:
        return Layer("connector", "fail", f"the last successful sync was {s['last_sync_age_s']:g} s ago", s)
    stuck = [c for c in diag["commands"]["pending"] if c["age_s"] > t.command_stale_s]
    if stuck:
        return Layer("connector", "fail", f"{len(stuck)} command(s) still pending after {t.command_stale_s:g} s although every layer before this one is healthy", {"pending": stuck})
    if not m["connected"]:
        return Layer("connector", "fail", "the connector's own MQTT subscription is down", m)
    lock, view = diag.get("lock"), diag["vendor"].get("lock_view")
    if lock and view and view["online"] is True and lock["online"] == 0:
        return Layer("connector", "fail", "the connector's record shows the lock offline while the vendor shows it online (a missed event the sync did not repair)",
                     {"record_online": lock["online"], "vendor_online": view["online"]})
    return Layer("connector", "ok", "the connector answers, its loop is running and its last sync succeeded", {"last_sync_age_s": s["last_sync_age_s"]})


# -- the diagnosis -----------------------------------------------------------------------------------------------------------------
def diagnose(symptom: str, t: Targets) -> Diagnosis:
    if symptom not in LAYERS_FOR:
        raise ValueError(f"unknown symptom {symptom!r}; choose one of {sorted(LAYERS_FOR)}")
    wanted = LAYERS_FOR[symptom]
    session = BrokerSession(t)
    layers: dict[str, Layer] = {}
    diag, health_error = None, None
    if any(n in wanted for n in ("oauth", "webhook", "connector")):
        resp, health_error = _get(f"{t.connector_url}/healthz", t.timeout)
        if resp is not None and resp.status_code == 200:
            d, health_error = _get(f"{t.connector_url}/diag?lock={t.lock_id}", max(t.timeout, 8.0))
            if d is not None and d.status_code == 200:
                diag = d.json()
            else:
                health_error = health_error or f"diagnostics answered {d.status_code}"
        elif resp is not None:
            health_error = f"health route answered {resp.status_code}"
    try:
        for name in wanted:
            if name == "broker":
                layers[name] = probe_broker(t, session)
            elif name == "device":
                layers[name] = probe_device(t, session, layers["broker"])
            elif name == "vendor_cloud":
                layers[name] = probe_vendor_cloud(t, diag, layers.get("device"))
            elif name == "oauth":
                layers[name] = probe_oauth(t, diag)
            elif name == "webhook":
                layers[name] = probe_webhook(t, diag)
            elif name == "connector":
                layers[name] = probe_connector(t, diag, health_error)
    finally:
        session.close()
    ordered = [layers[n] for n in wanted]
    broken = next((layer for layer in ordered if layer.status == "fail"), None)
    if broken:
        return Diagnosis(symptom, broken.name, broken.summary, NEXT_STEP[broken.name], ordered)
    return Diagnosis(symptom, None, "every layer probed is healthy, so the symptom was not reproduced from here", "Reproduce it while watching the connector log, or widen the symptom.", ordered)


def format_text(d: Diagnosis) -> str:
    lines = [f"symptom: {d.symptom}", f"verdict: {d.broken_layer or 'no layer failed'}", f"  {d.summary}", f"  next: {d.next_step}", "layers:"]
    for layer in d.layers:
        lines.append(f"  [{layer.status:>7}] {layer.name}: {layer.summary}")
        if layer.evidence:
            lines.append(f"            evidence: {json.dumps(layer.evidence, sort_keys=True, default=str)}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--symptom", required=True, choices=sorted(LAYERS_FOR))
    ap.add_argument("--lock", required=True)
    ap.add_argument("--broker", default="127.0.0.1:1883")
    ap.add_argument("--vendor", default="")
    ap.add_argument("--connector", default="")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    host, _, port = args.broker.partition(":")
    t = Targets(lock_id=args.lock, broker_host=host, broker_port=int(port or 1883), vendor_url=args.vendor.rstrip("/"), connector_url=args.connector.rstrip("/"),
                broker_user=os.environ.get("DIAG_MQTT_USER", "diag"), broker_password=os.environ.get("DIAG_MQTT_PASSWORD", ""))
    d = diagnose(args.symptom, t)
    print(json.dumps(asdict(d), indent=2) if args.json else format_text(d))
    return 0 if d.broken_layer is None else 1


if __name__ == "__main__":
    sys.exit(main())
