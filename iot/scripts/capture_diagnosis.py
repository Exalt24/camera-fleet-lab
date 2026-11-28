#!/usr/bin/env python3
"""Runs the diagnosis tool against the slice while ONE fault at a time is induced, and saves what the tool printed.

Every run starts from a healthy slice on a real mosquitto container, induces a fault in one layer, asks the tool about the symptom that fault
causes, prints its report, then removes the fault. The report is the tool's own output; nothing here edits it.

    python iot/scripts/capture_diagnosis.py [--save docs/iot/diagnosis_run.txt]
"""
from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

IOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(IOT))
sys.path.insert(0, str(IOT / "tests"))

import httpx  # noqa: E402

from harness import Stack, wait_until  # noqa: E402
from iotlab import broker as broker_mod  # noqa: E402
from iotlab import diagnose as dg  # noqa: E402
from iotlab.util import free_port  # noqa: E402


def lab(s: Stack, path: str, body: dict) -> None:
    httpx.post(s.cloud_srv.url + path, json=body)


def targets(s: Stack, **kw) -> dg.Targets:
    b = s.broker
    base = dict(lock_id=s.lock_id, broker_host=b.host, broker_port=b.port, broker_user="diag", broker_password=b.passwords["diag"],
                vendor_url=s.cloud_srv.url, connector_url=s.conn_srv.url, timeout=2.0)
    base.update(kw)
    return dg.Targets(**base)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--save")
    args = ap.parse_args()
    out: list[str] = []

    def emit(text: str = "") -> None:
        print(text, flush=True)
        out.append(text)

    def show(title: str, symptom: str, s: Stack, **kw) -> dg.Diagnosis:
        emit(f"=== {title}")
        d = dg.diagnose(symptom, targets(s, **kw))
        emit(dg.format_text(d))
        emit()
        return d

    if not broker_mod.docker_available():
        print("Docker is not running", file=sys.stderr)
        return 2
    broker = broker_mod.start_broker()
    tmp = Path(tempfile.mkdtemp(prefix="diagcap-"))
    s = Stack(broker, tmp, shapes=("a",), via_link=True, vendor_cfg={"access_ttl": 100000})
    verdicts: dict[str, str | None] = {}
    try:
        s.authorize()
        s.register_webhook()
        s.conn.sync_locks()
        lock, link, sim = s.lock_id, s.links[s.lock_id], s.sims[s.lock_id]

        for symptom in sorted(dg.LAYERS_FOR):
            verdicts[f"healthy / {symptom}"] = show(f"healthy slice, symptom {symptom}", symptom, s).broken_layer

        sim.hung = True
        verdicts["hung lock"] = show("fault: the lock is online but ignores commands", "unlock_unconfirmed", s).broken_layer
        sim.hung = False

        link.cut()
        wait_until(lambda: s.store.get_lock(lock)["mqtt_online"] == 0, timeout=10, what="the last will")
        verdicts["link cut"] = show("fault: the lock's link is cut (the broker publishes its last will)", "lock_offline", s).broken_layer
        link.heal()
        wait_until(lambda: s.store.get_lock(lock)["mqtt_online"] == 1 and s.store.get_lock(lock)["online"] == 1, timeout=15, what="the lock back")

        lab(s, "/_lab/faults", {"down": True})
        verdicts["vendor down"] = show("fault: the vendor cloud is down", "codes_not_syncing", s).broken_layer
        lab(s, "/_lab/faults", {"down": False})

        lab(s, "/_lab/faults", {"rate_limit_hard": 3600})
        verdicts["rate limited"] = show("fault: the vendor rate limits this app (Retry-After 3600 s)", "codes_not_syncing", s).broken_layer
        lab(s, "/_lab/faults", {"rate_limit_hard": 0})

        s.cloud.locks[lock].online = False
        verdicts["vendor view"] = show("fault: the vendor shows the lock offline while the broker shows it online", "lock_offline", s).broken_layer
        s.cloud.locks[lock].online = True

        lab(s, "/_lab/action", {"action": "strip_scopes", "scopes": ["codes:read", "codes:write"]})
        verdicts["scope"] = show("fault: the grant lost the access code scopes", "codes_not_syncing", s).broken_layer
        s.authorize()                                                    # a fresh grant restores them

        lab(s, "/_lab/action", {"action": "revoke_tokens"})
        verdicts["revoked"] = show("fault: the vendor revoked the grant", "codes_not_syncing", s).broken_layer
        s.authorize()

        lab(s, "/_lab/faults", {"webhook_secret_drift": True})
        sim.manual_turn("unlocked")
        wait_until(lambda: int(s.store.meta_prefix("webhook_rejected:").get("bad_signature", "0")) >= 1, what="a rejected delivery")
        verdicts["secret drift"] = show("fault: the vendor signs with a secret the connector does not hold", "webhook_silence", s).broken_layer
        lab(s, "/_lab/faults", {"webhook_secret_drift": False})
        s.register_webhook()                                             # registering again gives both sides the new secret

        lab(s, "/_lab/faults", {"drop_webhooks": True})
        sim.manual_turn("locked")
        verdicts["paused"] = show("fault: the vendor stopped pushing events (the feed still has them)", "webhook_silence", s).broken_layer
        s.conn.reconcile()
        verdicts["paused, repaired by polling"] = show("same fault after a reconcile repaired the lock state by polling", "webhook_silence", s).broken_layer
        lab(s, "/_lab/faults", {"drop_webhooks": False})

        s.conn.register_webhook(f"http://127.0.0.1:{free_port()}/webhooks/vendor")
        sim.manual_turn("unlocked")
        wait_until(lambda: len([d for d in s.cloud.deliveries if d["error"]]) >= 4, timeout=40, what="the failed deliveries")
        verdicts["dead endpoint"] = show("fault: the registered webhook address does not answer", "webhook_silence", s).broken_layer
        s.register_webhook()

        s.conn_srv.stop()
        verdicts["connector down"] = show("fault: the connector service is down", "webhook_silence", s).broken_layer
    finally:
        s.close()

    emit("=== fault: the broker container is stopped (a separate stack on its own broker)")
    b2 = broker_mod.start_broker()
    s2 = Stack(b2, Path(tempfile.mkdtemp(prefix="diagcap-")), shapes=("a",), vendor_cfg={"access_ttl": 100000})
    try:
        s2.authorize()
        b2.stop()
        d = dg.diagnose("lock_offline", targets(s2))
        emit(dg.format_text(d))
        verdicts["broker stopped"] = d.broken_layer
    finally:
        s2.close()
        b2.remove()
        broker.remove()
    emit()
    emit("verdicts (the induced layer, then what the tool said):")
    expected = {"hung lock": "device", "link cut": "device", "vendor down": "vendor_cloud", "rate limited": "vendor_cloud", "vendor view": "vendor_cloud",
                "scope": "oauth", "revoked": "oauth", "secret drift": "webhook", "paused": "webhook", "paused, repaired by polling": "webhook",
                "dead endpoint": "webhook", "connector down": "connector", "broker stopped": "broker"}
    ok = True
    for name, got in verdicts.items():
        want = None if name.startswith("healthy") else expected[name]
        emit(f"  {'ok  ' if got == want else 'WRONG'} {name}: {got}" + ("" if got == want else f" (wanted {want})"))
        ok = ok and got == want
    emit(f"{sum(1 for n, g in verdicts.items() if g == (None if n.startswith('healthy') else expected[n]))}/{len(verdicts)} runs named the induced layer" if ok else "NOT ALL RUNS NAMED THE INDUCED LAYER")
    if args.save:
        Path(args.save).parent.mkdir(parents=True, exist_ok=True)
        Path(args.save).write_text("\n".join(out) + "\n", encoding="utf-8")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
