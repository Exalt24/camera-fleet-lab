"""Fault injection for the diagnosis tool: the whole slice runs on a real broker, a fault is induced in ONE layer, and the tool must name that
layer from evidence, with every layer before it reporting healthy. A healthy baseline must report nothing, so the tool cannot pass by always
blaming something. Needs Docker."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

from harness import Stack, wait_until
from iotlab import diagnose as dg
from iotlab.util import free_port

IOT = Path(__file__).resolve().parent.parent
ALL_SYMPTOMS = sorted(dg.LAYERS_FOR)


def targets(stack, broker=None, **kw):
    b = broker or stack.broker
    base = dict(lock_id=stack.lock_id, broker_host=b.host, broker_port=b.port, broker_user="diag", broker_password=b.passwords["diag"],
                vendor_url=stack.cloud_srv.url, connector_url=stack.conn_srv.url, timeout=2.0)
    base.update(kw)
    return dg.Targets(**base)


def run(stack, symptom, **kw):
    return dg.diagnose(symptom, targets(stack, **kw))


def statuses(d):
    return {layer.name: layer.status for layer in d.layers}


def layer(d, name):
    return next(x for x in d.layers if x.name == name)


@pytest.fixture
def stack(broker, tmp_path):
    s = Stack(broker, tmp_path, shapes=("a",), via_link=True, vendor_cfg={"access_ttl": 100000})
    s.authorize()
    s.register_webhook()
    s.conn.sync_locks()
    yield s
    s.close()


def event_happens(stack, state="unlocked"):
    stack.sims[stack.lock_id].manual_turn(state)


# ---- the baseline: nothing broken, nothing blamed -----------------------------------------------------------------------------------------
@pytest.mark.parametrize("symptom", ALL_SYMPTOMS)
def test_a_healthy_slice_blames_no_layer(stack, symptom):
    d = run(stack, symptom)
    assert d.broken_layer is None, dg.format_text(d)
    assert all(x.status == "ok" for x in d.layers), dg.format_text(d)
    assert [x.name for x in d.layers] == dg.LAYERS_FOR[symptom]


def test_the_report_never_contains_a_password_token_or_code(stack):
    made = stack.conn.create_code(stack.lock_id, "guest", time.time(), time.time() + 3600)
    outputs = [dg.format_text(run(stack, s)) for s in ALL_SYMPTOMS]
    outputs.append(json.dumps([vars(x) for x in run(stack, "webhook_silence").layers], default=str))
    blob = "\n".join(outputs)
    secrets_in_play = list(stack.broker.passwords.values()) + list(stack.cloud.access) + list(stack.cloud.refresh) + [stack.cloud.webhook["secret"], stack.client_secret, made["code"]]
    for secret in secrets_in_play:
        assert secret not in blob


def test_a_low_battery_is_noted_but_is_not_a_fault(stack):
    stack.sims[stack.lock_id].set_battery(12)
    d = run(stack, "lock_offline")
    assert d.broken_layer is None and "battery LOW at 12%" in layer(d, "device").summary


# ---- broker -------------------------------------------------------------------------------------------------------------------------------
def test_a_stopped_broker_is_named_before_anything_else(make_broker, tmp_path):
    b = make_broker()
    s = Stack(b, tmp_path, shapes=("a",), vendor_cfg={"access_ttl": 100000})
    try:
        s.authorize()
        b.stop()                                                  # the real container is stopped
        for symptom in ("lock_offline", "unlock_unconfirmed"):
            d = run(s, symptom, broker=b)
            assert d.broken_layer == "broker", dg.format_text(d)
            assert "does not answer" in d.summary and statuses(d)["device"] == "unknown"
    finally:
        s.close()


def test_a_broker_that_refuses_the_diagnosis_user_is_a_broker_fault_with_the_reason(stack):
    d = run(stack, "lock_offline", broker_password="the-wrong-password")
    assert d.broken_layer == "broker" and "refused" in d.summary and "authentication" in d.summary
    assert "the-wrong-password" not in dg.format_text(d)


# ---- device -------------------------------------------------------------------------------------------------------------------------------
def test_a_lock_whose_link_died_is_a_device_fault_with_the_broker_healthy(stack):
    stack.links[stack.lock_id].cut()
    wait_until(lambda: stack.store.get_lock(stack.lock_id)["mqtt_online"] == 0, timeout=10, what="the last will")
    d = run(stack, "lock_offline")
    assert d.broken_layer == "device" and statuses(d)["broker"] == "ok", dg.format_text(d)
    assert "last will" in d.summary and layer(d, "device").evidence["status"] == "offline"


def test_a_lock_that_is_online_but_does_not_read_commands_is_a_device_fault(stack):
    stack.sims[stack.lock_id].hung = True
    for symptom in ("unlock_unconfirmed", "lock_offline"):
        d = run(stack, symptom)
        assert d.broken_layer == "device" and "did not answer a report command" in d.summary, dg.format_text(d)
        assert layer(d, "device").evidence["status"] == "online" and statuses(d)["broker"] == "ok"


def test_a_lock_the_broker_has_never_heard_of_is_a_device_fault(stack):
    d = dg.diagnose("lock_offline", targets(stack, lock_id="lock-that-never-existed"))
    assert d.broken_layer == "device" and "no status" in d.summary


# ---- vendor cloud ---------------------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("symptom", ["codes_not_syncing", "webhook_silence", "unlock_unconfirmed"])
def test_a_vendor_outage_is_named_and_the_local_layers_before_it_are_healthy(stack, symptom):
    httpx.post(stack.cloud_srv.url + "/_lab/faults", json={"down": True})
    d = run(stack, symptom)
    assert d.broken_layer == "vendor_cloud", dg.format_text(d)
    assert "503" in d.summary
    if symptom == "unlock_unconfirmed":
        assert statuses(d)["broker"] == "ok" and statuses(d)["device"] == "ok"


def test_a_vendor_that_rate_limits_this_app_is_named_with_its_retry_after(stack):
    stack.cloud.faults["rate_limit_hard"] = 3600
    d = run(stack, "codes_not_syncing")
    assert d.broken_layer == "vendor_cloud" and "rate limiting" in d.summary and "3600" in d.summary, dg.format_text(d)
    assert layer(d, "vendor_cloud").evidence["retry_after"] == 3600


def test_a_vendor_that_shows_an_online_lock_as_offline_is_a_vendor_fault(stack):
    stack.cloud.locks[stack.lock_id].online = False                # the vendor lost its own link to a lock that is fine
    d = run(stack, "lock_offline")
    assert d.broken_layer == "vendor_cloud", dg.format_text(d)
    assert statuses(d)["broker"] == "ok" and statuses(d)["device"] == "ok" and "shows the lock offline while the broker shows it online" in d.summary


# ---- oauth ---------------------------------------------------------------------------------------------------------------------------------
def test_a_revoked_grant_is_an_oauth_fault_the_first_time_and_after_it_is_recorded(stack):
    httpx.post(stack.cloud_srv.url + "/_lab/action", json={"action": "revoke_tokens"})
    first = run(stack, "codes_not_syncing")
    assert first.broken_layer == "oauth" and statuses(first)["vendor_cloud"] == "ok", dg.format_text(first)
    second = run(stack, "codes_not_syncing")
    assert second.broken_layer == "oauth" and "needs_reauth" in second.summary, dg.format_text(second)


def test_a_grant_that_lost_the_codes_scope_is_an_oauth_fault_naming_the_scope(stack):
    httpx.post(stack.cloud_srv.url + "/_lab/action", json={"action": "strip_scopes", "scopes": ["codes:read", "codes:write"]})
    d = run(stack, "codes_not_syncing")
    assert d.broken_layer == "oauth" and "lacks a scope" in d.summary and "codes:" in d.summary, dg.format_text(d)
    assert statuses(d)["vendor_cloud"] == "ok"


def test_a_connector_that_was_never_authorized_is_an_oauth_fault(broker, tmp_path):
    s = Stack(broker, tmp_path, shapes=("a",))
    try:
        d = run(s, "codes_not_syncing")
        assert d.broken_layer == "oauth" and "never authorized" in d.summary, dg.format_text(d)
    finally:
        s.close()


# ---- webhook -------------------------------------------------------------------------------------------------------------------------------
def test_a_signing_secret_mismatch_is_a_webhook_fault_with_the_reason(stack):
    stack.cloud.faults["webhook_secret_drift"] = True
    event_happens(stack)
    wait_until(lambda: int(stack.store.meta_prefix("webhook_rejected:").get("bad_signature", "0")) >= 1, what="a rejected delivery")
    d = run(stack, "webhook_silence")
    assert d.broken_layer == "webhook" and "bad_signature" in d.summary and "secret" in d.summary, dg.format_text(d)
    assert statuses(d)["vendor_cloud"] == "ok" and statuses(d)["oauth"] == "ok"


def test_a_vendor_that_stopped_delivering_is_a_webhook_fault_before_and_after_the_poll_repairs_the_state(stack):
    stack.cloud.faults["drop_webhooks"] = True
    event_happens(stack)
    before = run(stack, "webhook_silence")
    assert before.broken_layer == "webhook" and "polling" in before.summary, dg.format_text(before)
    stack.conn.reconcile()                                           # the state is repaired, the silence is still the fault
    after = run(stack, "webhook_silence")
    assert after.broken_layer == "webhook" and "only by polling" in after.summary, dg.format_text(after)
    assert layer(after, "webhook").evidence["recent_by_source"] == {"webhook": 0, "poll": 1}


def test_an_endpoint_the_vendor_cannot_reach_is_a_webhook_fault_with_the_delivery_errors(stack):
    stack.conn.register_webhook(f"http://127.0.0.1:{free_port()}/webhooks/vendor")        # nothing listens there
    event_happens(stack)
    wait_until(lambda: len(stack.cloud.deliveries) >= 4, timeout=30, what="the vendor's four failed attempts")     # Windows retries a SYN to a closed port for about 2 s
    d = run(stack, "webhook_silence")
    assert d.broken_layer == "webhook" and "delivery attempts are failing" in d.summary and "ConnectError" in d.summary, dg.format_text(d)


# ---- connector -----------------------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("symptom", ["codes_not_syncing", "webhook_silence"])
def test_a_connector_that_is_down_is_named_and_the_layers_that_depend_on_it_are_unknown(stack, symptom):
    stack.conn_srv.stop()
    d = run(stack, symptom)
    assert d.broken_layer == "connector" and "does not answer" in d.summary, dg.format_text(d)
    assert statuses(d)["vendor_cloud"] == "ok" and statuses(d)["oauth"] == "unknown"


def test_a_stalled_reconcile_loop_is_a_connector_fault(broker, tmp_path):
    s = Stack(broker, tmp_path, shapes=("a",), reconcile_interval=0.2, start_loop=True, vendor_cfg={"access_ttl": 100000})
    try:
        s.authorize()
        wait_until(lambda: s.store.meta_get("last_sync_at") and s.store.meta_get("last_sync_error") == "", what="a clean sync")
        s.svc.loop.paused = True
        time.sleep(1.6)
        d = run(s, "codes_not_syncing", stale_s=1.0)
        assert d.broken_layer == "connector" and "stalled" in d.summary, dg.format_text(d)
    finally:
        s.close()


def test_a_reconcile_that_keeps_failing_is_a_connector_fault_naming_the_error_class(broker, tmp_path):
    s = Stack(broker, tmp_path, shapes=("a",), reconcile_interval=0.2, start_loop=True, vendor_cfg={"access_ttl": 100000})
    try:
        s.authorize()
        wait_until(lambda: s.store.meta_get("last_sync_at") and s.store.meta_get("last_sync_error") == "", what="a clean sync")

        def broken(*a, **k):
            raise RuntimeError("the code sync has a bug")

        s.conn.sync_codes = broken
        wait_until(lambda: "RuntimeError" in (s.store.meta_get("last_sync_error") or ""), what="the failure to be recorded")
        d = run(s, "codes_not_syncing")
        assert d.broken_layer == "connector" and "RuntimeError" in d.summary, dg.format_text(d)
        assert "the code sync has a bug" not in dg.format_text(d), "only the class is recorded, never the message"
    finally:
        s.close()


def test_a_command_stuck_pending_with_every_other_layer_healthy_is_a_connector_fault(stack):
    stack.store.put_command("cmd_stuck", stack.lock_id, "unlock", "pending", time.time() - 120)
    d = run(stack, "unlock_unconfirmed")
    assert d.broken_layer == "connector" and "still pending" in d.summary, dg.format_text(d)
    assert all(statuses(d)[n] == "ok" for n in ("broker", "device", "vendor_cloud", "oauth", "webhook"))


def test_a_connector_that_lost_its_mqtt_subscription_is_a_connector_fault(stack):
    stack.svc.listener.stop()
    d = run(stack, "lock_offline")
    assert d.broken_layer == "connector" and "MQTT subscription is down" in d.summary, dg.format_text(d)


def test_a_record_that_still_says_offline_while_the_vendor_says_online_is_a_connector_fault(stack):
    stack.store.update_lock(stack.lock_id, online=0)
    d = run(stack, "lock_offline")
    assert d.broken_layer == "connector" and "record shows the lock offline" in d.summary, dg.format_text(d)


# ---- the verdict is the first failure in data order ------------------------------------------------------------------------------------------
def test_with_two_faults_the_verdict_is_the_earlier_layer_and_the_later_one_is_still_listed(stack):
    stack.links[stack.lock_id].cut()
    wait_until(lambda: stack.store.get_lock(stack.lock_id)["mqtt_online"] == 0, timeout=10, what="the last will")
    httpx.post(stack.cloud_srv.url + "/_lab/faults", json={"down": True})
    d = run(stack, "lock_offline")
    assert d.broken_layer == "device"
    assert statuses(d)["vendor_cloud"] == "fail", "the later fault is not hidden, it is downstream of the verdict"


def test_every_symptom_has_a_next_step_for_each_of_its_layers():
    for symptom, layers in dg.LAYERS_FOR.items():
        for name in layers:
            assert dg.NEXT_STEP[name]


def test_an_unknown_symptom_is_refused():
    with pytest.raises(ValueError):
        dg.diagnose("the_lock_is_haunted", dg.Targets(lock_id="x"))


# ---- the command line -------------------------------------------------------------------------------------------------------------------------
def cli(stack, symptom, extra=()):
    env = dict(os.environ, DIAG_MQTT_USER="diag", DIAG_MQTT_PASSWORD=stack.broker.passwords["diag"], PYTHONPATH=os.environ.get("IOT_SRC") or str(IOT))
    return subprocess.run([sys.executable, "-m", "iotlab.diagnose", "--symptom", symptom, "--lock", stack.lock_id, "--broker", f"{stack.broker.host}:{stack.broker.port}",
                           "--vendor", stack.cloud_srv.url, "--connector", stack.conn_srv.url, *extra], capture_output=True, text=True, encoding="utf-8", env=env, timeout=60, cwd=str(IOT))


def test_the_command_line_exits_zero_when_healthy_and_one_with_a_verdict_otherwise(stack):
    ok = cli(stack, "lock_offline")
    assert ok.returncode == 0 and "verdict: no layer failed" in ok.stdout and stack.broker.passwords["diag"] not in ok.stdout + ok.stderr
    httpx.post(stack.cloud_srv.url + "/_lab/faults", json={"down": True})
    bad = cli(stack, "codes_not_syncing")
    assert bad.returncode == 1 and "verdict: vendor_cloud" in bad.stdout and "next:" in bad.stdout
    as_json = cli(stack, "codes_not_syncing", ["--json"])
    assert json.loads(as_json.stdout)["broken_layer"] == "vendor_cloud"


# ---- more induced faults, each one aimed at a branch of the verdict -------------------------------------------------------------------------
def test_a_broker_user_that_connects_but_cannot_route_is_a_broker_fault(stack):
    d = run(stack, "lock_offline", broker_user="connector", broker_password=stack.broker.passwords["connector"])      # allowed in, not allowed to use diag/#
    assert d.broken_layer == "broker" and "did not deliver" in d.summary, dg.format_text(d)


def test_a_vendor_that_does_not_answer_at_all_is_a_vendor_fault(stack):
    stack.cloud_srv.stop()
    d = run(stack, "codes_not_syncing")
    assert d.broken_layer == "vendor_cloud" and "does not answer" in d.summary, dg.format_text(d)


def test_an_api_that_fails_while_its_health_route_is_green_is_a_vendor_fault(stack):
    httpx.post(stack.cloud_srv.url + "/_lab/faults", json={"api_down": True})
    d = run(stack, "codes_not_syncing")
    assert d.broken_layer == "vendor_cloud" and "health route is fine but its API fails" in d.summary, dg.format_text(d)


def test_a_token_endpoint_that_fails_is_a_vendor_fault_not_an_oauth_fault(broker, tmp_path):
    s = Stack(broker, tmp_path, shapes=("a",), vendor_cfg={"access_ttl": 10})       # shorter than the refresh skew, so every call must refresh
    try:
        s.authorize()
        httpx.post(s.cloud_srv.url + "/_lab/faults", json={"token_down": True})
        d = run(s, "codes_not_syncing")
        assert d.broken_layer == "vendor_cloud", dg.format_text(d)
        assert s.store.get_oauth()["status"] == "ok", "an outage must not be recorded as a revoked grant"
    finally:
        s.close()


def test_a_webhook_that_was_never_registered_is_a_webhook_fault(broker, tmp_path):
    s = Stack(broker, tmp_path, shapes=("a",), vendor_cfg={"access_ttl": 100000})
    try:
        s.authorize()
        d = run(s, "webhook_silence")
        assert d.broken_layer == "webhook" and "no webhook is registered" in d.summary, dg.format_text(d)
    finally:
        s.close()


def test_a_sync_that_has_not_succeeded_for_a_long_time_is_a_connector_fault(stack):
    stack.conn.reconcile()
    time.sleep(1.3)
    d = run(stack, "codes_not_syncing", stale_s=1.0)
    assert d.broken_layer == "connector" and "last successful sync was" in d.summary, dg.format_text(d)


def test_the_probes_are_read_only_the_door_and_its_battery_are_never_touched(stack):
    for symptom in ALL_SYMPTOMS:
        run(stack, symptom)
    sim = stack.sims[stack.lock_id]
    assert (sim.applied, sim.lock_state, sim.battery) == (0, "locked", 80)
