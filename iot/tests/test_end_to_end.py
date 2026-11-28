"""The whole slice on a real broker: lock simulators, the vendor stand-in, the connector. A command given through the connector travels
connector -> vendor REST -> MQTT -> lock, and the answer comes back by MQTT (to the connector) and by webhook (through the vendor)."""
from __future__ import annotations

import time

import pytest

from harness import Stack, wait_until
from iotlab.connector.vendor_client import VendorError


@pytest.fixture
def stack(broker, tmp_path):
    s = Stack(broker, tmp_path, shapes=("a", "b"), via_link=True)
    s.authorize()
    s.register_webhook()
    s.conn.sync_locks()
    yield s
    s.close()


def test_an_unlock_goes_out_over_mqtt_and_comes_back_two_ways(stack):
    lid, sim = stack.lock_id, stack.sims[stack.lock_id]
    cmd = stack.conn.send_command(lid, "unlock")
    wait_until(lambda: sim.lock_state == "unlocked", what="the lock to unlock")
    wait_until(lambda: stack.store.get_command(cmd["id"])["status"] == "confirmed", what="the command to be confirmed")
    wait_until(lambda: stack.store.get_lock(lid)["state"] == "unlocked", what="the webhook to update the vendor view")
    row = stack.store.get_lock(lid)
    assert row["mqtt_state"] == "unlocked", "the device's own view arrived over MQTT"
    assert stack.store.get_command(cmd["id"])["confirmed_by"] in ("mqtt", "webhook")
    assert stack.cloud.commands[cmd["id"]]["status"] == "confirmed"
    assert stack.store.count_events("webhook") == 1 and row["lock_seq"] == 1


def test_a_lock_and_unlock_round_trip_leaves_record_vendor_and_device_in_agreement(stack):
    lid, sim = stack.lock_id, stack.sims[stack.lock_id]
    stack.conn.send_command(lid, "unlock")
    wait_until(lambda: stack.store.get_lock(lid)["state"] == "unlocked", what="unlocked")
    stack.conn.send_command(lid, "lock")
    wait_until(lambda: stack.store.get_lock(lid)["state"] == "locked" and stack.store.get_lock(lid)["lock_seq"] == 2, what="locked again")
    row = stack.store.get_lock(lid)
    assert (row["state"], row["mqtt_state"], sim.lock_state, stack.cloud.locks[lid].state) == ("locked",) * 4
    assert not stack.store.pending_commands()


def test_a_hand_turned_lock_reaches_the_record_without_any_command(stack):
    lid, sim = stack.lock_id, stack.sims[stack.lock_id]
    sim.manual_turn("unlocked")
    wait_until(lambda: stack.store.get_lock(lid)["state"] == "unlocked", what="the webhook for a manual turn")
    evt = stack.cloud.events[-1]
    assert evt["data"]["source"] == "manual" and "command_id" not in evt["data"]


def test_a_low_battery_is_reported_by_the_lock_and_lands_in_the_record(stack):
    lid, sim = stack.lock_id, stack.sims[stack.lock_id]
    sim.set_battery(15)
    wait_until(lambda: stack.store.get_lock(lid)["battery_low"] == 1, what="the battery_low webhook")
    wait_until(lambda: stack.store.get_lock(lid)["mqtt_battery"] == 15, what="the device's own state over MQTT")
    row = stack.store.get_lock(lid)
    assert row["battery"] == 15 and row["mqtt_battery"] == 15
    assert [e["type"] for e in stack.cloud.events if e["lock_id"] == lid][-1] == "lock.battery_low"


def test_a_lock_that_loses_its_link_goes_offline_everywhere_and_comes_back(stack):
    lid = stack.lock_id
    stack.links[lid].cut()
    wait_until(lambda: stack.store.get_lock(lid)["mqtt_online"] == 0, timeout=10, what="the connector to see the last will")
    wait_until(lambda: stack.store.get_lock(lid)["online"] == 0, timeout=10, what="the vendor event lock.offline to reach the record")
    with pytest.raises(VendorError) as exc:
        stack.conn.send_command(lid, "unlock")
    assert exc.value.code == "lock_offline" and not stack.store.pending_commands()
    stack.links[lid].heal()
    wait_until(lambda: stack.store.get_lock(lid)["online"] == 1 and stack.store.get_lock(lid)["mqtt_online"] == 1, timeout=15, what="the lock to come back")


def test_a_command_a_hung_lock_never_answers_stays_pending_then_times_out_at_the_vendor(stack):
    lid = stack.lock_id
    stack.sims[lid].hung = True                                               # online per the broker, but not reading commands
    stack.cloud.cfg.command_timeout = 0.5
    cmd = stack.conn.send_command(lid, "unlock")
    time.sleep(0.8)
    assert stack.store.get_command(cmd["id"])["status"] == "pending", "nothing confirmed it"
    assert stack.conn.refresh_command(cmd["id"])["status"] == "timed_out"
    assert stack.sims[lid].lock_state == "locked"


def test_a_flapping_link_converges_once_it_settles_and_a_reconcile_runs(stack):
    lid, sim = stack.lock_id, stack.sims[stack.lock_id]
    stack.links[lid].start_flapping(mean_up=0.7, mean_down=0.5, seed=3)
    end = time.time() + 5
    n = 0
    while time.time() < end:
        try:
            stack.conn.send_command(lid, "unlock" if n % 2 == 0 else "lock")
        except VendorError:
            pass                                                              # the lock was offline at that moment
        n += 1
        time.sleep(0.3)
    stack.links[lid].stop_flapping()
    wait_until(lambda: stack.cloud.locks[lid].online is True, timeout=15, what="the vendor to see the lock online")
    time.sleep(1.0)
    stack.conn.reconcile()
    wait_until(lambda: stack.store.get_lock(lid)["state"] == sim.lock_state == stack.cloud.locks[lid].state, timeout=8, what="record, device and vendor to agree")
    assert stack.links[lid].cuts >= 2
