"""The lock simulator against a REAL mosquitto broker: retained state, the last will, QoS 1 redelivery, a flaky link, the low battery
report and the broker's own access control. Needs Docker (the `broker` fixture skips with a reason when it is not running)."""
from __future__ import annotations

import json
import random
import secrets
import time

import paho.mqtt.client as mqtt
import pytest

from harness import new_lock_id, wait_until
from iotlab.link import FlakyLink
from iotlab.lock_sim import LockSimulator


class Watcher:
    """An MQTT client that records every message on the topics it subscribes to."""

    def __init__(self, broker, user="observer", client_id=None):
        self.msgs: list[tuple[str, str]] = []
        self.rc = None
        self.c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id or f"w-{secrets.token_hex(3)}")
        self.c.username_pw_set(*broker.creds(user))
        self.c.on_message = lambda c, u, m: self.msgs.append((m.topic, m.payload.decode()))
        self.c.on_connect = lambda c, u, f, rc, p=None: setattr(self, "rc", rc)
        self.c.connect(broker.host, broker.port, keepalive=10)
        self.c.loop_start()
        wait_until(lambda: self.rc is not None, what="the watcher to connect")

    def sub(self, *topics):
        for t in topics:
            self.c.subscribe(t, qos=1)

    def last(self, topic):
        for t, p in reversed(self.msgs):
            if t == topic:
                return p
        return None

    def count(self, topic):
        return sum(1 for t, _ in self.msgs if t == topic)

    def close(self):
        self.c.disconnect()
        self.c.loop_stop()


@pytest.fixture
def lock(broker):
    lid = new_lock_id()
    sim = LockSimulator(lid, broker.host, broker.port, *broker.creds("device")).start()
    w = Watcher(broker)
    w.sub(f"locks/{lid}/#")
    yield sim, w, lid
    w.close()
    sim.stop(graceful=False)


def cmd(w, lid, cmd_id, action):
    w.c.publish(f"locks/{lid}/cmd", json.dumps({"cmd_id": cmd_id, "action": action}), qos=1)


def test_a_command_changes_the_lock_and_the_state_is_published_retained(lock, broker):
    sim, w, lid = lock
    wait_until(lambda: w.last(f"locks/{lid}/status") == "online", what="the status")
    cmd(w, lid, "c1", "unlock")
    wait_until(lambda: sim.lock_state == "unlocked", what="the unlock")
    wait_until(lambda: (json.loads(w.last(f"locks/{lid}/state") or "{}").get("last_cmd") == "c1"), what="the state to name the command")
    late = Watcher(broker)                                         # a client that connects afterwards still learns the state
    late.sub(f"locks/{lid}/state")
    wait_until(lambda: late.last(f"locks/{lid}/state"), what="the retained state")
    doc = json.loads(late.last(f"locks/{lid}/state"))
    assert doc["lock"] == "unlocked" and doc["last_cmd"] == "c1" and doc["battery"] == 79
    late.close()


def test_a_redelivered_command_is_applied_once(lock):
    sim, w, lid = lock
    for _ in range(3):
        cmd(w, lid, "dup-1", "unlock")
    cmd(w, lid, "dup-2", "lock")
    wait_until(lambda: sim.applied == 2 and sim.lock_state == "locked", what="both commands")
    assert sim.duplicates == 2 and sim.battery == 78


def test_report_republishes_the_state_without_touching_the_door(lock):
    sim, w, lid = lock
    wait_until(lambda: w.last(f"locks/{lid}/state"), what="the first state")
    before = (sim.lock_state, sim.battery, sim.applied)
    cmd(w, lid, "r1", "report")
    wait_until(lambda: (json.loads(w.last(f"locks/{lid}/state")).get("last_cmd") == "r1"), what="the report echo")
    assert (sim.lock_state, sim.battery, sim.applied) == before


@pytest.mark.parametrize("payload", [b"not json", b"[]", b'{"action":"unlock"}', b'{"cmd_id":"x","action":"detonate"}', b'{"cmd_id":5}'])
def test_garbage_commands_are_ignored(lock, payload):
    sim, w, lid = lock
    w.c.publish(f"locks/{lid}/cmd", payload, qos=1)
    cmd(w, lid, "after-garbage", "unlock")
    wait_until(lambda: sim.lock_state == "unlocked", what="the valid command after the garbage")
    assert sim.applied == 1


def test_a_jammed_lock_reports_jammed_instead_of_unlocked(lock):
    sim, w, lid = lock
    sim.jammed = True
    cmd(w, lid, "j1", "unlock")
    wait_until(lambda: sim.lock_state == "jammed", what="the jam")
    wait_until(lambda: json.loads(w.last(f"locks/{lid}/state"))["lock"] == "jammed", what="the jam to be published")


def test_a_hung_lock_stays_connected_and_ignores_commands(lock):
    sim, w, lid = lock
    sim.hung = True
    cmd(w, lid, "h1", "unlock")
    time.sleep(0.5)
    assert sim.lock_state == "locked" and sim.applied == 0 and w.last(f"locks/{lid}/status") == "online"


def test_the_battery_low_report_fires_once_per_crossing(lock):
    sim, w, lid = lock
    sim.set_battery(40)
    sim.set_battery(19)
    wait_until(lambda: w.count(f"locks/{lid}/event") == 1, what="the first battery_low")
    sim.set_battery(15)
    sim.set_battery(12)
    time.sleep(0.4)
    assert w.count(f"locks/{lid}/event") == 1, "still low, so no second report"
    doc = json.loads(w.last(f"locks/{lid}/event"))
    assert doc["type"] == "battery_low" and doc["battery"] == 19
    assert json.loads(w.last(f"locks/{lid}/state"))["battery_low"] is True
    sim.set_battery(60)
    sim.set_battery(9)
    wait_until(lambda: w.count(f"locks/{lid}/event") == 2, what="a second report after recovering and dropping again")


def test_a_lock_that_starts_low_does_not_report_it_as_a_new_crossing(broker):
    lid = new_lock_id()
    w = Watcher(broker)
    w.sub(f"locks/{lid}/#")
    sim = LockSimulator(lid, broker.host, broker.port, *broker.creds("device"), battery=10).start()
    try:
        wait_until(lambda: w.last(f"locks/{lid}/state"), what="the state")
        assert json.loads(w.last(f"locks/{lid}/state"))["battery_low"] is True
        time.sleep(0.3)
        assert w.count(f"locks/{lid}/event") == 0
    finally:
        sim.stop(graceful=False)
        w.close()


# ---- the link -----------------------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("mode", ["cut", "blackhole"])
def test_when_the_link_dies_the_broker_publishes_the_last_will_and_the_lock_comes_back(broker, mode):
    lid = new_lock_id()
    link = FlakyLink(broker.host, broker.port)
    sim = LockSimulator(lid, link.host, link.port, *broker.creds("device"), keepalive=2).start()
    w = Watcher(broker)
    w.sub(f"locks/{lid}/status")
    try:
        wait_until(lambda: w.last(f"locks/{lid}/status") == "online", what="online")
        getattr(link, mode)()
        wait_until(lambda: w.last(f"locks/{lid}/status") == "offline", timeout=10, what=f"the last will after a {mode}")
        late = Watcher(broker)                                  # the last will is retained: a client that arrives later still learns it
        late.sub(f"locks/{lid}/status")
        wait_until(lambda: late.last(f"locks/{lid}/status") == "offline", what="the retained last will")
        late.close()
        link.heal()
        wait_until(lambda: w.last(f"locks/{lid}/status") == "online", timeout=15, what="the lock to reconnect")
    finally:
        w.close()
        sim.stop(graceful=False)
        link.close()


def test_a_command_sent_while_the_link_is_down_is_lost_not_queued(broker):
    lid = new_lock_id()
    link = FlakyLink(broker.host, broker.port)
    sim = LockSimulator(lid, link.host, link.port, *broker.creds("device"), keepalive=2).start()
    w = Watcher(broker)
    w.sub(f"locks/{lid}/status")
    try:
        wait_until(lambda: w.last(f"locks/{lid}/status") == "online", what="online")
        link.cut()
        wait_until(lambda: w.last(f"locks/{lid}/status") == "offline", timeout=10, what="offline")
        cmd(w, lid, "lost-1", "unlock")
        link.heal()
        wait_until(lambda: w.last(f"locks/{lid}/status") == "online", timeout=15, what="back online")
        time.sleep(0.6)
        assert sim.lock_state == "locked" and sim.applied == 0, "the lock uses a clean session, so a command published while it was away is gone (the vendor will call it timed out)"
    finally:
        w.close()
        sim.stop(graceful=False)
        link.close()


def test_a_seeded_flapping_link_ends_consistent(broker):
    lid = new_lock_id()
    link = FlakyLink(broker.host, broker.port)
    sim = LockSimulator(lid, link.host, link.port, *broker.creds("device"), keepalive=2).start()
    w = Watcher(broker)
    w.sub(f"locks/{lid}/#")
    rng = random.Random(7)
    try:
        wait_until(lambda: w.last(f"locks/{lid}/status") == "online", what="online")
        link.start_flapping(mean_up=0.8, mean_down=0.6, seed=7)
        sent = 0
        end = time.time() + 6
        while time.time() < end:
            cmd(w, lid, f"f-{sent}", rng.choice(["lock", "unlock"]))
            sent += 1
            time.sleep(0.25)
        link.stop_flapping()
        wait_until(lambda: w.last(f"locks/{lid}/status") == "online", timeout=15, what="online after the flapping stops")
        cmd(w, lid, "final", "unlock")
        wait_until(lambda: sim.lock_state == "unlocked" and sim.last_cmd == "final", what="the final command")
        wait_until(lambda: json.loads(w.last(f"locks/{lid}/state"))["last_cmd"] == "final", what="the final retained state")
        assert link.cuts >= 2, "the link really flapped"
        assert sim.applied <= sent + 1
        assert json.loads(w.last(f"locks/{lid}/state"))["lock"] == sim.lock_state
    finally:
        w.close()
        sim.stop(graceful=False)
        link.close()


@pytest.mark.parametrize("seed", range(6))
def test_random_command_streams_with_redelivery_apply_each_command_id_once(broker, seed):
    rng = random.Random(seed)
    lid = new_lock_id()
    sim = LockSimulator(lid, broker.host, broker.port, *broker.creds("device")).start()
    w = Watcher(broker)
    try:
        ids = [f"s{seed}-{i}" for i in range(rng.randint(5, 15))]
        actions = {i: rng.choice(["lock", "unlock", "report"]) for i in ids}
        order = [i for i in ids for _ in range(rng.choice([1, 1, 2, 3]))]
        rng.shuffle(order)                                      # redelivery in any order
        for i in order:
            cmd(w, lid, i, actions[i])
        unique = len(set(order))
        wait_until(lambda: len(sim._seen) == unique and sim.duplicates == len(order) - unique, timeout=10, what="every delivery to be handled")
        assert sim.applied == sum(1 for i in set(order) if actions[i] != "report")
        assert sim.duplicates == len(order) - unique
    finally:
        w.close()
        sim.stop(graceful=False)


# ---- the broker's own access control ----------------------------------------------------------------------------------------------------------
def test_a_lock_cannot_write_another_locks_topics(broker):
    victim, mallory = new_lock_id(), new_lock_id()
    w = Watcher(broker)
    w.sub(f"locks/{victim}/#", f"locks/{mallory}/#")
    evil = Watcher(broker, user="device", client_id=mallory)
    evil.c.publish(f"locks/{victim}/state", json.dumps({"lock": "unlocked"}), qos=1).wait_for_publish(2)
    evil.c.publish(f"locks/{victim}/status", "online", qos=1, retain=True).wait_for_publish(2)
    evil.c.publish(f"locks/{mallory}/state", json.dumps({"lock": "locked"}), qos=1).wait_for_publish(2)      # its own topic is fine
    time.sleep(0.6)
    assert w.count(f"locks/{victim}/state") == 0 and w.count(f"locks/{victim}/status") == 0
    wait_until(lambda: w.count(f"locks/{mallory}/state") == 1, what="a lock writing its own topic")
    for x in (w, evil):
        x.close()


def test_the_connector_user_can_read_state_and_send_commands_but_not_forge_state(broker):
    lid = new_lock_id()
    w = Watcher(broker)
    w.sub(f"locks/{lid}/#")
    conn = Watcher(broker, user="connector")
    conn.c.publish(f"locks/{lid}/cmd", "{}", qos=1).wait_for_publish(2)
    conn.c.publish(f"locks/{lid}/state", json.dumps({"lock": "unlocked"}), qos=1).wait_for_publish(2)
    wait_until(lambda: w.count(f"locks/{lid}/cmd") == 1, what="a permitted command")
    time.sleep(0.5)
    assert w.count(f"locks/{lid}/state") == 0
    w.close()
    conn.close()


def test_anonymous_and_wrong_password_connections_are_refused(broker):
    for creds in (None, ("diag", "wrong-password")):
        c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"x-{secrets.token_hex(3)}")
        if creds:
            c.username_pw_set(*creds)
        got = []
        c.on_connect = lambda cl, u, f, rc, p=None: got.append(rc)
        c.connect(broker.host, broker.port, keepalive=5)
        c.loop_start()
        wait_until(lambda: got, what="a CONNACK")
        c.loop_stop()
        assert got[0].is_failure, f"{creds} must be refused"


def test_a_late_subscriber_learns_a_connected_lock_is_online(lock, broker):
    sim, w, lid = lock
    late = Watcher(broker)
    late.sub(f"locks/{lid}/status")
    wait_until(lambda: late.last(f"locks/{lid}/status") == "online", what="the retained online status")
    late.close()
