"""The MQTT topics of the doormat against the repo's real mosquitto broker (iot/mosquitto, with its per user access list).

The mat is the host emulation, connected as user `doormat` with its id as the client id. A controller connects as `doormatctl`. Needs Docker.
"""
from __future__ import annotations

import json
import queue
import time

import httpx
import paho.mqtt.client as mqtt
import pytest
from conftest import SRC, wait_until
from iotlab import broker as broker_mod

import sim_server

pytestmark = pytest.mark.broker


@pytest.fixture(scope="module")
def broker():
    if not broker_mod.docker_available():
        pytest.skip("Docker is not running, so the real mosquitto broker cannot start")
    b = broker_mod.start_broker()
    try:
        yield b
    finally:
        b.remove()


@pytest.fixture
def mat(broker):
    user, pw = broker.creds("doormat")
    s = sim_server.Sim("mat-mq", mqtt={"host": broker.host, "port": broker.port, "user": user, "password": pw})
    s.start(0, 0)
    yield s
    s.stop()


class Controller:
    def __init__(self, broker, user="doormatctl"):
        self.q: queue.Queue = queue.Queue()
        self.c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"ctl-{user}-{id(self)}")
        self.c.username_pw_set(*broker.creds(user))
        self.c.on_message = lambda cl, ud, m: self.q.put((m.topic, m.payload.decode(), m.retain))
        self.c.connect(broker.host, broker.port, keepalive=10)
        self.c.loop_start()

    def sub(self, topic):
        self.c.subscribe(topic, qos=1)
        time.sleep(0.4)

    def pub(self, topic, payload):
        self.c.publish(topic, payload, qos=1).wait_for_publish(5)

    def get(self, topic, timeout=6.0):
        end = time.time() + timeout
        while time.time() < end:
            try:
                t, p, r = self.q.get(timeout=0.3)
            except queue.Empty:
                continue
            if t == topic:
                return json.loads(p)
        raise AssertionError(f"nothing arrived on {topic}")

    def close(self):
        self.c.loop_stop()
        self.c.disconnect()


@pytest.fixture
def ctl(broker):
    c = Controller(broker)
    yield c
    c.close()


def status(s):
    return httpx.get(f"http://127.0.0.1:{s.http_port}/api/status").json()


def test_a_command_over_mqtt_changes_the_led_mode_and_is_acknowledged(mat, ctl):
    ctl.sub("doormat/mat-mq/event/ack")
    ctl.pub("doormat/mat-mq/cmd/led", json.dumps({"mode": "chase", "color": "#ff8800"}))
    assert ctl.get("doormat/mat-mq/event/ack") == {"ok": True, "type": "led"}
    s = status(mat)
    assert s["mode"] == "chase" and s["color"] == "#ff8800"


def test_greet_and_message_over_mqtt(mat, ctl):
    ctl.sub("doormat/mat-mq/event/ack")
    before = status(mat)["greetings"]
    ctl.pub("doormat/mat-mq/cmd/greet", "")
    assert ctl.get("doormat/mat-mq/event/ack")["ok"] is True
    assert status(mat)["greetings"] == before + 1
    ctl.pub("doormat/mat-mq/cmd/message", json.dumps({"text": "From the broker"}))
    assert ctl.get("doormat/mat-mq/event/ack")["ok"] is True
    assert status(mat)["message"] == "From the broker"


def test_a_bad_payload_is_acknowledged_with_the_reason_and_changes_nothing(mat, ctl):
    ctl.sub("doormat/mat-mq/event/ack")
    before = status(mat)
    ctl.pub("doormat/mat-mq/cmd/led", json.dumps({"mode": "strobe"}))
    assert ctl.get("doormat/mat-mq/event/ack") == {"ok": False, "err": "bad_mode"}
    ctl.pub("doormat/mat-mq/cmd/led", "{broken")
    assert ctl.get("doormat/mat-mq/event/ack") == {"ok": False, "err": "not_json"}
    ctl.pub("doormat/mat-mq/cmd/selfdestruct", "{}")
    assert ctl.get("doormat/mat-mq/event/ack") == {"ok": False, "err": "unknown_cmd"}
    after = status(mat)
    assert (after["mode"], after["color"], after["brightness"]) == (before["mode"], before["color"], before["brightness"])


def test_presence_events_and_the_retained_status_are_published(mat, ctl):
    ctl.sub("doormat/mat-mq/event/presence")
    ctl.sub("doormat/mat-mq/status")
    retained = ctl.get("doormat/mat-mq/status", timeout=8)
    assert retained["t"] == "status" and retained["id"] == "mat-mq"
    httpx.post(f"http://127.0.0.1:{mat.http_port}/sim/step", json={"ms": 800})
    ev = ctl.get("doormat/mat-mq/event/presence", timeout=6)
    assert ev["state"] == "occupied"
    assert ctl.get("doormat/mat-mq/event/presence", timeout=6)["state"] == "empty"


def test_a_late_subscriber_gets_the_retained_status(mat, broker):
    wait_until(lambda: status(mat), what="the mat to be up")
    time.sleep(1.2)  # the first retained status is published on the first clock pass
    late = Controller(broker)
    try:
        late.sub("doormat/mat-mq/status")
        topic, payload, retained = late.q.get(timeout=2)  # a retained message arrives at once, not at the next publish
        assert topic == "doormat/mat-mq/status" and retained is True
        assert json.loads(payload)["id"] == "mat-mq"
    finally:
        late.close()


def test_the_controller_cannot_forge_a_status_or_an_event(mat, broker):
    watcher = Controller(broker)
    forger = Controller(broker)
    try:
        watcher.sub("doormat/mat-mq/event/#")
        forger.pub("doormat/mat-mq/event/presence", json.dumps({"t": "presence", "state": "occupied", "forged": True}))
        time.sleep(1.0)
        forged = []
        while not watcher.q.empty():
            t, p, r = watcher.q.get()
            if "forged" in p:
                forged.append(p)
        assert forged == [], "the broker's access list must drop a write to an event topic from the controller user"
    finally:
        watcher.close()
        forger.close()


def test_one_mat_cannot_command_another(mat, broker):
    """The mat's own user may read only its own command topics (pattern read doormat/%c/cmd/#)."""
    user, pw = broker.creds("doormat")
    got: queue.Queue = queue.Queue()
    other = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="mat-other")
    other.username_pw_set(user, pw)
    other.on_message = lambda c, u, m: got.put(m.topic)
    other.connect(broker.host, broker.port, keepalive=10)
    other.loop_start()
    try:
        other.subscribe("doormat/mat-mq/cmd/#", qos=1)
        time.sleep(0.5)
        ctl = Controller(broker)
        ctl.pub("doormat/mat-mq/cmd/greet", "")
        ctl.close()
        time.sleep(1.0)
        assert got.empty(), "mat-other must not see commands addressed to mat-mq"
    finally:
        other.loop_stop()
        other.disconnect()


def test_a_topic_that_only_starts_like_a_route_is_not_that_route(mat, ctl):
    """A topic suffix such as `led x` must not be read as `led`: the device matches the whole suffix."""
    ctl.sub("doormat/mat-mq/event/ack")
    before = status(mat)
    ctl.pub("doormat/mat-mq/cmd/led x", json.dumps({"mode": "solid", "brightness": 11}))
    assert ctl.get("doormat/mat-mq/event/ack") == {"ok": False, "err": "unknown_cmd"}
    after = status(mat)
    assert (after["mode"], after["brightness"]) == (before["mode"], before["brightness"])
