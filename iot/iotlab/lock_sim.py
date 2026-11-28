"""A smart lock that speaks MQTT.

Topics, all QoS 1 (payloads are in iot/docs/contract.md):
  locks/<id>/cmd     in    {"cmd_id": "...", "action": "lock" | "unlock" | "report"}
  locks/<id>/state   out   retained: {"lock": "locked"|"unlocked"|"jammed", "battery": 0..100, "battery_low": bool,
                                      "last_cmd": "...", "seq": n, "ts": epoch}
  locks/<id>/status  out   retained "online" on connect; the broker publishes the last will "offline" when the link dies
  locks/<id>/event   out   not retained: {"type": "battery_low", ...} once each time the battery crosses the low mark

The client id is the lock id and the broker's ACL only lets it write its own topics. Commands are delivered at least once, so
the lock remembers the cmd_ids it has applied and a redelivered command changes nothing.
"""
from __future__ import annotations

import json
import threading
import time
from collections import OrderedDict

import paho.mqtt.client as mqtt

LOW_BATTERY = 20


def topic(lock_id: str, leaf: str) -> str:
    return f"locks/{lock_id}/{leaf}"


class LockSimulator:
    def __init__(self, lock_id: str, host: str, port: int, username: str, password: str, battery: int = 80,
                 keepalive: int = 2, clock=time.time):
        self.lock_id = lock_id
        self.host, self.port = host, port
        self.battery = battery
        self.lock_state = "locked"
        self.last_cmd: str | None = None
        self.seq = 0
        self.hung = False              # fault: stays connected and ignores every command
        self.jammed = False            # fault: an unlock attempt ends jammed
        self.applied = 0               # commands that changed the lock (a duplicate does not count)
        self.duplicates = 0
        self._seen: "OrderedDict[str, None]" = OrderedDict()
        self._low_reported = battery <= LOW_BATTERY
        self._clock = clock
        self._lock = threading.RLock()
        self._connected = threading.Event()
        self.keepalive = keepalive
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=lock_id)
        self.client.username_pw_set(username, password)
        self.client.will_set(topic(lock_id, "status"), "offline", qos=1, retain=True)
        self.client.reconnect_delay_set(min_delay=1, max_delay=1)
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
        self.client.on_disconnect = lambda *a, **k: self._connected.clear()

    # -- lifecycle ----------------------------------------------------------------------------------------------------
    def start(self, wait: float = 10.0) -> "LockSimulator":
        self.client.connect(self.host, self.port, keepalive=self.keepalive)
        self.client.loop_start()
        if not self._connected.wait(wait):
            raise RuntimeError(f"lock {self.lock_id} could not connect to the broker")
        return self

    def stop(self, graceful: bool = True) -> None:
        if graceful and self._connected.is_set():
            self.client.publish(topic(self.lock_id, "status"), "offline", qos=1, retain=True).wait_for_publish(2)
        self.client.disconnect()
        self.client.loop_stop()

    def wait_connected(self, timeout: float = 15.0) -> bool:
        return self._connected.wait(timeout)

    # -- mqtt ---------------------------------------------------------------------------------------------------------
    def _on_connect(self, client, userdata, flags, reason_code, properties=None):
        if reason_code != 0:
            return
        client.subscribe(topic(self.lock_id, "cmd"), qos=1)
        client.publish(topic(self.lock_id, "status"), "online", qos=1, retain=True)
        self._publish_state()
        self._connected.set()

    def _publish_state(self) -> None:
        with self._lock:
            self.seq += 1
            doc = {"lock": self.lock_state, "battery": self.battery, "battery_low": self.battery <= LOW_BATTERY,
                   "last_cmd": self.last_cmd, "seq": self.seq, "ts": round(self._clock(), 3)}
        self.client.publish(topic(self.lock_id, "state"), json.dumps(doc), qos=1, retain=True)

    def _on_message(self, client, userdata, msg):
        if self.hung:
            return
        try:
            cmd = json.loads(msg.payload)
            cmd_id, action = str(cmd["cmd_id"]), cmd["action"]
        except (ValueError, KeyError, TypeError):
            return
        with self._lock:
            if cmd_id in self._seen:
                self.duplicates += 1
                return                      # redelivered by the broker: already applied
            self._seen[cmd_id] = None
            while len(self._seen) > 200:
                self._seen.popitem(last=False)
            if action == "lock":
                self.lock_state = "locked"
            elif action == "unlock":
                self.lock_state = "jammed" if self.jammed else "unlocked"
            elif action != "report":
                return
            if action in ("lock", "unlock"):
                self.applied += 1
                self.battery = max(0, self.battery - 1)
            self.last_cmd = cmd_id
        self._publish_state()
        self._maybe_report_low_battery()

    # -- battery and manual use -----------------------------------------------------------------------------------------
    def set_battery(self, level: int) -> None:
        with self._lock:
            self.battery = max(0, min(100, level))
        self._publish_state()
        self._maybe_report_low_battery()

    def _maybe_report_low_battery(self) -> None:
        with self._lock:
            low = self.battery <= LOW_BATTERY
            fire = low and not self._low_reported
            self._low_reported = low
            level = self.battery
        if fire:
            doc = {"type": "battery_low", "battery": level, "ts": round(self._clock(), 3)}
            self.client.publish(topic(self.lock_id, "event"), json.dumps(doc), qos=1)

    def manual_turn(self, new_state: str) -> None:
        """Someone turns the thumbturn by hand: the state changes with no command behind it."""
        with self._lock:
            self.lock_state = new_state
        self._publish_state()
