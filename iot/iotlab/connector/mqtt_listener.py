"""The connector's direct MQTT subscription: the locks' own state and status messages, read as the `connector` broker user.

The lock id comes from the topic and is checked against the pattern locks/<id>/state|status. Payloads that are not valid JSON,
or that do not carry a known lock state, are counted and dropped; they never raise into the network thread.
"""
from __future__ import annotations

import json

import paho.mqtt.client as mqtt

from .safelog import SafeLogger
from .sync import Connector

log = SafeLogger("lockbridge.mqtt")


class MqttListener:
    def __init__(self, connector: Connector, host: str, port: int, username: str, password: str, client_id: str = "connector"):
        self.connector = connector
        self.host, self.port = host, port
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id)
        self.client.username_pw_set(username, password)
        self.client.reconnect_delay_set(min_delay=1, max_delay=5)
        self.client.on_connect = self._on_connect
        self.client.on_disconnect = self._on_disconnect
        self.client.on_message = self._on_message

    def start(self) -> "MqttListener":
        self.client.connect(self.host, self.port, keepalive=5)
        self.client.loop_start()
        return self

    def stop(self) -> None:
        self.client.disconnect()
        self.client.loop_stop()

    def _on_connect(self, client, userdata, flags, reason_code, properties=None):
        ok = reason_code == 0
        self.connector.store.meta_set("mqtt_connected", "1" if ok else "0")
        if ok:
            client.subscribe("locks/+/state", qos=1)
            client.subscribe("locks/+/status", qos=1)
        else:
            log.warning("broker refused the connection: %s", reason_code)

    def _on_disconnect(self, client, userdata, flags, reason_code, properties=None):
        self.connector.store.meta_set("mqtt_connected", "0")

    def _on_message(self, client, userdata, msg):
        parts = msg.topic.split("/")
        if len(parts) != 3 or parts[0] != "locks" or not parts[1]:
            return
        lock_id, leaf = parts[1], parts[2]
        try:
            if leaf == "state":
                try:
                    doc = json.loads(msg.payload)
                except ValueError:
                    doc = None
                self.connector.on_mqtt_state(lock_id, doc)
            elif leaf == "status":
                self.connector.on_mqtt_status(lock_id, msg.payload.decode(errors="replace"))
        except Exception as exc:                      # a bad message must not stop the network thread
            log.error("could not handle a message on %s: %s", msg.topic, exc.__class__.__name__)
