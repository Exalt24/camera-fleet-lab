# LIFESPAN: permanent
"""Builds the whole slice for a test: lock simulators and a vendor cloud on a real broker, and a connector on top, each in its own
thread, with short timings so a test takes seconds."""
from __future__ import annotations

import itertools
import json
import secrets
import time
import uuid
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx

from iotlab.connector.app import Service, ServiceConfig
from iotlab.connector.crypto import generate_key
from iotlab.connector.vendor_client import ClientConfig
from iotlab.link import FlakyLink
from iotlab.lock_sim import LockSimulator
from iotlab.util import ServerThread
from iotlab.vendor_cloud import VendorCloud, VendorConfig, build_app

_ids = itertools.count(1)
REDIRECT = "http://127.0.0.1:9/callback"


def wait_until(fn, timeout: float = 8.0, interval: float = 0.05, what: str = "the condition"):
    end = time.time() + timeout
    last = None
    while time.time() < end:
        last = fn()
        if last:
            return last
        time.sleep(interval)
    raise AssertionError(f"timed out waiting for {what} (last value {last!r})")


class FakeClock:
    def __init__(self, start: float = 1_800_000_000.0):
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class _Msg:
    def __init__(self, topic: str, payload: str):
        self.topic, self.payload = topic, payload.encode()


def new_lock_id() -> str:
    return f"lock-{next(_ids)}-{uuid.uuid4().hex[:4]}"


class Stack:
    """With a broker, the locks are real MQTT clients. With broker=None there is no MQTT at all: `lock_says` and `lock_status` hand the
    vendor cloud the same messages a lock would have published, so connector logic can be tested without Docker."""

    def __init__(self, broker, tmp_path: Path, shapes=("a",), clock=None, vendor_cfg: dict | None = None, reconcile_interval: float = 3600,
                 with_connector_mqtt: bool = True, start_loop: bool = False, connector_clock=None, webhook_tolerance: float = 300.0,
                 sleeper=None, via_link: bool = False, connector_cfg: dict | None = None):
        self.broker = broker
        self.links: dict[str, FlakyLink] = {}
        self.client_secret = secrets.token_urlsafe(16)
        self.lock_ids = [new_lock_id() for _ in shapes]
        cfg = VendorConfig(client_id="connector-app", client_secret=self.client_secret, redirect_uris=(REDIRECT,), delivery_backoff=0.05,
                           command_timeout=30, **(vendor_cfg or {}))
        self.cloud = VendorCloud(cfg, clock=clock or time.time)
        for lid, shape in zip(self.lock_ids, shapes):
            self.cloud.add_lock(lid, f"Door {lid[-4:]}", shape)
        if broker:
            self.cloud.attach_mqtt(broker.host, broker.port, *broker.creds("vendor"))
        self.cloud_srv = ServerThread(build_app(self.cloud)).start()
        self.sims: dict[str, LockSimulator] = {}
        if broker:
            for lid in self.lock_ids:
                host, port = broker.host, broker.port
                if via_link:
                    self.links[lid] = FlakyLink(broker.host, broker.port)
                    host, port = self.links[lid].host, self.links[lid].port
                self.sims[lid] = LockSimulator(lid, host, port, *broker.creds("device")).start()
        else:
            for lid in self.lock_ids:
                self.lock_status(lid, True)
                self.lock_says(lid, lock="locked")
        self.clock = connector_clock or (clock or time.time)
        self.db_path = tmp_path / "connector.db"
        mqtt_cfg = dict(host=broker.host, port=broker.port, username=broker.creds("connector")[0], password=broker.creds("connector")[1]) if broker else None
        self.svc = Service(
            ServiceConfig(db_path=str(self.db_path), keys=generate_key(),
                          vendor=ClientConfig(base_url=self.cloud_srv.url, client_id="connector-app", client_secret=self.client_secret,
                                              redirect_uri=REDIRECT, base_delay=0.01, max_delay=0.05, max_retry_after=5),
                          reconcile_interval=reconcile_interval, webhook_tolerance=webhook_tolerance,
                          mqtt=mqtt_cfg if with_connector_mqtt else None, **(connector_cfg or {})),
            clock=self.clock, sleeper=sleeper or (lambda s: time.sleep(min(s, 0.05))))
        self.svc.start(loop=start_loop)
        self.conn_srv = ServerThread(self.svc.app).start()
        self.conn = self.svc.connector
        self.store = self.svc.store
        # the vendor knows its locks only after their first state message reaches it
        wait_until(lambda: all(self.cloud.locks[x].online and self.cloud.locks[x].state for x in self.lock_ids), what="the vendor to see its locks")

    # -- offline stand-ins for what a lock publishes ------------------------------------------------------------------------------
    def lock_says(self, lock_id: str, lock: str = "locked", battery: int = 80, last_cmd: str | None = None) -> None:
        self.cloud._on_mqtt(None, None, _Msg(f"locks/{lock_id}/state", json.dumps({"lock": lock, "battery": battery, "battery_low": battery <= 20,
                                                                                    "last_cmd": last_cmd, "seq": 1, "ts": time.time()})))

    def lock_status(self, lock_id: str, online: bool) -> None:
        self.cloud._on_mqtt(None, None, _Msg(f"locks/{lock_id}/status", "online" if online else "offline"))

    @property
    def lock_id(self) -> str:
        return self.lock_ids[0]

    def authorize(self) -> None:
        url = self.svc.client.authorization_url()
        r = httpx.get(url, follow_redirects=False)
        assert r.status_code == 302, r.text
        q = parse_qs(urlparse(r.headers["location"]).query)
        self.svc.client.complete_authorization(q["code"][0], q["state"][0])

    def register_webhook(self) -> None:
        self.conn.register_webhook(self.conn_srv.url + "/webhooks/vendor")

    def close(self) -> None:
        for s in self.sims.values():
            try:
                s.stop(graceful=False)
            except Exception:
                pass
        for link in self.links.values():
            link.close()
        self.conn_srv.stop()
        self.svc.stop()
        self.cloud_srv.stop()
        self.cloud.close()
