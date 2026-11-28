"""Shared fixtures for the host side tests of the doormat control surface.

These run the host emulation (esp32/host/sim_server.py) in front of core_cli, the device logic compiled for the host. Build that first:

    cd esp32 && pio run -e core_cli

ESP32_SRC lets run_mutations.py point everything at a mutated copy of esp32/.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = Path(os.environ.get("ESP32_SRC") or HERE.parent)
sys.path.insert(0, str(SRC / "host"))
sys.path.insert(1, str(HERE.parent.parent / "iot"))  # the repo's mosquitto helper, for the MQTT tests

import pytest  # noqa: E402

import sim_server  # noqa: E402


@pytest.fixture(scope="module")
def sim():
    s = sim_server.Sim("mat-test")
    s.start(0, 0)
    try:
        yield s
    finally:
        s.stop()


@pytest.fixture
def base(sim):
    return f"http://127.0.0.1:{sim.http_port}"


def wait_until(fn, timeout: float = 8.0, interval: float = 0.05, what: str = "the condition"):
    import time

    end = time.time() + timeout
    last = None
    while time.time() < end:
        last = fn()
        if last:
            return last
        time.sleep(interval)
    raise AssertionError(f"timed out waiting for {what} (last value {last!r})")
