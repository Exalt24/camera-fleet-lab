"""Shared fixtures. The broker is a REAL mosquitto container: one per test session (or the one named by IOT_BROKER_JSON, which
run_mutations.py sets so that its many runs share a single broker). Tests that need Docker use the `broker` fixture and skip
with a reason when Docker is not running.

IOT_SRC lets run_mutations.py point the tests at a mutated copy of the code.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, os.environ.get("IOT_SRC") or str(HERE.parent))
sys.path.insert(1, str(HERE))

import pytest  # noqa: E402

from iotlab import broker as broker_mod  # noqa: E402


@pytest.fixture(scope="session")
def broker():
    shared = os.environ.get("IOT_BROKER_JSON")
    if shared:
        doc = json.loads(Path(shared).read_text(encoding="utf-8"))
        yield broker_mod.Broker(container=doc["container"], port=doc["port"], passwords=doc["passwords"], workdir=Path(doc["workdir"]))
        return
    if not broker_mod.docker_available():
        pytest.skip("Docker is not running, so the real mosquitto broker cannot start")
    b = broker_mod.start_broker()
    try:
        yield b
    finally:
        b.remove()


@pytest.fixture
def make_broker():
    """A private broker for a test that stops or breaks it."""
    if not broker_mod.docker_available():
        pytest.skip("Docker is not running, so the real mosquitto broker cannot start")
    made = []

    def factory():
        b = broker_mod.start_broker()
        made.append(b)
        return b

    yield factory
    for b in made:
        b.remove()
