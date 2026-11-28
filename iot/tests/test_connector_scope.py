"""The connector is the vendor's client for the locks the vendor knows. The broker carries every lock on it, and a connector that called the
vendor about all of them would burn its rate limit (found when a shared broker held dozens of retained locks and the code sync hit a 429)."""
from __future__ import annotations

import httpx
import pytest

from harness import Stack


@pytest.fixture
def stack(tmp_path):
    s = Stack(None, tmp_path, shapes=("a", "b", "c"))
    s.authorize()
    yield s
    s.close()


def test_a_lock_seen_only_on_the_broker_is_not_the_vendors_business(stack):
    stack.conn.sync_locks()
    asked: list[str] = []
    real = stack.svc.client.request
    stack.svc.client.request = lambda method, path, **kw: (asked.append(path), real(method, path, **kw))[1]
    for i in range(30):
        stack.conn.on_mqtt_state(f"someone-elses-lock-{i}", {"lock": "locked", "battery": 50})
    stack.conn.sync_codes()
    assert not [p for p in asked if "someone-elses-lock" in p] and len(asked) == 3
    assert len(stack.store.list_locks()) == 33 and len(stack.store.list_locks(managed_only=True)) == 3
    assert len(httpx.get(stack.conn_srv.url + "/locks").json()["data"]) == 3
