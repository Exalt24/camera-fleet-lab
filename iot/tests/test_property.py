"""Seeded property test for the event projection.

The dimensions that matter all vary together in each seeded world: several locks, six event types, events delivered out of order, 0 to 3
times each (a dropped event, a normal one, duplicates), over two sources (webhook and poll), with snapshots that land at random moments.

Rules that must hold at every step of every world:
  1. one row per event id, however many times it was delivered
  2. a lock's sequence never goes down
  3. delivering an event id that is already recorded changes nothing at all
  4. a state the record holds is always one the lock really passed through
and at the end of every world, after one snapshot from the vendor, the record equals the vendor's truth (the reconcile promise).
"""
from __future__ import annotations

import random

import pytest

from iotlab.connector.crypto import CredentialVault, generate_key
from iotlab.connector.normalize import normalize_lock
from iotlab.connector.store import Store
from iotlab.connector.sync import Connector

KINDS = ["locked", "unlocked", "jammed", "offline", "online", "battery_low"]
LOCKS = ["l1", "l2", "l3"]


def build_world(rng: random.Random):
    truth = {l: {"state": "locked", "online": True, "battery": 80, "seq": 0} for l in LOCKS}
    passed = {l: {"locked"} for l in LOCKS}
    events = []
    for _ in range(rng.randint(15, 60)):
        lock = rng.choice(LOCKS)
        t = truth[lock]
        kind = rng.choice(KINDS)
        t["seq"] += 1
        data = {}
        if kind in ("locked", "unlocked", "jammed"):
            t["state"] = kind
            passed[lock].add(kind)
        elif kind == "offline":
            t["online"] = False
        elif kind == "online":
            t["online"] = True
        else:
            t["battery"] = data["battery"] = rng.randint(1, 20)
        events.append({"id": f"evt_{len(events)}", "type": f"lock.{kind}", "lock_id": lock, "occurred_at": 1_800_000_000 + len(events),
                       "seq": len(events) + 1, "lock_seq": t["seq"], "data": data})
    deliveries = [(e, rng.choice(["webhook", "poll"])) for e in events for _ in range(rng.choice([0, 1, 1, 1, 2, 3]))]
    rng.shuffle(deliveries)
    return events, deliveries, truth, passed


def snapshot_of(truth, lock):
    t = truth[lock]
    return normalize_lock({"id": lock, "name": lock, "state": t["state"].upper(), "battery_level": t["battery"], "online": t["online"], "seq": t["seq"],
                           "updated_at": 1_800_000_000})


def table(store):
    return [store.get_lock(l) for l in LOCKS], store.count_events()


@pytest.mark.parametrize("seed", range(120))
def test_projection_rules_hold_in_a_random_world(seed, tmp_path):
    rng = random.Random(seed)
    events, deliveries, truth, passed = build_world(rng)
    store = Store(str(tmp_path / "p.db"))
    conn = Connector(store, CredentialVault(generate_key()), None, clock=lambda: 1_800_100_000.0)
    seen_ids: set[str] = set()
    last_seq = {l: 0 for l in LOCKS}
    for evt, source in deliveries:
        before = table(store)
        was_known = evt["id"] in seen_ids
        result = conn.apply_event(evt, source)
        seen_ids.add(evt["id"])
        if was_known:
            assert result == "duplicate" and table(store) == before, f"seed {seed}: a repeated delivery changed something"
        assert store.count_events() == len(seen_ids), f"seed {seed}: rule 1"
        row = store.get_lock(evt["lock_id"])
        assert row["lock_seq"] >= last_seq[evt["lock_id"]], f"seed {seed}: rule 2"
        last_seq[evt["lock_id"]] = row["lock_seq"]
        assert row["state"] in passed[evt["lock_id"]] | {"unknown"}, f"seed {seed}: rule 4"
        if rng.random() < 0.15:                                    # a snapshot lands at a random moment
            conn._apply_snapshot(snapshot_of(truth, evt["lock_id"]))
            last_seq[evt["lock_id"]] = store.get_lock(evt["lock_id"])["lock_seq"]
    for lock in LOCKS:                                             # the reconcile promise
        conn._apply_snapshot(snapshot_of(truth, lock))
        row = store.get_lock(lock)
        assert (row["state"], bool(row["online"]), row["battery"], row["lock_seq"]) == (truth[lock]["state"], truth[lock]["online"], truth[lock]["battery"], truth[lock]["seq"]), f"seed {seed}: {lock} did not converge"
    store.close()
