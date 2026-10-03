#!/usr/bin/env python
"""Summarise the stored probe history since a given UTC time: how many probes, how many states, longest handshake age.
    python scripts/soak_summary.py 18:47:24      (UTC, from the history_transitions output)
"""
import json
import sys
import urllib.request

since = sys.argv[1]
rows = json.loads(urllib.request.urlopen("http://127.0.0.1:8100/history?limit=500", timeout=10).read())
rows = [r for r in rows if r["ts"][11:19] >= since][::-1]
states = sorted({r["state"] for r in rows})
ages = [r["handshake_age_s"] for r in rows if r["handshake_age_s"] is not None]
first, last = rows[0]["ts"][11:19], rows[-1]["ts"][11:19]
print(f"{len(rows)} probes from {first} to {last} UTC, states seen: {states}, "
      f"handshake age min {min(ages)} s, max {max(ages)} s")
resets = sum(1 for a, b in zip(ages, ages[1:]) if b < a - 20)
print(f"handshake age dropped back to near zero {resets} time(s): that is the number of WireGuard rekeys observed")
