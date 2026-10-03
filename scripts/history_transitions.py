#!/usr/bin/env python
"""Print the stored probe history as state TRANSITIONS (oldest first): what the monitor saw, and when.
    python scripts/history_transitions.py [limit]
"""
import json
import sys
import urllib.request

limit = int(sys.argv[1]) if len(sys.argv) > 1 else 500
rows = json.loads(urllib.request.urlopen(f"http://127.0.0.1:8100/history?limit={limit}", timeout=10).read())[::-1]
prev = None
for r in rows:
    key = (r["state"], r["tunnel_ok"], r["tcp_ok"], r["rtsp_ok"])
    if key != prev:
        print(f"{r['ts'][11:19]}  state={r['state']:<12} tunnel={str(r['tunnel_ok']):<5} tcp={str(r['tcp_ok']):<5} rtsp={str(r['rtsp_ok']):<5} "
              f"handshake_age={r['handshake_age_s']}  {(r['error'] or '')[:70]}")
        prev = key
print(f"({len(rows)} probes shown)")
