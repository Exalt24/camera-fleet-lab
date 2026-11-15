"""Turns the monitor's probe history into a log of state transitions, one JSON object per line.

The hub already stores every probe and serves them at /history. This reads that API, so hub/ is not modified, and writes a line
only when the state changes (up, degraded, blocked, tunnel_down). Wazuh reads the file as JSON.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import urllib.error
import urllib.request

HUB = os.environ.get("HUB_URL", "http://hub:8000")
OUT = os.environ.get("TRANSITIONS_FILE", "/feed/fleet_transitions.jsonl")
POLL_S = float(os.environ.get("POLL_S", "2"))


def transitions(rows: list[dict], last_state: str | None, last_ts: str | None) -> tuple[list[dict], str | None, str | None]:
    """rows are probe rows, newest first (the /history order). Returns (new transition records, new last state, new last ts).
    A row already seen (ts not newer than last_ts) is skipped. The first row ever seen sets the baseline without a record."""
    fresh = [r for r in reversed(rows) if last_ts is None or r["ts"] > last_ts]
    out = []
    for r in fresh:
        if last_state is not None and r["state"] != last_state:
            out.append({"ts": r["ts"], "source": "fleet-monitor", "event": "state_transition", "camera": r["camera"],
                        "prev_state": last_state, "state": r["state"], "tunnel_ok": r["tunnel_ok"], "tcp_ok": r["tcp_ok"],
                        "rtsp_ok": r["rtsp_ok"], "handshake_age_s": r["handshake_age_s"], "error": r["error"]})
        last_state = r["state"]
        last_ts = r["ts"]
    return out, last_state, last_ts


def fetch() -> list[dict] | None:
    try:
        with urllib.request.urlopen(HUB + "/history?limit=20", timeout=5) as resp:
            return json.loads(resp.read())
    except (urllib.error.URLError, OSError, ValueError):
        return None


def main() -> int:
    state = ts = None
    stop = threading.Event()
    print(f"fleet-exporter: polling {HUB}/history, writing transitions to {OUT}", flush=True)
    while not stop.wait(POLL_S):
        rows = fetch()
        if not rows:
            continue
        records, state, ts = transitions(rows, state, ts)
        if records:
            with open(OUT, "a", encoding="utf-8") as fh:
                for rec in records:
                    fh.write(json.dumps(rec) + "\n")
                    print("fleet-exporter: " + rec["prev_state"] + " -> " + rec["state"], flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
