#!/usr/bin/env python
"""How long does the tunnel take to come back after the VPN is blocked for a while, and why?

Blocks WireGuard UDP on the site router for BLOCK_S seconds, unblocks, then samples the handshake age on both ends and
the edge's iptables counters every 2 seconds, printing when each side first sees a fresh handshake.
    python scripts/measure_recovery.py [block_seconds]
"""
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BLOCK_S = int(sys.argv[1]) if len(sys.argv) > 1 else 40


def dc(service, *cmd):
    r = subprocess.run(["docker", "compose", "exec", "-T", service, *cmd], cwd=ROOT, capture_output=True, text=True, timeout=30)
    return (r.stdout + r.stderr).strip()


def age(service):
    out = dc(service, "wg", "show", "wg0", "latest-handshakes")
    m = re.search(r"\s(\d+)\s*$", out.splitlines()[-1]) if out else None
    ts = int(m.group(1)) if m else 0
    return None if ts == 0 else round(time.time() - ts, 1)


def main():
    rule = ["-p", "udp", "--dport", "51820", "-j", "DROP"]
    print(f"blocking WireGuard UDP on the edge for {BLOCK_S}s")
    dc("edge", "iptables", "-I", "OUTPUT", "1", *rule)
    time.sleep(BLOCK_S)
    print("conntrack entries for the tunnel on the edge BEFORE unblocking:")
    print("  " + (dc("edge", "conntrack", "-L", "-p", "udp").replace("\n", "\n  ") or "(none)"))
    dc("edge", "iptables", "-D", "OUTPUT", *rule)
    t0 = time.time()
    print("unblocked; sampling every 2 s")
    seen = {"edge": None, "hub": None}
    while time.time() - t0 < 180 and not all(seen.values()):
        for side in ("edge", "hub"):
            a = age(side)
            if seen[side] is None and a is not None and a < (time.time() - t0) + 2 and a < 6:
                seen[side] = round(time.time() - t0, 1)
        time.sleep(2)
    print(f"first fresh handshake seen: edge after {seen['edge']}s, hub after {seen['hub']}s (since the unblock)")


if __name__ == "__main__":
    main()
