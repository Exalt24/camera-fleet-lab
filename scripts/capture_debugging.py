#!/usr/bin/env python
"""Capture the real command output you would use to debug each fault, into docs/debugging_capture.txt, so DEBUGGING.md
quotes measured output and not remembered output.
    python scripts/capture_debugging.py
"""
import json
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = []
DNAT = ["PREROUTING", "-i", "wg0", "-p", "tcp", "-m", "multiport", "--dports", "8554,8889", "-j", "DNAT", "--to-destination", "10.20.0.10"]
BLOCK = ["-p", "udp", "--dport", "51820", "-j", "DROP"]


def dc(service, *cmd, timeout=40):
    r = subprocess.run(["docker", "compose", "exec", "-T", service, *cmd], cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    return (r.stdout + r.stderr).strip()


def wait_state(want, cap=60):
    """Poll the monitor once a second until it reports `want` (or the cap passes), instead of sleeping a guessed time."""
    end = time.time() + cap
    while time.time() < end:
        try:
            with urllib.request.urlopen("http://127.0.0.1:8100/status", timeout=3) as resp:
                if json.loads(resp.read()).get("state") == want:
                    return True
        except (urllib.error.URLError, OSError, ValueError):
            pass
        time.sleep(1)
    return False


def section(title, service, *cmd):
    OUT.append(f"\n$ docker compose exec {service} {' '.join(cmd)}    # {title}")
    OUT.append(dc(service, *cmd))


def main():
    OUT.append("== healthy baseline ==")
    section("the tunnel from the edge's side", "edge", "wg", "show", "wg0")
    section("what the NAT rule has forwarded so far", "edge", "iptables", "-t", "nat", "-L", "PREROUTING", "-n", "-v")
    section("the firewall: only the forwarded ports are accepted, everything else dropped", "edge", "iptables", "-L", "FORWARD", "-n", "-v")

    OUT.append("\n== FAULT B: the DNAT rule is gone, the tunnel is healthy ==")
    dc("edge", "iptables", "-t", "nat", "-D", *DNAT)
    wait_state("blocked")
    OUT.append("\n$ docker compose exec edge timeout 9 tcpdump -ni wg0 -c 8 'tcp port 8554 or icmp'    # SYNs arrive, nothing answers; pings still do")
    OUT.append(dc("edge", "sh", "-c", "timeout 9 tcpdump -ni wg0 -c 8 'tcp port 8554 or icmp' 2>&1 | grep -v listening"))
    section("the NAT chain is empty: there is no rule left to translate the tunnel address to the camera", "edge", "iptables", "-t", "nat", "-L", "PREROUTING", "-n", "-v")
    dc("edge", "iptables", "-t", "nat", "-A", *DNAT)
    wait_state("up")

    OUT.append("\n== FAULT A: WireGuard UDP blocked on the site router ==")
    dc("edge", "iptables", "-I", "OUTPUT", "1", *BLOCK)
    wait_state("tunnel_down")
    OUT.append("\n$ docker compose exec edge timeout 8 tcpdump -ni eth0 -c 6 udp port 51820    # what crosses the edge's WAN interface on the WireGuard port while the block is on")
    OUT.append(dc("edge", "sh", "-c", "timeout 8 tcpdump -ni eth0 -c 6 udp port 51820 2>&1 | grep -v listening"))
    section("the DROP rule's packet counter is the evidence that the edge IS trying to send and being stopped", "edge", "iptables", "-L", "OUTPUT", "-n", "-v")
    dc("edge", "iptables", "-D", "OUTPUT", *BLOCK)
    wait_state("up")
    section("recovered: a fresh handshake", "edge", "wg", "show", "wg0", "latest-handshakes")

    (ROOT / "docs").mkdir(exist_ok=True)
    (ROOT / "docs" / "debugging_capture.txt").write_text("\n".join(OUT) + "\n", encoding="utf-8")
    print("wrote docs/debugging_capture.txt")


if __name__ == "__main__":
    main()
