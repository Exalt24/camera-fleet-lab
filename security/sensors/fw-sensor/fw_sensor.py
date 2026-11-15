"""Writes the site router's dropped packets to a log file, one syslog style line per packet.

It runs in the edge container's network namespace (compose: network_mode "service:edge"), so edge/ is not modified. The edge's
firewall policy is DROP on INPUT and FORWARD, and the rules before it accept only the design's traffic. This sensor appends one
NFLOG rule at the end of each chain, so a packet that reaches it is a packet the policy is about to drop, and reads the packets
with `tcpdump -i nflog:<group>`. (The kernel LOG target does not work inside a container's network namespace, NFLOG does.)

Output line (decoded by security/wazuh/camera_fleet_decoders.xml):
Nov 15 12:00:01 edge fw-sensor: action=DROP chain=INPUT in=wg0 src=10.8.0.1 dst=10.8.0.2 proto=TCP sport=41234 dport=22 flags=S
"""
from __future__ import annotations

import re
import subprocess
import sys
import threading
import time

GROUPS = {"INPUT": 7, "FORWARD": 8}
OUT = "/feed/edge_firewall.log"
HOST = "edge"
# Wazuh's log collector opens the files it is told about when it starts. A file that appears later is only noticed on its next
# periodic check (about a minute) and the first sweep after a fresh start was missed that way, so every file Wazuh reads is
# created here, empty, before the manager starts (compose: wazuh depends on this service).
FEED_FILES = ["/feed/edge_firewall.log", "/feed/sim_firewall.log", "/feed/ssh_auth.log"]

# tcpdump -nn -t on the nflog pseudo interface prints, for example:
#   IP 10.8.0.1.41234 > 10.8.0.2.22: Flags [S], seq 1234, win 64240, length 0
#   IP 10.8.0.1.5353 > 10.8.0.2.9999: UDP, length 5
#   IP 10.8.0.1 > 10.8.0.2: ICMP echo request, id 1, seq 1, length 64
LINE = re.compile(r"^IP (?P<src>\d+\.\d+\.\d+\.\d+)(?:\.(?P<sport>\d+))? > (?P<dst>\d+\.\d+\.\d+\.\d+)(?:\.(?P<dport>\d+))?: (?P<rest>.*)$")


def parse(line: str, chain: str = "INPUT", iface: str = "wg0"):
    """One tcpdump line to the fields of a drop, or None when it is not an IPv4 packet line."""
    m = LINE.match(line.strip())
    if not m:
        return None
    rest = m.group("rest")
    flags = re.search(r"Flags \[([^\]]*)\]", rest)
    if flags:
        proto = "TCP"
    elif rest.startswith("UDP") or "UDP," in rest:
        proto = "UDP"
    elif "ICMP" in rest:
        proto = "ICMP"
    else:
        proto = "OTHER"
    return {"chain": chain, "in": iface, "src": m.group("src"), "dst": m.group("dst"), "proto": proto,
            "sport": m.group("sport") or "0", "dport": m.group("dport") or "0", "flags": flags.group(1) if flags else "-"}


def render(d: dict, now: float | None = None) -> str:
    stamp = time.strftime("%b %d %H:%M:%S", time.gmtime(now if now is not None else time.time()))
    return (f"{stamp} {HOST} fw-sensor: action=DROP chain={d['chain']} in={d['in']} src={d['src']} dst={d['dst']} "
            f"proto={d['proto']} sport={d['sport']} dport={d['dport']} flags={d['flags']}")


def ensure_feed_files() -> None:
    for path in FEED_FILES:
        open(path, "a", encoding="utf-8").close()


def install_rules() -> None:
    for chain, group in GROUPS.items():
        rule = [chain, "-j", "NFLOG", "--nflog-group", str(group), "--nflog-prefix", f"fw-drop-{chain}"]
        if subprocess.run(["iptables", "-C", *rule], capture_output=True).returncode != 0:
            subprocess.run(["iptables", "-A", *rule], check=True)
            print(f"fw-sensor: appended NFLOG rule to {chain} (group {group})", flush=True)


def follow(chain: str, group: int, lock: threading.Lock) -> None:
    proc = subprocess.Popen(["tcpdump", "-nn", "-l", "-t", "-i", f"nflog:{group}"], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True)
    assert proc.stdout is not None
    for raw in proc.stdout:
        d = parse(raw, chain)
        if d is None:
            continue
        with lock, open(OUT, "a", encoding="utf-8") as fh:
            fh.write(render(d) + "\n")


def main() -> int:
    ensure_feed_files()
    install_rules()
    lock = threading.Lock()
    threads = [threading.Thread(target=follow, args=(c, g, lock), daemon=True) for c, g in GROUPS.items()]
    for t in threads:
        t.start()
    print("fw-sensor: reading drops from the edge firewall into " + OUT, flush=True)
    for t in threads:
        t.join()
    return 1


if __name__ == "__main__":
    sys.exit(main())
