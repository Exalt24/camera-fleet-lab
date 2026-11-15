#!/usr/bin/env python3
"""Generates SIMULATED log lines for the security layer. Nothing here is measured from a running service.

The lab has no ssh server and no internet-facing router, so the authentication log and a sweep from an outside address are
written by this script in the formats the real programs use (OpenSSH's sshd messages, the lab's fw-sensor line). They go to files
that no real service writes (ssh_auth.log, sim_firewall.log); the measured logs are fleet_transitions.jsonl and edge_firewall.log.
Wazuh puts the file name in each alert's location field, so the source of every alert is visible.

Scenarios:
  benign        a few ordinary logins, one mistyped password, then the right one (the quiet run)
  brute-force   many failures for invalid users and root from one address, then one success (a brute force that worked)
  sweep         one outside address probes many closed ports on the site router (firewall drops)
  sweep-login   a sweep from one address, then a successful ssh login from the same address

    python security/simulate/ssh_auth_gen.py --scenario brute-force --src 203.0.113.50
    python security/simulate/ssh_auth_gen.py --scenario sweep --src 203.0.113.77 --deliver compose --project cfl-sec
"""
from __future__ import annotations

import argparse
import random
import subprocess
import sys
import time

SSH_FILE = "ssh_auth.log"
FW_FILE = "sim_firewall.log"
HOST = "edge"
USERS_INVALID = ["admin", "test", "oracle", "ubuntu", "pi", "user", "guest", "postgres", "ftpuser", "support", "git", "deploy1"]
SWEEP_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 1433, 3306, 3389, 5432, 5900, 8080, 8443]


def stamp(now: float) -> str:
    return time.strftime("%b %d %H:%M:%S", time.gmtime(now))


def sshd(now: float, pid: int, msg: str) -> str:
    return f"{stamp(now)} {HOST} sshd[{pid}]: {msg}"


def fw(now: float, src: str, dport: int, sport: int) -> str:
    return (f"{stamp(now)} {HOST} fw-sensor: action=DROP chain=INPUT in=eth0 src={src} dst=172.30.0.2 proto=TCP "
            f"sport={sport} dport={dport} flags=S")


def brute_force(src: str, rng: random.Random, now: float, failures: int = 14) -> list[str]:
    lines, pid, t = [], rng.randint(2000, 9000), now
    for i in range(failures):
        pid += rng.randint(1, 3)
        port = rng.randint(40000, 60000)
        if i % 4 == 3:
            lines.append(sshd(t, pid, f"Failed password for root from {src} port {port} ssh2"))
        else:
            user = rng.choice(USERS_INVALID)
            lines.append(sshd(t, pid, f"Failed password for invalid user {user} from {src} port {port} ssh2"))
        lines.append(sshd(t, pid, f"Connection closed by authenticating user {src} port {port} [preauth]") if i % 5 == 4 else
                     sshd(t, pid, f"Disconnected from invalid user {rng.choice(USERS_INVALID)} {src} port {port} [preauth]"))
        t += rng.uniform(0.4, 1.6)
    pid += 2
    lines.append(sshd(t, pid, f"Accepted password for deploy from {src} port {rng.randint(40000, 60000)} ssh2"))
    lines.append(sshd(t, pid, "pam_unix(sshd:session): session opened for user deploy(uid=1001) by (uid=0)"))
    return lines


def benign(rng: random.Random, now: float) -> list[str]:
    src = "198.51.100.7"
    return [
        sshd(now, 1801, f"Accepted publickey for ops from {src} port 40212 ssh2: ED25519 SHA256:q1w2e3r4t5y6u7i8o9p0"),
        sshd(now + 60, 1822, f"Failed password for ops from {src} port 40290 ssh2"),
        sshd(now + 64, 1822, f"Accepted password for ops from {src} port 40290 ssh2"),
        sshd(now + 900, 1900, f"Accepted publickey for ops from {src} port 40300 ssh2: ED25519 SHA256:q1w2e3r4t5y6u7i8o9p0"),
    ]


def sweep(src: str, rng: random.Random, now: float, ports: int = 12) -> list[str]:
    chosen = rng.sample(SWEEP_PORTS, ports)
    sport = rng.randint(30000, 50000)
    return [fw(now + i * 0.3, src, p, sport + i) for i, p in enumerate(chosen)]


def make(scenario: str, src: str, seed: int, now: float | None = None) -> tuple[str, list[str]]:
    """-> (file name the lines belong in, lines)."""
    rng = random.Random(seed)
    now = time.time() if now is None else now
    if scenario == "benign":
        return SSH_FILE, benign(rng, now)
    if scenario == "brute-force":
        return SSH_FILE, brute_force(src, rng, now)
    if scenario == "sweep":
        return FW_FILE, sweep(src, rng, now)
    if scenario == "sweep-login":
        return "both", sweep(src, rng, now) + [sshd(now + 8, rng.randint(3000, 3999), f"Accepted password for deploy from {src} port {rng.randint(40000, 60000)} ssh2")]
    raise ValueError(f"unknown scenario {scenario}")


def deliver_compose(project: str, filename: str, lines: list[str]) -> None:
    cmd = ["docker", "compose", "-p", project, "exec", "-T", "wazuh", "sh", "-c", f"cat >> /feed/{filename}"]
    r = subprocess.run(cmd, input="\n".join(lines) + "\n", capture_output=True, text=True, encoding="utf-8", timeout=60)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or "docker compose exec failed")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Generate SIMULATED ssh and firewall log lines.")
    p.add_argument("--scenario", choices=["benign", "brute-force", "sweep", "sweep-login"], required=True)
    p.add_argument("--src", default="203.0.113.50", help="the attacker address (TEST-NET-3, documentation range)")
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--deliver", choices=["stdout", "compose"], default="stdout")
    p.add_argument("--project", default="cfl-sec", help="compose project name (with --deliver compose)")
    p.add_argument("--gap", type=float, default=3.0, help="seconds between the sweep and the login in sweep-login (the manager reads "
                   "separate files in parallel, so without a gap the login can be analysed before the sweep that came first)")
    args = p.parse_args(argv)
    target, lines = make(args.scenario, args.src, args.seed)
    if args.scenario == "sweep-login":
        parts = [(FW_FILE, [ln for ln in lines if "fw-sensor" in ln]), (SSH_FILE, [ln for ln in lines if "sshd" in ln])]
    else:
        parts = [(target, lines)]
    for n, (filename, chunk) in enumerate(parts):
        if n and args.deliver == "compose":
            time.sleep(args.gap)
        if args.deliver == "compose":
            deliver_compose(args.project, filename, chunk)
            print(f"SIMULATED: wrote {len(chunk)} {args.scenario} lines to /feed/{filename} in the wazuh container")
        else:
            print(f"# SIMULATED {args.scenario} lines for {filename}")
            print("\n".join(chunk))
    return 0


if __name__ == "__main__":
    sys.exit(main())
