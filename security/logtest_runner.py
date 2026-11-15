"""Runs log lines through Wazuh's own wazuh-logtest inside the manager container and returns what each line did.

wazuh-logtest keeps one session per run, so lines sent in one run share correlation state (a frequency rule counts the lines
sent before it). Each scenario file is therefore one run: a fresh session, no memory of the other scenarios.

    python security/logtest_runner.py security/logs/planted/ssh_brute_force_success.log
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PROJECT = "cfl-sec"


def parse_logtest(text: str) -> list[dict]:
    """One dict per input line: its decoder and, when a rule fired, the rule's id, level, description and groups."""
    events = []
    for block in re.split(r"\*\*Phase 1: Completed pre-decoding\.", text)[1:]:
        ev = {"decoder": None, "rule_id": None, "level": None, "description": None, "groups": [], "mitre": [], "alert": False}
        m = re.search(r"\*\*Phase 2: Completed decoding\.\s+name: '([^']*)'", block)
        if m:
            ev["decoder"] = m.group(1)
        m = re.search(r"\*\*Phase 3: Completed filtering \(rules\)\.(.*)", block, re.S)
        if m:
            body = m.group(1)
            for key in ("id", "level", "description", "groups", "mitre.id", "info"):
                mm = re.search(r"^\s+" + re.escape(key) + r": '(.*)'$", body, re.M)
                if mm:
                    val = mm.group(1)
                    if key == "groups":
                        ev["groups"] = re.findall(r"'([^']+)'", val)
                    elif key == "mitre.id":
                        ev["mitre"] = re.findall(r"'([^']+)'", val)
                    elif key == "id":
                        ev["rule_id"] = val
                    else:
                        ev[key] = val
            ev["alert"] = "**Alert to be generated." in body
        events.append(ev)
    return events


def run_logtest(lines: list[str], project: str = DEFAULT_PROJECT, timeout: int = 120) -> list[dict]:
    cmd = ["docker", "compose", "-p", project, "exec", "-T", "wazuh", "/var/ossec/bin/wazuh-logtest"]
    r = subprocess.run(cmd, cwd=ROOT, input="\n".join(lines) + "\n", capture_output=True, text=True, timeout=timeout,
                       env=_env())
    events = parse_logtest(r.stdout + "\n" + r.stderr)
    if len(events) != len(lines):
        raise RuntimeError(f"wazuh-logtest returned {len(events)} results for {len(lines)} lines: {(r.stderr or r.stdout)[-400:]}")
    for ev, line in zip(events, lines):
        ev["line"] = line
    return events


def _env():
    import os
    env = dict(os.environ)
    env["MSYS_NO_PATHCONV"] = "1"
    return env


BASE_RULES = {"100100", "100200"}   # parents and no_log base rules: wazuh-logtest reports 100200 as an alert, the manager does not write it


def fired(events: list[dict], low: int = 100000, high: int = 199999) -> list[str]:
    """Rule ids in the lab's own 100000 range that raised an alert, in order, without the base rules."""
    return [e["rule_id"] for e in events if e["alert"] and e["rule_id"] and low <= int(e["rule_id"]) <= high and e["rule_id"] not in BASE_RULES]


if __name__ == "__main__":
    path = Path(sys.argv[1])
    evs = run_logtest([ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()])
    for e in evs:
        tag = f"rule {e['rule_id']} level {e['level']}" if e["alert"] else "no alert"
        print(f"{tag:24} {e['line'][:110]}")
    print("lab rules fired:", json.dumps(fired(evs)))
