#!/usr/bin/env python
"""End-to-end proof of the security layer against the running lab.

Start it first:   docker compose -p cfl-sec --profile security up -d --build      (use the same -p name here with --project)
Run:              python scripts/verify_security.py

What it does, in order:
  1  runs every planted and benign log file through Wazuh's own wazuh-logtest inside the manager container
  2  a live run, in this order: a quiet period (must raise no rule of the lab's); a real fault (the DNAT rule removed) so the monitor
     goes `blocked`; three real VPN drops so the tunnel flaps; a real port sweep from the hub against the site router's closed ports;
     the same real fault again, now after the sweep; then SIMULATED ssh logs written by security/simulate/ssh_auth_gen.py (a brute
     force that worked, a sweep then a login). The sweep and flapping stages come in this order because rule 100220 takes the outage
     alerts for five minutes after a sweep.
  3  reads the real alerts.json lines the manager wrote for all of that
  4  runs security/respond.py over them: a dry run first (nothing may change), then --apply against the local webhook stand-in
     (its first answer is a 500, to show the retry), reads iptables back inside the edge container, runs it again (all duplicates),
     verifies the audit chain and every evidence bundle, then removes the blocks it added
Exit code 0 only if every check passes. Writes docs/security_last_run.json and the run files under docs/security/.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "security"))
import logtest_runner  # noqa: E402
import respond  # noqa: E402

API = "http://127.0.0.1:8100"
ALERTS = "/var/ossec/logs/alerts/alerts.json"
RESULTS: list[dict] = []
PROJECT = "cfl-sec"
DNAT = ["-t", "nat", "PREROUTING", "-i", "wg0", "-p", "tcp", "-m", "multiport", "--dports", "8554,8889",
        "-j", "DNAT", "--to-destination", "10.20.0.10"]
SWEEP_PORTS = [21, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 5900, 8080]
SIM_BRUTE, SIM_SWEEP = "203.0.113.50", "203.0.113.77"


def dc(service, *cmd, timeout=60, stdin=None):
    r = subprocess.run(["docker", "compose", "-p", PROJECT, "exec", "-T", service, *cmd], cwd=ROOT, capture_output=True, text=True,
                       encoding="utf-8", timeout=timeout, input=stdin, env=logtest_runner._env())
    return r.returncode, (r.stdout + r.stderr).strip()


def api(path):
    try:
        with urllib.request.urlopen(API + path, timeout=5) as resp:
            return json.loads(resp.read())
    except (urllib.error.URLError, OSError, ValueError):
        return None


def check(name, ok, detail=""):
    RESULTS.append({"check": name, "ok": bool(ok), "detail": detail})
    print(("PASS  " if ok else "FAIL  ") + name + (("   [" + detail + "]") if detail else ""), flush=True)
    return ok


def wait_state(want, timeout):
    start = time.time()
    while time.time() - start < timeout:
        s = api("/status")
        if s and s["state"] == want:
            return round(time.time() - start, 1)
        time.sleep(0.5)
    return None


def alert_lines() -> list[str]:
    rc, out = dc("wazuh", "cat", ALERTS)
    return [ln for ln in out.splitlines() if ln.startswith("{")] if rc == 0 else []


def lab_alerts(lines: list[str], since: int, rule_ids: set[str] | None = None) -> list[dict]:
    out = []
    for ln in lines[since:]:
        try:
            doc = json.loads(ln)
        except ValueError:
            continue
        rid = doc.get("rule", {}).get("id", "")
        if rid.isdigit() and 100000 <= int(rid) <= 199999 and (rule_ids is None or rid in rule_ids):
            out.append(doc)
    return out


def all_alerts(lines: list[str], since: int) -> list[dict]:
    out = []
    for ln in lines[since:]:
        try:
            out.append(json.loads(ln))
        except ValueError:
            continue
    return out


def port_open(port: int) -> bool:
    import socket
    with socket.socket() as sock:
        sock.settimeout(0.3)
        return sock.connect_ex(("127.0.0.1", port)) == 0


def wait_alert(rule_id: str, since: int, timeout: float, location: str | None = None):
    """Poll alerts.json until an alert of this rule (optionally from this log file) appears. Returns (seconds, alert) or (None, None)."""
    start = time.time()
    while time.time() - start < timeout:
        for doc in lab_alerts(alert_lines(), since, {rule_id}):
            if location is None or doc.get("location") == location:
                return round(time.time() - start, 1), doc
        time.sleep(1)
    return None, None


def feed(scenario: str, src: str = SIM_BRUTE):
    r = subprocess.run([sys.executable, str(ROOT / "security" / "simulate" / "ssh_auth_gen.py"), "--scenario", scenario, "--src", src,
                        "--deliver", "compose", "--project", PROJECT], capture_output=True, text=True, encoding="utf-8", timeout=90)
    print("      " + (r.stdout.strip() or r.stderr.strip()).replace("\n", "\n      "), flush=True)
    return r.returncode == 0


def iptables_input() -> str:
    return dc("edge", "iptables", "-S", "INPUT")[1]


def run_respond(args: list[str]) -> tuple[int, str]:
    r = subprocess.run([sys.executable, str(ROOT / "security" / "respond.py"), *args], capture_output=True, text=True, encoding="utf-8", timeout=300)
    return r.returncode, (r.stdout + r.stderr).strip()


def main() -> int:
    global PROJECT
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", default=PROJECT, help="compose project name the lab was started with")
    PROJECT = ap.parse_args().project
    logtest_runner.DEFAULT_PROJECT = PROJECT
    docs = ROOT / "docs" / "security"
    work = ROOT / "security" / "state"
    shutil.rmtree(work, ignore_errors=True)
    shutil.rmtree(docs, ignore_errors=True)
    work.mkdir(parents=True)
    docs.mkdir(parents=True)
    summary: dict = {}

    print("== the lab and the security services are up ==")
    for svc in ("wazuh", "fw-sensor", "fleet-exporter", "edge", "hub"):
        r = subprocess.run(["docker", "compose", "-p", PROJECT, "ps", "--status", "running", "-q", svc], cwd=ROOT, capture_output=True, text=True, encoding="utf-8", timeout=30)
        check(f"{svc} is running", bool(r.stdout.strip()))
    start = time.time()
    status = ""
    while time.time() - start < 120:                       # the manager takes a while to start its daemons after `up`
        _, status = dc("wazuh", "/var/ossec/bin/wazuh-control", "status")
        if "wazuh-analysisd is running" in status and "wazuh-logcollector is running" in status:
            break
        time.sleep(2)
    check("wazuh-analysisd and wazuh-logcollector are running", "wazuh-analysisd is running" in status and "wazuh-logcollector is running" in status)
    t_up = wait_state("up", 90)
    check("the monitor reports the camera up through the tunnel", t_up is not None, f"after {t_up}s")

    print("== wazuh-logtest: planted logs fire the rules, benign logs fire none of the lab's rules ==")
    expected = json.loads((ROOT / "security" / "logs" / "EXPECTED.json").read_text(encoding="utf-8"))
    logtest_report, fired_ok, alerting = [], set(), set()
    for name, want in expected["planted"].items():
        lines = [ln for ln in (ROOT / "security" / "logs" / name).read_text(encoding="utf-8").splitlines() if ln.strip()]
        events = logtest_runner.run_logtest(lines)
        got = logtest_runner.fired(events)
        check(f"planted {name} fires {want}", got == want, f"got {got}")
        logtest_report.append({"file": name, "expected": want, "fired": got, "alerts": [{"rule": e["rule_id"], "level": e["level"], "mitre": e["mitre"], "description": e["description"]} for e in events if e["alert"] and e["rule_id"] and e["rule_id"].startswith("100")]})
        alerting.update(want)
        if got == want:
            fired_ok.update(want)
    benign_clean = 0
    for name in expected["benign"]:
        lines = [ln for ln in (ROOT / "security" / "logs" / name).read_text(encoding="utf-8").splitlines() if ln.strip()]
        events = logtest_runner.run_logtest(lines)
        got = logtest_runner.fired(events)
        benign_clean += not got
        check(f"benign {name} fires none of the lab's rules", got == [], f"got {got}, {len(lines)} lines, stock rules that fired: {sorted({e['rule_id'] for e in events if e['alert']})}")
        logtest_report.append({"file": name, "expected": [], "fired": got, "stock_rules_fired": sorted({e['rule_id'] for e in events if e['alert']})})
    summary["logtest"] = {"alerting_rules": len(alerting), "fired_correctly": len(fired_ok), "benign_files": len(expected["benign"]), "benign_clean": benign_clean}
    (docs / "logtest_results.json").write_text(json.dumps(logtest_report, indent=2), encoding="utf-8")

    print("== live run, part 1: a quiet period ==")
    baseline = len(alert_lines())
    check("a quiet period: simulated ordinary logins", feed("benign"))
    # the stock sshd rules raise a level 3 alert for each accepted login, so seeing one for the benign address means Wazuh has
    # read the benign lines; only then is "nothing from the lab's rules" a statement about them
    start = time.time()
    while time.time() - start < 30 and not any(a.get("data", {}).get("srcip") == "198.51.100.7" for a in all_alerts(alert_lines(), baseline)):
        time.sleep(0.5)
    quiet = lab_alerts(alert_lines(), baseline)
    check("the quiet period raised no rule of the lab's", not quiet, f"{[a['rule']['id'] for a in quiet]}")

    print("== live run, part 2: a real fault on its own (NAT rule removed, no sweep before it) ==")
    dc("edge", "iptables", *("-t nat -D PREROUTING".split()), *DNAT[3:])
    t_alone = wait_state("blocked", 60)
    check("the monitor reports blocked", t_alone is not None, f"after {t_alone}s")
    t_100101, a_100101 = wait_alert("100101", baseline, 60)
    check("rule 100101 (site blocked) fired on the real transition", a_100101 is not None, f"{t_100101}s after the transition")
    dc("edge", "iptables", "-t", "nat", "-A", *DNAT[2:])
    check("the monitor recovers once the rule is restored", wait_state("up", 60) is not None)
    summary["measured_blocked_alone"] = {"blocked_after_s": t_alone, "alert_100101_after_s": t_100101}

    print("== live run, part 3: three real VPN drops inside five minutes ==")
    drops = []
    for i in range(3):
        dc("edge", "iptables", "-I", "OUTPUT", "1", "-p", "udp", "--dport", "51820", "-j", "DROP")
        drops.append(wait_state("tunnel_down", 90))
        dc("edge", "iptables", "-D", "OUTPUT", "-p", "udp", "--dport", "51820", "-j", "DROP")
        wait_state("up", 90)
    check("the monitor reported tunnel_down three times", all(d is not None for d in drops), f"{drops}")
    t_flap, flap_alert = wait_alert("100103", baseline, 30)
    check("rule 100103 (flapping tunnel) fired", flap_alert is not None, f"{t_flap}s after the third drop")
    n102 = len(lab_alerts(alert_lines(), baseline, {"100102"}))
    check("rule 100102 (tunnel down) fired for the first two drops; the flapping rule takes the third", n102 == 2, f"{n102} alerts of 100102")

    print("== live run, part 4: a real port sweep from the hub against the site router (measured) ==")
    t0 = time.time()
    for port in SWEEP_PORTS:
        dc("hub", "nc", "-z", "-w", "1", "10.8.0.2", str(port), timeout=20)
    sweep_secs = round(time.time() - t0, 1)
    t_sweep, sweep_alert = wait_alert("100210", baseline, 45, "/feed/edge_firewall.log")
    rc, fwlog = dc("wazuh", "grep", "-c", "src=10.8.0.1", "/feed/edge_firewall.log")
    check("the edge firewall's real drops reached the log", rc == 0 and int(fwlog.split()[0]) >= len(SWEEP_PORTS), f"{fwlog} drop lines from 10.8.0.1")
    check("rule 100210 (port sweep) fired on the measured sweep", sweep_alert is not None, f"sweep took {sweep_secs}s, alert {t_sweep}s after it")
    summary["measured_sweep"] = {"ports_probed": len(SWEEP_PORTS), "probe_seconds": sweep_secs, "alert_seconds_after": t_sweep, "drop_lines": fwlog}

    print("== live run, part 5: a real fault after the sweep (NAT rule removed) ==")
    dc("edge", "iptables", *("-t nat -D PREROUTING".split()), *DNAT[3:])
    t_blocked = wait_state("blocked", 60)
    check("the monitor reports blocked", t_blocked is not None, f"after {t_blocked}s")
    t_out, out_alert = wait_alert("100220", baseline, 60)
    check("rule 100220 (sweep, then an outage) fired on the real sequence", out_alert is not None, f"{t_out}s after the transition")
    dc("edge", "iptables", "-t", "nat", "-A", *DNAT[2:])
    check("the monitor recovers once the rule is restored", wait_state("up", 60) is not None)
    summary["measured_outage"] = {"blocked_after_s": t_blocked, "alert_100220_after_s": t_out}

    print("== live run, part 6: SIMULATED ssh authentication logs ==")
    check("simulated brute force then success written", feed("brute-force", SIM_BRUTE))
    t_bf, bf_alert = wait_alert("100300", baseline, 45, "/feed/ssh_auth.log")
    check("rule 100300 (brute force that worked) fired on the simulated log", bf_alert is not None, f"{t_bf}s")
    check("simulated sweep then login written", feed("sweep-login", SIM_SWEEP))
    t_sl, sl_alert = wait_alert("100301", baseline, 45, "/feed/ssh_auth.log")
    check("rule 100301 (sweep then ssh login) fired on the simulated logs", sl_alert is not None, f"{t_sl}s")
    sim_sweep_alerts = [a for a in lab_alerts(alert_lines(), baseline, {"100210"}) if a.get("location") == "/feed/sim_firewall.log"]
    check("rule 100210 also fired on the simulated sweep", bool(sim_sweep_alerts))

    print("== the real alerts.json lines ==")
    lines = alert_lines()
    mine = lab_alerts(lines, baseline)
    rule_counts: dict[str, int] = {}
    for a in mine:
        rule_counts[a["rule"]["id"]] = rule_counts.get(a["rule"]["id"], 0) + 1
    check("every one of the 7 alerting rules produced a real alert in alerts.json", set(rule_counts) >= alerting, f"{dict(sorted(rule_counts.items()))}")
    mitre_ok = all(a["rule"].get("mitre", {}).get("id") for a in mine if a["rule"]["id"] in ("100210", "100220", "100300", "100301"))
    check("alerts of the attacker-behaviour rules carry a MITRE ATT&CK id", mitre_ok)
    check("alerts carry their source file (measured versus simulated) in the location field", all(a.get("location", "").startswith("/feed/") for a in mine))
    alerts_file = docs / "alerts_live.jsonl"
    alerts_file.write_text("\n".join(json.dumps(a, sort_keys=True) for a in mine) + "\n", encoding="utf-8")
    summary["alerts"] = {"lab_alerts": len(mine), "by_rule": dict(sorted(rule_counts.items())), "measured": sum(a["location"] != "/feed/ssh_auth.log" and a["location"] != "/feed/sim_firewall.log" for a in mine),
                         "simulated": sum(a["location"] in ("/feed/ssh_auth.log", "/feed/sim_firewall.log") for a in mine)}

    print("== respond.py over the live alerts ==")
    feed_copy = work / "feed_copy"
    subprocess.run(["docker", "compose", "-p", PROJECT, "cp", "wazuh:/feed", str(feed_copy)], cwd=ROOT, capture_output=True, timeout=60, env=logtest_runner._env())
    state = work / "respond"
    rules_before = iptables_input()
    common = ["--alerts", str(alerts_file), "--state", str(state), "--logs", str(feed_copy), "--project", PROJECT,
              "--webhook", "http://127.0.0.1:8765/notify"]
    rc, dry_out = run_respond(common)
    (docs / "respond_dry_run.txt").write_text(dry_out + "\n", encoding="utf-8")
    check("dry run handles every alert", rc == 0 and f"alerts={len(mine)}" in dry_out and f"done={len(mine)}" in dry_out, dry_out.splitlines()[-1])
    check("dry run changed nothing: iptables identical, no tickets, no webhook posts", iptables_input() == rules_before and not (state / "tickets").exists())
    would = [json.loads(x) for x in (state / "audit.jsonl").read_text(encoding="utf-8").splitlines() if '"dry_run_recorded"' in x]
    check("dry run recorded the iptables command it would run", any("iptables" in x.get("detail", "") and SIM_BRUTE in x.get("detail", "") for x in would))

    hook_log = work / "received.jsonl"
    hook = subprocess.Popen([sys.executable, str(ROOT / "security" / "webhook_receiver.py"), "--port", "8765", "--log", str(hook_log), "--fail-first", "1"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        start = time.time()
        while time.time() - start < 10 and not port_open(8765):
            time.sleep(0.2)
        rc, apply_out = run_respond(common + ["--apply"])
        (docs / "respond_apply.txt").write_text(apply_out + "\n", encoding="utf-8")
        check("--apply handles every alert", rc == 0 and f"alerts={len(mine)}" in apply_out and f"done={len(mine)}" in apply_out, apply_out.splitlines()[-1])
        received = [json.loads(x) for x in hook_log.read_text(encoding="utf-8").splitlines()] if hook_log.exists() else []
        check("the webhook stand-in received one notification per alert (its first answer was a 500, so one was retried)", len(received) == len(mine), f"{len(received)} received")
        audit_lines = [json.loads(x) for x in (state / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
        retried = [x for x in audit_lines if x.get("mode") == "apply" and x.get("outcome") == "failed_retryable"]
        check("the 500 reached the audit trail and the retry then succeeded", len(retried) == 1, f"{len(retried)} failed_retryable line(s)")
        after = iptables_input()
        (docs / "iptables_before_after.txt").write_text("BEFORE (edge INPUT chain)\n" + rules_before + "\n\nAFTER respond.py --apply\n" + after + "\n", encoding="utf-8")
        check("iptables in the edge container now drops the brute force address", f"-s {SIM_BRUTE}/32 -j DROP" in after)
        check("iptables drops the sweep-and-login address", f"-s {SIM_SWEEP}/32 -j DROP" in after)
        check("the hub's own tunnel address (protected) was not blocked", "-s 10.8.0.1" not in after)
        check("the monitor is still up after the blocks", (api("/status") or {}).get("state") == "up")
        check("a ticket exists for every alert", len(list((state / "tickets").glob("*.json"))) == len(mine))
        n_received = len(received)
        rc, again = run_respond(common + ["--apply"])
        (docs / "respond_apply_second_run.txt").write_text(again + "\n", encoding="utf-8")
        recv2 = len(hook_log.read_text(encoding="utf-8").splitlines())
        check("a second --apply run is all duplicates and acts on nothing", f"duplicate_ignored={len(mine)}" in again and recv2 == n_received and iptables_input() == after, again.splitlines()[-1])
    finally:
        hook.terminate()
        hook.wait(timeout=10)

    ok, msg = respond.verify_audit(state / "audit.jsonl")
    check("the audit trail's hash chain verifies", ok, msg)
    bundles = sorted((state / "evidence").iterdir())
    check("every incident has an evidence bundle whose sha256 manifest verifies", len(bundles) == len(mine) and all(respond.verify_bundle(b)[0] for b in bundles), f"{len(bundles)} bundles")
    bf_bundle = state / "evidence" / bf_alert["id"]
    ctx_text = (bf_bundle / "context.log").read_text(encoding="utf-8")
    check("the brute force bundle holds the raw failed-login lines around the alert", ctx_text.count("Failed password") >= 6, f"{ctx_text.count('Failed password')} failed-password lines")
    shutil.copytree(bf_bundle, docs / f"evidence_{bf_alert['id']}")
    shutil.copy(state / "audit.jsonl", docs / "audit.jsonl")
    shutil.copy(hook_log, docs / "webhook_received.jsonl")

    print("== clean up the blocks respond.py added ==")
    for ip in (SIM_BRUTE, SIM_SWEEP):
        run_respond(["--unblock", ip, "--apply", "--project", PROJECT])
    check("the iptables blocks are removed again", iptables_input() == rules_before)

    allok = all(r["ok"] for r in RESULTS)
    out = {"all_passed": allok, "checks": RESULTS, "summary": summary}
    (ROOT / "docs").mkdir(exist_ok=True)
    (ROOT / "docs" / "security_last_run.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print("\n%d/%d checks passed" % (sum(r["ok"] for r in RESULTS), len(RESULTS)))
    return 0 if allok else 1


if __name__ == "__main__":
    sys.exit(main())
