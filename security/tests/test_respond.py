"""Tests for security/respond.py, the playbook engine, including the failure cases and a seeded property test.

Covers: dry run is the default and acts on nothing, apply runs the steps, the same alert id never acts twice, a step that times
out is retried with backoff and then fails, a webhook answering 500 is retried and a 4xx is not, a protected address is never
blocked, every attempt reaches the audit trail (a hash chain), and the evidence bundle's manifest catches an edited file.

The module under test is loaded from RESPOND_PATH when set, so run_mutations.py can run these same tests against a copy with one
behaviour removed and require a red run.
    python -m pytest security/tests/test_respond.py -q
"""
from __future__ import annotations

import importlib.util
import json
import os
import random
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
SECURITY = HERE.parent
TARGET = Path(os.environ.get("RESPOND_PATH") or SECURITY / "respond.py")

spec = importlib.util.spec_from_file_location("respond_under_test", TARGET)
rs = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = rs
spec.loader.exec_module(rs)


def boom_http(url, body, timeout):
    raise AssertionError("the webhook was called")


def boom_run(cmd, timeout):
    raise AssertionError("a command was run: " + " ".join(cmd))


BOOK = {
    "name": "pb", "match": {"rule_ids": [100300]},
    "steps": [
        {"name": "enrich", "type": "enrich"},
        {"name": "notify", "type": "notify", "timeout_s": 1, "retries": 2, "backoff_s": 1},
        {"name": "block", "type": "block", "timeout_s": 1},
        {"name": "ticket", "type": "ticket"},
    ],
}


def alert(aid="1.1", rule=100300, srcip="203.0.113.50", **extra):
    doc = {"id": aid, "timestamp": "2026-11-15T14:10:20.000+0000", "rule": {"id": str(rule), "level": 13, "description": "test rule", "mitre": {"id": ["T1110"]}},
           "full_log": "Nov 15 14:10:20 edge sshd[1]: Accepted password for deploy from 203.0.113.50 port 1 ssh2"}
    if srcip:
        doc["data"] = {"srcip": srcip}
    doc.update(extra)
    return doc


class Rig:
    def __init__(self, tmp, apply=False, http=boom_http, runner=boom_run, books=None, handlers=None):
        self.tmp = Path(tmp)
        self.sleeps: list[float] = []
        self.ctx = rs.Context(apply, self.tmp, "http://127.0.0.1:9/notify", http_post=http, runner=runner, sleep=self.sleeps.append)
        self.audit = rs.Audit(self.tmp / "audit.jsonl")
        self.ledger = rs.Ledger(self.tmp / "ledger.sqlite")
        self.engine = rs.Engine(books or [BOOK], self.ledger, self.audit, self.ctx, handlers)

    def lines(self):
        p = self.tmp / "audit.jsonl"
        return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines()] if p.exists() else []


class Recorder:
    """Stands in for the webhook and for iptables, and counts what really happened."""

    def __init__(self, statuses=None):
        self.posts, self.cmds, self.statuses = [], [], list(statuses or [])

    def http(self, url, body, timeout):
        self.posts.append(body)
        return self.statuses.pop(0) if self.statuses else 200

    def run(self, cmd, timeout):
        self.cmds.append(cmd)
        return 1 if cmd[-4:-3] == ["-C"] or "-C" in cmd else 0, ""


# --- dry run -----------------------------------------------------------------------------------------------------------

def test_dry_run_is_the_default_and_acts_on_nothing(tmp_path):
    rig = Rig(tmp_path)                                   # boom stubs: any real action fails the test
    res = rig.engine.handle(alert())
    assert res["outcome"] == "done" and res["mode"] == "dry-run"
    steps = {s["step"]: s for s in res["steps"]}
    assert steps["block"]["result"]["dry_run"] is True
    assert "iptables" in steps["block"]["result"]["would_run"] and "203.0.113.50" in steps["block"]["result"]["would_run"]
    assert "-p cfl" not in steps["block"]["result"]["would_run"]
    assert not (tmp_path / "tickets").exists()
    assert {x["outcome"] for x in rig.lines() if x.get("step")} == {"ok", "dry_run_recorded"}


def test_apply_runs_the_steps(tmp_path):
    rec = Recorder()
    rig = Rig(tmp_path, apply=True, http=rec.http, runner=rec.run)
    res = rig.engine.handle(alert())
    assert res["outcome"] == "done" and res["mode"] == "apply"
    assert len(rec.posts) == 1 and rec.posts[0]["alert_id"] == "1.1" and rec.posts[0]["srcip"] == "203.0.113.50"
    assert any("-I" in c and "203.0.113.50" in c and c[-1] == "DROP" for c in rec.cmds)
    assert all(c[:6] == ["docker", "compose", "-p", "camera-fleet-lab", "exec", "-T"] and c[6] == "edge" and c[7] == "iptables" for c in rec.cmds)
    assert json.loads((tmp_path / "tickets" / "1.1.json").read_text(encoding="utf-8"))["status"] == "open"


def test_block_checks_for_an_existing_rule_first(tmp_path):
    cmds = []

    def run(cmd, timeout):
        cmds.append(cmd)
        return 0, ""                                       # -C succeeds: the rule is already there
    rig = Rig(tmp_path, apply=True, http=lambda u, b, t: 200, runner=run)
    res = rig.engine.handle(alert())
    block = next(s for s in res["steps"] if s["step"] == "block")
    assert block["result"] == {"already_blocked": "203.0.113.50"}
    assert len(cmds) == 1 and "-C" in cmds[0]


def test_a_protected_address_is_never_blocked(tmp_path):
    rec = Recorder()
    for ip in ("10.8.0.1", "10.20.0.10", "172.30.0.10", "127.0.0.1"):
        rig = Rig(tmp_path / ip.replace(".", "_"), apply=True, http=rec.http, runner=rec.run)
        res = rig.engine.handle(alert(aid="p-" + ip, srcip=ip))
        block = next(s for s in res["steps"] if s["step"] == "block")
        assert "skipped" in block["result"]
    assert rec.cmds == []


@pytest.mark.parametrize("bad", ["not-an-ip", "999.1.1.1", "", "203.0.113.50; rm -rf /", "203.0.113.50 -j ACCEPT"])
def test_a_bad_source_address_is_refused_not_passed_to_iptables(tmp_path, bad):
    rec = Recorder()
    rig = Rig(tmp_path, apply=True, http=rec.http, runner=rec.run)
    res = rig.engine.handle(alert(srcip=bad))
    block = next(s for s in res["steps"] if s["step"] == "block")
    assert block["outcome"] == "failed" and rec.cmds == []


# --- idempotency -------------------------------------------------------------------------------------------------------

def test_the_same_alert_id_never_acts_twice(tmp_path):
    rec = Recorder()
    rig = Rig(tmp_path, apply=True, http=rec.http, runner=rec.run)
    first = rig.engine.handle(alert())
    second = rig.engine.handle(alert())
    assert first["outcome"] == "done" and second["outcome"] == "duplicate_ignored"
    assert len(rec.posts) == 1 and len([c for c in rec.cmds if "-I" in c]) == 1
    assert any(x["outcome"] == "duplicate_ignored" for x in rig.lines())


def test_a_restart_remembers_through_the_ledger(tmp_path):
    rec = Recorder()
    Rig(tmp_path, apply=True, http=rec.http, runner=rec.run).engine.handle(alert())
    again = Rig(tmp_path, apply=True, http=rec.http, runner=rec.run).engine.handle(alert())
    assert again["outcome"] == "duplicate_ignored" and len(rec.posts) == 1


def test_a_dry_run_does_not_use_up_the_alert(tmp_path):
    rec = Recorder()
    dry = Rig(tmp_path).engine.handle(alert())
    live = Rig(tmp_path, apply=True, http=rec.http, runner=rec.run).engine.handle(alert())
    assert dry["outcome"] == "done" and live["outcome"] == "done" and len(rec.posts) == 1
    assert Rig(tmp_path).engine.handle(alert())["outcome"] == "duplicate_ignored"      # a second dry run is a duplicate


def test_different_alert_ids_each_act(tmp_path):
    rec = Recorder()
    rig = Rig(tmp_path, apply=True, http=rec.http, runner=rec.run)
    for i in range(3):
        rig.engine.handle(alert(aid=f"a{i}", srcip=f"203.0.113.{i + 1}"))
    assert len(rec.posts) == 3


# --- timeout, retry and backoff ----------------------------------------------------------------------------------------

def test_a_step_that_times_out_is_retried_with_backoff_and_then_fails(tmp_path):
    import threading
    release = threading.Event()
    started = []

    def hangs(step, a, ctx, timeout):
        started.append(1)
        release.wait(10)                                    # never finishes inside the step's 0.05 s limit
        return {}
    book = {"name": "pb", "match": {"rule_ids": [100300]}, "steps": [{"name": "notify", "type": "notify", "timeout_s": 0.05, "retries": 2, "backoff_s": 1}]}
    rig = Rig(tmp_path, apply=True, books=[book], handlers={**rs.HANDLERS, "notify": hangs})
    try:
        res = rig.engine.handle(alert())                    # returns only because the engine gave up on the hung handler
    finally:
        release.set()
    assert res["outcome"] == "failed" and res["steps"][0]["attempts"] == 3 and len(started) == 3
    assert rig.sleeps == [1.0, 2.0]                         # exponential backoff, no sleep after the last attempt
    outcomes = [x["outcome"] for x in rig.lines() if x.get("step") == "notify"]
    assert outcomes == ["timeout", "timeout", "timeout"]


def test_webhook_500_is_retried_then_succeeds(tmp_path):
    rec = Recorder([500, 500, 200])
    rig = Rig(tmp_path, apply=True, http=rec.http, runner=rec.run)
    res = rig.engine.handle(alert())
    notify = next(s for s in res["steps"] if s["step"] == "notify")
    assert res["outcome"] == "done" and notify["attempts"] == 3 and len(rec.posts) == 3
    assert rig.sleeps == [1.0, 2.0]
    assert [x["outcome"] for x in rig.lines() if x.get("step") == "notify"] == ["failed_retryable", "failed_retryable", "ok"]


def test_webhook_500_forever_fails_after_the_retries_and_the_alert_is_marked_failed(tmp_path):
    rec = Recorder([500] * 10)
    rig = Rig(tmp_path, apply=True, http=rec.http, runner=rec.run)
    res = rig.engine.handle(alert())
    assert res["outcome"] == "failed" and len(rec.posts) == 3
    assert rig.ledger.counts() == {"failed": 1}


def test_webhook_4xx_is_not_retried(tmp_path):
    rec = Recorder([400])
    rig = Rig(tmp_path, apply=True, http=rec.http, runner=rec.run)
    res = rig.engine.handle(alert())
    notify = next(s for s in res["steps"] if s["step"] == "notify")
    assert notify["outcome"] == "failed" and notify["attempts"] == 3 and len(rec.posts) == 1 and rig.sleeps == []
    assert [x["outcome"] for x in rig.lines() if x.get("step") == "notify"] == ["failed_permanent"]


def test_a_failed_alert_can_be_retried_and_finished_steps_are_not_repeated(tmp_path):
    rec = Recorder([500] * 3)                               # the first run's notify never gets through
    rig = Rig(tmp_path, apply=True, http=rec.http, runner=rec.run)
    assert rig.engine.handle(alert())["outcome"] == "failed"
    blocks_before = len([c for c in rec.cmds if "-I" in c])
    again = Rig(tmp_path, apply=True, http=rec.http, runner=rec.run).engine.handle(alert())
    assert again["outcome"] == "done"
    skipped = [s["step"] for s in again["steps"] if s["outcome"] == "skipped_already_done"]
    assert skipped == ["enrich", "block", "ticket"]         # these finished in the first pass, only notify is run again
    assert len([c for c in rec.cmds if "-I" in c]) == blocks_before == 1
    assert len(rec.posts) == 4 and Rig(tmp_path, apply=True, http=rec.http, runner=rec.run).engine.handle(alert())["outcome"] == "duplicate_ignored"


def test_a_crashing_handler_is_contained(tmp_path):
    def crash(step, a, ctx, timeout):
        raise KeyError("bug")
    rig = Rig(tmp_path, handlers={**rs.HANDLERS, "enrich": crash})
    res = rig.engine.handle(alert())
    assert res["outcome"] == "failed" and res["steps"][0]["outcome"] == "failed"
    assert any(x["outcome"] == "failed_unexpected" for x in rig.lines())
    assert rig.engine.handle(alert(aid="2.2"))["alert_id"] == "2.2"           # the next alert still runs


# --- audit trail -------------------------------------------------------------------------------------------------------

def test_every_attempt_is_audited_with_the_alert_id_and_the_chain_verifies(tmp_path):
    rec = Recorder([500, 200])
    rig = Rig(tmp_path, apply=True, http=rec.http, runner=rec.run)
    rig.engine.handle(alert(aid="X-9"))
    mine = [x for x in rig.lines() if x.get("alert_id") == "X-9"]
    steps = [x for x in mine if x.get("step")]
    assert len(steps) == 5                                    # enrich, notify twice, block, ticket
    assert all(x["mode"] == "apply" and x["playbook"] == "pb" and x["ts"].endswith("Z") for x in mine)
    assert mine[0]["outcome"] == "started" and mine[-1]["outcome"] == "finished_done"
    ok, msg = rs.verify_audit(tmp_path / "audit.jsonl")
    assert ok, msg


def test_an_edited_or_removed_audit_line_is_detected(tmp_path):
    rec = Recorder()
    rig = Rig(tmp_path, apply=True, http=rec.http, runner=rec.run)
    rig.engine.handle(alert())
    path = tmp_path / "audit.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(lines[:2] + lines[3:]) + "\n", encoding="utf-8")        # remove one line
    assert rs.verify_audit(path)[0] is False
    path.write_text("\n".join(lines).replace('"outcome": "ok"', '"outcome": "fine"', 1) + "\n", encoding="utf-8")
    assert rs.verify_audit(path)[0] is False
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert rs.verify_audit(path)[0] is True


def test_the_audit_chain_continues_after_a_restart(tmp_path):
    for i in range(2):
        Rig(tmp_path).engine.handle(alert(aid=f"r{i}"))
    assert rs.verify_audit(tmp_path / "audit.jsonl")[0] is True


# --- evidence bundle ---------------------------------------------------------------------------------------------------

def test_the_bundle_has_the_alert_the_log_lines_and_a_manifest_that_catches_edits(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "ssh_auth.log").write_text("Nov 15 14:10:05 edge sshd[1]: Failed password for root from 203.0.113.50 port 1 ssh2\n"
                                       "Nov 15 09:00:00 edge sshd[1]: Failed password for root from 198.51.100.1 port 1 ssh2\n", encoding="utf-8")
    rec = Recorder()
    rig = Rig(tmp_path / "state", apply=True, http=rec.http, runner=rec.run)
    rig.ctx.log_dirs = [logs]
    rig.engine.handle(alert(previous_output="Nov 15 14:10:04 edge sshd[1]: Failed password for root from 203.0.113.50 port 1 ssh2"))
    folder = tmp_path / "state" / "evidence" / "1.1"
    assert sorted(p.name for p in folder.iterdir()) == ["MANIFEST.sha256", "alert.json", "audit_excerpt.jsonl", "context.log", "playbook_result.json"]
    ctx = (folder / "context.log").read_text(encoding="utf-8")
    assert "14:10:04" in ctx and "14:10:05" in ctx and "Accepted password" in ctx
    assert "09:00:00" not in ctx                              # outside the time window
    assert json.loads((folder / "alert.json").read_text(encoding="utf-8"))["id"] == "1.1"
    manifest = (folder / "MANIFEST.sha256").read_text(encoding="utf-8").splitlines()
    assert len(manifest) == 4 and all(len(x.split("  ")[0]) == 64 for x in manifest)
    assert rs.verify_bundle(folder) == (True, [])
    (folder / "alert.json").write_text("{}", encoding="utf-8")
    ok, problems = rs.verify_bundle(folder)
    assert not ok and "alert.json was changed" in problems
    (folder / "context.log").unlink()
    assert "context.log is missing" in rs.verify_bundle(folder)[1]


def test_a_bundle_folder_without_a_manifest_fails(tmp_path):
    assert rs.verify_bundle(tmp_path) == (False, ["MANIFEST.sha256 is missing"])


# --- reading alerts and playbooks --------------------------------------------------------------------------------------

def test_unreadable_alert_lines_are_counted_and_skipped(tmp_path):
    p = tmp_path / "alerts.json"
    p.write_text(json.dumps(alert("a")) + "\nnot json\n{\"id\": \"b\"}\n[1,2]\n\n" + json.dumps(alert("c")) + "\n", encoding="utf-8")
    alerts, bad = rs.read_alerts(p)
    assert [a["id"] for a in alerts] == ["a", "c"] and bad == 3


def test_an_alert_with_no_playbook_is_recorded_not_acted_on(tmp_path):
    rig = Rig(tmp_path)
    res = rig.engine.handle(alert(rule=5716))
    assert res["outcome"] == "no_playbook" and any(x["outcome"] == "no_playbook" for x in rig.lines())


def test_playbook_validation_rejects_bad_definitions():
    assert rs.validate_playbook({"name": "x", "match": {"rule_ids": [1]}, "steps": [{"type": "format-disk"}]})
    assert rs.validate_playbook({"name": "x", "match": {"rule_ids": [1]}, "steps": []})
    assert rs.validate_playbook({"match": {"rule_ids": [1]}, "steps": [{"type": "notify"}]})
    assert rs.validate_playbook({"name": "x", "match": {}, "steps": [{"type": "notify"}]})
    assert rs.validate_playbook({"name": "x", "match": {"rule_ids": [1]}, "steps": [{"type": "notify"}, {"type": "notify"}]})
    assert rs.validate_playbook("text")
    assert rs.validate_playbook({"name": "x", "match": {"rule_ids": [1]}, "steps": [{"type": "notify"}]}) == []


def test_the_shipped_playbooks_load_and_cover_every_alerting_rule():
    books = rs.load_playbooks(SECURITY / "playbooks")
    assert len(books) >= 5
    root = ET.parse(SECURITY / "wazuh" / "camera_fleet_rules.xml").getroot()
    alerting = {r.get("id") for r in root.iter("rule") if int(r.get("level")) >= 3 and r.findtext("options") != "no_log"}
    assert alerting and all(rs.pick_playbook(books, rid) for rid in alerting), alerting
    for b in books:
        assert [s["type"] for s in b["steps"]][0] == "enrich"
        for s in b["steps"]:
            if s["type"] in ("notify", "block"):
                assert float(s["timeout_s"]) > 0


# --- the command line --------------------------------------------------------------------------------------------------

def test_cli_dry_run_twice_second_run_is_all_duplicates(tmp_path, capsys):
    alerts = tmp_path / "alerts.json"
    alerts.write_text("\n".join([json.dumps(alert("a1")), "garbage", json.dumps(alert("a2", rule=100210, srcip="10.8.0.1"))]) + "\n", encoding="utf-8")
    argv = ["--alerts", str(alerts), "--playbooks", str(SECURITY / "playbooks"), "--state", str(tmp_path / "state")]
    assert rs.main(argv) == 0
    first = capsys.readouterr().out
    assert "mode=dry-run alerts=2 unreadable_lines=1 done=2" in first
    assert rs.main(argv) == 0
    assert "duplicate_ignored=2" in capsys.readouterr().out
    ok, msg = rs.verify_audit(tmp_path / "state" / "audit.jsonl")
    assert ok, msg


def test_cli_verify_commands(tmp_path, capsys):
    Rig(tmp_path).engine.handle(alert())
    assert rs.main(["--verify-audit", str(tmp_path / "audit.jsonl")]) == 0
    assert rs.main(["--verify-bundle", str(tmp_path / "evidence" / "1.1")]) == 0
    (tmp_path / "evidence" / "1.1" / "alert.json").write_text("x", encoding="utf-8")
    assert rs.main(["--verify-bundle", str(tmp_path / "evidence" / "1.1")]) == 1
    assert "alert.json was changed" in capsys.readouterr().out


def test_cli_unblock_is_a_dry_run_without_apply(capsys):
    assert rs.main(["--unblock", "203.0.113.50"]) == 0
    assert "dry run, would run" in capsys.readouterr().out


# --- property test: many seeded worlds ---------------------------------------------------------------------------------

def run_world(seed, tmp):
    """Random alerts (ids repeat, addresses include protected and invalid ones), random webhook answers, a restart between
    passes, dry and apply runs mixed. Rules checked in every world:
      1 a dry run never touches the webhook or iptables
      2 an alert id gets at most one successful notify, and an address at most one iptables insert, however many passes and restarts
      3 a protected address never gets an iptables insert
      4 the audit chain verifies at the end and every handled alert id appears in it
      5 work that failed comes back: after a clean final pass no alert is left failed
    """
    rng = random.Random(seed)
    ips = ["203.0.113.5", "198.51.100.7", "10.8.0.1", "10.20.0.10", "bogus", None, "203.0.113.5"]
    base = [alert(aid=f"w{i}", rule=rng.choice([100300, 100210, 100101, 5716, 100220]), srcip=rng.choice(ips)) for i in range(rng.randint(5, 14))]
    alerts = base + [rng.choice(base) for _ in range(rng.randint(0, 8))]          # exact duplicates of some alerts
    rng.shuffle(alerts)
    # a block step on a missing or invalid address fails for good, whatever is retried; those alerts may stay failed
    unfixable = {a["id"] for a in alerts if a["rule"]["id"] in ("100300", "100210") and (a.get("data", {}).get("srcip") in (None, "bogus"))}
    ok_posts: dict[str, int] = {}
    inserts: dict[str, int] = {}
    installed: set[str] = set()
    seen_ids = set()
    dry_touch = []
    books = rs.load_playbooks(SECURITY / "playbooks")
    for pass_no in range(3):
        final = pass_no == 2
        apply = final or (pass_no > 0 and rng.random() < 0.85)
        statuses = [200] * 50 if final else [rng.choice([200, 200, 500, 400]) for _ in range(60)]

        def http(url, body, timeout, statuses=statuses, apply=apply):
            if not apply:
                dry_touch.append(("http", body))
            status = statuses.pop(0) if statuses else 200
            if status == 200:
                ok_posts[body["alert_id"]] = ok_posts.get(body["alert_id"], 0) + 1
            return status

        def run(cmd, timeout, apply=apply):
            if not apply:
                dry_touch.append(("run", cmd))
            ip = cmd[cmd.index("-s") + 1]
            if "-C" in cmd:
                return (0 if ip in installed else 1), ""
            installed.add(ip)
            inserts[ip] = inserts.get(ip, 0) + 1
            return 0, ""
        ctx = rs.Context(apply, tmp, "http://127.0.0.1:9/n", http_post=http, runner=run, sleep=lambda s: None)
        engine = rs.Engine(books, rs.Ledger(tmp / "ledger.sqlite"), rs.Audit(tmp / "audit.jsonl"), ctx)
        for a in alerts:
            engine.handle(a)
            seen_ids.add(a["id"])
    assert not dry_touch, f"seed {seed}: a dry run touched the outside world {dry_touch[:2]}"
    assert all(n <= 1 for n in ok_posts.values()), f"seed {seed}: an alert notified twice {ok_posts}"
    assert not (set(inserts) & {"10.8.0.1", "10.20.0.10"}), f"seed {seed}: a protected address was blocked {inserts}"
    assert all(n <= 1 for n in inserts.values()), f"seed {seed}: the same address was inserted twice {inserts}"
    ok, msg = rs.verify_audit(tmp / "audit.jsonl")
    assert ok, f"seed {seed}: {msg}"
    audited = {json.loads(x).get("alert_id") for x in (tmp / "audit.jsonl").read_text(encoding="utf-8").splitlines()}
    assert {a["id"] for a in alerts} <= audited, f"seed {seed}: an alert left no audit line"
    ledger = rs.Ledger(tmp / "ledger.sqlite")
    failed = {r[0] for r in ledger.db.execute("SELECT alert_id FROM alerts WHERE mode='apply' AND status='failed'")}
    assert failed <= unfixable, f"seed {seed}: alerts {failed - unfixable} failed and did not come back"


@pytest.mark.parametrize("seed", range(20))
def test_random_worlds_keep_every_rule(seed, tmp_path):
    run_world(seed, tmp_path)
