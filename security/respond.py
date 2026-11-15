#!/usr/bin/env python3
"""A small SOAR style responder for the camera lab's Wazuh alerts.

It reads alerts.json (one JSON alert per line), picks a playbook from security/playbooks/*.yml by rule id, and runs the
playbook's steps (enrich, notify, block, ticket). What it guarantees, and what security/tests/ checks:

  dry run is the default   nothing outside this folder's state directory is touched: notify, block and ticket only print
                           and record what they WOULD do. --apply turns them on. enrich only reads, so it always runs.
  idempotency              a ledger (SQLite) records every alert id and every step. The same alert id never acts twice in
                           the same mode. A dry run does not use up the alert, so --apply can still act on it later.
  timeout and retry        every step has a timeout and a retry count with exponential backoff. A 5xx answer and a timeout
                           are retried, a 4xx answer is not (retrying a bad request cannot fix it).
  audit trail              every attempt of every step is appended to audit.jsonl with the alert id. Each line carries the
                           sha256 of the line before it, so an edited or removed line is visible (--verify-audit).
  evidence bundle          one folder per incident: the alert JSON, the raw log lines around it, what the playbook did, and
                           MANIFEST.sha256 with a sha256 per file (--verify-bundle checks it).

The notify step posts to security/webhook_receiver.py, a local stand-in for a chat or paging webhook. The block step runs
`iptables` only inside the lab's edge container, and only with --apply. A protected address (the hub's tunnel address, the
site router, the camera) is never blocked, so a response can not cut the monitor's own path.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import re
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
GENESIS_HASH = "0" * 64
DEFAULT_PROTECTED = ["10.8.0.0/24", "10.20.0.0/24", "172.30.0.0/24", "127.0.0.0/8"]


class StepTimeout(Exception):
    """A step did not finish inside its time limit."""


class RetryableError(Exception):
    """A failure that may pass on the next attempt (a 5xx answer, a refused connection)."""


class PermanentError(Exception):
    """A failure another attempt cannot fix (a 4xx answer, a protected address, a malformed address)."""


# --- time and hashing helpers ------------------------------------------------------------------------------------------

def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def write_lf(path: Path, text: str) -> None:
    """Write text as UTF-8 with LF line endings on every platform. The evidence manifest hashes the bytes of these files, so a
    Windows run must not write CRLF (git then rewrites it and the manifest no longer matches the checked out file)."""
    Path(path).write_bytes(text.encode("utf-8"))


def call_with_timeout(fn, timeout_s: float):
    """Run fn() and give up after timeout_s. The worker is a daemon thread, so a handler that ignores its own timeout can
    not keep the responder alive, and the caller always gets control back on time."""
    box: dict = {}

    def work():
        try:
            box["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 - handed back to the caller
            box["error"] = exc

    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(timeout_s)
    if t.is_alive():
        raise StepTimeout(f"no answer within {timeout_s}s")
    if "error" in box:
        raise box["error"]
    return box.get("value")


# --- audit trail -------------------------------------------------------------------------------------------------------

class Audit:
    """Append only JSON lines, each carrying the sha256 of the previous line."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.prev = GENESIS_HASH
        if self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    self.prev = sha256_bytes(line.encode("utf-8"))

    def write(self, **fields) -> dict:
        with self.lock:
            entry = {"ts": now_iso(), **fields, "prev": self.prev}
            line = json.dumps(entry, sort_keys=True, ensure_ascii=False)
            with open(self.path, "ab") as fh:
                fh.write(line.encode("utf-8") + b"\n")
            self.prev = sha256_bytes(line.encode("utf-8"))
        return entry


def verify_audit(path: Path) -> tuple[bool, str]:
    prev, n = GENESIS_HASH, 0
    for i, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            return False, f"line {i} is not JSON"
        if entry.get("prev") != prev:
            return False, f"line {i} does not follow the line before it (a line was edited or removed)"
        prev = sha256_bytes(line.encode("utf-8"))
        n += 1
    return True, f"{n} audit lines, chain intact"


# --- ledger (idempotency) ----------------------------------------------------------------------------------------------

class Ledger:
    """SQLite record of what was done. An alert is keyed by (alert id, mode); a step by (alert id, mode, step)."""

    def __init__(self, path: Path | str):
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS alerts (alert_id TEXT, mode TEXT, playbook TEXT, status TEXT, ts TEXT,"
                        " PRIMARY KEY (alert_id, mode))")
        self.db.execute("CREATE TABLE IF NOT EXISTS steps (alert_id TEXT, mode TEXT, step TEXT, status TEXT, ts TEXT,"
                        " PRIMARY KEY (alert_id, mode, step))")
        self.db.commit()

    def claim(self, alert_id: str, mode: str, playbook: str) -> bool:
        """True when this run may act on the alert. False when it was already handled in this mode. A failed alert may
        be claimed again, and its finished steps are still skipped."""
        cur = self.db.execute("INSERT OR IGNORE INTO alerts VALUES (?,?,?,?,?)", (alert_id, mode, playbook, "running", now_iso()))
        if cur.rowcount == 1:
            self.db.commit()
            return True
        cur = self.db.execute("UPDATE alerts SET status='running', ts=? WHERE alert_id=? AND mode=? AND status='failed'",
                              (now_iso(), alert_id, mode))
        self.db.commit()
        return cur.rowcount == 1

    def finish(self, alert_id: str, mode: str, status: str) -> None:
        self.db.execute("UPDATE alerts SET status=?, ts=? WHERE alert_id=? AND mode=?", (status, now_iso(), alert_id, mode))
        self.db.commit()

    def step_done(self, alert_id: str, mode: str, step: str) -> bool:
        row = self.db.execute("SELECT status FROM steps WHERE alert_id=? AND mode=? AND step=?", (alert_id, mode, step)).fetchone()
        return bool(row and row[0] == "ok")

    def mark_step(self, alert_id: str, mode: str, step: str, status: str) -> None:
        self.db.execute("INSERT OR REPLACE INTO steps VALUES (?,?,?,?,?)", (alert_id, mode, step, status, now_iso()))
        self.db.commit()

    def counts(self) -> dict:
        return {r[0]: r[1] for r in self.db.execute("SELECT status, COUNT(*) FROM alerts GROUP BY status")}


# --- playbooks ---------------------------------------------------------------------------------------------------------

STEP_TYPES = {"enrich", "notify", "block", "ticket"}


def load_playbooks(folder: Path) -> list[dict]:
    books = []
    for path in sorted(Path(folder).glob("*.yml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        problems = validate_playbook(doc)
        if problems:
            raise ValueError(f"{path.name}: " + "; ".join(problems))
        doc["_file"] = path.name
        books.append(doc)
    return books


def validate_playbook(doc) -> list[str]:
    if not isinstance(doc, dict):
        return ["not a mapping"]
    problems = []
    if not doc.get("name"):
        problems.append("no name")
    if not isinstance((doc.get("match") or {}).get("rule_ids"), list):
        problems.append("match.rule_ids must be a list")
    steps = doc.get("steps")
    if not isinstance(steps, list) or not steps:
        problems.append("no steps")
        return problems
    seen = set()
    for i, st in enumerate(steps):
        if not isinstance(st, dict) or st.get("type") not in STEP_TYPES:
            problems.append(f"step {i + 1} has an unknown type")
            continue
        name = st.get("name") or st["type"]
        if name in seen:
            problems.append(f"step name {name} is used twice")
        seen.add(name)
    return problems


def pick_playbook(books: list[dict], rule_id: str) -> dict | None:
    for book in books:
        if str(rule_id) in [str(x) for x in book["match"]["rule_ids"]]:
            return book
    return None


# --- alert reading -----------------------------------------------------------------------------------------------------

def get_path(obj, dotted: str, default=None):
    cur = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def read_alerts(path: Path) -> tuple[list[dict], int]:
    """Returns (alerts, number of lines skipped as unreadable). One bad line never stops the rest."""
    alerts, bad = [], 0
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            doc = json.loads(line)
        except ValueError:
            bad += 1
            continue
        if isinstance(doc, dict) and doc.get("id") and get_path(doc, "rule.id"):
            alerts.append(doc)
        else:
            bad += 1
    return alerts, bad


def alert_epoch(alert: dict) -> float | None:
    ts = alert.get("timestamp")
    if not isinstance(ts, str):
        return None
    try:
        return dt.datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=dt.timezone.utc).timestamp()
    except ValueError:
        return None


ISO_TS = re.compile(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})")
SYSLOG_TS = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})")
MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def line_epoch(line: str, year: int) -> float | None:
    m = ISO_TS.search(line)
    if m:
        try:
            return dt.datetime.strptime(m.group(1) + "T" + m.group(2), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=dt.timezone.utc).timestamp()
        except ValueError:
            return None
    m = SYSLOG_TS.match(line)
    if m and m.group(1) in MONTHS:
        try:
            return dt.datetime(year, MONTHS[m.group(1)], int(m.group(2)), *[int(x) for x in m.group(3).split(":")],
                               tzinfo=dt.timezone.utc).timestamp()
        except ValueError:
            return None
    return None


def context_lines(alert: dict, log_dirs: list[Path], window_s: int = 120, cap: int = 200) -> list[str]:
    """The raw log lines around the alert: Wazuh's own full_log and previous_output, then every line of the given log
    files whose timestamp is within window_s of the alert."""
    lines: list[str] = []
    for chunk in (alert.get("previous_output"), alert.get("full_log")):
        if isinstance(chunk, str) and chunk.strip():
            lines.extend(x for x in chunk.splitlines() if x.strip())
    at = alert_epoch(alert)
    if at is not None:
        year = dt.datetime.fromtimestamp(at, dt.timezone.utc).year
        for folder in log_dirs:
            for path in sorted(Path(folder).glob("*")):
                if not path.is_file():
                    continue
                for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
                    ts = line_epoch(raw, year)
                    if ts is not None and abs(ts - at) <= window_s:
                        lines.append(f"{path.name}: {raw}")
    seen, out = set(), []
    for line in lines:
        if line not in seen:
            seen.add(line)
            out.append(line)
    return out[:cap]


# --- step handlers -----------------------------------------------------------------------------------------------------

class Context:
    def __init__(self, apply: bool, state_dir: Path, webhook_url: str | None = None, project: str = "camera-fleet-lab",
                 protected: list[str] | None = None, runner=None, http_post=None, sleep=time.sleep, log_dirs=None,
                 seen_sources: dict | None = None):
        self.apply = apply
        self.state_dir = Path(state_dir)
        self.webhook_url = webhook_url
        self.project = project
        self.protected = [ipaddress.ip_network(p) for p in (protected or DEFAULT_PROTECTED)]
        self.runner = runner or self._run
        self.http_post = http_post or self._post
        self.sleep = sleep
        self.log_dirs = [Path(p) for p in (log_dirs or [])]
        self.seen_sources = seen_sources if seen_sources is not None else {}

    @staticmethod
    def _run(cmd: list[str], timeout: float) -> tuple[int, str]:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout + r.stderr).strip()

    @staticmethod
    def _post(url: str, body: dict, timeout: float) -> int:
        req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status
        except urllib.error.HTTPError as exc:
            return exc.code

    def is_protected(self, ip: ipaddress._BaseAddress) -> bool:
        return any(ip in net for net in self.protected)


def srcip_of(alert: dict) -> str | None:
    ip = get_path(alert, "data.srcip")
    return ip if isinstance(ip, str) else None


def step_enrich(step: dict, alert: dict, ctx: Context, timeout: float) -> dict:
    """Read only: say what kind of address the alert names and whether it was seen before in this run."""
    ip = srcip_of(alert)
    out = {"srcip": ip, "rule_id": str(get_path(alert, "rule.id")), "level": get_path(alert, "rule.level"),
           "mitre": get_path(alert, "rule.mitre.id", []), "csf": get_path(alert, "rule.info", None)}
    if ip:
        try:
            addr = ipaddress.ip_address(ip)
            out["address_class"] = ("protected" if ctx.is_protected(addr) else "private" if addr.is_private
                                    else "global")
            out["valid_ip"] = True
        except ValueError:
            out["valid_ip"] = False
            out["address_class"] = "invalid"
        out["alerts_from_this_source_in_run"] = ctx.seen_sources.get(ip, 0)
    return out


def step_notify(step: dict, alert: dict, ctx: Context, timeout: float) -> dict:
    url = step.get("url") or ctx.webhook_url
    body = {"alert_id": alert.get("id"), "rule_id": str(get_path(alert, "rule.id")), "level": get_path(alert, "rule.level"),
            "description": get_path(alert, "rule.description"), "srcip": srcip_of(alert),
            "mitre": get_path(alert, "rule.mitre.id", []), "text": step.get("text", "")}
    if not ctx.apply:
        return {"dry_run": True, "would_post": url, "body": body}
    if not url:
        raise PermanentError("no webhook url given")
    status = ctx.http_post(url, body, timeout)
    if status >= 500:
        raise RetryableError(f"webhook answered {status}")
    if status >= 400:
        raise PermanentError(f"webhook answered {status}")
    return {"posted": url, "status": status}


def step_ticket(step: dict, alert: dict, ctx: Context, timeout: float) -> dict:
    ticket = {"alert_id": alert.get("id"), "title": f"{get_path(alert, 'rule.description')} (rule {get_path(alert, 'rule.id')})",
              "severity_level": get_path(alert, "rule.level"), "status": "open", "opened": now_iso(),
              "evidence_dir": f"evidence/{alert.get('id')}"}
    if not ctx.apply:
        return {"dry_run": True, "would_write": f"tickets/{alert.get('id')}.json", "ticket": ticket}
    folder = ctx.state_dir / "tickets"
    folder.mkdir(parents=True, exist_ok=True)
    write_lf(folder / f"{alert.get('id')}.json", json.dumps(ticket, indent=2))
    return {"wrote": f"tickets/{alert.get('id')}.json"}


def block_command(project: str, ip: str, action: str = "-I") -> list[str]:
    cmd = ["docker", "compose", "-p", project, "exec", "-T", "edge", "iptables"]
    return cmd + (["-I", "INPUT", "1"] if action == "-I" else [action, "INPUT"]) + ["-s", ip, "-j", "DROP"]


def step_block(step: dict, alert: dict, ctx: Context, timeout: float) -> dict:
    ip = srcip_of(alert)
    try:
        addr = ipaddress.ip_address(ip or "")
    except ValueError:
        raise PermanentError(f"no valid source address to block ({ip!r})") from None
    if ctx.is_protected(addr):
        return {"skipped": f"{ip} is a protected address and is never blocked"}
    cmd = block_command(ctx.project, str(addr))
    if not ctx.apply:
        return {"dry_run": True, "would_run": " ".join(cmd)}
    rc, _ = ctx.runner(block_command(ctx.project, str(addr), "-C"), timeout)
    if rc == 0:
        return {"already_blocked": str(addr)}
    rc, out = ctx.runner(cmd, timeout)
    if rc != 0:
        raise RetryableError(f"iptables returned {rc}: {out[:200]}")
    return {"ran": " ".join(cmd)}


HANDLERS = {"enrich": step_enrich, "notify": step_notify, "ticket": step_ticket, "block": step_block}


# --- the engine --------------------------------------------------------------------------------------------------------

class Engine:
    def __init__(self, books: list[dict], ledger: Ledger, audit: Audit, ctx: Context, handlers: dict | None = None):
        self.books, self.ledger, self.audit, self.ctx = books, ledger, audit, ctx
        self.handlers = handlers or HANDLERS
        self.mode = "apply" if ctx.apply else "dry-run"

    def run_step(self, alert: dict, book: dict, step: dict) -> dict:
        name = step.get("name") or step["type"]
        alert_id = str(alert["id"])
        if self.ledger.step_done(alert_id, self.mode, name):
            self.audit.write(alert_id=alert_id, playbook=book["name"], step=name, mode=self.mode, outcome="skipped_already_done")
            return {"step": name, "outcome": "skipped_already_done"}
        timeout = float(step.get("timeout_s", 10))
        attempts = int(step.get("retries", 0)) + 1
        backoff = float(step.get("backoff_s", 1))
        handler = self.handlers[step["type"]]
        last = ""
        for attempt in range(1, attempts + 1):
            try:
                result = call_with_timeout(lambda: handler(step, alert, self.ctx, timeout), timeout)
            except PermanentError as exc:
                last = f"permanent: {exc}"
                self.audit.write(alert_id=alert_id, playbook=book["name"], step=name, mode=self.mode, attempt=attempt,
                                 outcome="failed_permanent", detail=str(exc))
                break
            except (StepTimeout, RetryableError) as exc:
                last = f"{exc.__class__.__name__}: {exc}"
                self.audit.write(alert_id=alert_id, playbook=book["name"], step=name, mode=self.mode, attempt=attempt,
                                 outcome="timeout" if isinstance(exc, StepTimeout) else "failed_retryable", detail=str(exc))
                if attempt < attempts:
                    self.ctx.sleep(backoff * (2 ** (attempt - 1)))
                continue
            except Exception as exc:  # noqa: BLE001 - a handler bug must not stop the other alerts
                last = f"unexpected {exc.__class__.__name__}: {exc}"
                self.audit.write(alert_id=alert_id, playbook=book["name"], step=name, mode=self.mode, attempt=attempt,
                                 outcome="failed_unexpected", detail=str(exc))
                break
            self.audit.write(alert_id=alert_id, playbook=book["name"], step=name, mode=self.mode, attempt=attempt,
                             outcome="dry_run_recorded" if result.get("dry_run") else "ok", detail=json.dumps(result, sort_keys=True))
            self.ledger.mark_step(alert_id, self.mode, name, "ok")
            return {"step": name, "outcome": "ok", "attempts": attempt, "result": result}
        self.ledger.mark_step(alert_id, self.mode, name, "failed")
        return {"step": name, "outcome": "failed", "attempts": attempts, "error": last}

    def handle(self, alert: dict, log_dirs: list[Path] | None = None) -> dict:
        alert_id = str(alert.get("id"))
        rule_id = str(get_path(alert, "rule.id"))
        book = pick_playbook(self.books, rule_id)
        if book is None:
            self.audit.write(alert_id=alert_id, rule_id=rule_id, mode=self.mode, outcome="no_playbook")
            return {"alert_id": alert_id, "outcome": "no_playbook"}
        if not self.ledger.claim(alert_id, self.mode, book["name"]):
            self.audit.write(alert_id=alert_id, rule_id=rule_id, playbook=book["name"], mode=self.mode, outcome="duplicate_ignored")
            return {"alert_id": alert_id, "outcome": "duplicate_ignored"}
        self.audit.write(alert_id=alert_id, rule_id=rule_id, playbook=book["name"], mode=self.mode, outcome="started")
        results = [self.run_step(alert, book, st) for st in book["steps"]]
        failed = [r for r in results if r["outcome"] == "failed"]
        status = "failed" if failed else "done"
        self.ledger.finish(alert_id, self.mode, status)
        self.audit.write(alert_id=alert_id, playbook=book["name"], mode=self.mode, outcome="finished_" + status)
        summary = {"alert_id": alert_id, "rule_id": rule_id, "playbook": book["name"], "mode": self.mode, "outcome": status,
                   "steps": results}
        write_bundle(self.ctx.state_dir, alert, summary, context_lines(alert, log_dirs or self.ctx.log_dirs), self.audit.path)
        src = srcip_of(alert)
        if src:
            self.ctx.seen_sources[src] = self.ctx.seen_sources.get(src, 0) + 1
        return summary


# --- evidence bundle ---------------------------------------------------------------------------------------------------

def write_bundle(state_dir: Path, alert: dict, summary: dict, lines: list[str], audit_path: Path) -> Path:
    folder = Path(state_dir) / "evidence" / str(alert["id"])
    folder.mkdir(parents=True, exist_ok=True)
    write_lf(folder / "alert.json", json.dumps(alert, indent=2, sort_keys=True))
    write_lf(folder / "context.log", "\n".join(lines) + ("\n" if lines else ""))
    write_lf(folder / "playbook_result.json", json.dumps(summary, indent=2, sort_keys=True))
    mine = [ln for ln in Path(audit_path).read_text(encoding="utf-8").splitlines() if f'"alert_id": "{alert["id"]}"' in ln]
    write_lf(folder / "audit_excerpt.jsonl", "\n".join(mine) + "\n")
    names = ["alert.json", "context.log", "playbook_result.json", "audit_excerpt.jsonl"]
    manifest = "".join(f"{sha256_file(folder / n)}  {n}\n" for n in names)
    write_lf(folder / "MANIFEST.sha256", manifest)
    return folder


def verify_bundle(folder: Path) -> tuple[bool, list[str]]:
    folder = Path(folder)
    manifest = folder / "MANIFEST.sha256"
    if not manifest.exists():
        return False, ["MANIFEST.sha256 is missing"]
    problems = []
    for line in manifest.read_text(encoding="utf-8").splitlines():
        digest, _, name = line.partition("  ")
        target = folder / name
        if not target.exists():
            problems.append(f"{name} is missing")
        elif sha256_file(target) != digest:
            problems.append(f"{name} was changed")
    return not problems, problems


# --- command line ------------------------------------------------------------------------------------------------------

def run(args) -> int:
    state = Path(args.state)
    books = load_playbooks(Path(args.playbooks))
    alerts, bad = read_alerts(Path(args.alerts))
    audit = Audit(state / "audit.jsonl")
    ctx = Context(args.apply, state, args.webhook, args.project, args.protect or None, log_dirs=[Path(p) for p in args.logs or []])
    engine = Engine(books, Ledger(state / "ledger.sqlite"), audit, ctx)
    if bad:
        audit.write(outcome="alert_lines_skipped", detail=f"{bad} unreadable alert line(s)")
    tally: dict[str, int] = {}
    for alert in alerts:
        res = engine.handle(alert)
        tally[res["outcome"]] = tally.get(res["outcome"], 0) + 1
        tag = " ".join(f"{s['step']}={s['outcome']}" for s in res.get("steps", []))
        print(f"{res['alert_id']}  rule {get_path(alert, 'rule.id')}  {res['outcome']}  {tag}")
    print(f"mode={engine.mode} alerts={len(alerts)} unreadable_lines={bad} " + " ".join(f"{k}={v}" for k, v in sorted(tally.items())))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Run playbooks over Wazuh alerts. Dry run unless --apply is given.")
    p.add_argument("--alerts", help="alerts.json from the Wazuh manager (one JSON alert per line)")
    p.add_argument("--playbooks", default=str(HERE / "playbooks"))
    p.add_argument("--state", default=str(HERE / "state"), help="ledger, audit trail, evidence bundles and tickets go here")
    p.add_argument("--logs", nargs="*", help="folders of raw logs to quote in the evidence bundle")
    p.add_argument("--webhook", help="URL of the notify receiver, for example http://127.0.0.1:8765/notify")
    p.add_argument("--project", default="camera-fleet-lab", help="compose project name of the lab (for the block step)")
    p.add_argument("--protect", nargs="*", help="addresses never blocked (default: the lab's own networks)")
    p.add_argument("--apply", action="store_true", help="really notify, write tickets and run iptables in the edge container")
    p.add_argument("--unblock", metavar="IP", help="remove an iptables DROP this tool added (needs --apply)")
    p.add_argument("--verify-bundle", metavar="DIR")
    p.add_argument("--verify-audit", metavar="FILE")
    args = p.parse_args(argv)
    if args.verify_bundle:
        ok, problems = verify_bundle(Path(args.verify_bundle))
        print("bundle intact" if ok else "bundle FAILED: " + "; ".join(problems))
        return 0 if ok else 1
    if args.verify_audit:
        ok, msg = verify_audit(Path(args.verify_audit))
        print(("audit ok: " if ok else "audit FAILED: ") + msg)
        return 0 if ok else 1
    if args.unblock:
        ipaddress.ip_address(args.unblock)
        cmd = block_command(args.project, args.unblock, "-D")
        if not args.apply:
            print("dry run, would run: " + " ".join(cmd))
            return 0
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        print((r.stdout + r.stderr).strip() or f"removed rule for {args.unblock}")
        return r.returncode
    if not args.alerts:
        p.error("--alerts is required")
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
