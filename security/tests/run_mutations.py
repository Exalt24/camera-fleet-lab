#!/usr/bin/env python3
"""Mutation controls for the two pieces of security code that have tests: junos_review.py and respond.py.

For each mutant this copies the module to a temp folder, changes it in one known way, points the module's own test file at the
copy (JUNOS_REVIEW_PATH or RESPOND_PATH) and runs pytest. A mutant is CAUGHT when pytest fails. A mutant that leaves every test
green means a test is missing, and this script exits 1.

  junos_review.py  16 mutants, one per rule: the rule's function is made to report nothing
  respond.py       13 mutants: remove the idempotency check, remove the retry, make a dry run act, drop the audit write, and so on

    python security/tests/run_mutations.py [--save docs/security-mutation-run.txt]
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SECURITY = HERE.parent

RESPOND_MUTANTS = [
    ("remove the idempotency check (a duplicate alert acts again)",
     'if not self.ledger.claim(alert_id, self.mode, book["name"]):', "if False:"),
    ("remove the retry (one attempt per step)",
     'attempts = int(step.get("retries", 0)) + 1', "attempts = 1"),
    ("make a dry run act (the block step runs iptables in dry run)",
     'if not ctx.apply:\n        return {"dry_run": True, "would_run"', 'if False:\n        return {"dry_run": True, "would_run"'),
    ("drop the audit write (nothing reaches audit.jsonl)",
     'with open(self.path, "a", encoding="utf-8") as fh:\n                fh.write(line + "\\n")', "pass"),
    ("do not enforce the step timeout",
     "result = call_with_timeout(lambda: handler(step, alert, self.ctx, timeout), timeout)", "result = handler(step, alert, self.ctx, timeout)"),
    ("retry a 4xx answer (a bad request is retried)",
     'if status >= 400:\n        raise PermanentError(f"webhook answered {status}")', 'if status >= 400:\n        raise RetryableError(f"webhook answered {status}")'),
    ("treat a 5xx answer as success",
     "if status >= 500:\n        raise RetryableError", "if False:\n        raise RetryableError"),
    ("block a protected address",
     "if ctx.is_protected(addr):", "if False:"),
    ("stop checking the manifest digest",
     "elif sha256_file(target) != digest:", "elif False:"),
    ("let a dry run use up the alert (dry run and apply share one key)",
     'self.mode = "apply" if ctx.apply else "dry-run"', 'self.mode = "apply"'),
    ("backoff does not grow (constant wait)",
     "backoff * (2 ** (attempt - 1))", "backoff"),
    ("break the audit chain (every line points at the genesis hash)",
     'entry = {"ts": now_iso(), **fields, "prev": self.prev}', 'entry = {"ts": now_iso(), **fields, "prev": GENESIS_HASH}'),
    ("repeat finished steps when a failed alert is run again",
     "if self.ledger.step_done(alert_id, self.mode, name):", "if False:"),
]


def junos_mutants(source: str):
    for m in re.finditer(r"^def (check_JR\d+)\(cfg: Config\) -> list\[Finding\]:\n", source, re.M):
        name = m.group(1)
        yield (f"switch off {name.replace('check_', '')}", m.group(0), m.group(0) + "    return []\n")


def run_pytest(test_file: Path, env_name: str, module_copy: Path) -> tuple[bool, str]:
    env = dict(os.environ)
    env[env_name] = str(module_copy)
    r = subprocess.run([sys.executable, "-m", "pytest", str(test_file), "-q", "-x", "-p", "no:cacheprovider"], capture_output=True,
                       text=True, encoding="utf-8", env=env, timeout=600)
    tail = [ln for ln in r.stdout.splitlines() if ln.strip()][-1:] or [""]
    return r.returncode != 0, tail[0]


def run_group(label: str, module: Path, test_file: Path, env_name: str, mutants, log) -> tuple[int, int]:
    source = module.read_text(encoding="utf-8")
    base_ok, base_tail = run_pytest(test_file, env_name, module)
    log(f"{label}: baseline, unchanged module: {'FAILED' if base_ok else 'green'} ({base_tail})")
    if base_ok:
        return 0, -1
    caught = total = 0
    for name, old, new in mutants:
        total += 1
        if old not in source:
            log(f"  FAIL  {name}: the anchor is not in the module, the mutation did not apply")
            continue
        work = Path(tempfile.mkdtemp(prefix="mut-"))
        try:
            copy = work / module.name
            copy.write_text(source.replace(old, new, 1), encoding="utf-8")
            red, tail = run_pytest(test_file, env_name, copy)
        finally:
            shutil.rmtree(work, ignore_errors=True)
        caught += red
        log(f"  {'CAUGHT' if red else 'MISSED'}  {name}  [{tail}]")
    log(f"{label}: {caught}/{total} mutants caught")
    return caught, total


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--save")
    args = ap.parse_args()
    out: list[str] = []

    def log(line: str) -> None:
        print(line, flush=True)
        out.append(line)

    junos = SECURITY / "junos_review.py"
    respond = SECURITY / "respond.py"
    c1, t1 = run_group("junos_review.py", junos, HERE / "test_junos_review.py", "JUNOS_REVIEW_PATH", list(junos_mutants(junos.read_text(encoding="utf-8"))), log)
    c2, t2 = run_group("respond.py", respond, HERE / "test_respond.py", "RESPOND_PATH", RESPOND_MUTANTS, log)
    ok = t1 > 0 and t2 > 0 and c1 == t1 and c2 == t2
    log(f"total: {c1 + c2}/{max(t1, 0) + max(t2, 0)} mutants caught" + ("" if ok else "  (NOT ALL CAUGHT)"))
    if args.save:
        Path(args.save).parent.mkdir(parents=True, exist_ok=True)
        Path(args.save).write_text("\n".join(out) + "\n", encoding="utf-8")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
