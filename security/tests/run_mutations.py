#!/usr/bin/env python3
"""Mutation controls for the pieces of security code that have tests: junos_review.py, respond.py, vuln/cve_triage.py, the Keycloak realm file and the hub's headers.py.

For each mutant this copies the module to a temp folder, changes it in one known way, points the module's own test file at the
copy (JUNOS_REVIEW_PATH or RESPOND_PATH) and runs pytest. A mutant is CAUGHT when pytest fails. A mutant that leaves every test
green means a test is missing, and this script exits 1.

  junos_review.py  16 mutants, one per rule: the rule's function is made to report nothing
  respond.py       13 mutants: remove the idempotency check, remove the retry, make a dry run act, drop the audit write, and so on
  cve_triage.py    16 mutants: break the ranking order, drop the KEV boost, treat a failed lookup as clean, drop the exposure rule, and so on
  realm JSON       12 mutants: remove each setting (OTP required action, brute force detection, short token lifespan, no committed secret, ...) from a copy
  hub headers.py   13 mutants: bring back 'unsafe-inline', hash only the first inline block, use the wrong digest, drop no-store, give JSON the page policy, and so on

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
HUB_APP = SECURITY.parent / "hub" / "app"

RESPOND_MUTANTS = [
    ("remove the idempotency check (a duplicate alert acts again)",
     'if not self.ledger.claim(alert_id, self.mode, book["name"]):', "if False:"),
    ("remove the retry (one attempt per step)",
     'attempts = int(step.get("retries", 0)) + 1', "attempts = 1"),
    ("make a dry run act (the block step runs iptables in dry run)",
     'if not ctx.apply:\n        return {"dry_run": True, "would_run"', 'if False:\n        return {"dry_run": True, "would_run"'),
    ("drop the audit write (nothing reaches audit.jsonl)",
     'with open(self.path, "ab") as fh:\n                fh.write(line.encode("utf-8") + b"\\n")', "pass"),
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


CVE_MUTANTS = [
    ("break the ranking order (CVSS compared before EPSS)",
     "return (kev_group, epss, cvss, reach, f.id)", "return (kev_group, cvss, epss, reach, f.id)"),
    ("drop the KEV boost (a known exploited CVE ranks like any other)",
     "kev_group = 0 if f.kev is True else (1 if f.kev is None else 2)", "kev_group = 0"),
    ("treat a failed lookup as clean (the component reads ok with no CVEs)",
     'results.append(ComponentResult(comp, "failed", str(err), 0, exp, exp_detail))', 'results.append(ComponentResult(comp, "ok", "", 0, exp, exp_detail))'),
    ("drop the exposure rule (reachable and internal rank alike)",
     'reach = 0 if f.exposure == "reachable" else 1', "reach = 0"),
    ("treat an unloaded KEV catalogue as 'not exploited'",
     "kev = None if kev_map is None else (cve.id in kev_map)", "kev = False if kev_map is None else (cve.id in kev_map)"),
    ("remove the CVE id tie-break (equal findings keep input order)",
     "return (kev_group, epss, cvss, reach, f.id)", "return (kev_group, epss, cvss, reach)"),
    ("a missing EPSS sorts first instead of last",
     'epss = -f.epss if f.epss is not None else float("inf")', 'epss = -f.epss if f.epss is not None else float("-inf")'),
    ("remove the NVD rate limit",
     "if self.last is not None and now - self.last < self.min_interval:", "if False:"),
    ("remove the retry (one attempt per lookup)",
     "for attempt in range(1, self.retries + 1):", "for attempt in range(1, 2):"),
    ("skip the CPE dictionary check (a product with no CPE reads as clean)",
     "if known == 0:", "if False:"),
    ("a failed KEV lookup becomes an empty catalogue",
     'kev_map, kev_note = None, f"the KEV catalogue lookup failed: {err}"', 'kev_map, kev_note = {}, f"the KEV catalogue lookup failed: {err}"'),
    ("ignore the version range when picking the fixed version",
     "if k is None or k <= mine or (start is not None and mine < start):", "if k is None:"),
    ("accept a garbled NVD answer",
     '        raise ParseError("the NVD answer has no `vulnerabilities` list and `totalResults` number")', "        return"),
    ("count a platform match as a finding",
     'if not any(m.get("vulnerable") for m in covered):', "if False:"),
    ("count a CVE whose ranges stop short of the version as a finding",
     'if not covered:\n        return "outside-range"', 'if False:\n        return "outside-range"'),
    ("read only the first NVD page",
     'start += len(page["vulnerabilities"])', "start = total"),
]

REALM_MUTANTS = [
    ("a sample user is not required to configure OTP", '"requiredActions": ["CONFIGURE_TOTP"],', '"requiredActions": [],'),
    ("the Configure OTP action is disabled", '"enabled": true, "defaultAction": true', '"enabled": false, "defaultAction": true'),
    ("brute force detection is off", '"bruteForceProtected": true', '"bruteForceProtected": false'),
    ("brute force needs 1000 failures before it locks", '"failureFactor": 5', '"failureFactor": 1000'),
    ("the access token lives a day", '"accessTokenLifespan": 60', '"accessTokenLifespan": 86400'),
    ("a client secret is committed", '"secret": "${CFL_DASHBOARD_CLIENT_SECRET}"', '"secret": "committed-secret-value"'),
    ("the fleet-admin role is gone", '"name": "fleet-admin"', '"name": "fleet-root"'),
    ("fleet-admin no longer includes fleet-viewer", '"composite": true,', '"composite": false,'),
    ("the dashboard client allows the password grant", '"directAccessGrantsEnabled": false', '"directAccessGrantsEnabled": true'),
    ("PKCE is not required", '"pkce.code.challenge.method": "S256"', '"pkce.code.challenge.method": ""'),
    ("the redirect URI is a wildcard", '"http://127.0.0.1:4180/oauth2/callback"', '"http://127.0.0.1:4180/*"'),
    ("the OTP policy is no longer time based", '"otpPolicyType": "totp"', '"otpPolicyType": "hotp"'),
]

HEADERS_MUTANTS = [
    ("the answers are cacheable again", '"Cache-Control": "no-store",', '"Cache-Control": "max-age=3600",'),
    ("script-src allows unsafe-inline again", "script-src {_sources(scripts)}", "script-src 'unsafe-inline' {_sources(scripts)}"),
    ("style-src allows unsafe-inline again", "style-src {_sources(styles)}", "style-src 'unsafe-inline' {_sources(styles)}"),
    ("only the first inline block is hashed",
     "return [csp_hash(b) for b in _INLINE_SCRIPT.findall(html)], [csp_hash(b) for b in _INLINE_STYLE.findall(html)]",
     "return [csp_hash(b) for b in _INLINE_SCRIPT.findall(html)][:1], [csp_hash(b) for b in _INLINE_STYLE.findall(html)][:1]"),
    ("the hash is taken over the stripped text (a browser hashes the exact text)",
     'hashlib.sha256(body.encode("utf-8"))', 'hashlib.sha256(body.strip().encode("utf-8"))'),
    ("the digest is SHA-1", "hashlib.sha256(", "hashlib.sha1("),
    ("a script with a src counts as an inline block", "(?![^>]*\\bsrc\\s*=)", ""),
    ("a page with no inline script allows unsafe-inline", "if hashes else \"'none'\"", "if hashes else \"'unsafe-inline'\""),
    ("a JSON answer gets the page policy",
     'return dashboard_policy if (content_type or "").lower().startswith("text/html") else API_CSP', "return dashboard_policy"),
    ("an HTML answer is no longer recognised", '.startswith("text/html")', '.startswith("text/plain")'),
    ("the allow-nothing policy can be framed", "form-action 'none'; frame-ancestors 'none'\"\n\n# an inline", "form-action 'none'\"\n\n# an inline"),
    ("the nosniff header is dropped", '"X-Content-Type-Options": "nosniff"', '"X-Content-Type-Options": "sniff"'),
    ("the page can be framed", '"X-Frame-Options": "DENY"', '"X-Frame-Options": "SAMEORIGIN"'),
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
    c3, t3 = run_group("cve_triage.py", SECURITY / "vuln" / "cve_triage.py", HERE / "test_cve_triage.py", "CVE_TRIAGE_PATH", CVE_MUTANTS, log)
    c4, t4 = run_group("realm-camera-fleet.json", SECURITY / "iam" / "realm-camera-fleet.json", HERE / "test_iam_realm.py", "REALM_PATH", REALM_MUTANTS, log)
    c5, t5 = run_group("hub/app/headers.py", HUB_APP / "headers.py", HERE / "test_hub_headers.py", "HUB_HEADERS_PATH", HEADERS_MUTANTS, log)
    ok = min(t1, t2, t3, t4, t5) > 0 and c1 == t1 and c2 == t2 and c3 == t3 and c4 == t4 and c5 == t5
    log(f"total: {c1 + c2 + c3 + c4 + c5}/{sum(max(t, 0) for t in (t1, t2, t3, t4, t5))} mutants caught" + ("" if ok else "  (NOT ALL CAUGHT)"))
    if args.save:
        Path(args.save).parent.mkdir(parents=True, exist_ok=True)
        Path(args.save).write_text("\n".join(out) + "\n", encoding="utf-8")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
