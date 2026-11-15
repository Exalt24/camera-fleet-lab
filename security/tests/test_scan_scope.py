"""Tests for the scope guard shared by security/vuln/scan.sh (Nuclei) and security/vuln/zap.sh (OWASP ZAP). A scanner may only be pointed at
the lab's own services, so the guard must refuse everything else before Docker is touched. `<script> --check-scope <url>` runs only the
guard and exits 0 (in scope) or 2 (refused). Every case runs against both scripts, and one test requires that they source the one
function in scope_guard.sh instead of keeping a copy each, so the two cannot drift apart.
    python -m pytest security/tests/test_scan_scope.py -q
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
VULN = ROOT / "security" / "vuln"
SCAN = VULN / "scan.sh"
ZAP = VULN / "zap.sh"
SCRIPTS = pytest.mark.parametrize("script", [SCAN, ZAP], ids=["nuclei-scan.sh", "zap.sh"])


def _bash() -> str | None:
    # on Windows the first `bash` on PATH can be the WSL launcher, so prefer Git for Windows' bash
    for cand in (r"C:\Program Files\Git\bin\bash.exe", r"C:\Program Files\Git\usr\bin\bash.exe"):
        if os.path.exists(cand):
            return cand
    return shutil.which("bash")


BASH = _bash()
pytestmark = pytest.mark.skipif(BASH is None, reason="bash is not installed")


def guard(script: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([BASH, str(script), *args], capture_output=True, text=True, encoding="utf-8", timeout=30)


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:8100", "http://127.0.0.1:4180/oauth2/auth", "http://127.5.5.5", "http://localhost:8180/realms/camera-fleet", "http://[::1]:8000",
    "http://172.30.0.10:8000", "http://172.30.0.30:4180", "http://10.50.0.3:8080", "http://10.40.0.2:3306", "http://10.20.0.10:8889", "http://10.8.0.2:8554",
])
@SCRIPTS
def test_loopback_and_lab_addresses_are_in_scope(script, url):
    r = guard(script, "--check-scope", url)
    assert r.returncode == 0, r.stderr


@pytest.mark.parametrize("url", [
    "http://8.8.8.8", "http://1.1.1.1:443", "https://example.com", "http://scanme.nmap.org", "http://192.168.1.10", "http://10.0.0.1", "http://172.17.0.2",
    "http://172.30.1.5", "http://172.30.0.256", "http://10.50.1.1", "http://169.254.169.254/latest/meta-data",
])
@SCRIPTS
def test_everything_outside_the_lab_is_refused_with_exit_2(script, url):
    r = guard(script, "--check-scope", url)
    assert r.returncode == 2 and "refused" in r.stderr, r.stdout + r.stderr


@pytest.mark.parametrize("url", [
    "http://127.0.0.1.evil.example.com",        # a name that starts like a loopback address
    "http://localhost.evil.example.com",
    "http://user@127.0.0.1",                     # credentials: the real host can hide behind the @
    "http://127.0.0.1@8.8.8.8",
    "http://010.050.000.001",                    # leading zeros are octal to some tools: 8.40.0.1
    "http://0x7f.0.0.1", "http://2130706433", "http://127.1",   # other ways to write an address
    "ftp://127.0.0.1", "127.0.0.1:8100", "http://127.0.0.1 http://8.8.8.8", "http://",
])
@SCRIPTS
def test_tricks_for_hiding_an_outside_host_are_refused(script, url):
    assert guard(script, "--check-scope", url).returncode == 2


@SCRIPTS
def test_one_refused_target_stops_the_run_before_docker_is_touched(script):
    r = guard(script, "--check-scope", "http://8.8.8.8", "--project", "does-not-exist")
    assert r.returncode == 2
    assert "docker" not in (r.stdout + r.stderr).lower().replace("refused", "")


@SCRIPTS
def test_a_refused_extra_target_is_refused_even_next_to_a_good_one(script):
    r = guard(script, "--project", "cfl-nonexistent", "--target", "http://127.0.0.1:8100", "--target", "http://8.8.8.8")
    assert r.returncode == 2 and "8.8.8.8" in r.stderr


def test_both_scanners_source_the_one_guard_and_neither_keeps_a_copy():
    guard_src = (VULN / "scope_guard.sh").read_text(encoding="utf-8")
    assert "scope_ok()" in guard_src and "LAB_CIDRS=(" in guard_src
    for script in (SCAN, ZAP):
        text = script.read_text(encoding="utf-8")
        assert 'source "$HERE/scope_guard.sh"' in text, script.name
        assert "scope_ok()" not in text and "LAB_CIDRS=(" not in text and "in_cidr()" not in text, f"{script.name} has its own copy of the guard"


def test_the_zap_script_refuses_a_target_by_hand_before_it_looks_for_containers():
    r = guard(ZAP, "--project", "cfl-nonexistent", "--target", "http://127.0.0.1:8100", "--target", "http://scanme.nmap.org")
    assert r.returncode == 2 and "scanme.nmap.org" in r.stderr and "no lab service" not in r.stderr


def test_the_zap_script_rejects_an_unknown_argument_with_exit_3_and_an_unknown_service_for_only():
    assert guard(ZAP, "--nope").returncode == 3
    assert guard(ZAP, "--project", "cfl-nonexistent", "--only", "keycloak").returncode == 3
