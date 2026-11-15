"""Tests for the scope guard in security/vuln/scan.sh. The scanner may only be pointed at the lab's own services, so the guard must
refuse everything else before Docker is touched. `scan.sh --check-scope <url>` runs only the guard and exits 0 (in scope) or 2 (refused).
    python -m pytest security/tests/test_scan_scope.py -q
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
SCAN = ROOT / "security" / "vuln" / "scan.sh"


def _bash() -> str | None:
    # on Windows the first `bash` on PATH can be the WSL launcher, so prefer Git for Windows' bash
    for cand in (r"C:\Program Files\Git\bin\bash.exe", r"C:\Program Files\Git\usr\bin\bash.exe"):
        if os.path.exists(cand):
            return cand
    return shutil.which("bash")


BASH = _bash()
pytestmark = pytest.mark.skipif(BASH is None, reason="bash is not installed")


def guard(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([BASH, str(SCAN), *args], capture_output=True, text=True, encoding="utf-8", timeout=30)


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:8100", "http://127.0.0.1:4180/oauth2/auth", "http://127.5.5.5", "http://localhost:8180/realms/camera-fleet", "http://[::1]:8000",
    "http://172.30.0.10:8000", "http://172.30.0.30:4180", "http://10.50.0.3:8080", "http://10.40.0.2:3306", "http://10.20.0.10:8889", "http://10.8.0.2:8554",
])
def test_loopback_and_lab_addresses_are_in_scope(url):
    r = guard("--check-scope", url)
    assert r.returncode == 0, r.stderr


@pytest.mark.parametrize("url", [
    "http://8.8.8.8", "http://1.1.1.1:443", "https://example.com", "http://scanme.nmap.org", "http://192.168.1.10", "http://10.0.0.1", "http://172.17.0.2",
    "http://172.30.1.5", "http://172.30.0.256", "http://10.50.1.1", "http://169.254.169.254/latest/meta-data",
])
def test_everything_outside_the_lab_is_refused_with_exit_2(url):
    r = guard("--check-scope", url)
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
def test_tricks_for_hiding_an_outside_host_are_refused(url):
    assert guard("--check-scope", url).returncode == 2


def test_one_refused_target_stops_the_run_before_docker_is_touched():
    r = guard("--check-scope", "http://8.8.8.8", "--project", "does-not-exist")
    assert r.returncode == 2
    assert "docker" not in (r.stdout + r.stderr).lower().replace("refused", "")


def test_a_refused_extra_target_is_refused_even_next_to_a_good_one():
    r = guard("--project", "cfl-nonexistent", "--target", "http://127.0.0.1:8100", "--target", "http://8.8.8.8")
    assert r.returncode == 2 and "8.8.8.8" in r.stderr
