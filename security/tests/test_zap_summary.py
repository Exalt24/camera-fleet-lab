"""Tests for security/vuln/zap_summary.py, which turns a zap-baseline JSON report into the counts written to zap_summary.txt.
The report shape (site, alerts, riskdesc, count) is the one ZAP 2.17.0 wrote in the run saved in docs/security/vuln/zap/.
    python -m pytest security/tests/test_zap_summary.py -q
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
spec = importlib.util.spec_from_file_location("zap_summary_under_test", ROOT / "security" / "vuln" / "zap_summary.py")
zs = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = zs
spec.loader.exec_module(zs)

DOC = {"@version": "2.17.0", "site": [{"alerts": [
    {"name": "CSP: script-src unsafe-inline", "riskdesc": "Medium (High)", "count": "2"},
    {"name": "CSP: style-src unsafe-inline", "riskdesc": "Medium (High)", "count": "2"},
    {"name": "Modern Web Application", "riskdesc": "Informational (Medium)", "count": "2"},
]}]}


def test_counts_are_by_risk_level_in_severity_order():
    lines = zs.summarise(DOC)
    assert lines[0] == "  ZAP version 2.17.0, 3 alert types: Medium 2, Informational 1"
    assert lines[1] == "  - CSP: script-src unsafe-inline [Medium], 2 instances"


def test_a_report_with_no_alerts_says_none_and_a_report_with_no_site_does_not_crash():
    assert zs.summarise({"@version": "2.17.0", "site": [{"alerts": []}]})[0].endswith("0 alert types: none")
    assert zs.summarise({"@version": "2.17.0"})[0].endswith("0 alert types: none")


def test_the_saved_real_report_is_readable_when_present():
    saved = ROOT / "docs" / "security" / "vuln" / "zap" / "zap_hub.json"
    if saved.exists():
        doc = json.loads(saved.read_text(encoding="utf-8"))
        assert zs.summarise(doc)[0].startswith("  ZAP version 2.17.0")
