"""Tests for hub/app/headers.py, the response headers of the hub. Offline and with no FastAPI: the module is pure functions.

A ZAP baseline scan of the lab (docs/vuln-and-iam.md) flagged the dashboard's Content-Security-Policy for `'unsafe-inline'` in script-src and
style-src, and the hub's answers for having no Cache-Control. The tests pin the fix: the policy lists the hash of each inline block and
nothing else, the hash is the one a browser computes, the dashboard has no inline style attribute or event handler (the strict policy would
block them), and every answer is no-store.

The module is loaded from HUB_HEADERS_PATH when set, so run_mutations.py can run these same tests against a copy with one behaviour
removed and require a red run.
    python -m pytest security/tests/test_hub_headers.py -q
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import os
import re
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
DASHBOARD = ROOT / "hub" / "app" / "dashboard.html"
TARGET = Path(os.environ.get("HUB_HEADERS_PATH") or ROOT / "hub" / "app" / "headers.py")

spec = importlib.util.spec_from_file_location("hub_headers_under_test", TARGET)
hh = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = hh
spec.loader.exec_module(hh)

PAGE = "<html><head><style>body{margin:0}</style></head><body><script>const a = 1;\nfetch('/status');</script></body></html>"


def sha256_b64(text: str) -> str:
    return base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")


def directive(policy: str, name: str) -> str:
    for part in policy.split(";"):
        part = part.strip()
        if part.startswith(name + " "):
            return part[len(name) + 1:]
    raise AssertionError(f"no {name} directive in {policy!r}")


def test_a_hash_is_the_sha256_of_the_exact_block_text():
    assert hh.csp_hash("alert(1)") == "'sha256-" + sha256_b64("alert(1)") + "'"
    assert hh.csp_hash("alert(1) ") != hh.csp_hash("alert(1)")      # whitespace is part of what a browser hashes


def test_the_policy_holds_the_hash_of_the_inline_script_and_the_inline_style_and_no_unsafe_inline():
    csp = hh.dashboard_csp(PAGE)
    assert directive(csp, "script-src") == "'sha256-" + sha256_b64("const a = 1;\nfetch('/status');") + "'"
    assert directive(csp, "style-src") == "'sha256-" + sha256_b64("body{margin:0}") + "'"
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp


def test_every_inline_block_is_listed_not_only_the_first():
    html = "<script>one()</script><script>two()</script><style>a{}</style><style>b{}</style>"
    csp = hh.dashboard_csp(html)
    assert directive(csp, "script-src").count("sha256-") == 2 and directive(csp, "style-src").count("sha256-") == 2


def test_a_script_with_a_src_is_not_an_inline_block():
    scripts, _ = hh.inline_sources('<script src="/static/app.js"></script><script>real()</script>')
    assert scripts == [hh.csp_hash("real()")]


def test_a_page_with_no_inline_script_or_style_allows_none():
    csp = hh.dashboard_csp("<html><body>plain</body></html>")
    assert directive(csp, "script-src") == "'none'" and directive(csp, "style-src") == "'none'"


def test_the_policy_keeps_the_restrictions_that_were_already_there():
    csp = hh.dashboard_csp(PAGE)
    assert directive(csp, "default-src") == "'none'"
    assert directive(csp, "frame-ancestors") == "'none'" and directive(csp, "base-uri") == "'none'" and directive(csp, "form-action") == "'none'"
    assert directive(csp, "connect-src") == "'self'"


def test_a_json_answer_gets_the_allow_nothing_policy_and_an_html_one_gets_the_dashboard_policy():
    dash = hh.dashboard_csp(PAGE)
    assert hh.csp_for("application/json", dash) == hh.API_CSP
    assert hh.csp_for(None, dash) == hh.API_CSP
    assert hh.csp_for("text/html; charset=utf-8", dash) == dash
    assert "script-src" not in hh.API_CSP and "frame-ancestors 'none'" in hh.API_CSP


def test_every_answer_is_no_store():
    assert hh.BASE_HEADERS["Cache-Control"] == "no-store"


def test_the_nine_headers_of_the_first_fix_are_still_set():
    for name in ("X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Permissions-Policy", "Cross-Origin-Opener-Policy",
                 "Cross-Origin-Resource-Policy", "Cross-Origin-Embedder-Policy", "X-Permitted-Cross-Domain-Policies"):
        assert name in hh.BASE_HEADERS, name
    assert hh.BASE_HEADERS["X-Content-Type-Options"] == "nosniff" and hh.BASE_HEADERS["X-Frame-Options"] == "DENY"


# --- the real dashboard page: the strict policy blocks inline attributes and handlers, so the page must not have any
DASH_HTML = DASHBOARD.read_text(encoding="utf-8")


def test_the_dashboard_has_no_inline_style_attribute():
    assert not re.search(r"<[a-zA-Z][^>]*\sstyle\s*=", DASH_HTML), "an inline style attribute would be blocked by style-src"


def test_the_dashboard_has_no_inline_event_handler_attribute_and_no_javascript_url():
    assert not re.search(r"<[a-zA-Z][^>]*\son[a-z]+\s*=", DASH_HTML), "an inline handler would be blocked by script-src"
    assert "javascript:" not in DASH_HTML.lower()


def test_the_dashboard_script_does_not_set_a_style_attribute_by_string():
    assert "setAttribute(\"style\"" not in DASH_HTML and "setAttribute('style'" not in DASH_HTML


def test_the_real_dashboard_policy_holds_one_script_hash_and_one_style_hash():
    csp = hh.dashboard_csp(DASH_HTML)
    assert directive(csp, "script-src").count("sha256-") == 1 and directive(csp, "style-src").count("sha256-") == 1
    assert "unsafe-inline" not in csp
