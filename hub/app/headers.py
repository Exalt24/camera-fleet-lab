"""The response headers the hub sets on every answer. Pure functions and constants, no FastAPI, so the policy can be tested on its own.

The dashboard is one HTML file with one inline script and one inline style. Its Content-Security-Policy lists the SHA-256 hash of each
inline block instead of allowing `'unsafe-inline'`, so a script or style injected into the page would not run. The hashes are computed
from the same text the hub serves, so editing the page can never leave the policy stale. Every other answer (JSON) gets a policy that
allows nothing. A ZAP baseline scan flagged the old `'unsafe-inline'` policy, see docs/vuln-and-iam.md.
"""
from __future__ import annotations

import base64
import hashlib
import re

# Set on every answer. `Cache-Control: no-store` is here because /whoami is per user and /status is live: nothing should be reused from a cache.
BASE_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "X-Permitted-Cross-Domain-Policies": "none",
    "Cache-Control": "no-store",
}

API_CSP = "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

# an inline block is a <script> or <style> element with no src; the group is the exact text a browser hashes
_INLINE_SCRIPT = re.compile(r"<script(?![^>]*\bsrc\s*=)[^>]*>(.*?)</script\s*>", re.S | re.I)
_INLINE_STYLE = re.compile(r"<style[^>]*>(.*?)</style\s*>", re.S | re.I)


def csp_hash(body: str) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(body.encode("utf-8")).digest()).decode("ascii") + "'"


def inline_sources(html: str) -> tuple[list[str], list[str]]:
    """The CSP hash of every inline script block and every inline style block in the page."""
    return [csp_hash(b) for b in _INLINE_SCRIPT.findall(html)], [csp_hash(b) for b in _INLINE_STYLE.findall(html)]


def _sources(hashes: list[str]) -> str:
    return " ".join(hashes) if hashes else "'none'"


def dashboard_csp(html: str) -> str:
    scripts, styles = inline_sources(html)
    return (f"default-src 'none'; script-src {_sources(scripts)}; style-src {_sources(styles)}; "
            "img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


def csp_for(content_type: str | None, dashboard_policy: str) -> str:
    """The dashboard's policy for an HTML answer, the allow-nothing policy for everything else."""
    return dashboard_policy if (content_type or "").lower().startswith("text/html") else API_CSP
