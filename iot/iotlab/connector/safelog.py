"""Logging that cannot leak a credential.

Two layers. The code does not pass tokens or access codes to a log call at all. As a second layer every message goes through
redact(), which masks any value registered as a secret and anything shaped like a bearer token, a vendor token, a webhook
secret or a token or secret query parameter. A traceback is redacted the same way.
"""
from __future__ import annotations

import logging
import re
import threading
import traceback

_secrets: set[str] = set()
_mu = threading.Lock()
MASK = "[redacted]"

_PATTERNS = [
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"\b(?:at|rt|whsec|code)_[A-Za-z0-9_-]{8,}"),
    re.compile(r"(?i)\b(access_token|refresh_token|client_secret|secret|password|pin)\s*[=:]\s*\S+"),
]


def register_secret(value: str | None) -> None:
    """Tell the logger a value is secret (a token, an access code, a webhook secret) so it is masked wherever it appears."""
    if value and len(value) >= 4:
        with _mu:
            _secrets.add(value)


def redact(text: str) -> str:
    with _mu:
        known = sorted(_secrets, key=len, reverse=True)
    for s in known:
        text = text.replace(s, MASK)
    for pat in _PATTERNS:
        text = pat.sub(lambda m: (m.group(1) + "=" + MASK) if m.lastindex else MASK, text)
    return text


class SafeLogger:
    def __init__(self, name: str):
        self._log = logging.getLogger(name)

    def _emit(self, level: int, msg: str, args: tuple, exc: bool = False) -> None:
        if not self._log.isEnabledFor(level):
            return
        text = msg % args if args else msg
        if exc:
            text += "\n" + traceback.format_exc()
        self._log.log(level, "%s", redact(text))

    def debug(self, msg: str, *args) -> None:
        self._emit(logging.DEBUG, msg, args)

    def info(self, msg: str, *args) -> None:
        self._emit(logging.INFO, msg, args)

    def warning(self, msg: str, *args) -> None:
        self._emit(logging.WARNING, msg, args)

    def error(self, msg: str, *args) -> None:
        self._emit(logging.ERROR, msg, args)

    def exception(self, msg: str, *args) -> None:
        self._emit(logging.ERROR, msg, args, exc=True)
