"""Verifying a signed webhook.

The contract (iot/docs/contract.md): the vendor sends X-Vendor-Timestamp (epoch seconds) and X-Vendor-Signature, which holds one or
more `v1=<hex>` values where each is HMAC-SHA256(secret, "<timestamp>.<raw body>"). Several values are allowed so a secret can be
rotated without a gap. The check, in order:

  1. both headers are present and the timestamp is an integer          -> missing_headers / malformed_timestamp
  2. one of the signatures matches, compared in constant time          -> bad_signature
  3. the timestamp is within the tolerance of now, past or future      -> stale_timestamp   (this is the replay window)

The signature is checked before the window so that an unsigned request learns nothing about the window.
"""
from __future__ import annotations

import hashlib
import hmac
from typing import Mapping

TIMESTAMP_HEADER = "x-vendor-timestamp"
SIGNATURE_HEADER = "x-vendor-signature"
DEFAULT_TOLERANCE = 300


class WebhookRejected(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def expected_signature(secret: str, timestamp: str, body: bytes) -> str:
    return hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()


def verify(secret: str, headers: Mapping[str, str], body: bytes, now: float, tolerance: float = DEFAULT_TOLERANCE) -> int:
    """Returns the timestamp when the request is genuine and fresh, otherwise raises WebhookRejected(reason)."""
    lowered = {k.lower(): v for k, v in headers.items()}
    ts_raw, sig_raw = lowered.get(TIMESTAMP_HEADER), lowered.get(SIGNATURE_HEADER)
    if not ts_raw or not sig_raw:
        raise WebhookRejected("missing_headers")
    if not ts_raw.isdigit():
        raise WebhookRejected("malformed_timestamp")
    candidates = [p.strip()[3:] for p in sig_raw.replace(",", " ").split() if p.strip().startswith("v1=")]
    want = expected_signature(secret, ts_raw, body)
    if not any(hmac.compare_digest(c, want) for c in candidates):
        raise WebhookRejected("bad_signature")
    if abs(now - int(ts_raw)) > tolerance:
        raise WebhookRejected("stale_timestamp")
    return int(ts_raw)
