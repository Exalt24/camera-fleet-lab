"""Table tests for webhook signature and replay window verification (iot/iotlab/connector/webhook.py)."""
from __future__ import annotations

import hmac

import pytest

from iotlab.connector import webhook
from iotlab.connector.webhook import WebhookRejected, verify
from iotlab.vendor_cloud import sign

SECRET = "whsec_unit-test-secret"
NOW = 1_800_000_000
BODY = b'{"id":"evt_1","type":"lock.unlocked"}'


def headers(ts=NOW, secret=SECRET, body=BODY, sig=None, **extra):
    h = {"X-Vendor-Timestamp": str(ts), "X-Vendor-Signature": sig if sig is not None else sign(secret, ts, body)}
    h.update(extra)
    return h


def reason(**kw) -> str:
    h = kw.pop("h", None) or headers()
    body = kw.pop("body", BODY)
    with pytest.raises(WebhookRejected) as exc:
        verify(SECRET, h, body, kw.pop("now", NOW), **kw)
    return exc.value.reason


def test_a_genuine_fresh_request_is_accepted_and_returns_its_timestamp():
    assert verify(SECRET, headers(), BODY, NOW) == NOW


@pytest.mark.parametrize("drop", ["X-Vendor-Timestamp", "X-Vendor-Signature"])
def test_a_missing_header_is_rejected(drop):
    h = headers()
    del h[drop]
    assert reason(h=h) == "missing_headers"


@pytest.mark.parametrize("ts", ["abc", "-5", "1.5e9", "1800000000.5", " ", "0x10"])
def test_a_timestamp_that_is_not_whole_seconds_is_rejected(ts):
    h = {"X-Vendor-Timestamp": ts, "X-Vendor-Signature": sign(SECRET, NOW, BODY)}
    assert reason(h=h) == "malformed_timestamp"


def test_a_wrong_secret_is_a_bad_signature():
    assert reason(h=headers(secret="whsec_someone-else")) == "bad_signature"


def test_a_changed_body_is_a_bad_signature():
    assert reason(body=BODY.replace(b"unlocked", b"locked")) == "bad_signature"


def test_the_timestamp_is_part_of_what_is_signed():
    # a signature made for one timestamp cannot be reused with another, so the replay window cannot be dodged by editing the header
    h = headers()
    h["X-Vendor-Timestamp"] = str(NOW + 1)
    assert reason(h=h) == "bad_signature"


@pytest.mark.parametrize("offset,ok", [(0, True), (-299, True), (-300, True), (-301, False), (299, True), (300, True), (301, False), (-86400, False), (86400, False)])
def test_the_replay_window_is_symmetric_and_includes_its_edge(offset, ok):
    ts = NOW + offset
    h = headers(ts=ts)
    if ok:
        assert verify(SECRET, h, BODY, NOW) == ts
    else:
        assert reason(h=h) == "stale_timestamp"


def test_a_custom_tolerance_is_honoured():
    h = headers(ts=NOW - 11)
    assert reason(h=h, tolerance=10) == "stale_timestamp"
    assert verify(SECRET, h, BODY, NOW, tolerance=11) == NOW - 11


def test_an_unsigned_old_request_learns_nothing_about_the_window():
    # the signature is checked before the window, so a forged stale request is a bad_signature, never a stale_timestamp
    h = {"X-Vendor-Timestamp": str(NOW - 99999), "X-Vendor-Signature": "v1=" + "0" * 64}
    assert reason(h=h) == "bad_signature"


@pytest.mark.parametrize("make,ok", [
    (lambda good: f"v1={'0' * 64} {good}", True),                 # two values: a rotation, the second is the live one
    (lambda good: f"{good},v1={'0' * 64}", True),                 # comma separated, the first is the live one
    (lambda good: f"v1={'0' * 64}", False),
    (lambda good: "v0=" + good[3:], False),                       # a scheme we do not speak
    (lambda good: "v1=", False),
    (lambda good: good[3:], False),                               # the digest without its scheme prefix
    (lambda good: good.upper(), False),                           # hex compared case sensitively is fine, a changed digest is not accepted
])
def test_signature_header_forms(make, ok):
    good = sign(SECRET, NOW, BODY)
    h = {"X-Vendor-Timestamp": str(NOW), "X-Vendor-Signature": make(good)}
    if ok:
        assert verify(SECRET, h, BODY, NOW) == NOW
    else:
        assert reason(h=h) == "bad_signature"


def test_header_names_are_case_insensitive():
    h = {"x-vendor-timestamp": str(NOW), "X-VENDOR-SIGNATURE": sign(SECRET, NOW, BODY)}
    assert verify(SECRET, h, BODY, NOW) == NOW


def test_the_signature_is_compared_in_constant_time(monkeypatch):
    calls = []
    real = hmac.compare_digest
    monkeypatch.setattr(webhook.hmac, "compare_digest", lambda a, b: (calls.append(1), real(a, b))[1])
    verify(SECRET, headers(), BODY, NOW)
    assert calls, "the digest must be compared with hmac.compare_digest"
