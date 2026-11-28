"""Credential vault, the third party record's own rules, field normalisation and the secret-safe logger."""
from __future__ import annotations

import logging
import os
import sqlite3

import pytest

from iotlab.connector import safelog
from iotlab.connector.crypto import CredentialVault, VaultError, generate_key, load_or_create_key
from iotlab.connector.normalize import normalize_code, normalize_lock
from iotlab.connector.store import Store
from iotlab.util import parse_ts


# ---- the vault -------------------------------------------------------------------------------------------------------------------
def test_a_value_round_trips_and_the_ciphertext_does_not_contain_it():
    v = CredentialVault(generate_key())
    token = v.encrypt("rt_super-secret-refresh-token")
    assert "super-secret" not in token and token != "rt_super-secret-refresh-token"
    assert v.decrypt(token) == "rt_super-secret-refresh-token"


def test_two_encryptions_of_one_value_differ():
    v = CredentialVault(generate_key())
    assert v.encrypt("same") != v.encrypt("same")


def test_the_wrong_key_cannot_read_a_value():
    a, b = CredentialVault(generate_key()), CredentialVault(generate_key())
    with pytest.raises(VaultError):
        b.decrypt(a.encrypt("x"))


def test_a_tampered_ciphertext_is_refused():
    v = CredentialVault(generate_key())
    token = v.encrypt("x")
    with pytest.raises(VaultError):
        v.decrypt(token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB"))


def test_key_rotation_reads_the_old_and_writes_the_new():
    old, new = generate_key(), generate_key()
    written_under_old = CredentialVault(old).encrypt("kept")
    both = CredentialVault([new, old])
    assert both.decrypt(written_under_old) == "kept"                 # the old value is still readable
    rotated = both.rotate(written_under_old)
    assert CredentialVault(new).decrypt(rotated) == "kept"           # and re-encrypted under the new key alone
    with pytest.raises(VaultError):
        CredentialVault(old).decrypt(rotated)                         # the old key no longer opens it


@pytest.mark.parametrize("keys", ["", [], ",,", "   "])
def test_no_key_is_an_error_not_a_silent_default(keys):
    with pytest.raises(VaultError):
        CredentialVault(keys)


def test_a_malformed_key_is_an_error():
    with pytest.raises(VaultError):
        CredentialVault("not-a-fernet-key")


def test_comma_separated_keys_work():
    a, b = generate_key(), generate_key()
    assert CredentialVault(f"{a}, {b}").decrypt(CredentialVault(b).encrypt("x")) == "x"


def test_key_file_is_created_once_and_reused(tmp_path):
    p = tmp_path / "state" / "k.key"
    first = load_or_create_key(p)
    assert load_or_create_key(p) == first
    CredentialVault(first)                                             # a usable key
    if os.name == "posix":
        assert (p.stat().st_mode & 0o777) == 0o600, "the key file must be readable by its owner only"


# ---- the record ------------------------------------------------------------------------------------------------------------------
def test_an_event_id_can_be_recorded_once(tmp_path):
    s = Store(str(tmp_path / "t.db"))
    assert s.insert_event("evt_1", "l1", "lock.locked", 1.0, 2.0, 1, "webhook") is True
    assert s.insert_event("evt_1", "l1", "lock.locked", 1.0, 3.0, 1, "poll") is False
    assert s.count_events() == 1 and s.count_events("webhook") == 1 and s.count_events("poll") == 0


def test_only_a_pending_command_is_settled(tmp_path):
    s = Store(str(tmp_path / "t.db"))
    s.put_command("c1", "l1", "unlock", "pending", 1.0)
    assert s.settle_command("c1", "confirmed", "mqtt", 2.0) is True
    assert s.settle_command("c1", "failed", "poll", 3.0) is False, "a late echo must not rewrite a known result"
    row = s.get_command("c1")
    assert (row["status"], row["confirmed_by"]) == ("confirmed", "mqtt")


def test_a_failed_transaction_rolls_back(tmp_path):
    s = Store(str(tmp_path / "t.db"))
    with pytest.raises(RuntimeError):
        with s.transaction():
            s.insert_event("evt_9", "l1", "t", 1.0, 1.0, 1, "poll")
            raise RuntimeError("boom")
    assert s.count_events() == 0


def test_unknown_columns_are_refused(tmp_path):
    s = Store(str(tmp_path / "t.db"))
    with pytest.raises(ValueError):
        s.update_lock("l1", nonsense=1)
    with pytest.raises(ValueError):
        s.update_code("x", nonsense=1)


def test_the_oauth_row_is_written_whole(tmp_path):
    s = Store(str(tmp_path / "t.db"))
    s.set_oauth("A1", "R1", 100.0, "locks:read", 1.0)
    s.set_oauth("A2", "R2", 200.0, "locks:read", 2.0)
    row = s.get_oauth()
    assert (row["access_token_enc"], row["refresh_token_enc"], row["expires_at"]) == ("A2", "R2", 200.0)


# ---- normalisation: three shapes of one lock and the ways a field goes missing --------------------------------------------------------
SHAPES = [
    ({"id": "a", "name": "A", "state": "LOCKED", "battery_level": 87, "firmware": "1.4.2", "online": True, "updated_at": 1_700_000_000, "seq": 3},
     dict(state="locked", battery=87, online=True, firmware="1.4.2", vendor_updated_at=1_700_000_000.0, seq=3)),
    ({"id": "b", "name": "B", "locked": False, "battery_pct": 15, "connected": False, "updated_at": "2026-11-28T10:00:00Z"},
     dict(state="unlocked", battery=15, online=False, firmware=None, vendor_updated_at=parse_ts("2026-11-28T10:00:00Z"), seq=None)),
    ({"id": "c", "name": "C", "lock_state": "locked", "battery": "62%", "online": 1, "fw": "2.0", "updated": "2026-11-28T10:00:00+08:00"},
     dict(state="locked", battery=62, online=True, firmware="2.0", vendor_updated_at=parse_ts("2026-11-28T10:00:00+08:00"), seq=None)),
]


@pytest.mark.parametrize("raw,want", SHAPES, ids=["shape a", "shape b", "shape c"])
def test_each_vendor_shape_becomes_one_shape(raw, want):
    got = normalize_lock(raw)
    for k, v in want.items():
        assert got[k] == v, k


@pytest.mark.parametrize("battery,want", [("62%", 62), (" 62 % ", 62), (62.4, 62), (0, 0), (100, 100), (101, None), (-1, None), ("abc", None),
                                           (True, None), (None, None), ("", None), ("150%", None), ([], None)])
def test_a_battery_reading_is_unknown_when_it_cannot_be_trusted(battery, want):
    assert normalize_lock({"id": "x", "battery": battery})["battery"] == want


def test_a_missing_battery_is_unknown_not_zero():
    assert normalize_lock({"id": "x", "state": "locked"})["battery"] is None


@pytest.mark.parametrize("raw,want", [({"state": "UNLOCKED"}, "unlocked"), ({"state": " Jammed "}, "jammed"), ({"lock_state": "locked"}, "locked"),
                                       ({"locked": True}, "locked"), ({"locked": False}, "unlocked"), ({"locked": False, "jammed": True}, "jammed"),
                                       ({"state": "ajar"}, None), ({"state": None}, None), ({"locked": "yes"}, None), ({}, None)])
def test_state_spellings(raw, want):
    assert normalize_lock({"id": "x", **raw})["state"] == want


@pytest.mark.parametrize("raw,want", [({"online": True}, True), ({"online": False}, False), ({"connected": 1}, True), ({"online": 0}, False),
                                       ({"online": "true"}, True), ({"online": "FALSE"}, False), ({"online": "maybe"}, None), ({}, None), ({"online": 2}, None)])
def test_online_spellings(raw, want):
    assert normalize_lock({"id": "x", **raw})["online"] == want


@pytest.mark.parametrize("value,want", [(1_700_000_000, 1_700_000_000.0), ("1700000000", 1_700_000_000.0), ("2026-11-28T10:00:00Z", 1795860000.0),
                                         ("2026-11-28T10:00:00", 1795860000.0), ("", None), (0, None), (-5, None), ("garbage", None), (None, None), (True, None)])
def test_a_time_is_epoch_seconds_or_unknown_never_1970(value, want):
    assert parse_ts(value) == want


@pytest.mark.parametrize("raw", [None, "x", [], {}, {"name": "no id"}, {"id": ""}])
def test_an_object_without_an_id_is_not_a_lock(raw):
    assert normalize_lock(raw) is None
    assert normalize_code(raw) is None


def test_a_code_with_an_unknown_status_is_not_trusted():
    assert normalize_code({"id": "ac_1", "status": "weird"})["status"] is None
    c = normalize_code({"id": "ac_1", "status": "active", "starts_at": 1_700_000_000, "ends_at": "2026-11-28T10:00:00Z"})
    assert c["starts_at"] == 1_700_000_000.0 and c["ends_at"] == 1795860000.0


# ---- the logger -----------------------------------------------------------------------------------------------------------------------
def test_a_registered_secret_is_masked_wherever_it_appears():
    safelog.register_secret("sekret-value-123")
    assert "sekret-value-123" not in safelog.redact("token is sekret-value-123 ok, again sekret-value-123")


@pytest.mark.parametrize("text", [
    "Authorization: Bearer abcdefghijklmnop12345", "got at_AbCdEf123456789 back", "refresh rt_ZZZZZZZZZZ11111", "secret whsec_abcdefgh12345",
    "code code_abcdefghij1234", "access_token=abc123xyz", "client_secret: hunter2hunter2", "password=hunter2", "pin=123456",
])
def test_token_shaped_text_is_masked_even_when_unregistered(text):
    out = safelog.redact(text)
    assert safelog.MASK in out
    for leaked in ("abcdefghijklmnop12345", "AbCdEf123456789", "ZZZZZZZZZZ11111", "abcdefgh12345", "abcdefghij1234", "abc123xyz", "hunter2", "123456"):
        assert leaked not in out


def test_ordinary_text_is_left_alone():
    assert safelog.redact("lock lock-1 is unlocked, battery 80") == "lock lock-1 is unlocked, battery 80"


def test_the_logger_masks_arguments_and_tracebacks(caplog):
    safelog.register_secret("tok-ABCDEFGH-9999")
    log = safelog.SafeLogger("lockbridge.test")
    with caplog.at_level(logging.DEBUG, logger="lockbridge.test"):
        log.info("value %s", "tok-ABCDEFGH-9999")
        try:
            raise RuntimeError("failed with tok-ABCDEFGH-9999 inside")
        except RuntimeError:
            log.exception("it broke")
    assert "tok-ABCDEFGH-9999" not in caplog.text
    assert "it broke" in caplog.text and safelog.MASK in caplog.text


def test_a_very_short_value_is_not_registered_as_a_secret():
    safelog.register_secret("ab")
    assert safelog.redact("a lab on a table") == "a lab on a table"


def test_the_encrypted_columns_never_hold_plaintext_on_disk(tmp_path):
    path = tmp_path / "t.db"
    s = Store(str(path))
    v = CredentialVault(generate_key())
    s.set_oauth(v.encrypt("at_PLAINTEXT-ACCESS"), v.encrypt("rt_PLAINTEXT-REFRESH"), 1.0, "x", 1.0)
    s.set_secret("webhook_secret", v.encrypt("whsec_PLAINTEXT-HOOK"))
    s.put_code("ac_1", "l1", "guest", v.encrypt("482913"), 1.0, 2.0, "active", "connector", 1.0)
    s.close()
    raw = b"".join(p.read_bytes() for p in tmp_path.glob("t.db*"))
    for plain in (b"PLAINTEXT-ACCESS", b"PLAINTEXT-REFRESH", b"PLAINTEXT-HOOK", b"482913"):
        assert plain not in raw
    assert sqlite3.connect(str(path)).execute("SELECT count(*) FROM access_codes").fetchone()[0] == 1
