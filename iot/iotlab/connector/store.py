"""The third party record: one small SQLite database holding locks, access codes, events, commands and the OAuth tokens.

Tokens, the webhook secret and access codes are stored only as ciphertext (the values passed in here are already encrypted by the
vault). The events table has the vendor's event id as its primary key, which is what makes a duplicate delivery harmless.
"""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS oauth (
  id INTEGER PRIMARY KEY CHECK (id = 1), access_token_enc TEXT, refresh_token_enc TEXT, expires_at REAL, scope TEXT,
  status TEXT NOT NULL DEFAULT 'ok', last_error TEXT, refreshed_at REAL);
CREATE TABLE IF NOT EXISTS secrets (name TEXT PRIMARY KEY, value_enc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS locks (
  id TEXT PRIMARY KEY, name TEXT, state TEXT NOT NULL DEFAULT 'unknown', online INTEGER, battery INTEGER, battery_low INTEGER,
  firmware TEXT, vendor_updated_at REAL, lock_seq INTEGER NOT NULL DEFAULT 0, synced_at REAL,
  mqtt_state TEXT, mqtt_battery INTEGER, mqtt_online INTEGER, mqtt_seen_at REAL);
CREATE TABLE IF NOT EXISTS access_codes (
  id TEXT PRIMARY KEY, lock_id TEXT NOT NULL, name TEXT, code_enc TEXT, starts_at REAL, ends_at REAL,
  status TEXT NOT NULL, origin TEXT NOT NULL, created_at REAL, revoked_at REAL);
CREATE TABLE IF NOT EXISTS events (
  event_id TEXT PRIMARY KEY, lock_id TEXT, type TEXT, occurred_at REAL, received_at REAL, seq INTEGER, source TEXT);
CREATE TABLE IF NOT EXISTS commands (
  id TEXT PRIMARY KEY, lock_id TEXT NOT NULL, action TEXT NOT NULL, status TEXT NOT NULL, issued_at REAL, confirmed_at REAL, confirmed_by TEXT);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""

LOCK_COLUMNS = {"name", "state", "online", "battery", "battery_low", "firmware", "vendor_updated_at", "lock_seq", "synced_at",
                "mqtt_state", "mqtt_battery", "mqtt_online", "mqtt_seen_at"}
CODE_COLUMNS = {"name", "code_enc", "starts_at", "ends_at", "status", "revoked_at"}


class Store:
    def __init__(self, path: str):
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._mu = threading.RLock()
        with self._mu:
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.executescript(SCHEMA)

    def close(self) -> None:
        with self._mu:
            self._db.close()

    @contextmanager
    def transaction(self):
        with self._mu:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            else:
                self._db.execute("COMMIT")

    def _one(self, sql: str, args: tuple = ()) -> dict | None:
        with self._mu:
            row = self._db.execute(sql, args).fetchone()
        return dict(row) if row else None

    def _all(self, sql: str, args: tuple = ()) -> list[dict]:
        with self._mu:
            return [dict(r) for r in self._db.execute(sql, args).fetchall()]

    def _run(self, sql: str, args: tuple = ()) -> int:
        with self._mu:
            return self._db.execute(sql, args).rowcount

    # -- oauth and secrets ----------------------------------------------------------------------------------------------
    def get_oauth(self) -> dict | None:
        return self._one("SELECT * FROM oauth WHERE id = 1")

    def set_oauth(self, access_enc: str, refresh_enc: str, expires_at: float, scope: str, now: float) -> None:
        """One statement, so a crash cannot leave a new access token with the old refresh token (the old one is already spent)."""
        self._run(
            "INSERT INTO oauth (id, access_token_enc, refresh_token_enc, expires_at, scope, status, last_error, refreshed_at) "
            "VALUES (1, ?, ?, ?, ?, 'ok', NULL, ?) ON CONFLICT(id) DO UPDATE SET access_token_enc=excluded.access_token_enc, "
            "refresh_token_enc=excluded.refresh_token_enc, expires_at=excluded.expires_at, scope=excluded.scope, status='ok', "
            "last_error=NULL, refreshed_at=excluded.refreshed_at",
            (access_enc, refresh_enc, expires_at, scope, now))

    def set_oauth_status(self, status: str | None, error: str | None) -> None:
        self._run("INSERT INTO oauth (id, status) VALUES (1, 'ok') ON CONFLICT(id) DO NOTHING")
        if status is not None:
            self._run("UPDATE oauth SET status = ?, last_error = ? WHERE id = 1", (status, error))
        else:
            self._run("UPDATE oauth SET last_error = ? WHERE id = 1", (error,))

    def set_secret(self, name: str, value_enc: str) -> None:
        self._run("INSERT INTO secrets (name, value_enc) VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET value_enc=excluded.value_enc", (name, value_enc))

    def get_secret(self, name: str) -> str | None:
        row = self._one("SELECT value_enc FROM secrets WHERE name = ?", (name,))
        return row["value_enc"] if row else None

    # -- meta ---------------------------------------------------------------------------------------------------------------
    def meta_get(self, key: str, default: str | None = None) -> str | None:
        row = self._one("SELECT value FROM meta WHERE key = ?", (key,))
        return row["value"] if row else default

    def meta_set(self, key: str, value) -> None:
        self._run("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))

    def meta_incr(self, key: str) -> int:
        with self._mu:
            n = int(self.meta_get(key, "0")) + 1
            self.meta_set(key, n)
            return n

    def meta_prefix(self, prefix: str) -> dict[str, str]:
        return {r["key"][len(prefix):]: r["value"] for r in self._all("SELECT key, value FROM meta WHERE key LIKE ?", (prefix + "%",))}

    # -- locks --------------------------------------------------------------------------------------------------------------
    def get_lock(self, lock_id: str) -> dict | None:
        return self._one("SELECT * FROM locks WHERE id = ?", (lock_id,))

    def list_locks(self) -> list[dict]:
        return self._all("SELECT * FROM locks ORDER BY id")

    def ensure_lock(self, lock_id: str) -> None:
        self._run("INSERT OR IGNORE INTO locks (id, name) VALUES (?, ?)", (lock_id, lock_id))

    def update_lock(self, lock_id: str, **cols) -> None:
        bad = set(cols) - LOCK_COLUMNS
        if bad or not cols:
            raise ValueError(f"unknown lock column {sorted(bad)}")
        self.ensure_lock(lock_id)
        sets = ", ".join(f"{k} = ?" for k in cols)
        self._run(f"UPDATE locks SET {sets} WHERE id = ?", (*cols.values(), lock_id))

    # -- access codes -----------------------------------------------------------------------------------------------------------
    def put_code(self, code_id: str, lock_id: str, name, code_enc, starts_at, ends_at, status: str, origin: str, now: float) -> None:
        self._run("INSERT INTO access_codes (id, lock_id, name, code_enc, starts_at, ends_at, status, origin, created_at) VALUES (?,?,?,?,?,?,?,?,?) "
                  "ON CONFLICT(id) DO NOTHING", (code_id, lock_id, name, code_enc, starts_at, ends_at, status, origin, now))

    def get_code(self, code_id: str) -> dict | None:
        return self._one("SELECT * FROM access_codes WHERE id = ?", (code_id,))

    def list_codes(self, lock_id: str | None = None) -> list[dict]:
        if lock_id:
            return self._all("SELECT * FROM access_codes WHERE lock_id = ? ORDER BY id", (lock_id,))
        return self._all("SELECT * FROM access_codes ORDER BY id")

    def update_code(self, code_id: str, **cols) -> None:
        bad = set(cols) - CODE_COLUMNS
        if bad or not cols:
            raise ValueError(f"unknown code column {sorted(bad)}")
        sets = ", ".join(f"{k} = ?" for k in cols)
        self._run(f"UPDATE access_codes SET {sets} WHERE id = ?", (*cols.values(), code_id))

    # -- events -----------------------------------------------------------------------------------------------------------------
    def insert_event(self, event_id: str, lock_id: str, type_: str, occurred_at, received_at: float, seq, source: str) -> bool:
        """True when the event is new. The primary key refuses a second copy, which is the whole idempotency guard."""
        return self._run("INSERT OR IGNORE INTO events (event_id, lock_id, type, occurred_at, received_at, seq, source) VALUES (?,?,?,?,?,?,?)",
                         (event_id, lock_id, type_, occurred_at, received_at, seq, source)) == 1

    def count_events(self, source: str | None = None, since_received: float = 0) -> int:
        if source:
            row = self._one("SELECT COUNT(*) AS n FROM events WHERE source = ? AND received_at >= ?", (source, since_received))
        else:
            row = self._one("SELECT COUNT(*) AS n FROM events WHERE received_at >= ?", (since_received,))
        return row["n"]

    def max_event_seq(self) -> int:
        row = self._one("SELECT MAX(seq) AS m FROM events")
        return row["m"] or 0

    # -- commands -----------------------------------------------------------------------------------------------------------------
    def put_command(self, command_id: str, lock_id: str, action: str, status: str, now: float) -> None:
        self._run("INSERT INTO commands (id, lock_id, action, status, issued_at) VALUES (?,?,?,?,?) ON CONFLICT(id) DO NOTHING",
                  (command_id, lock_id, action, status, now))

    def get_command(self, command_id: str) -> dict | None:
        return self._one("SELECT * FROM commands WHERE id = ?", (command_id,))

    def settle_command(self, command_id: str, status: str, by: str, now: float) -> bool:
        """Only a pending command is settled, so a late echo cannot overwrite a result that is already known."""
        return self._run("UPDATE commands SET status = ?, confirmed_at = ?, confirmed_by = ? WHERE id = ? AND status = 'pending'",
                         (status, now, by, command_id)) == 1

    def pending_commands(self) -> list[dict]:
        return self._all("SELECT * FROM commands WHERE status = 'pending' ORDER BY issued_at")
