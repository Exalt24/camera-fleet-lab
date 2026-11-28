"""Turns the vendor's inconsistent objects into one shape.

The lock objects name the same thing three ways (state / locked / lock_state, battery_level / battery_pct / battery as "62%",
online / connected / 1 or 0) and leave fields out. The rules: a field that is missing or out of range is None (unknown), never 0
and never clipped, and a missing time is None, never 1970.
"""
from __future__ import annotations

from ..util import parse_ts

STATES = ("locked", "unlocked", "jammed")


def norm_state(raw: dict) -> str | None:
    if raw.get("jammed") is True:
        return "jammed"
    for key in ("state", "lock_state"):
        v = raw.get(key)
        if isinstance(v, str) and v.strip().lower() in STATES:
            return v.strip().lower()
    if isinstance(raw.get("locked"), bool):
        return "locked" if raw["locked"] else "unlocked"
    return None


def norm_battery(raw: dict) -> int | None:
    for key in ("battery_level", "battery_pct", "battery"):
        v = raw.get(key)
        if isinstance(v, bool) or v is None:
            continue
        if isinstance(v, str):
            v = v.strip().rstrip("%").strip()
            try:
                v = float(v)
            except ValueError:
                continue
        if isinstance(v, (int, float)) and 0 <= v <= 100:
            return int(round(v))
    return None


def norm_online(raw: dict) -> bool | None:
    for key in ("online", "connected"):
        v = raw.get(key)
        if isinstance(v, bool):
            return v
        if v in (0, 1):
            return bool(v)
        if isinstance(v, str) and v.lower() in ("true", "false"):
            return v.lower() == "true"
    return None


def normalize_lock(raw: dict) -> dict | None:
    if not isinstance(raw, dict) or not raw.get("id"):
        return None
    seq = raw.get("seq")
    return {
        "id": str(raw["id"]),
        "name": str(raw["name"]) if raw.get("name") else None,
        "state": norm_state(raw),
        "battery": norm_battery(raw),
        "online": norm_online(raw),
        "firmware": raw.get("firmware") or raw.get("fw") or None,
        "vendor_updated_at": parse_ts(raw.get("updated_at") if raw.get("updated_at") is not None else raw.get("updated")),
        "seq": seq if isinstance(seq, int) and not isinstance(seq, bool) else None,
    }


def normalize_code(raw: dict) -> dict | None:
    if not isinstance(raw, dict) or not raw.get("id"):
        return None
    starts, ends = parse_ts(raw.get("starts_at")), parse_ts(raw.get("ends_at"))
    status = raw.get("status")
    return {"id": str(raw["id"]), "name": raw.get("name"), "starts_at": starts, "ends_at": ends,
            "status": status if status in ("scheduled", "active", "expired", "revoked") else None, "code": raw.get("code")}
