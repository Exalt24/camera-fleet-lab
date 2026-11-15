#!/usr/bin/env python3
"""Prints the counts by risk level and one line per alert type from a zap-baseline JSON report.
    python security/vuln/zap_summary.py docs/security/vuln/zap/zap_hub.json
"""
import json
import sys

ORDER = ("High", "Medium", "Low", "Informational")


def alerts_of(doc: dict) -> list[dict]:
    return [a for site in doc.get("site", []) for a in site.get("alerts", [])]


def risk_of(alert: dict) -> str:
    return alert["riskdesc"].split(" ")[0]


def summarise(doc: dict) -> list[str]:
    alerts = alerts_of(doc)
    by: dict[str, int] = {}
    for a in alerts:
        by[risk_of(a)] = by.get(risk_of(a), 0) + 1
    counts = ", ".join(f"{k} {by[k]}" for k in ORDER if k in by) or "none"
    lines = [f"  ZAP version {doc.get('@version')}, {len(alerts)} alert types: {counts}"]
    lines += [f"  - {a['name']} [{risk_of(a)}], {a.get('count')} instances" for a in alerts]
    return lines


if __name__ == "__main__":
    with open(sys.argv[1], encoding="utf-8") as fh:
        print("\n".join(summarise(json.load(fh))))
