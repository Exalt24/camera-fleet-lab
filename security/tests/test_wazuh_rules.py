"""Checks on the Wazuh decoders and rules.

The first group runs anywhere (no Docker): it reads the XML and checks the rules' own bookkeeping. The second group runs the planted
and benign log files through wazuh-logtest inside the manager container and is skipped when the container is not up
(docker compose -p cfl-sec --profile security up -d).
    python -m pytest security/tests/test_wazuh_rules.py -q
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

SECURITY = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SECURITY))
import logtest_runner  # noqa: E402

RULES = ET.parse(SECURITY / "wazuh" / "camera_fleet_rules.xml").getroot()
DECODERS = (SECURITY / "wazuh" / "camera_fleet_decoders.xml").read_text(encoding="utf-8")
EXPECTED = json.loads((SECURITY / "logs" / "EXPECTED.json").read_text(encoding="utf-8"))
CSF_FUNCTIONS = ("GOVERN", "IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER")


def rules():
    return list(RULES.iter("rule"))


def alerting_rules():
    """Rules that can write an alert: level 3 or more and not marked no_log (the base rules are kept for correlation only)."""
    return [r for r in rules() if int(r.get("level")) >= 3 and r.findtext("options") != "no_log"]


def test_rule_ids_are_unique_and_in_the_100000_range():
    ids = [int(r.get("id")) for r in rules()]
    assert len(ids) == len(set(ids)) and all(100000 <= i <= 199999 for i in ids)


def test_every_rule_has_a_description_and_a_level():
    for r in rules():
        assert (r.findtext("description") or "").strip(), r.get("id")
        assert r.get("level").isdigit()


def test_every_alerting_rule_names_a_nist_csf_function_and_subcategory():
    for r in alerting_rules():
        info = r.findtext("info") or ""
        assert "NIST CSF 2.0" in info and any(f in info for f in CSF_FUNCTIONS), r.get("id")
        assert re.search(r"\b[A-Z]{2}\.[A-Z]{2}-\d{2}\b", info), r.get("id")


def test_mitre_ids_are_well_formed_and_only_on_attacker_behaviour():
    with_mitre = {r.get("id"): [i.text for i in r.iter("id")] for r in rules() if r.find("mitre") is not None}
    for rid, ids in with_mitre.items():
        assert ids and all(re.fullmatch(r"T\d{4}(\.\d{3})?", i) for i in ids), rid
    # outage rules describe operations events, not attacker behaviour: no ATT&CK technique may be claimed for them
    for rid in ("100101", "100102", "100103"):
        assert rid not in with_mitre


def test_rule_references_point_at_rules_that_exist():
    own = {r.get("id") for r in rules()}
    for r in rules():
        for tag in ("if_sid", "if_matched_sid"):
            for el in r.findall(tag):
                for ref in (el.text or "").split(","):
                    ref = ref.strip()
                    if ref.startswith("100"):
                        assert ref in own, (r.get("id"), ref)


def test_frequency_rules_have_a_timeframe_and_the_base_rule_never_writes_an_alert():
    for r in rules():
        if r.get("frequency"):
            assert r.get("timeframe"), r.get("id")
    base = next(r for r in rules() if r.get("id") == "100200")
    # a frequency rule only counts events the manager would alert on (level 3 or more, measured), so the base rule is level 3 and no_log
    assert int(base.get("level")) >= 3 and base.findtext("options") == "no_log"
    assert int(next(r for r in rules() if r.get("id") == "100100").get("level")) == 0


def test_the_firewall_decoder_has_one_field_name_per_capture_group():
    regex = re.search(r"<regex>(.*)</regex>", DECODERS).group(1)
    order = re.search(r"<order>(.*)</order>", DECODERS).group(1).split(",")
    assert len(re.findall(r"\((?!\?)", regex)) == len(order)
    assert "dst_port" in order      # a dynamic field name, so the sweep rule's not_same_field can compare it


def test_the_scenario_files_exist_and_every_alerting_rule_is_planted():
    planted = {r for ids in EXPECTED["planted"].values() for r in ids}
    alerting = {r.get("id") for r in alerting_rules()}
    assert planted == alerting, (planted ^ alerting)
    for name in list(EXPECTED["planted"]) + list(EXPECTED["benign"]):
        assert (SECURITY / "logs" / name).read_text(encoding="utf-8").strip()


def manager_up() -> bool:
    try:
        r = subprocess.run(["docker", "compose", "-p", logtest_runner.DEFAULT_PROJECT, "ps", "-q", "wazuh"], cwd=SECURITY.parent,
                           capture_output=True, text=True, encoding="utf-8", timeout=20)
        return bool(r.stdout.strip())
    except (OSError, subprocess.SubprocessError):
        return False


needs_manager = pytest.mark.skipif(not manager_up(), reason="the Wazuh manager container is not running (docker compose -p cfl-sec --profile security up -d)")


def fired_for(name: str):
    lines = [ln for ln in (SECURITY / "logs" / name).read_text(encoding="utf-8").splitlines() if ln.strip()]
    return logtest_runner.fired(logtest_runner.run_logtest(lines))


@needs_manager
@pytest.mark.parametrize("name", sorted(EXPECTED["planted"]))
def test_the_planted_log_fires_the_expected_rules(name):
    assert fired_for(name) == EXPECTED["planted"][name]


@needs_manager
@pytest.mark.parametrize("name", sorted(EXPECTED["benign"]))
def test_the_benign_log_fires_none_of_the_labs_rules(name):
    assert fired_for(name) == []
