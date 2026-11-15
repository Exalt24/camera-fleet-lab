"""Tests for security/junos_review.py.

The reviewer is checked against sample configurations written from Juniper's public documentation: two clean ones (no finding
allowed) and four with planted faults (every planted fault found exactly once, nothing else reported). Small inline
configurations pin the parser and the corners of each rule. Hostile, empty and garbled input must not raise.

The module under test is loaded from the path in JUNOS_REVIEW_PATH when it is set, so run_mutations.py can point the same tests
at a copy with one rule switched off and require a red run.
    python -m pytest security/tests/test_junos_review.py -q
"""
from __future__ import annotations

import importlib.util
import json
import os
import random
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
SECURITY = HERE.parent
TARGET = Path(os.environ.get("JUNOS_REVIEW_PATH") or SECURITY / "junos_review.py")
SAMPLES = SECURITY / "junos"
EXPECTED = json.loads((SAMPLES / "EXPECTED.json").read_text(encoding="utf-8"))

spec = importlib.util.spec_from_file_location("junos_review_under_test", TARGET)
jr = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = jr
spec.loader.exec_module(jr)


def real(findings):
    return [f for f in findings if f.rule != "JR000"]


def rules_of(text):
    return sorted(f.rule for f in real(jr.review_text(text)))


# --- the sample configurations -----------------------------------------------------------------------------------------

@pytest.mark.parametrize("name", EXPECTED["clean"])
def test_a_clean_configuration_reports_nothing(name):
    found = jr.review_file(SAMPLES / name)
    assert found == [], [f.as_dict() for f in found]


@pytest.mark.parametrize("name", sorted(EXPECTED["planted"]))
def test_every_planted_fault_is_found_and_nothing_else(name):
    found = real(jr.review_file(SAMPLES / name))
    left = list(found)
    for want in EXPECTED["planted"][name]:
        match = [f for f in left if f.rule == want["rule"] and want["statement"] in f.text]
        assert len(match) == 1, f"{name}: expected {want}, got {len(match)} matching finding(s) in {[f.as_dict() for f in found]}"
        left.remove(match[0])
    assert not left, f"{name}: unplanted findings {[f.as_dict() for f in left]}"


def test_every_rule_is_exercised_by_a_planted_fault():
    planted = {w["rule"] for lst in EXPECTED["planted"].values() for w in lst}
    assert planted == {c.__name__.replace("check_", "") for c in jr.RULES}


def test_every_finding_has_severity_line_and_fix():
    for name in EXPECTED["planted"]:
        for f in real(jr.review_file(SAMPLES / name)):
            assert f.severity in jr.SEVERITIES and f.severity != "info"
            assert f.fix.strip() and f.message.strip()
            assert f.line >= 0
            if f.rule not in ("JR015", "JR016"):
                assert f.line > 0 and f.text.startswith("set ")


def test_the_line_points_at_the_statement():
    lines = (SAMPLES / "fault-management-plane.set").read_text(encoding="utf-8").splitlines()
    f = next(x for x in jr.review_file(SAMPLES / "fault-management-plane.set") if x.rule == "JR004" and "telnet" in x.text)
    assert lines[f.line - 1].strip() == "set system services telnet"


# --- the cli -----------------------------------------------------------------------------------------------------------

def run_cli(*args):
    return subprocess.run([sys.executable, str(TARGET), *args], capture_output=True, text=True, encoding="utf-8", timeout=60)


def test_cli_exit_codes_and_json():
    ok = run_cli(str(SAMPLES / "edge-router-clean.set"))
    assert ok.returncode == 0 and "no findings" in ok.stdout
    bad = run_cli(str(SAMPLES / "fault-management-plane.set"), "--format", "json")
    assert bad.returncode == 1
    doc = json.loads(bad.stdout)
    assert len(doc) == 1 and any(f["rule"] == "JR003" for f in next(iter(doc.values())))
    high_only = run_cli(str(SAMPLES / "fault-logging-and-services.set"), "--fail-on", "critical")
    assert high_only.returncode == 0


# --- parser ------------------------------------------------------------------------------------------------------------

def test_quoted_strings_and_set_prefix():
    toks = jr.tokenize('set system root-authentication ssh-ed25519 "ssh-ed25519 AAAA key"')
    assert toks[-1] == "ssh-ed25519 AAAA key" and toks[0] == "set"


def test_unbalanced_quote_does_not_raise():
    assert jr.tokenize('set system host-name "oops')[-1] == "oops"


def test_deactivate_and_delete_remove_statements():
    base = "set system services telnet\n"
    assert "JR004" in rules_of(base + "set system ntp server 1.1.1.1\nset system syslog host 2.2.2.2 any any\n")
    for verb in ("deactivate", "delete"):
        text = base + f"{verb} system services telnet\nset system ntp server 1.1.1.1\nset system syslog host 2.2.2.2 any any\n"
        assert "JR004" not in rules_of(text)


def test_prompt_and_comment_lines_are_ignored_not_reported():
    text = "user@router> show configuration | display set\n## Last commit: today\n# note\nset system ntp server 1.1.1.1\n"
    cfg = jr.parse_config(text)
    assert len(cfg.stmts) == 1 and cfg.unparsed == []


def test_unknown_lines_are_reported_not_dropped():
    found = jr.review_text("set system ntp server 1.1.1.1\nthis is not junos\n")
    note = [f for f in found if f.rule == "JR000"]
    assert note and "skipped" in note[0].message and note[0].line == 2


def test_insert_reorders_terms():
    head = "set firewall family inet filter F term a from source-address 10.0.0.0/8\nset firewall family inet filter F term a then accept\n"
    mid = "set firewall family inet filter F term b from source-address 10.1.0.0/16\nset firewall family inet filter F term b then discard\n"
    tail = "set firewall family inet filter F term z then count z\nset firewall family inet filter F term z then discard\n"
    noise = "set system ntp server 1.1.1.1\nset system syslog host 2.2.2.2 any any\n"
    assert "JR007" in rules_of(head + mid + tail + noise)
    moved = head + mid + "insert firewall family inet filter F term b before term a\n" + tail + noise
    assert "JR007" not in rules_of(moved)


# --- corners of the rules ----------------------------------------------------------------------------------------------

QUIET = "set system ntp server 1.1.1.1\nset system syslog host 2.2.2.2 any any\n"


def test_filter_with_an_except_value_is_not_called_shadowed():
    text = (QUIET + "set firewall family inet filter F term a from source-address 10.0.0.0/8\nset firewall family inet filter F term a then accept\n"
            "set firewall family inet filter F term b from source-address 10.1.0.0/16 except\nset firewall family inet filter F term b then discard\n"
            "set firewall family inet filter F term z then count z\nset firewall family inet filter F term z then log\nset firewall family inet filter F term z then discard\n")
    assert "JR007" not in rules_of(text)


def test_next_term_does_not_shadow():
    text = (QUIET + "set firewall family inet filter F term a then count seen\nset firewall family inet filter F term a then next-term\n"
            "set firewall family inet filter F term b from protocol tcp\nset firewall family inet filter F term b then discard\n")
    assert "JR007" not in rules_of(text)


def test_prefix_list_resolution_drives_the_open_source_check():
    text = (QUIET + "set policy-options prefix-list anyone 0.0.0.0/0\n"
            "set firewall family inet filter M term t from source-prefix-list anyone\nset firewall family inet filter M term t from protocol tcp\n"
            "set firewall family inet filter M term t from destination-port ssh\nset firewall family inet filter M term t then accept\n"
            "set firewall family inet filter M term z then count z\nset firewall family inet filter M term z then log\nset firewall family inet filter M term z then discard\n"
            "set interfaces lo0 unit 0 family inet filter input M\n")
    found = real(jr.review_text(text))
    assert [f.rule for f in found] == ["JR003"] and found[0].severity == "critical"


def test_ssh_from_a_trusted_prefix_is_fine():
    text = (QUIET + "set policy-options prefix-list mgmt 192.0.2.0/24\n"
            "set firewall family inet filter M term t from source-prefix-list mgmt\nset firewall family inet filter M term t from protocol tcp\n"
            "set firewall family inet filter M term t from destination-port ssh\nset firewall family inet filter M term t then accept\n"
            "set firewall family inet filter M term z then count z\nset firewall family inet filter M term z then log\nset firewall family inet filter M term z then discard\n"
            "set interfaces lo0 unit 0 family inet filter input M\n")
    assert rules_of(text) == []


def test_port_ranges_cover_management_ports():
    text = (QUIET + "set firewall family inet filter M term t from protocol tcp\nset firewall family inet filter M term t from destination-port 1-1024\n"
            "set firewall family inet filter M term t then accept\nset firewall family inet filter M term z then count z\n"
            "set firewall family inet filter M term z then log\nset firewall family inet filter M term z then discard\n")
    assert "JR003" in rules_of(text)


def test_bgp_internal_group_needs_no_policy_or_limit_but_needs_auth():
    text = (QUIET + "set protocols bgp group core type internal\nset protocols bgp group core neighbor 10.0.0.2\n")
    assert rules_of(text) == ["JR008"]


def test_bgp_group_level_settings_are_inherited_by_the_neighbour():
    text = (QUIET + "set protocols bgp group g type external\nset protocols bgp group g authentication-key \"k\"\nset protocols bgp group g import i\n"
            "set protocols bgp group g export e\nset protocols bgp group g family inet unicast prefix-limit maximum 10\n"
            "set protocols bgp group g neighbor 192.0.2.9\n"
            "set policy-options policy-statement i term a from route-filter 10.0.0.0/8 orlonger\nset policy-options policy-statement i term a then accept\n"
            "set policy-options policy-statement e term a from route-filter 10.0.0.0/8 orlonger\nset policy-options policy-statement e term a then accept\n")
    assert rules_of(text) == []


def test_authentication_key_chain_counts_as_authentication():
    text = QUIET + "set protocols bgp group g type internal\nset protocols bgp group g authentication-key-chain kc\nset protocols bgp group g neighbor 10.0.0.2\n"
    assert rules_of(text) == []


def test_policy_term_with_a_from_clause_is_not_accept_all():
    text = QUIET + "set policy-options policy-statement p term a from protocol direct\nset policy-options policy-statement p term a then accept\n"
    assert rules_of(text) == []


def test_policy_shadow_by_a_broader_route_filter():
    text = (QUIET + "set policy-options policy-statement p term wide from route-filter 10.0.0.0/8 orlonger\nset policy-options policy-statement p term wide then accept\n"
            "set policy-options policy-statement p term narrow from route-filter 10.1.0.0/16 exact\nset policy-options policy-statement p term narrow then reject\n")
    assert "JR007" in rules_of(text)
    exact_first = (QUIET + "set policy-options policy-statement p term a from route-filter 10.0.0.0/8 exact\nset policy-options policy-statement p term a then accept\n"
                   "set policy-options policy-statement p term b from route-filter 10.1.0.0/16 exact\nset policy-options policy-statement p term b then reject\n")
    assert "JR007" not in rules_of(exact_first)


def test_rtbh_term_with_community_is_fine_and_without_is_not():
    with_c = QUIET + "set policy-options community bh members 65535:666\nset policy-options policy-statement p term t from community bh\nset policy-options policy-statement p term t then next-hop discard\nset policy-options policy-statement p term t then accept\n"
    without = with_c.replace("set policy-options policy-statement p term t from community bh\n", "set policy-options policy-statement p term t from protocol bgp\n")
    assert rules_of(with_c) == []
    assert rules_of(without) == ["JR013"]


def test_static_discard_route_with_community_is_fine():
    text = QUIET + "set routing-options static route 192.0.2.1/32 discard\nset routing-options static route 192.0.2.1/32 community 65535:666\n"
    assert rules_of(text) == []
    assert rules_of(QUIET + "set routing-options static route 192.0.2.1/32 discard\n") == ["JR013"]
    assert rules_of(QUIET + "set routing-options static route 192.0.2.0/24 discard\n") == []


def test_root_with_a_key_is_fine_and_ssh_root_allow_is_not():
    ok = QUIET + 'set system root-authentication ssh-ed25519 "ssh-ed25519 AAAA k"\nset system root-authentication encrypted-password "x"\n'
    assert rules_of(ok) == []
    assert rules_of(ok + "set system services ssh root-login allow\n") == ["JR003", "JR005"]


def test_ntp_peer_counts_and_syslog_file_alone_does_not():
    assert "JR015" not in rules_of("set system ntp peer 1.1.1.1\nset system syslog host 2.2.2.2 any any\n")
    assert "JR016" in rules_of("set system ntp server 1.1.1.1\nset system syslog file messages any notice\n")


def test_final_term_with_a_condition_is_not_a_final_discard():
    text = QUIET + "set firewall family inet filter F term only from protocol tcp\nset firewall family inet filter F term only then count c\nset firewall family inet filter F term only then discard\n"
    assert rules_of(text) == ["JR001"]


def test_old_style_filter_without_a_family_is_read():
    text = QUIET + "set firewall filter log-discard term one then count counter\nset firewall filter log-discard term one then log\nset firewall filter log-discard term one then discard\n"
    assert rules_of(text) == []


# --- hostile, empty and garbled input ----------------------------------------------------------------------------------

def test_empty_input_is_reported_not_judged():
    for text in ("", "\n\n   \n", "# only a comment\n"):
        found = jr.review_text(text)
        assert [f.rule for f in found] == ["JR000"] and "no set statements" in found[0].message


def test_brace_format_is_recognised_and_not_misjudged():
    found = jr.review_text("system {\n    host-name r1;\n}\n")
    assert found and all(f.rule == "JR000" for f in found)
    assert any("display set" in f.fix for f in found)


@pytest.mark.parametrize("payload", [
    "set", "set \n", "set \"", "set system services telnet\x00\x00", "\x00\x01\x02\xff", "set " + "a " * 5000,
    "set firewall family inet filter F term t from destination-port ssh-" + "9" * 400, "set protocols bgp group", "set protocols bgp neighbor",
    "set policy-options policy-statement", "set policy-options policy-statement p term", "insert", "insert a before", "insert x before y z",
    "set firewall family inet filter F term t from source-prefix-list nosuch\nset firewall family inet filter F term t then accept",
    "set firewall family inet filter F term t from source-address not-an-ip\nset firewall family inet filter F term t then accept",
    "set policy-options policy-statement p term t from route-filter 999.0.0.0/8 orlonger\nset policy-options policy-statement p term t then accept\nset policy-options policy-statement p term u from route-filter 10.0.0.0/8 upto /x\nset policy-options policy-statement p term u then accept",
    "set routing-options static route\nset routing-options static route 1.2.3.4/32",
    "set interfaces lo0 unit 0 family inet filter input", "set interfaces", "﻿set system services telnet", "set système services téléphone",
])
def test_hostile_single_inputs_do_not_raise(payload):
    jr.review_text(payload)


def test_a_huge_input_is_refused_not_parsed():
    found = jr.review_text("set system ntp server 1.1.1.1\n" * 400_000)
    assert found and found[0].rule == "JR000" and "larger" in found[0].message


def test_a_very_long_line_is_skipped():
    found = jr.review_text("set system ntp server 1.1.1.1\nset system " + "x" * 5000 + "\n")
    assert any(f.rule == "JR000" and "skipped" in f.message for f in found)


def test_unreadable_path_does_not_raise(tmp_path):
    found = jr.review_file(tmp_path / "missing.set")
    assert found and found[0].rule == "JR000"
    assert jr.review_file(tmp_path)[0].rule == "JR000"          # a directory


def test_random_garbage_never_raises():
    rng = random.Random(1234)
    words = ["set", "system", "services", "telnet", "firewall", "family", "inet", "filter", "term", "from", "then", "accept", "discard",
             "protocols", "bgp", "group", "neighbor", "policy-options", "policy-statement", "route-filter", "10.0.0.0/8", "orlonger",
             "interfaces", "lo0", "unit", "0", "input", "community", "next-hop", "static", "route", "insert", "before", "delete", "deactivate",
             '"', "{", "}", ";", "\x00", "999.1.1.1", "ssh", "1-65535", "except", "[", "]", "/32", "::1/128"]
    for _ in range(400):
        lines = [" ".join(rng.choice(words) for _ in range(rng.randint(0, 12))) for _ in range(rng.randint(0, 25))]
        jr.review_text("\n".join(lines))


def test_findings_are_sorted_worst_first():
    found = real(jr.review_file(SAMPLES / "fault-management-plane.set"))
    order = [jr.SEVERITIES.index(f.severity) for f in found]
    assert order == sorted(order, reverse=True)
