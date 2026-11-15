"""Offline tests for the pieces that feed Wazuh: the fleet exporter, the firewall sensor's line parser and the log generator."""
from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

SECURITY = Path(__file__).resolve().parent.parent


def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, SECURITY / rel)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


fx = load("fleet_exporter_t", "sensors/fleet-exporter/fleet_exporter.py")
fw = load("fw_sensor_t", "sensors/fw-sensor/fw_sensor.py")
gen = load("ssh_auth_gen_t", "simulate/ssh_auth_gen.py")


def row(ts, state, **kw):
    base = {"ts": ts, "camera": "cam1", "state": state, "tunnel_ok": state != "tunnel_down", "tcp_ok": state in ("up", "degraded"),
            "rtsp_ok": state == "up", "handshake_age_s": 5.0, "error": None}
    base.update(kw)
    return base


def test_exporter_writes_only_on_a_state_change():
    rows = [row("2026-11-15T10:00:15", "up"), row("2026-11-15T10:00:10", "blocked"), row("2026-11-15T10:00:05", "up"), row("2026-11-15T10:00:00", "up")]
    out, state, ts = fx.transitions(rows, None, None)
    assert [(r["prev_state"], r["state"]) for r in out] == [("up", "blocked"), ("blocked", "up")]
    assert state == "up" and ts == "2026-11-15T10:00:15"


def test_exporter_first_row_is_a_baseline_and_seen_rows_are_skipped():
    out, state, ts = fx.transitions([row("2026-11-15T10:00:00", "blocked")], None, None)
    assert out == [] and state == "blocked"
    again, state2, _ = fx.transitions([row("2026-11-15T10:00:00", "blocked")], state, ts)
    assert again == [] and state2 == "blocked"


def test_exporter_record_carries_the_fields_the_rules_read():
    out, _, _ = fx.transitions([row("2026-11-15T10:00:05", "tunnel_down", error="no packet crosses the VPN"), row("2026-11-15T10:00:00", "up")], None, None)
    rec = out[0]
    assert rec["source"] == "fleet-monitor" and rec["event"] == "state_transition" and rec["state"] == "tunnel_down" and rec["prev_state"] == "up"
    assert rec["error"] == "no packet crosses the VPN"


def test_firewall_sensor_parses_tcp_udp_and_icmp_lines():
    tcp = fw.parse("IP 10.8.0.1.41234 > 10.8.0.2.22: Flags [S], seq 1234, win 64240, length 0")
    assert tcp == {"chain": "INPUT", "in": "wg0", "src": "10.8.0.1", "dst": "10.8.0.2", "proto": "TCP", "sport": "41234", "dport": "22", "flags": "S"}
    udp = fw.parse("IP 10.8.0.1.5353 > 10.8.0.2.9999: UDP, length 5", "FORWARD")
    assert udp["proto"] == "UDP" and udp["dport"] == "9999" and udp["chain"] == "FORWARD"
    icmp = fw.parse("IP 10.8.0.1 > 10.8.0.2: ICMP echo request, id 1, seq 1, length 64")
    assert icmp["proto"] == "ICMP" and icmp["dport"] == "0"
    assert fw.parse("garbage") is None and fw.parse("IP6 fe80::1 > ff02::1: ICMP6") is None and fw.parse("") is None


def test_firewall_sensor_line_matches_the_decoder_regex():
    line = fw.render(fw.parse("IP 10.8.0.1.41234 > 10.8.0.2.22: Flags [S], seq 1, length 0"), now=1763215321)
    decoder = (SECURITY / "wazuh" / "camera_fleet_decoders.xml").read_text(encoding="utf-8")
    regex = re.search(r"<regex>(.*)</regex>", decoder).group(1)
    m = re.search(regex, line)          # the classes used (\w \S \d) mean the same in Wazuh's regex and in Python's
    assert m and m.groups() == ("DROP", "INPUT", "wg0", "10.8.0.1", "10.8.0.2", "TCP", "41234", "22")


def test_generator_brute_force_has_many_failures_then_one_success():
    name, lines = gen.make("brute-force", "203.0.113.50", seed=7, now=1763215321)
    assert name == "ssh_auth.log"
    fails = [ln for ln in lines if "Failed password" in ln]
    assert len(fails) >= 10 and all("203.0.113.50" in ln for ln in fails)
    assert sum("Accepted password" in ln for ln in lines) == 1
    assert any("invalid user" in ln for ln in fails)
    assert all(re.match(r"^[A-Z][a-z]{2} \d{2} \d{2}:\d{2}:\d{2} edge sshd\[\d+\]: ", ln) for ln in lines)


def test_generator_is_repeatable_for_a_seed_and_varies_between_seeds():
    a = gen.make("brute-force", "203.0.113.50", 7, now=1763215321)
    assert a == gen.make("brute-force", "203.0.113.50", 7, now=1763215321)
    assert a != gen.make("brute-force", "203.0.113.50", 8, now=1763215321)


def test_generator_sweep_hits_many_different_closed_ports_from_one_address():
    name, lines = gen.make("sweep", "203.0.113.77", seed=7, now=1763215321)
    assert name == "sim_firewall.log"
    ports = {re.search(r"dport=(\d+)", ln).group(1) for ln in lines}
    assert len(ports) >= 8 and all("src=203.0.113.77" in ln for ln in lines)


def test_generator_benign_has_one_typo_and_no_burst():
    _, lines = gen.make("benign", "x", 7, now=1763215321)
    assert sum("Failed" in ln for ln in lines) == 1 and sum("Accepted" in ln for ln in lines) == 3


def test_generator_sweep_login_ends_with_a_login_from_the_sweeping_address():
    _, lines = gen.make("sweep-login", "203.0.113.77", 7, now=1763215321)
    assert "fw-sensor" in lines[0] and "Accepted password for deploy from 203.0.113.77" in lines[-1]
