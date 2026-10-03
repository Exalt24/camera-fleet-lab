#!/usr/bin/env python
"""End-to-end proof against the running lab (docker compose up -d --build first).

It does not just check that things answer. It checks the properties the design claims, then BREAKS the network two
different ways and checks the monitor tells the two faults apart, which is the whole point of probing in layers:

  fault A  the VPN drops (WireGuard UDP blocked on the site router)    -> tunnel handshake goes stale
  fault B  the NAT rule disappears (DNAT removed on the site router)   -> tunnel stays FRESH, the port goes silent

Exit code 0 only if every check passes. Writes docs/last_run.json with the measured numbers.
"""
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

API = "http://127.0.0.1:8100"
ROOT = Path(__file__).resolve().parent.parent
RESULTS = []
DNAT = ["-t", "nat", "PREROUTING", "-i", "wg0", "-p", "tcp", "-m", "multiport", "--dports", "8554,8889",
        "-j", "DNAT", "--to-destination", "10.20.0.10"]


def dc(service, *cmd, timeout=30):
    r = subprocess.run(["docker", "compose", "exec", "-T", service, *cmd], cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr).strip()


def api(path):
    try:
        with urllib.request.urlopen(API + path, timeout=5) as resp:
            return json.loads(resp.read())
    except (urllib.error.URLError, OSError, ValueError):
        return None


def check(name, ok, detail=""):
    RESULTS.append({"check": name, "ok": bool(ok), "detail": detail})
    print(("PASS  " if ok else "FAIL  ") + name + (("   [" + detail + "]") if detail else ""))
    return ok


def wait_state(want, timeout, label):
    """Poll /status once a second. Returns (seconds until the state was seen or None, timeline of transitions)."""
    start = time.time()
    timeline, last = [], None
    while time.time() - start < timeout:
        s = api("/status")
        if s:
            key = (s["state"], s["tunnel_ok"], s["tcp_ok"], s["rtsp_ok"])
            if key != last:
                timeline.append({"t": round(time.time() - start, 1), "state": s["state"], "tunnel_ok": s["tunnel_ok"],
                                 "tcp_ok": s["tcp_ok"], "rtsp_ok": s["rtsp_ok"], "handshake_age_s": s["handshake_age_s"],
                                 "error": s["error"]})
                last = key
            if s["state"] == want:
                return round(time.time() - start, 1), timeline
        time.sleep(1)
    return None, timeline


def main():
    print("== steady state ==")
    t_up, _ = wait_state("up", 60, "initial")
    check("monitor reports the camera UP through the tunnel", t_up is not None, f"after {t_up}s" if t_up is not None else "never")
    s = api("/status") or {}
    check("stream decodes: h264 640x360 over RTSP through the tunnel",
          s.get("codec") == "h264" and s.get("resolution") == "640x360", f"{s.get('codec')} {s.get('resolution')}")
    check("a packet crosses the tunnel (ping through WireGuard)", s.get("tunnel_ok") is True)
    # NOTE the handshake age is NOT asserted fresh. WireGuard re-handshakes about every 120 s, so a healthy tunnel's age
    # sits anywhere from 0 to ~3 minutes; the first version of this monitor got that wrong and flagged a working tunnel.
    check("the handshake age is within WireGuard's session limit (180 s)", (s.get("handshake_age_s") or 999) <= 180, f"{s.get('handshake_age_s')}s")

    print("== the camera is reachable ONLY through the tunnel ==")
    rc, out = dc("hub", "nc", "-z", "-w", "3", "10.20.0.10", "8554")
    check("hub cannot reach the camera's own address directly (no route to the site network)", rc != 0, out[:80])
    rc, _ = dc("hub", "nc", "-z", "-w", "3", "10.8.0.2", "8554")
    check("hub reaches RTSP via the edge's tunnel address (DNAT)", rc == 0)
    rc, out = dc("hub", "curl", "-sL", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "5", "http://10.8.0.2:8889/cam1")
    check("WebRTC signalling page is served through the tunnel (HTTP 200)", out.strip() == "200", out.strip())

    print("== the firewall allows only what the design needs ==")
    rc, _ = dc("hub", "nc", "-z", "-w", "3", "10.8.0.2", "22")
    check("a non-forwarded port (22) on the edge is silently dropped", rc != 0)
    rc, _ = dc("hub", "ping", "-c", "1", "-W", "2", "10.8.0.2")
    check("ICMP across the tunnel is allowed", rc == 0)

    print("== persistence and the connection pool ==")
    # Poll instead of reading once: right after a cold start the monitor may have stored only one or two probes yet, and a
    # one-shot read made this check flaky on a fresh clone (it passed on the next run with the same code).
    hist = []
    for _ in range(30):
        hist = api("/history?limit=20") or []
        if len(hist) >= 3:
            break
        time.sleep(1)
    check("probe history is stored in MariaDB", len(hist) >= 3, f"{len(hist)} rows")
    pool = api("/pool") or {}
    check("the pool is configured and not exhausted", pool.get("size") == 5 and pool.get("checked_out", 99) <= 1, json.dumps(pool))

    print("== fault A: the VPN drops (WireGuard UDP blocked on the site router) ==")
    dc("edge", "iptables", "-I", "OUTPUT", "1", "-p", "udp", "--dport", "51820", "-j", "DROP")
    t_down_a, tl_a = wait_state("tunnel_down", 90, "A down")
    check("fault A is detected as TUNNEL_DOWN (no packet crosses the VPN)", t_down_a is not None, f"after {t_down_a}s")
    stale = max([e["handshake_age_s"] or 0 for e in tl_a] + [0])
    first_error_a = next((e["error"] for e in tl_a if e["state"] == "tunnel_down"), None)
    dc("edge", "iptables", "-D", "OUTPUT", "-p", "udp", "--dport", "51820", "-j", "DROP")
    t_rec_a, _ = wait_state("up", 90, "A recovery")
    check("fault A recovers on its own once the VPN can talk again (keepalive re-handshake)", t_rec_a is not None, f"after {t_rec_a}s")

    print("== fault B: the NAT rule disappears but the tunnel is healthy ==")
    dc("edge", "iptables", "-t", "nat", "-D", *DNAT[2:])
    t_down_b, tl_b = wait_state("blocked", 60, "B blocked")
    s_b = api("/status") or {}
    check("fault B is detected as BLOCKED (the VPN works, the camera port does not)", t_down_b is not None, f"after {t_down_b}s")
    check("fault B is told apart from fault A: packets still cross the tunnel",
          s_b.get("tunnel_ok") is True and s_b.get("state") == "blocked", f"state={s_b.get('state')} tunnel_ok={s_b.get('tunnel_ok')}")
    dc("edge", "iptables", "-t", "nat", "-A", *DNAT[2:])
    t_rec_b, _ = wait_state("up", 60, "B recovery")
    check("fault B recovers once the DNAT rule is restored", t_rec_b is not None, f"after {t_rec_b}s")

    ok = all(r["ok"] for r in RESULTS)
    out = {
        "all_passed": ok, "checks": RESULTS,
        "fault_a": {"detected_after_s": t_down_a, "recovered_after_s": t_rec_a, "max_handshake_age_s": stale,
                    "first_down_error": first_error_a, "timeline": tl_a},
        "fault_b": {"detected_after_s": t_down_b, "recovered_after_s": t_rec_b, "timeline": tl_b},
    }
    (ROOT / "docs").mkdir(exist_ok=True)
    (ROOT / "docs" / "last_run.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print("\n%d/%d checks passed" % (sum(r["ok"] for r in RESULTS), len(RESULTS)))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
