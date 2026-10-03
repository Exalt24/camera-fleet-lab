"""Offline tests for the probe layer: no Docker, no network, no WireGuard. They pin the properties that matter for a
monitor that sits next to a flaky VPN: it must classify correctly, time out instead of hanging, kill what it starts,
and never stall the event loop."""
import asyncio
import json
import sys
import time

import pytest

from app import probe


# ---- wg handshake parsing --------------------------------------------------------------------------------------------
def test_never_handshaken_peer_is_none_not_zero_age():
    # `wg show` prints 0 for a peer that never completed a handshake. Reading that as "0 seconds old" would call a dead
    # tunnel fresh.
    assert probe.parse_latest_handshakes("PEERKEY=\t0\n", now=1000.0) is None


def test_newest_handshake_across_peers_wins():
    text = "AAA=\t900\nBBB=\t990\nCCC=\t0\n"
    assert probe.parse_latest_handshakes(text, now=1000.0) == 10.0


def test_garbage_and_empty_output_are_none():
    assert probe.parse_latest_handshakes("", now=1000.0) is None
    assert probe.parse_latest_handshakes("not a handshake line\n", now=1000.0) is None


# ---- classification: the layers fail differently, so the verdict must too --------------------------------------------
@pytest.mark.parametrize(
    "tunnel_ok,tcp_ok,rtsp_ok,expected",
    [
        (True, True, True, "up"),
        (True, True, False, "degraded"),      # port answers, no video: a camera or encoder problem
        (True, False, False, "blocked"),      # the VPN works, the port does not: NAT rule, firewall or camera off
        (False, False, False, "tunnel_down"), # no packet crosses the VPN at all
        (False, True, True, "tunnel_down"),   # a dead tunnel outranks a stream result that looked fine a moment ago
    ],
)
def test_classify(tunnel_ok, tcp_ok, rtsp_ok, expected):
    assert probe.classify(tunnel_ok, tcp_ok, rtsp_ok) == expected


async def test_a_healthy_tunnel_with_an_old_handshake_is_still_up(monkeypatch):
    """REGRESSION for a real bug in this lab. The first version called the tunnel stale after 30 s on the assumption that
    persistent keepalive refreshes the handshake. It does not: WireGuard re-handshakes about every 120 s, so a healthy
    tunnel's handshake age sits anywhere from 0 to ~3 minutes, and the monitor reported a working camera as down."""
    async def ok_tcp(*a, **k):
        return True, 1.0, None

    async def ok_ffprobe(*a, **k):
        return True, "h264", 640, 360, None

    async def ok_ping(*a, **k):
        return True

    async def old_handshake(*a, **k):
        return 150.0

    monkeypatch.setattr(probe, "tcp_check", ok_tcp)
    monkeypatch.setattr(probe, "ffprobe_rtsp", ok_ffprobe)
    monkeypatch.setattr(probe, "tunnel_ping", ok_ping)
    monkeypatch.setattr(probe, "handshake_age", old_handshake)
    result = await probe.probe_camera("10.8.0.2")
    assert result.state == "up" and result.handshake_age_s == 150.0


async def test_tunnel_ping_false_when_the_command_fails_or_is_missing(monkeypatch):
    async def failed(*a, **k):
        return 1, b"", b"100% packet loss"

    monkeypatch.setattr(probe, "run_cmd", failed)
    assert await probe.tunnel_ping("10.8.0.2") is False

    async def missing(*a, **k):
        raise FileNotFoundError("ping")

    monkeypatch.setattr(probe, "run_cmd", missing)
    assert await probe.tunnel_ping("10.8.0.2") is False


async def test_a_dead_tunnel_skips_the_slow_probes_entirely(monkeypatch):
    """When no packet can cross the VPN there is no point opening a socket or starting ffprobe; doing so just makes every
    cycle wait out two timeouts."""
    calls = []

    async def no_ping(*a, **k):
        return False

    async def spy_tcp(*a, **k):
        calls.append("tcp")
        return True, 1.0, None

    async def spy_ffprobe(*a, **k):
        calls.append("ffprobe")
        return True, "h264", 1, 1, None

    async def none_age(*a, **k):
        return None

    monkeypatch.setattr(probe, "tunnel_ping", no_ping)
    monkeypatch.setattr(probe, "tcp_check", spy_tcp)
    monkeypatch.setattr(probe, "ffprobe_rtsp", spy_ffprobe)
    monkeypatch.setattr(probe, "handshake_age", none_age)
    result = await probe.probe_camera("10.8.0.2")
    assert result.state == "tunnel_down" and calls == []


# ---- ffprobe output --------------------------------------------------------------------------------------------------
def test_parse_ffprobe_reads_codec_and_size():
    out = json.dumps({"streams": [{"codec_name": "h264", "width": 640, "height": 360}]}).encode()
    assert probe.parse_ffprobe(out) == ("h264", 640, 360)


@pytest.mark.parametrize("raw", [b"", b"{}", b'{"streams": []}', b"not json"])
def test_parse_ffprobe_bad_output_is_all_none(raw):
    assert probe.parse_ffprobe(raw) == (None, None, None)


async def test_ffprobe_nonzero_exit_reports_the_last_error_line(monkeypatch):
    async def fake(*args, timeout):
        return 1, b"", b"first line\nConnection refused\n"

    monkeypatch.setattr(probe, "run_cmd", fake)
    ok, codec, _w, _h, err = await probe.ffprobe_rtsp("rtsp://x/y")
    assert not ok and codec is None and err.endswith("Connection refused")


async def test_ffprobe_no_video_stream_is_a_failure_even_with_exit_zero(monkeypatch):
    async def fake(*args, timeout):
        return 0, b'{"streams": []}', b""

    monkeypatch.setattr(probe, "run_cmd", fake)
    ok, *_rest, err = await probe.ffprobe_rtsp("rtsp://x/y")
    assert not ok and "no video stream" in err


# ---- tcp_check -------------------------------------------------------------------------------------------------------
async def test_tcp_check_open_port_ok():
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        ok, ms, err = await probe.tcp_check("127.0.0.1", port, timeout=2.0)
    finally:
        server.close()
        await server.wait_closed()
    assert ok and ms is not None and err is None


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows retries SYNs to a closed local port for about 2 s before failing, so it looks like a timeout; "
           "Linux (where the monitor actually runs, in the container) refuses immediately",
)
async def test_tcp_check_closed_port_is_refused_not_timeout():
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    server.close()
    await server.wait_closed()
    ok, ms, err = await probe.tcp_check("127.0.0.1", port, timeout=2.0)
    assert not ok and ms is None and "timed out" not in err


async def test_tcp_check_blackhole_times_out_with_the_dropped_not_refused_message(monkeypatch):
    # A firewall that DROPS gives no answer at all; that is a different fault from a refusal and needs a different fix.
    async def hang(*a, **k):
        await asyncio.sleep(30)

    monkeypatch.setattr(asyncio, "open_connection", hang)
    start = time.perf_counter()
    ok, ms, err = await probe.tcp_check("10.255.255.1", 8554, timeout=0.3)
    assert not ok and "dropped" in err and time.perf_counter() - start < 2.0


# ---- subprocess discipline -------------------------------------------------------------------------------------------
async def test_run_cmd_kills_the_process_on_timeout():
    holder = {}
    real = asyncio.create_subprocess_exec

    async def spy(*args, **kw):
        proc = await real(*args, **kw)
        holder["proc"] = proc
        return proc

    asyncio.create_subprocess_exec = spy
    try:
        with pytest.raises(asyncio.TimeoutError):
            await probe.run_cmd(sys.executable, "-c", "import time; time.sleep(30)", timeout=0.5)
    finally:
        asyncio.create_subprocess_exec = real
    assert holder["proc"].returncode is not None, "a timed-out subprocess must not be left running"


async def test_event_loop_keeps_ticking_while_a_probe_is_hung(monkeypatch):
    """The reason the probes are async: a camera that never answers must not freeze the API that is reporting on it."""
    async def hung(*a, **k):
        await asyncio.sleep(1.0)
        return False, None, None, None, "hung"

    monkeypatch.setattr(probe, "ffprobe_rtsp", hung)

    async def fast_tcp(*a, **k):
        return True, 1.0, None

    monkeypatch.setattr(probe, "tcp_check", fast_tcp)

    async def no_wg(*a, **k):
        return 2.0

    async def ok_ping(*a, **k):
        return True

    monkeypatch.setattr(probe, "handshake_age", no_wg)
    monkeypatch.setattr(probe, "tunnel_ping", ok_ping)

    ticks = 0

    async def ticker():
        nonlocal ticks
        while True:
            await asyncio.sleep(0.05)
            ticks += 1

    t = asyncio.create_task(ticker())
    result = await probe.probe_camera("10.8.0.2")
    t.cancel()
    assert result.state == "degraded"
    assert ticks >= 15, f"the loop only ticked {ticks} times during a 1 s hung probe: something blocked it"
