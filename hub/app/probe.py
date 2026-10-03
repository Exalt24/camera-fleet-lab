"""Probes for one camera behind a VPN. Every probe is async and has a hard timeout, so a hung camera or a dead tunnel
can never block the event loop that is also serving the API.

Three layers, checked separately because they fail separately and the fix differs:
  tunnel  : when did WireGuard last complete a handshake with the site router (`wg show`)
  tcp     : can we open the RTSP port through the tunnel
  stream  : does ffprobe actually read a video stream over RTSP (a port can answer while the stream is dead)
"""
from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass

# WireGuard re-handshakes about every 120 s while traffic flows, and a session cannot outlive 180 s without one. The
# handshake age of a HEALTHY tunnel therefore cycles from 0 up to roughly 2 to 3 minutes. An earlier version of this
# monitor treated "older than 30 s" as stale on the assumption that persistent keepalive refreshes the handshake. It does
# not (keepalive only holds the NAT mapping open), so a perfectly healthy tunnel was reported down most of the time.
# The age is reported as information; whether the tunnel WORKS is decided by sending a packet through it.
SESSION_LIMIT_S = 180.0


@dataclass
class ProbeResult:
    tunnel_ok: bool
    tcp_ok: bool
    tcp_ms: float | None
    rtsp_ok: bool
    codec: str | None
    width: int | None
    height: int | None
    handshake_age_s: float | None
    state: str
    error: str | None


async def tcp_check(host: str, port: int, timeout: float = 3.0) -> tuple[bool, float | None, str | None]:
    """Open and close a TCP connection. The timeout covers the connect, so a firewall that silently drops (no RST) is
    reported as a timeout instead of hanging the caller."""
    start = time.perf_counter()
    try:
        _reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except asyncio.TimeoutError:
        return False, None, "tcp connect timed out (packets dropped, not refused)"
    except OSError as exc:
        return False, None, f"tcp connect failed: {exc.__class__.__name__}"
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return True, round((time.perf_counter() - start) * 1000, 1), None


async def run_cmd(*args: str, timeout: float) -> tuple[int, bytes, bytes]:
    """Run a subprocess without blocking the loop, and KILL it on timeout. A subprocess left running after its caller
    gave up is how a monitor slowly leaks processes."""
    proc = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise
    return proc.returncode if proc.returncode is not None else -1, out, err


def parse_ffprobe(stdout: bytes) -> tuple[str | None, int | None, int | None]:
    try:
        stream = json.loads(stdout or b"{}")["streams"][0]
        return stream.get("codec_name"), stream.get("width"), stream.get("height")
    except (ValueError, KeyError, IndexError):
        return None, None, None


async def ffprobe_rtsp(url: str, timeout: float = 6.0) -> tuple[bool, str | None, int | None, int | None, str | None]:
    try:
        code, out, err = await run_cmd(
            "ffprobe", "-v", "error", "-rtsp_transport", "tcp", "-select_streams", "v:0",
            "-show_entries", "stream=codec_name,width,height", "-of", "json", url,
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        return False, None, None, None, "ffprobe timed out (no video within the deadline)"
    if code != 0:
        return False, None, None, None, "ffprobe failed: " + (err.decode(errors="replace").strip().splitlines() or ["?"])[-1]
    codec, width, height = parse_ffprobe(out)
    if codec is None:
        return False, None, None, None, "ffprobe returned no video stream"
    return True, codec, width, height, None


def parse_latest_handshakes(text: str, now: float) -> float | None:
    """`wg show wg0 latest-handshakes` prints `<peer public key>\\t<unix seconds>`; 0 means a handshake never happened.
    Returns the age in seconds of the most recent handshake across peers, or None if there has never been one."""
    newest = 0
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].isdigit():
            newest = max(newest, int(parts[1]))
    return None if newest == 0 else max(0.0, now - newest)


async def handshake_age(iface: str = "wg0") -> float | None:
    try:
        code, out, _ = await run_cmd("wg", "show", iface, "latest-handshakes", timeout=3.0)
    except (asyncio.TimeoutError, FileNotFoundError):
        return None
    return parse_latest_handshakes(out.decode(), time.time()) if code == 0 else None


async def tunnel_ping(host: str, timeout: float = 2.0) -> bool:
    """One ICMP echo through the tunnel to the site router. It does not depend on the NAT rule that forwards the camera
    ports, which is exactly why it can separate 'the VPN is down' from 'the VPN is fine but the port is not forwarded'."""
    try:
        code, _out, _err = await run_cmd("ping", "-c", "1", "-W", str(int(timeout)), host, timeout=timeout + 2)
    except (asyncio.TimeoutError, FileNotFoundError):
        return False
    return code == 0


def classify(tunnel_ok: bool, tcp_ok: bool, rtsp_ok: bool) -> str:
    """Layered, because each layer fails for a different reason and the fix differs:
    tunnel_down : a packet cannot cross the VPN at all (WireGuard blocked, keys, endpoint, the 4G link)
    blocked     : the VPN works but the camera port does not answer (NAT/DNAT rule, firewall, camera off)
    degraded    : the port answers but no video decodes (encoder or camera problem, not the network)
    up          : the stream decodes through the tunnel"""
    if not tunnel_ok:
        return "tunnel_down"
    if not tcp_ok:
        return "blocked"
    if not rtsp_ok:
        return "degraded"
    return "up"


async def probe_camera(host: str, rtsp_port: int = 8554, path: str = "cam1") -> ProbeResult:
    age = await handshake_age()
    tunnel_ok = await tunnel_ping(host)
    tcp_ok, tcp_ms, tcp_err = (False, None, None)
    rtsp_ok, codec, width, height, rtsp_err = (False, None, None, None, None)
    if tunnel_ok:
        tcp_ok, tcp_ms, tcp_err = await tcp_check(host, rtsp_port)
        if tcp_ok:
            rtsp_ok, codec, width, height, rtsp_err = await ffprobe_rtsp(f"rtsp://{host}:{rtsp_port}/{path}")
    return ProbeResult(
        tunnel_ok=tunnel_ok, tcp_ok=tcp_ok, tcp_ms=tcp_ms, rtsp_ok=rtsp_ok, codec=codec, width=width, height=height,
        handshake_age_s=None if age is None else round(age, 1), state=classify(tunnel_ok, tcp_ok, rtsp_ok),
        error=("tunnel ping failed: no packet crosses the VPN" if not tunnel_ok else None) or tcp_err or rtsp_err,
    )
