"""The REST routes, the WebSocket stream, the display picture and the camera stand in, over real sockets against the host emulation."""
from __future__ import annotations

import json
import math
import struct
import subprocess
import time
import wave

import httpx
import pytest
from conftest import SRC, wait_until
from websockets.sync.client import connect


def status(base):
    return httpx.get(f"{base}/api/status").json()


def post(base, route, body):
    raw = body if isinstance(body, str) else json.dumps(body)
    return httpx.post(f"{base}/api/{route}", content=raw, headers={"Content-Type": "application/json"})


def test_status_has_the_documented_fields(base):
    s = status(base)
    for key in ("t", "id", "occupied", "mode", "active", "color", "brightness", "message", "mic", "uptime_ms", "steps", "greetings", "pressure", "net"):
        assert key in s, key
    assert s["t"] == "status" and s["id"] == "mat-test" and s["color"].startswith("#") and len(s["color"]) == 7


def test_greet_flashes_and_shows_a_message(base):
    before = status(base)["greetings"]
    r = post(base, "greet", "")
    assert r.status_code == 200 and r.json() == {"ok": True, "type": "greet"}
    s = status(base)
    assert s["greetings"] == before + 1 and s["active"] == "greeting" and s["message"]


@pytest.mark.parametrize("mode", ["off", "solid", "breathing", "chase", "rainbow"])
def test_every_led_mode_can_be_set(base, mode):
    assert post(base, "led", {"mode": mode}).status_code == 200
    assert status(base)["mode"] == mode


def test_colour_and_brightness(base):
    assert post(base, "led", {"color": "#12ab34", "brightness": 77}).status_code == 200
    s = status(base)
    assert s["color"] == "#12ab34" and s["brightness"] == 77


@pytest.mark.parametrize(
    "route,body,err",
    [
        ("led", {"mode": "strobe"}, "bad_mode"),
        ("led", {"mode": "greeting"}, "bad_mode"),
        ("led", {"color": "red"}, "bad_color"),
        ("led", {"brightness": 300}, "bad_brightness"),
        ("led", {}, "missing_field"),
        ("message", {"text": "   "}, "bad_text"),
        ("message", {"index": 9}, "bad_index"),
        ("message", {"index": 7}, "bad_index"),
        ("message", {}, "missing_field"),
        ("wifi", {"ssid": "home", "pass": "short"}, "bad_wifi"),
        ("led", "not json", "not_json"),
        ("led", "[1,2]", "not_json"),
    ],
)
def test_bad_commands_are_refused_with_a_reason(base, route, body, err):
    before = status(base)
    r = post(base, route, body)
    assert r.status_code == 400 and r.json() == {"ok": False, "err": err}
    after = status(base)
    for k in ("mode", "color", "brightness", "greetings"):
        assert after[k] == before[k], f"a refused command changed {k}"


def test_a_body_over_the_limit_is_refused(base):
    r = post(base, "message", json.dumps({"text": "x" * 3000}))
    assert r.status_code == 400 and r.json()["err"] == "too_long"
    assert post(base, "greet", "").status_code == 200, "the line protocol to the device logic is still in step after an oversize body"


def test_an_unknown_route_is_404(base):
    assert post(base, "reboot", "{}").status_code == 404
    assert httpx.get(f"{base}/nothing").status_code == 404


def test_custom_message_is_cleaned_and_shown(base):
    assert post(base, "message", {"text": "  Mind   the <step> \"now\" "}).status_code == 200
    assert status(base)["message"] == 'Mind the <step> "now"'


def test_the_wifi_command_never_echoes_the_password(base):
    r = post(base, "wifi", {"ssid": "home", "pass": "correct horse battery"})
    assert r.status_code == 200 and "correct" not in r.text and r.json()["type"] == "wifi"


def test_the_display_is_a_valid_bmp_that_changes_with_the_expression(base):
    def lit(bmp: bytes) -> int:
        off = struct.unpack_from("<I", bmp, 10)[0]
        return sum(bin(b).count("1") for b in bmp[off:])

    post(base, "greet", "")
    happy = httpx.get(f"{base}/api/display")
    assert happy.headers["content-type"] == "image/bmp" and happy.content[:2] == b"BM"
    assert struct.unpack_from("<ii", happy.content, 18) == (128, 48) and len(happy.content) == 14 + 40 + 8 + 16 * 48
    wait_until(lambda: status(base)["active"] != "greeting", timeout=6, what="the greeting to end")
    time.sleep(0.3)
    idle = httpx.get(f"{base}/api/display").content
    assert lit(happy.content) != lit(idle) and lit(idle) > 500


def test_a_step_on_the_mat_is_seen_over_websocket_and_greets(sim, base):
    with connect(f"ws://127.0.0.1:{sim.ws_port}/") as ws:
        first = json.loads(ws.recv(timeout=3))
        assert first["t"] == "status"
        steps = first["steps"]
        assert httpx.post(f"{base}/sim/step", json={"ms": 1200}).status_code == 200
        seen = []
        end = time.time() + 6
        while time.time() < end and not ({"occupied", "empty"} <= {m.get("state") for m in seen if m.get("t") == "presence"}):
            try:
                seen.append(json.loads(ws.recv(timeout=1)))
            except TimeoutError:
                pass
        states = [m["state"] for m in seen if m.get("t") == "presence"]
        assert states[:2] == ["occupied", "empty"], states
        occ = next(m for m in seen if m.get("t") == "presence" and m["state"] == "occupied")
        assert occ["steps"] == steps + 1
        assert any(m.get("t") == "status" and m["active"] == "greeting" for m in seen)


def test_the_stream_carries_mic_and_led_frames_and_takes_commands(sim):
    with connect(f"ws://127.0.0.1:{sim.ws_port}/") as ws:
        ws.recv(timeout=3)
        ws.send(json.dumps({"cmd": "led", "mode": "solid", "color": "#ff0000", "brightness": 255}))
        kinds, frames, reply = set(), [], None
        end = time.time() + 9  # a greeting from an earlier test may still be flashing for up to 2.5 s, and it overrides the mode
        while time.time() < end and not (reply and "mic" in kinds and any(f["px"] == "ff0000" * 24 for f in frames)):
            m = json.loads(ws.recv(timeout=2))
            kinds.add(m.get("t"))
            if m.get("ok") is not None:
                reply = m
            if m.get("t") == "frame":
                frames.append(m)
        assert reply == {"ok": True, "type": "led"}
        assert {"mic", "frame"} <= kinds
        solid = [f for f in frames if f["px"] == "ff0000" * 24]
        assert solid, "after the solid red command a frame of 24 red pixels arrives"
        ws.send("garbage")
        bad = None
        while bad is None:
            m = json.loads(ws.recv(timeout=2))
            if m.get("ok") is False:
                bad = m
        assert bad["err"] == "not_json"


def test_the_microphone_level_reaches_the_stream(sim, base):
    httpx.post(f"{base}/sim/mic", json={"value": 77})
    try:
        with connect(f"ws://127.0.0.1:{sim.ws_port}/") as ws:
            levels = []
            end = time.time() + 4
            while time.time() < end and 77 not in levels:
                m = json.loads(ws.recv(timeout=2))
                if m.get("t") == "mic":
                    levels.append(m["level"])
            assert 77 in levels
    finally:
        httpx.post(f"{base}/sim/mic", json={"value": None})


def test_the_camera_stand_in_serves_real_jpeg_frames_with_correct_framing(base):
    with httpx.stream("GET", f"{base}/stream", timeout=10) as r:
        assert r.headers["content-type"].startswith("multipart/x-mixed-replace; boundary=doormatframe")
        buf = b""
        frames = []
        for chunk in r.iter_bytes():
            buf += chunk
            while True:
                i = buf.find(b"\r\n--doormatframe\r\n")
                if i < 0:
                    break
                j = buf.find(b"\r\n\r\n", i)
                if j < 0:
                    break
                head = buf[i:j].decode()
                n = int(head.split("Content-Length: ")[1].split("\r\n")[0])
                if len(buf) < j + 4 + n:
                    break
                frames.append(buf[j + 4 : j + 4 + n])
                buf = buf[j + 4 + n :]
            if len(frames) >= 3:
                break
    assert len(frames) >= 3
    for f in frames:
        assert f[:2] == b"\xff\xd8" and f[-2:] == b"\xff\xd9"  # a whole JPEG, so Content-Length matched the data
    assert len(set(frames)) == len(frames), "the bar moves, so no two frames are the same"


def test_a_single_capture_is_a_jpeg(base):
    r = httpx.get(f"{base}/capture")
    assert r.headers["content-type"] == "image/jpeg" and r.content[:2] == b"\xff\xd8"


def test_the_page_is_served_from_the_same_origin(base):
    r = httpx.get(f"{base}/")
    assert r.status_code == 200 and "Doormat control" in r.text


def test_the_greeting_sound_is_four_rising_notes_in_a_wav(tmp_path):
    cli = SRC / ".pio" / "build" / "core_cli" / ("program.exe" if __import__("os").name == "nt" else "program")
    wav_path = tmp_path / "greeting.wav"
    out = subprocess.run([str(cli)], input=f"wav {wav_path} 16000\nquit\n", capture_output=True, text=True, encoding="utf-8", timeout=20).stdout
    assert json.loads(out.splitlines()[0]) == {"ok": True, "samples": 10400}
    with wave.open(str(wav_path)) as w:
        assert (w.getnchannels(), w.getsampwidth(), w.getframerate(), w.getnframes()) == (1, 2, 16000, 10400)
        data = struct.unpack("<%dh" % w.getnframes(), w.readframes(w.getnframes()))
    # Rising zero crossings per note window give the pitch: 523, 659, 784 and 1047 Hz.
    windows = [(0, 130), (130, 260), (260, 390), (390, 650)]
    pitches = []
    for a, b in windows:
        seg = data[a * 16 : b * 16]
        crossings = sum(1 for i in range(1, len(seg)) if seg[i - 1] < 0 <= seg[i])
        pitches.append(crossings / ((b - a) / 1000))
    for got, want in zip(pitches, (523, 659, 784, 1047)):
        assert math.isclose(got, want, rel_tol=0.08), (got, want)
    assert max(abs(x) for x in data) <= 12000


def test_a_pretty_printed_body_with_newlines_is_one_command(base):
    r = post(base, "led", '{\r\n  "mode": "chase",\r\n  "brightness": 90\r\n}\r\n')
    assert r.status_code == 200 and r.json() == {"ok": True, "type": "led"}
    s = status(base)
    assert s["mode"] == "chase" and s["brightness"] == 90
