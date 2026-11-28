#!/usr/bin/env python3
# LIFESPAN: permanent (the mutation controls of the doormat firmware logic and its control surface, run before a change to a guard and by CI for the anchors)
"""Mutation controls: every guard in the doormat code is broken, one at a time, and a test must go red.

For each mutant this copies esp32/ to a temp folder, changes ONE thing in ONE file of the copy and runs the tests that are meant to notice:

  unity   a firmware logic file: `pio test -e native -f <suite>` on the copy (needs g++ on PATH; the tests are the Unity suites in test/)
  api     sim_server.py (the host emulation of the REST, WebSocket and MQTT surface): tests/test_sim_api.py
  page    web/index.html: tests/test_web_page.py (Chromium through Playwright)
  mqtt    sim_server.py's MQTT bridge: tests/test_mqtt.py (needs Docker, a real mosquitto broker)

A mutant is CAUGHT when its tests fail. A mutant that leaves them green means a test is missing, and this script exits 1. A mutant that does
not compile or whose anchor text is not in the file is reported as an ERROR (also exit 1), because a renamed line would silently turn a mutant
into a no-op. The unmodified copy is run first for each kind and must be green.

    python tests/run_mutations.py [--group unity|api|page|mqtt|all] [--jobs N] [--only TEXT] [--check-anchors] [--save FILE]
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LIB = "lib/doormat_core/"


@dataclass
class M:
    id: str
    kind: str          # unity, api, page, mqtt
    suite: str         # the Unity suite folder name, or the pytest file
    file: str
    old: str
    new: str
    why: str


MUTANTS: list[M] = [
    # ---- presence ----
    M("presence-band-equal", "unity", "test_presence", LIB + "presence.cpp", "c.offThreshold >= c.onThreshold", "c.offThreshold > c.onThreshold", "an equal on and off threshold is not repaired"),
    M("presence-off-inclusive", "unity", "test_presence", LIB + "presence.cpp", "(raw <= cfg_.offThreshold)", "(raw < cfg_.offThreshold)", "a reading exactly on the off threshold no longer releases"),
    M("presence-on-inclusive", "unity", "test_presence", LIB + "presence.cpp", "(raw >= cfg_.onThreshold)", "(raw > cfg_.onThreshold)", "a reading exactly on the on threshold no longer counts"),
    M("presence-no-forget", "unity", "test_presence", LIB + "presence.cpp", "    pending_ = false;\n    return PresenceEvent::None;", "    return PresenceEvent::None;", "a half finished edge is not forgotten when the reading leaves"),
    M("presence-swapped-debounce", "unity", "test_presence", LIB + "presence.cpp", "occupied_ ? cfg_.debounceOffMs : cfg_.debounceOnMs", "occupied_ ? cfg_.debounceOnMs : cfg_.debounceOffMs", "the two debounce times are swapped"),
    M("presence-debounce-boundary", "unity", "test_presence", LIB + "presence.cpp", "< needed) return PresenceEvent::None;", "<= needed) return PresenceEvent::None;", "the debounce fires one sample late"),
    M("presence-no-last-raw", "unity", "test_presence", LIB + "presence.cpp", "  lastRaw_ = raw;\n", "", "the last reading is not kept"),
    M("presence-on-floor", "unity", "test_presence", LIB + "presence.cpp", "if (c.onThreshold < 2) c.onThreshold = 2;", "if (c.onThreshold < 0) c.onThreshold = 2;", "an on threshold of 0 is accepted"),
    # ---- effects ----
    M("effects-breathing-floor", "unity", "test_effects", LIB + "effects.cpp", "static_cast<uint8_t>(20 + (", "static_cast<uint8_t>(0 + (", "breathing goes fully dark"),
    M("effects-chase-tail", "unity", "test_effects", LIB + "effects.cpp", "{255, 150, 80, 35}", "{255, 150, 80, 0}", "the chase tail loses a pixel"),
    M("effects-chase-speed", "unity", "test_effects", LIB + "effects.cpp", "(tMs / 60) % n", "(tMs / 61) % n", "the chase step is not 60 ms"),
    M("effects-chase-length", "unity", "test_effects", LIB + "effects.cpp", "out[i] = d < 4 ?", "out[i] = d < 3 ?", "the chase tail is a pixel short"),
    M("effects-rainbow-still", "unity", "test_effects", LIB + "effects.cpp", "tMs / 12) & 255", "tMs / 12000) & 255", "the rainbow does not rotate"),
    M("effects-rainbow-saturation", "unity", "test_effects", LIB + "effects.cpp", "hsvToRgb(hue, 255, 255)", "hsvToRgb(hue, 200, 255)", "the rainbow is washed out"),
    M("effects-greeting-phase", "unity", "test_effects", LIB + "effects.cpp", "((tMs / 250) % 2) == 0", "((tMs / 250) % 2) == 1", "the greeting flash starts on white"),
    M("effects-greeting-fade", "unity", "test_effects", LIB + "effects.cpp", "EffectEngine::kGreetingMs - 500;", "EffectEngine::kGreetingMs - 1500;", "the greeting fade starts a second early"),
    M("effects-greeting-end", "unity", "test_effects", LIB + "effects.cpp", "(nowMs - greetingStart_) < kGreetingMs", "(nowMs - greetingStart_) <= kGreetingMs", "the greeting lasts a millisecond too long"),
    M("effects-greeting-as-base", "unity", "test_effects", LIB + "effects.cpp", "if (m != Mode::Greeting) mode_ = m;", "mode_ = m;", "greeting can be set as a base mode"),
    M("effects-mode-list", "unity", "test_effects", LIB + "effects.cpp", "Mode::Chase, Mode::Rainbow};", "Mode::Chase};", "rainbow cannot be selected by name"),
    M("effects-brightness", "unity", "test_effects", LIB + "effects.cpp", "out[i] = scaled(out[i], brightness_);", "out[i] = out[i];", "the brightness setting is not applied"),
    # ---- messages ----
    M("messages-del-char", "unity", "test_messages", LIB + "messages.cpp", "c < 0x20 || c > 0x7E", "c < 0x20 || c > 0x7F", "the DEL character is kept"),
    M("messages-no-trim", "unity", "test_messages", LIB + "messages.cpp", "while (n > 0 && out[n - 1] == ' ') n--;", "", "trailing spaces are kept"),
    M("messages-no-collapse", "unity", "test_messages", LIB + "messages.cpp", "      if (lastSpace) continue;\n", "", "runs of spaces are kept"),
    M("messages-list-limit", "unity", "test_messages", LIB + "messages.cpp", "if (count_ >= kMaxMessages) return false;", "if (count_ > kMaxMessages) return false;", "one message too many is accepted"),
    M("messages-hold", "unity", "test_messages", LIB + "messages.cpp", "(nowMs - shownAt_) < kHoldMs", "(nowMs - shownAt_) <= kHoldMs", "a message stays a millisecond too long"),
    M("messages-rotate-idle", "unity", "test_messages", LIB + "messages.cpp", "if (!occupied || !hasShown_ || count_ == 0) return;", "if (occupied || !hasShown_ || count_ == 0) return;", "rotation runs only on an empty mat"),
    M("messages-rotate-boundary", "unity", "test_messages", LIB + "messages.cpp", "(nowMs - lastChange_) >= kRotateMs", "(nowMs - lastChange_) > kRotateMs", "rotation is a millisecond late"),
    M("messages-select-bound", "unity", "test_messages", LIB + "messages.cpp", "if (index >= count_) return false;", "if (index > count_) return false;", "select accepts the first index past the list"),
    M("messages-select-next", "unity", "test_messages", LIB + "messages.cpp", "  next_ = (index + 1) % count_;", "  next_ = index % count_;", "after select the same message comes round again"),
    # ---- eyes ----
    M("eyes-blink-rate", "unity", "test_eyes", LIB + "eyes.cpp", "nextBlink_ = nowMs + 2000 + rnd() % 3000;\n    } else {", "nextBlink_ = nowMs + 2000 + rnd() % 30000;\n    } else {", "blinks become rare"),
    M("eyes-gaze-range", "unity", "test_eyes", LIB + "eyes.cpp", "rnd() % 13) - 6", "rnd() % 13) - 3", "the gaze leaves its range"),
    M("eyes-happy-cut", "unity", "test_eyes", LIB + "eyes.cpp", "for (int y = cy + 2;", "for (int y = cy + 20;", "happy eyes keep their lower half"),
    M("eyes-no-pupil", "unity", "test_eyes", LIB + "eyes.cpp", "} else if (f.open > 30) {", "} else if (f.open > 130) {", "the pupil is never drawn"),
    M("eyes-happy-end", "unity", "test_eyes", LIB + "eyes.cpp", "static_cast<int32_t>(nowMs - happyUntil_) >= 0", "static_cast<int32_t>(nowMs - happyUntil_) > 0", "the happy face lasts a millisecond too long"),
    # ---- command parser ----
    M("command-brightness-max", "unity", "test_command", LIB + "command.cpp", "br->num > 255", "br->num > 256", "brightness 256 is accepted"),
    M("command-text-and-index", "unity", "test_command", LIB + "command.cpp", "if (t && ix) return ParseError::BadText;", "", "a message with both text and index is accepted"),
    M("command-wifi-short", "unity", "test_command", LIB + "command.cpp", "(pl < 8 || pl > 64)", "(pl < 1 || pl > 64)", "a one character Wi-Fi password is accepted"),
    M("command-ssid-long", "unity", "test_command", LIB + "command.cpp", "sl > 32", "sl > 33", "a 33 character network name is accepted"),
    M("command-unicode-escape", "unity", "test_command", LIB + "command.cpp", "default: return ParseError::NotJson;\n      }\n    }\n    if (n + 1 >= cap)", "default: ch = e; break;\n      }\n    }\n    if (n + 1 >= cap)", "a \\u escape is accepted as text"),
    M("command-body-limit", "unity", "test_command", LIB + "command.cpp", "if (len > kMaxBody)", "if (len > kMaxBody + 100)", "a body over 256 bytes is parsed"),
    M("command-pair-limit", "unity", "test_command", LIB + "command.cpp", "if (*count >= kMaxPairs)", "if (*count > kMaxPairs)", "a ninth key overruns the pair table"),
    M("command-colour-length", "unity", "test_command", LIB + "command.cpp", "strlen(s) != 6", "strlen(s) != 7", "colours must be seven digits"),
    M("command-index-max", "unity", "test_command", LIB + "command.cpp", "ix->num >= static_cast<long>(MessageScheduler::kMaxMessages)", "ix->num > static_cast<long>(MessageScheduler::kMaxMessages)", "message index 8 is accepted"),
    M("command-trailing-junk", "unity", "test_command", LIB + "command.cpp", "      c.skipWs();\n      return c.p == c.end ? ParseError::Ok : ParseError::NotJson;\n    }\n    return ParseError::NotJson;", "      c.skipWs();\n      return ParseError::Ok;\n    }\n    return ParseError::NotJson;", "text after the closing brace is ignored"),
    M("command-route-vs-body", "unity", "test_command", LIB + "command.cpp", "  const char* verb = route;\n  if (!verb) {", "  const char* verb = route;\n  if (!verb || find(pairs, np, \"cmd\")) {", "a cmd field in the body overrides the route"),
    # ---- protocol ----
    M("protocol-truncation", "unity", "test_protocol", LIB + "protocol.cpp", "static_cast<size_t>(w) < cap) ?", "static_cast<size_t>(w) <= cap) ?", "a cut off string is returned as complete"),
    M("protocol-mic-floor", "unity", "test_protocol", LIB + "protocol.cpp", "if (db <= -60.0) return 0;", "if (db <= -50.0) return 0;", "the microphone meter floor moves to -50 dB"),
    M("protocol-escape-backslash", "unity", "test_protocol", LIB + "protocol.cpp", "if (c == '\"' || c == '\\\\') {", "if (c == '\"') {", "a backslash is not escaped in JSON"),
    M("protocol-frame-sampling", "unity", "test_protocol", LIB + "protocol.cpp", "leds[(i * n) / samples]", "leds[i]", "the frame event takes the first pixels instead of spreading"),
    M("protocol-bmp-order", "unity", "test_protocol", LIB + "protocol.cpp", "static_cast<size_t>(h - 1 - y) * rowOut", "static_cast<size_t>(y) * rowOut", "the BMP is upside down"),
    # ---- tones ----
    M("tones-no-fade", "unity", "test_tones", LIB + "tones.cpp", "kFadeMs = 10;", "kFadeMs = 0;", "the notes start with a click"),
    M("tones-length", "unity", "test_tones", LIB + "tones.cpp", "{1047, 260}", "{1047, 261}", "the greeting is a millisecond longer"),
    M("tones-negative-amp", "unity", "test_tones", LIB + "tones.cpp", "if (amp < 0) amp = 0;", "", "a negative amplitude inverts the sound"),
    # ---- the device brain ----
    M("app-first-greeting", "unity", "test_app", LIB + "app.cpp", "if (!hasGreeted_ ||", "if (", "the first step in the first seconds is not greeted"),
    M("app-no-step-count", "unity", "test_app", LIB + "app.cpp", "    steps_++;\n", "", "steps are not counted"),
    M("app-no-rotation", "unity", "test_app", LIB + "app.cpp", "messages_.tick(nowMs, presence_.occupied());", "messages_.tick(nowMs, false);", "messages do not rotate while someone stands there"),
    M("app-no-happy", "unity", "test_app", LIB + "app.cpp", "  eyes_.setHappy(nowMs + EffectEngine::kGreetingMs, nowMs);\n", "", "the face does not turn happy on a greeting"),
    M("app-no-brightness", "unity", "test_app", LIB + "app.cpp", "if (c.hasBrightness) effects_.setBrightness(c.brightness);", "", "a brightness command is ignored"),
    M("app-greet-cooldown-for-requests", "unity", "test_app", LIB + "app.cpp", "greet(nowMs);  // a request", "if (!hasGreeted_ || static_cast<uint32_t>(nowMs - lastGreet_) >= cfg_.greetCooldownMs) greet(nowMs);  // a request", "a greet request is held back by the sensor cooldown"),
    # ---- the host emulation and the page ----
    M("api-body-limit", "api", "tests/test_sim_api.py", "host/sim_server.py", "MAX_BODY = 600", "MAX_BODY = 6000", "an oversize body reaches the line protocol"),
    M("api-clock-moves-on", "api", "tests/test_sim_api.py", "host/sim_server.py", "reply = json.loads(self.core.ask(f\"cmd @T@ {route or '-'} {body}\"))", "reply = json.loads(self.core.ask(f\"cmd 0 {route or '-'} {body}\"))", "commands carry time 0 instead of the device clock"),
    M("api-newlines", "api", "tests/test_sim_api.py", "host/sim_server.py", "body = body.replace(\"\\r\", \" \").replace(\"\\n\", \" \")", "pass", "a newline in a body splits the line protocol"),
    M("api-ws-commands", "api", "tests/test_sim_api.py", "host/sim_server.py", "code, doc = self.command(None, body)\n                    conn.send(json.dumps(doc))", "code, doc = self.command(None, body)", "a WebSocket command gets no answer"),
    M("api-route-whitelist", "api", "tests/test_sim_api.py", "host/sim_server.py", "if route not in (\"greet\", \"led\", \"message\", \"wifi\"):", "if False:", "any REST route is passed to the device"),
    M("api-stream-framing", "api", "tests/test_sim_api.py", "host/sim_server.py", "self.wfile.write(head + jpg)", "self.wfile.write(head + jpg[:-2])", "the MJPEG part is shorter than its Content-Length"),
    M("mqtt-route-whitelist", "mqtt", "tests/test_mqtt.py", "host/sim_server.py", "\"wifi\") else \"unknown\", body)", "\"wifi\") else route, body)", "a topic like `led x` is read as `led`"),
    M("mqtt-no-ack", "mqtt", "tests/test_mqtt.py", "host/sim_server.py", "client.publish(f\"doormat/{self.id}/event/ack\", json.dumps(doc), qos=1)", "pass", "a command over MQTT is never acknowledged"),
    M("mqtt-no-retain", "mqtt", "tests/test_mqtt.py", "host/sim_server.py", "self.core.ask(f\"status @T@ {self.id} {self.net}\"), retain=True)", "self.core.ask(f\"status @T@ {self.id} {self.net}\"), retain=False)", "the status is not retained for late subscribers"),
    M("page-html-injection", "page", "tests/test_web_page.py", "web/index.html", "$('msg').textContent = s.message || '';", "$('msg').innerHTML = s.message || '';", "a message is rendered as HTML"),
    M("page-camera-scheme", "page", "tests/test_web_page.py", "web/index.html", "if (!/^https?:\\/\\//i.test(url)) {", "if (false) {", "a javascript: camera address is loaded"),
    M("page-pressed-state", "page", "tests/test_web_page.py", "web/index.html", "String(btns[i].dataset.mode === s.mode)", "'false'", "the active LED mode is not shown"),
    M("page-wifi-guard", "page", "tests/test_web_page.py", "web/index.html", "if (!ssid) { log('Type the network name first', 'err'); return; }", "", "an empty network name is sent"),
    M("page-brightness-int", "page", "tests/test_web_page.py", "web/index.html", "brightness: parseInt(this.value, 10)", "brightness: this.value", "brightness is sent as a string"),
    M("page-refusal-text", "page", "tests/test_web_page.py", "web/index.html", "log('The board refused it: ' + (res.json.err || 'error'), 'err');", "log('Sent: ' + route, 'ok');", "a refusal is shown as success"),
    M("page-presence-text", "page", "tests/test_web_page.py", "web/index.html", "$('presence').dataset.state = occupied ? 'occupied' : 'empty';", "$('presence').dataset.state = 'empty';", "the presence dot never lights"),
    M("page-mic-meter", "page", "tests/test_web_page.py", "web/index.html", "$('mic').style.width = level + '%';", "$('mic').style.width = (level / 2) + '%';", "the microphone meter shows half the level"),
    M("page-ws-live-state", "page", "tests/test_web_page.py", "web/index.html", "ws.onopen = function () { wsLive = true; setConn('live', 'live'); };", "ws.onopen = function () { wsLive = true; };", "the page never says the stream is live"),
]


def sh_env(**extra) -> dict:
    e = dict(os.environ)
    e.update(extra)
    return e


def copy_tree(dst: Path, with_cli: bool) -> None:
    def ignore(d, names):
        base = Path(d)
        skip = {"__pycache__", ".pytest_cache", ".qemu", "docs", "node_modules"}
        if base == ROOT:
            skip.add(".pio")
        return [n for n in names if n in skip]

    shutil.copytree(ROOT, dst, ignore=ignore)
    if with_cli:
        built = ROOT / ".pio" / "build" / "core_cli"
        if not built.exists():
            raise SystemExit("run `pio run -e core_cli` first: the host tests need the compiled device logic")
        shutil.copytree(built, dst / ".pio" / "build" / "core_cli")


def apply(m: M, tree: Path) -> str | None:
    path = tree / m.file
    text = path.read_text(encoding="utf-8").replace("\r\n", "\n")
    n = text.count(m.old)
    if n != 1:
        return f"anchor found {n} times in {m.file}: {m.old[:60]!r}"
    path.write_text(text.replace(m.old, m.new), encoding="utf-8", newline="\n")
    return None


def run_tests(m: M, tree: Path, broker_json: str | None) -> tuple[int, str]:
    if m.kind == "unity":
        cmd = [sys.executable, "-m", "platformio", "test", "-e", "native", "-f", m.suite]
        env = sh_env()
    else:
        cmd = [sys.executable, "-m", "pytest", "-q", "-x", "-W", "ignore", m.suite]
        env = sh_env(ESP32_SRC=str(tree), ESP32_SHOTS=str(tree / "_shots"), IOT_SRC=str(ROOT.parent / "iot"))
    p = subprocess.run(cmd, cwd=tree, capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, timeout=900)
    return p.returncode, p.stdout + p.stderr


def first_failure(out: str) -> str:
    for ln in out.splitlines():
        if "[FAILED]" in ln:
            return re.sub(r"^.*main\.cpp:\d+: ", "", ln).split(":")[0].strip()
        if ln.startswith("FAILED "):
            return ln.split("::")[-1].split(" ")[0]
    return "a test failed"


def one(m: M, kinds_with_cli: set[str]) -> tuple[M, str, str]:
    tmp = Path(tempfile.mkdtemp(prefix="doormat-mut-"))
    try:
        tree = tmp / "esp32"
        copy_tree(tree, m.kind != "unity")
        err = apply(m, tree)
        if err:
            return m, "ERROR", err
        code, out = run_tests(m, tree, None)
        if code == 0:
            return m, "SURVIVED", "every test still passed"
        failed = ("[FAILED]" in out) or ("FAILED " in out) or (" failed" in out)
        if m.kind == "unity" and not failed and "error:" in out:
            return m, "ERROR", "the mutant did not compile"
        return m, "CAUGHT", first_failure(out)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def baseline(kind: str) -> tuple[bool, str]:
    tmp = Path(tempfile.mkdtemp(prefix="doormat-base-"))
    try:
        tree = tmp / "esp32"
        copy_tree(tree, kind != "unity")
        sample = next(m for m in MUTANTS if m.kind == kind)
        if kind == "unity":
            cmd = [sys.executable, "-m", "platformio", "test", "-e", "native"]
            env = sh_env()
        else:
            cmd = [sys.executable, "-m", "pytest", "-q", "-x", "-W", "ignore"] + sorted({m.suite for m in MUTANTS if m.kind == kind})
            env = sh_env(ESP32_SRC=str(tree), ESP32_SHOTS=str(tree / "_shots"), IOT_SRC=str(ROOT.parent / "iot"))
        p = subprocess.run(cmd, cwd=tree, capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, timeout=900)
        tail = [ln for ln in (p.stdout + p.stderr).splitlines() if ln.strip()][-1:]
        return p.returncode == 0, (tail[0] if tail else "no output")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--group", default="all", choices=["unity", "api", "page", "mqtt", "all"])
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--only")
    ap.add_argument("--check-anchors", action="store_true", help="only check that every mutant still applies to the code")
    ap.add_argument("--save")
    a = ap.parse_args()
    chosen = [m for m in MUTANTS if (a.group == "all" or m.kind == a.group) and (not a.only or a.only in m.id)]
    lines: list[str] = []

    def say(s: str) -> None:
        print(s, flush=True)
        lines.append(s)

    if a.check_anchors:
        bad = 0
        for m in chosen:
            text = (ROOT / m.file).read_text(encoding="utf-8").replace("\r\n", "\n")
            n = text.count(m.old)
            if n != 1:
                bad += 1
                say(f"ANCHOR {m.id}: found {n} times in {m.file}")
        say(f"anchors: {len(chosen)} mutants, {bad} do not apply")
        return 1 if bad else 0

    if shutil.which("g++") is None and any(m.kind == "unity" for m in chosen):
        say("NOT RUN: g++ is not on PATH, which the PlatformIO native tests need")
        return 2
    start = time.time()
    kinds = sorted({m.kind for m in chosen})
    for k in kinds:
        ok, tail = baseline(k)
        say(f"baseline {k}: {'green' if ok else 'RED'}  ({tail})")
        if not ok:
            say("NOT RUN: the unmodified code does not pass its own tests, so a red mutant would prove nothing")
            return 2
    results: list[tuple[M, str, str]] = []
    with ThreadPoolExecutor(max_workers=a.jobs) as pool:
        for m, verdict, detail in pool.map(lambda m: one(m, set()), chosen):
            results.append((m, verdict, detail))
            say(f"{verdict:8} {m.kind:5} {m.id:34} {m.why}  [{detail}]")
    caught = sum(1 for _, v, _ in results if v == "CAUGHT")
    survived = sum(1 for _, v, _ in results if v == "SURVIVED")
    errors = sum(1 for _, v, _ in results if v == "ERROR")
    say(f"mutants: {len(results)}, caught: {caught}, survived: {survived}, errors: {errors}, in {time.time() - start:.0f} s")
    for k in kinds:
        sub = [r for r in results if r[0].kind == k]
        say(f"  {k}: {sum(1 for r in sub if r[1] == 'CAUGHT')} of {len(sub)} caught")
    if a.save:
        Path(a.save).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0 if (survived == 0 and errors == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
