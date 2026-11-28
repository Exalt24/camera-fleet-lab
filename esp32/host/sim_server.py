#!/usr/bin/env python3
# LIFESPAN: permanent (the host emulation of the device's network side, used by the API, MQTT and web page tests and for trying the page without a board)
"""The doormat's control surface on the host: the same REST routes, WebSocket stream and MQTT topics the firmware serves, in front of the
real device logic.

Every command goes to `core_cli` (lib/doormat_core compiled for the host), the same code the ESP32 links, so a rule in the command parser or
in the LED engine is exercised here exactly as it runs on the board. What this file adds is only transport: an HTTP server, a WebSocket server,
an MQTT client and a clock that ticks the device every 20 ms. Pins are replaced by `/sim/*` routes that set the pressure and the microphone
level, and the camera board is replaced by a generated test frame (a moving bar with a frame counter) served as MJPEG.

    python esp32/host/sim_server.py --http-port 8080 --ws-port 8081 [--mqtt-host 127.0.0.1 --mqtt-port 1883 --mqtt-user doormat --mqtt-pass ...]
    open http://127.0.0.1:8080/?wsport=8081
"""
from __future__ import annotations

import argparse
import io
import json
import os
import random
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
ESP32 = HERE.parent
CORE_CLI = ESP32 / ".pio" / "build" / "core_cli" / ("program.exe" if os.name == "nt" else "program")
INDEX = ESP32 / "web" / "index.html"
MAX_BODY = 600  # the device refuses more than 256 bytes, this only keeps one request from overrunning the line protocol below


class Core:
    """The device logic, one line in and one line out, behind a lock."""

    def __init__(self, cli: Path = CORE_CLI, clock=lambda: 0):
        self.clock = clock
        if not cli.exists():
            raise SystemExit(f"{cli} is missing: run `pio run -e core_cli` in esp32/ first")
        self.proc = subprocess.Popen([str(cli)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1, encoding="utf-8")
        self.lock = threading.Lock()

    def ask(self, line: str) -> str:
        """The first @T@ in the line becomes the device clock, read INSIDE the lock so two threads can never hand the device a time that goes backwards."""
        assert chr(10) not in line
        with self.lock:
            line = line.replace("@T@", str(self.clock()), 1)
            self.proc.stdin.write(line + chr(10))
            self.proc.stdin.flush()
            return self.proc.stdout.readline().rstrip("\r\n")

    def close(self) -> None:
        try:
            with self.lock:
                self.proc.stdin.write("quit\n")
                self.proc.stdin.flush()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()


class Sim:
    def __init__(self, device_id: str = "mat-sim", cli: Path = CORE_CLI, mqtt: dict | None = None):
        self.id = device_id
        self.t0 = time.monotonic()
        self.core = Core(cli, self.now)
        self.rng = random.Random(1)
        self.pressure = 100
        self.mic_override: int | None = None
        self.clients: set = set()
        self.clients_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.http: ThreadingHTTPServer | None = None
        self.ws_server = None
        self.mqtt = None
        self.mqtt_cfg = mqtt
        self.threads: list[threading.Thread] = []
        self.last_occupied = False
        self.frame_no = 0

    # ---- time and commands ----
    def now(self) -> int:
        return int((time.monotonic() - self.t0) * 1000)

    def command(self, route: str | None, body: str) -> tuple[int, dict]:
        body = body.replace("\r", " ").replace("\n", " ")
        if len(body) > MAX_BODY:
            return 400, {"ok": False, "err": "too_long"}
        if route == "status":
            line = self.core.ask(f"status @T@ {self.id} {self.net}")
            doc = json.loads(line)
            return (200 if doc.get("t") == "status" else 500), doc
        reply = json.loads(self.core.ask(f"cmd @T@ {route or '-'} {body}"))
        if reply.get("ok") and reply.get("type") in ("led", "message", "greet"):
            self.broadcast(self.core.ask(f"status @T@ {self.id} {self.net}"))
        return (200 if reply.get("ok") else 400), reply

    net = "sta"

    # ---- fan out to WebSocket pages and MQTT ----
    def broadcast(self, text: str) -> None:
        with self.clients_lock:
            clients = list(self.clients)
        for c in clients:
            try:
                c.send(text)
            except Exception:
                with self.clients_lock:
                    self.clients.discard(c)

    def publish(self, sub: str, payload: str, retain: bool = False) -> None:
        if self.mqtt is not None:
            self.mqtt.publish(f"doormat/{self.id}/{sub}", payload, qos=1, retain=retain)

    # ---- the device clock ----
    def tick_loop(self) -> None:
        next_mic = next_frame = next_status = 0.0
        while not self.stop_event.is_set():
            noise = self.rng.randint(-40, 40)
            pressure = max(0, self.pressure + noise)
            mic = self.mic_override if self.mic_override is not None else (45 + self.rng.randint(0, 20) if self.last_occupied else 4 + self.rng.randint(0, 5))
            res = json.loads(self.core.ask(f"tick @T@ {pressure} {mic}"))
            if res.get("ev") in ("step_on", "step_off"):
                self.last_occupied = res["ev"] == "step_on"
                ev = self.core.ask("presence @T@")
                self.broadcast(ev)
                self.publish("event/presence", ev)
                self.broadcast(self.core.ask(f"status @T@ {self.id} {self.net}"))
            if res.get("greet") or res.get("sound"):
                self.broadcast(self.core.ask(f"status @T@ {self.id} {self.net}"))
            mono = time.monotonic()
            if mono >= next_mic:
                next_mic = mono + 0.2
                self.broadcast(self.core.ask(f"mic {mic}"))
            if mono >= next_frame:
                next_frame = mono + 0.2
                self.broadcast(self.core.ask("frame @T@ 24"))
            if mono >= next_status:
                next_status = mono + 5.0
                self.publish("status", self.core.ask(f"status @T@ {self.id} {self.net}"), retain=True)
            self.stop_event.wait(0.02)

    # ---- servers ----
    def start(self, http_port: int = 0, ws_port: int = 0, host: str = "127.0.0.1") -> None:
        sim = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):  # quiet
                pass

            def _send(self, code: int, body: bytes, ctype: str = "application/json") -> None:
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

            def _json(self, code: int, doc: dict) -> None:
                self._send(code, json.dumps(doc).encode())

            def do_GET(self):
                path = self.path.split("?")[0]
                if path == "/":
                    self._send(200, INDEX.read_bytes(), "text/html; charset=utf-8")
                elif path == "/api/status":
                    self._json(*sim.command("status", ""))
                elif path == "/api/display":
                    bmp = bytes.fromhex(sim.core.ask(f"eyes @T@"))
                    self._send(200, bmp, "image/bmp")
                elif path == "/api/messages":
                    self._send(200, sim.core.ask("messages").encode())
                elif path == "/stream":
                    self._stream()
                elif path == "/capture":
                    self._send(200, sim.test_frame(), "image/jpeg")
                else:
                    self._json(404, {"ok": False, "err": "not_found"})

            def do_POST(self):
                path = self.path.split("?")[0]
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(min(length, 65536)).decode("utf-8", "replace") if length else ""
                if path.startswith("/api/"):
                    route = path[len("/api/"):]
                    if route not in ("greet", "led", "message", "wifi"):
                        self._json(404, {"ok": False, "err": "not_found"})
                        return
                    self._json(*sim.command(route, raw))
                elif path.startswith("/sim/"):
                    doc = json.loads(raw or "{}")
                    if path == "/sim/pressure":
                        sim.pressure = int(doc["value"])
                    elif path == "/sim/mic":
                        sim.mic_override = None if doc.get("value") is None else int(doc["value"])
                    elif path == "/sim/step":
                        sim.pressure = 2400
                        threading.Timer(float(doc.get("ms", 1500)) / 1000.0, lambda: setattr(sim, "pressure", 100)).start()
                    else:
                        self._json(404, {"ok": False})
                        return
                    self._json(200, {"ok": True})
                else:
                    self._json(404, {"ok": False, "err": "not_found"})

            def _stream(self):
                self.send_response(200)
                self.send_header("Content-Type", "multipart/x-mixed-replace; boundary=doormatframe")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Connection", "close")
                self.end_headers()
                try:
                    while not sim.stop_event.is_set():
                        jpg = sim.test_frame()
                        head = bytes.fromhex(sim.core.ask(f"mjpeghdr {len(jpg)}"))
                        self.wfile.write(head + jpg)
                        self.wfile.flush()
                        time.sleep(0.12)
                except (BrokenPipeError, ConnectionError, OSError):
                    pass

        self.http = ThreadingHTTPServer((host, http_port), Handler)
        self.http.daemon_threads = True
        self.http_port = self.http.server_address[1]
        self._spawn(self.http.serve_forever)

        from websockets.sync.server import serve

        def ws_handler(conn):
            with self.clients_lock:
                self.clients.add(conn)
            try:
                conn.send(self.core.ask(f"status @T@ {self.id} {self.net}"))
                for msg in conn:
                    body = msg if isinstance(msg, str) else msg.decode("utf-8", "replace")
                    code, doc = self.command(None, body)
                    conn.send(json.dumps(doc))
            except Exception:
                pass
            finally:
                with self.clients_lock:
                    self.clients.discard(conn)

        self.ws_server = serve(ws_handler, host, ws_port)
        self.ws_port = self.ws_server.socket.getsockname()[1]
        self._spawn(self.ws_server.serve_forever)
        self._spawn(self.tick_loop)
        if self.mqtt_cfg:
            self._start_mqtt(self.mqtt_cfg)

    def _spawn(self, fn) -> None:
        th = threading.Thread(target=fn, daemon=True)
        th.start()
        self.threads.append(th)

    def _start_mqtt(self, cfg: dict) -> None:
        import paho.mqtt.client as mqtt

        c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=self.id)
        c.username_pw_set(cfg["user"], cfg["password"])
        c.will_set(f"doormat/{self.id}/status", '{"t":"status","online":false}', qos=1, retain=True)
        prefix = f"doormat/{self.id}/cmd/"

        def on_connect(client, userdata, flags, rc, props=None):
            client.subscribe(prefix + "#", qos=1)

        def on_message(client, userdata, msg):
            route = msg.topic[len(prefix):]
            if not route:
                return
            body = msg.payload[: MAX_BODY + 1].decode("utf-8", "replace")
            code, doc = self.command(route if route in ("greet", "led", "message", "status", "wifi") else "unknown", body)
            client.publish(f"doormat/{self.id}/event/ack", json.dumps(doc), qos=1)

        c.on_connect = on_connect
        c.on_message = on_message
        c.connect(cfg["host"], cfg["port"], keepalive=10)
        c.loop_start()
        self.mqtt = c

    # ---- the camera stand in: a generated frame, labelled as one ----
    def test_frame(self) -> bytes:
        from PIL import Image, ImageDraw

        self.frame_no += 1
        w, h = 320, 240
        img = Image.new("RGB", (w, h), (18, 24, 32))
        d = ImageDraw.Draw(img)
        for x in range(0, w, 32):
            d.line([(x, 0), (x, h)], fill=(34, 46, 60))
        for y in range(0, h, 32):
            d.line([(0, y), (w, y)], fill=(34, 46, 60))
        bar = (self.frame_no * 9) % w
        d.rectangle([bar, 0, bar + 14, h], fill=(58, 176, 255))
        d.text((10, 10), "TEST FRAME SOURCE (host)", fill=(232, 238, 244))
        d.text((10, 26), f"frame {self.frame_no}", fill=(143, 160, 178))
        buf = io.BytesIO()
        img.save(buf, "JPEG", quality=70)
        return buf.getvalue()

    def stop(self) -> None:
        self.stop_event.set()
        if self.mqtt is not None:
            try:
                self.mqtt.loop_stop()
                self.mqtt.disconnect()
            except Exception:
                pass
        if self.http is not None:
            self.http.shutdown()
            self.http.server_close()
        if self.ws_server is not None:
            self.ws_server.shutdown()
        self.core.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--http-port", type=int, default=8080)
    ap.add_argument("--ws-port", type=int, default=8081)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--id", default="mat-sim")
    ap.add_argument("--mqtt-host")
    ap.add_argument("--mqtt-port", type=int, default=1883)
    ap.add_argument("--mqtt-user", default="doormat")
    ap.add_argument("--mqtt-pass", default="")
    a = ap.parse_args()
    mq = {"host": a.mqtt_host, "port": a.mqtt_port, "user": a.mqtt_user, "password": a.mqtt_pass} if a.mqtt_host else None
    sim = Sim(a.id, mqtt=mq)
    sim.start(a.http_port, a.ws_port, a.host)
    print(f"doormat host emulation: http://{a.host}:{sim.http_port}/?wsport={sim.ws_port}  (Ctrl-C to stop)")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        sim.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
