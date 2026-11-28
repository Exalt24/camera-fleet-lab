"""A TCP forwarder that stands in for a bad link between a device and the broker.

  cut()       every open connection is reset and new ones are refused (a router that lost its uplink)
  blackhole() connections stay open but nothing is forwarded either way (a 4G link that silently stopped; the broker only
              notices when the MQTT keepalive runs out, then it publishes the client's last will)
  heal()      forward again
  start_flapping(...) cuts and heals at random from a seeded generator, so a flaky run can be repeated
"""
from __future__ import annotations

import random
import socket
import threading


class FlakyLink:
    def __init__(self, target_host: str, target_port: int, listen_port: int | None = None):
        self.target = (target_host, target_port)
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", listen_port or 0))
        self._srv.listen(16)
        self.port = self._srv.getsockname()[1]
        self.host = "127.0.0.1"
        self._mode = "up"
        self._lock = threading.Lock()
        self._pairs: list[tuple[socket.socket, socket.socket]] = []
        self._stop = threading.Event()
        self.cuts = 0
        threading.Thread(target=self._accept, daemon=True).start()
        self._flapper: threading.Thread | None = None
        self._flap_stop = threading.Event()

    @property
    def mode(self) -> str:
        return self._mode

    def _accept(self) -> None:
        while not self._stop.is_set():
            try:
                client, _ = self._srv.accept()
            except OSError:
                return
            if self._mode == "cut":
                client.close()
                continue
            try:
                upstream = socket.create_connection(self.target, timeout=3)
            except OSError:
                client.close()
                continue
            with self._lock:
                self._pairs.append((client, upstream))
            for a, b in ((client, upstream), (upstream, client)):
                threading.Thread(target=self._pump, args=(a, b), daemon=True).start()

    def _pump(self, src: socket.socket, dst: socket.socket) -> None:
        try:
            while not self._stop.is_set():
                data = src.recv(4096)
                if not data:
                    break
                while self._mode == "blackhole" and not self._stop.is_set():
                    self._stop.wait(0.05)         # hold the bytes: nothing arrives and nothing is refused
                if self._mode == "cut":
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            for s in (src, dst):
                try:
                    s.close()
                except OSError:
                    pass

    def cut(self) -> None:
        self._mode = "cut"
        self.cuts += 1
        with self._lock:
            pairs, self._pairs = self._pairs, []
        for a, b in pairs:
            for s in (a, b):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                s.close()

    def blackhole(self) -> None:
        self._mode = "blackhole"

    def heal(self) -> None:
        self._mode = "up"

    def start_flapping(self, mean_up: float, mean_down: float, seed: int = 1) -> None:
        rng = random.Random(seed)
        self._flap_stop = threading.Event()
        stop = self._flap_stop

        def run() -> None:
            while not stop.is_set():
                if stop.wait(rng.expovariate(1 / mean_up)):
                    return
                self.cut()
                if stop.wait(rng.expovariate(1 / mean_down)):
                    return
                self.heal()

        self._flapper = threading.Thread(target=run, daemon=True)
        self._flapper.start()

    def stop_flapping(self) -> None:
        self._flap_stop.set()
        if self._flapper:
            self._flapper.join(timeout=3)
        self._flapper = None
        self.heal()

    def close(self) -> None:
        self._flap_stop.set()
        self._stop.set()
        self.heal()
        self.cut()
        try:
            self._srv.close()
        except OSError:
            pass
