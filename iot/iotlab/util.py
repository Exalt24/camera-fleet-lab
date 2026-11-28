"""Small helpers shared by the stand-ins and the tests: free ports, a uvicorn server in a thread, timestamp parsing."""
from __future__ import annotations

import socket
import threading
import time
from datetime import datetime, timezone

import uvicorn


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ServerThread:
    """Runs a FastAPI app on loopback in a background thread until stop() is called."""

    def __init__(self, app, port: int | None = None):
        self.port = port or free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        self._server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=self.port, log_level="warning", access_log=False))
        self._thread = threading.Thread(target=self._server.run, daemon=True)

    def start(self) -> "ServerThread":
        self._thread.start()
        deadline = time.time() + 10
        while not self._server.started:
            if time.time() > deadline:
                raise RuntimeError("the server did not start")
            time.sleep(0.02)
        return self

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=5)


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(value) -> float | None:
    """Epoch seconds (int, float or numeric string) or ISO 8601 with Z or an offset, to epoch seconds. Anything else is None,
    never 0: a missing time must not read as 1970."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value) if value > 0 else None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            number = float(text)
            return number if number > 0 else None
        except ValueError:
            pass
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    return None
