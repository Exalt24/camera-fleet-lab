"""Starts a real mosquitto broker in Docker with a generated password file and the ACL in iot/mosquitto/.

The passwords are random per broker and live only in the returned object and, for the command line, in iot/state/broker.json
(gitignored). Nothing here is mocked: tests talk to a real MQTT broker.

    python -m iotlab.broker up        # start one, write iot/state/broker.json
    python -m iotlab.broker down      # remove every container this module started
"""
from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

import paho.mqtt.client as mqtt

from .util import free_port

IMAGE = "eclipse-mosquitto:2.0.22"
LABEL = "cfl-iot=1"
CONF_DIR = Path(__file__).resolve().parent.parent / "mosquitto"
STATE_DIR = Path(__file__).resolve().parent.parent / "state"
USERS = ("device", "vendor", "connector", "diag", "observer", "doormat", "doormatctl")


def _docker(*args: str, timeout: float = 120) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)


def docker_available() -> bool:
    try:
        return _docker("info", timeout=20).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


@dataclass
class Broker:
    container: str
    port: int
    passwords: dict[str, str]
    workdir: Path = field(repr=False)
    host: str = "127.0.0.1"

    def creds(self, user: str) -> tuple[str, str]:
        return user, self.passwords[user]

    def stop(self) -> None:
        """Stop the container (the broker process dies and so does every retained message)."""
        _docker("stop", "-t", "1", self.container)

    def start_again(self) -> None:
        _docker("start", self.container)
        wait_ready(self)

    def remove(self) -> None:
        _docker("rm", "-f", "-v", self.container)
        shutil.rmtree(self.workdir, ignore_errors=True)

    def logs(self) -> str:
        r = _docker("logs", self.container)
        return r.stdout + r.stderr


def wait_ready(broker: Broker, timeout: float = 25.0) -> None:
    deadline = time.time() + timeout
    last = "no attempt"
    while time.time() < deadline:
        c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="ready-probe")
        c.username_pw_set(*broker.creds("diag"))
        try:
            rc = c.connect(broker.host, broker.port, keepalive=5)
            c.loop_start()
            t0 = time.time()
            while time.time() - t0 < 2 and not c.is_connected():
                time.sleep(0.05)
            ok = c.is_connected()
            c.loop_stop()
            c.disconnect()
            if ok:
                return
            last = f"connect rc={rc}, not acknowledged"
        except OSError as exc:
            last = exc.__class__.__name__
        time.sleep(0.2)
    raise RuntimeError(f"the broker did not become ready: {last}\n{broker.logs()[-800:]}")


def start_broker() -> Broker:
    port = free_port()
    workdir = Path(tempfile.mkdtemp(prefix="cfl-iot-broker-"))
    passwords = {u: secrets.token_urlsafe(18) for u in USERS}
    shutil.copy(CONF_DIR / "mosquitto.conf", workdir / "mosquitto.conf")
    shutil.copy(CONF_DIR / "acl.conf", workdir / "acl")
    cmds = []
    for i, (user, pw) in enumerate(passwords.items()):
        cmds.append(f"mosquitto_passwd {'-c' if i == 0 else ''} -b /cfg/passwd {user} {pw}")
    r = _docker("run", "--rm", "--label", LABEL, "-v", f"{workdir}:/cfg", IMAGE, "sh", "-c", " && ".join(cmds))
    if r.returncode != 0:
        raise RuntimeError("could not create the broker password file: " + r.stderr[-300:].replace(passwords["device"], "***"))
    name = f"cfl-iot-mosquitto-{port}"
    run = _docker(
        "run", "-d", "--label", LABEL, "--name", name, "-p", f"127.0.0.1:{port}:1883",
        "-v", f"{workdir}:/mosquitto/config",       # the image's entrypoint chowns this folder, so it cannot be read only
        IMAGE,
    )
    if run.returncode != 0:
        raise RuntimeError("could not start the broker: " + run.stderr[-300:])
    broker = Broker(container=name, port=port, passwords=passwords, workdir=workdir)
    try:
        wait_ready(broker)
    except Exception:
        broker.remove()
        raise
    return broker


def remove_all() -> int:
    ids = _docker("ps", "-aq", "--filter", f"label={LABEL}").stdout.split()
    for i in ids:
        _docker("rm", "-f", "-v", i)
    return len(ids)


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in ("up", "down"):
        print(__doc__)
        return 2
    if sys.argv[1] == "down":
        print(f"removed {remove_all()} container(s)")
        shutil.rmtree(STATE_DIR / "broker.json", ignore_errors=True)
        return 0
    b = start_broker()
    STATE_DIR.mkdir(exist_ok=True)
    path = STATE_DIR / "broker.json"
    path.write_text(json.dumps({"host": b.host, "port": b.port, "container": b.container, "passwords": b.passwords}), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    print(f"broker {b.container} on {b.host}:{b.port}; credentials in {path} (gitignored)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
