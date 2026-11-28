"""The connector as a service: a FastAPI app with the webhook receiver, a read API over the third party record, a diagnostics route
for the diagnosis tool, and a background loop that reconciles on a timer.

Run it:  python -m iotlab.connector.app   (reads its settings from the environment, see main())
"""
from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .crypto import CredentialVault, load_or_create_key
from .mqtt_listener import MqttListener
from .safelog import SafeLogger
from .store import Store
from .sync import Connector, _error_label
from .vendor_client import ClientConfig, RateLimited, ReauthRequired, VendorClient, VendorError, VendorUnavailable
from .webhook import WebhookRejected

log = SafeLogger("lockbridge.app")

_REJECT_STATUS = {"bad_signature": 401, "missing_headers": 401, "no_secret": 401, "stale_timestamp": 400, "malformed_timestamp": 400,
                  "malformed_body": 400}


@dataclass
class ServiceConfig:
    db_path: str
    keys: str
    vendor: ClientConfig
    reconcile_interval: float = 30.0
    mqtt: dict | None = None            # {"host", "port", "username", "password"}
    webhook_tolerance: float = 300.0


class ReconcileLoop:
    """Calls reconcile() every `interval` seconds. An error is recorded and the loop carries on; it never dies on one."""

    def __init__(self, connector: Connector, interval: float):
        self.connector, self.interval = connector, interval
        self._stop = threading.Event()
        self.paused = False                       # lab fault: the loop is alive but does nothing (a stalled worker)
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> "ReconcileLoop":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=5)

    def _run(self) -> None:
        while not self._stop.is_set():
            if not self.paused:
                self.connector.store.meta_set("loop_tick_at", self.connector.clock())
                try:
                    self.connector.reconcile()
                except Exception as exc:
                    log.warning("reconcile failed: %s", _error_label(exc))
            self._stop.wait(self.interval)


class Service:
    def __init__(self, cfg: ServiceConfig, clock=time.time, sleeper=time.sleep, http=None):
        self.cfg = cfg
        self.store = Store(cfg.db_path)
        self.vault = CredentialVault(cfg.keys)
        self.client = VendorClient(cfg.vendor, self.store, self.vault, clock=clock, sleeper=sleeper, http=http)
        self.connector = Connector(self.store, self.vault, self.client, clock=clock, webhook_tolerance=cfg.webhook_tolerance)
        self.loop = ReconcileLoop(self.connector, cfg.reconcile_interval)
        self.listener: MqttListener | None = None
        self.app = build_app(self)

    def start(self, loop: bool = True) -> "Service":
        if self.cfg.mqtt:
            self.listener = MqttListener(self.connector, **self.cfg.mqtt).start()
        if loop:
            self.loop.start()
        return self

    def stop(self) -> None:
        self.loop.stop()
        if self.listener:
            self.listener.stop()
        self.store.close()


def build_app(svc: Service) -> FastAPI:
    app = FastAPI(title="lock connector", docs_url=None, redoc_url=None, openapi_url=None)
    conn = svc.connector

    @app.post("/webhooks/vendor")
    async def webhook(request: Request):
        body = await request.body()
        try:
            return conn.receive_webhook(request.headers, body)
        except WebhookRejected as exc:
            return JSONResponse({"error": exc.reason}, status_code=_REJECT_STATUS.get(exc.reason, 400))

    @app.get("/healthz")
    def healthz():
        conn.store.meta_get("x")                  # the database answers
        return {"status": "ok"}

    @app.get("/diag")
    def diag(lock: str | None = None):
        return conn.diagnostics(lock)

    @app.get("/locks")
    def locks():
        return {"data": conn.store.list_locks(managed_only=True)}

    @app.get("/locks/{lock_id}")
    def lock(lock_id: str):
        row = conn.store.get_lock(lock_id)
        return row if row else JSONResponse({"error": "not_found"}, status_code=404)

    def _vendor_failure(exc: Exception) -> JSONResponse:
        if isinstance(exc, ReauthRequired):
            return JSONResponse({"error": "reauth_required"}, status_code=502)
        if isinstance(exc, RateLimited):
            return JSONResponse({"error": "vendor_rate_limited", "retry_after": exc.retry_after}, status_code=503)
        if isinstance(exc, VendorError):
            return JSONResponse({"error": exc.code}, status_code=502 if exc.status >= 500 else 400)
        return JSONResponse({"error": "vendor_unavailable"}, status_code=503)

    @app.post("/locks/{lock_id}/commands")
    async def command(lock_id: str, request: Request):
        body = await request.json()
        try:
            return conn.send_command(lock_id, body.get("action", ""))
        except ValueError:
            return JSONResponse({"error": "invalid_action"}, status_code=400)
        except (VendorError, VendorUnavailable) as exc:
            return _vendor_failure(exc)

    @app.post("/locks/{lock_id}/codes")
    async def new_code(lock_id: str, request: Request):
        body = await request.json()
        try:
            return JSONResponse(conn.create_code(lock_id, str(body["name"]), float(body["starts_at"]), float(body["ends_at"])), status_code=201,
                                headers={"Cache-Control": "no-store"})
        except (KeyError, ValueError, TypeError):
            return JSONResponse({"error": "invalid_request"}, status_code=400)
        except (VendorError, VendorUnavailable) as exc:
            return _vendor_failure(exc)

    @app.get("/locks/{lock_id}/codes")
    def codes(lock_id: str):
        # ciphertext never leaves the service: the list says whether a code is held, not what it is
        return {"data": [{k: v for k, v in c.items() if k != "code_enc"} | {"held": c["code_enc"] is not None} for c in conn.store.list_codes(lock_id)]}

    @app.delete("/codes/{code_id}")
    def revoke(code_id: str):
        try:
            row = conn.revoke_code(code_id)
        except KeyError:
            return JSONResponse({"error": "not_found"}, status_code=404)
        except (VendorError, VendorUnavailable) as exc:
            return _vendor_failure(exc)
        return {"id": row["id"], "status": row["status"]}

    @app.post("/reconcile")
    def reconcile():
        try:
            return conn.reconcile()
        except (VendorError, VendorUnavailable) as exc:
            return _vendor_failure(exc)

    @app.post("/_lab/loop")
    async def lab_loop(request: Request):
        svc.loop.paused = bool((await request.json()).get("paused"))
        return {"paused": svc.loop.paused}

    return app


def main() -> None:
    import uvicorn
    cfg = ServiceConfig(
        db_path=os.environ.get("CONNECTOR_DB", "iot/state/connector.db"),
        keys=os.environ.get("CONNECTOR_KEYS") or load_or_create_key(os.environ.get("CONNECTOR_KEY_FILE", "iot/state/connector.key")),
        vendor=ClientConfig(base_url=os.environ["VENDOR_BASE_URL"], client_id=os.environ["VENDOR_CLIENT_ID"],
                            client_secret=os.environ["VENDOR_CLIENT_SECRET"], redirect_uri=os.environ["VENDOR_REDIRECT_URI"]),
        reconcile_interval=float(os.environ.get("RECONCILE_INTERVAL", "30")),
        mqtt=({"host": os.environ["MQTT_HOST"], "port": int(os.environ.get("MQTT_PORT", "1883")), "username": os.environ["MQTT_USER"],
               "password": os.environ["MQTT_PASSWORD"]} if os.environ.get("MQTT_HOST") else None),
    )
    svc = Service(cfg).start()
    uvicorn.run(svc.app, host="127.0.0.1", port=int(os.environ.get("PORT", "8300")), log_level="warning")


if __name__ == "__main__":
    main()
