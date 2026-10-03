"""Fleet monitor API. A background task probes the camera through the VPN every few seconds and stores each result;
the HTTP handlers only read the database, so a dead tunnel makes the STATUS wrong-looking, never the API slow."""
from __future__ import annotations

import asyncio
import contextlib
import logging
import os

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy import text

from . import db
from .probe import probe_camera

# uvicorn only configures its own loggers, so without this the monitor's own log lines are silently dropped (the root
# logger defaults to WARNING). A monitor that cannot log what it saw is the first thing to fix when debugging it.
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("fleet")

# The route handlers are called by FastAPI's router, not by name, so they are the deliberate public surface.
__all__ = ["app", "dashboard", "health", "status", "history", "pool"]

DATABASE_URL = os.environ["DATABASE_URL"]
CAMERA_HOST = os.environ.get("CAMERA_HOST", "10.8.0.2")
CAMERA_NAME = os.environ.get("CAMERA_NAME", "cam1")
PROBE_INTERVAL_S = float(os.environ.get("PROBE_INTERVAL_S", "5"))


async def wait_for_db(engine, attempts: int = 30) -> None:
    for i in range(attempts):
        try:
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            return
        except Exception as exc:  # noqa: BLE001 - startup race with the database container
            log.info("db not ready (%s), retry %d/%d", exc.__class__.__name__, i + 1, attempts)
            await asyncio.sleep(1)
    raise RuntimeError("database never became ready")


async def probe_loop(sessions) -> None:
    while True:
        try:
            result = await probe_camera(CAMERA_HOST)
            await db.save_probe(sessions, CAMERA_NAME, result)
            log.info("probe %s state=%s tunnel=%s tcp=%s rtsp=%s age=%s err=%s", CAMERA_NAME, result.state,
                     result.tunnel_ok, result.tcp_ok, result.rtsp_ok, result.handshake_age_s, result.error)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - one bad cycle must not stop the monitor
            log.exception("probe cycle failed")
        await asyncio.sleep(PROBE_INTERVAL_S)


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    engine = db.make_engine(DATABASE_URL)
    await wait_for_db(engine)
    async with engine.begin() as conn:
        await conn.run_sync(db.Base.metadata.create_all)
    app.state.engine = engine
    app.state.sessions = db.make_sessions(engine)
    task = asyncio.create_task(probe_loop(app.state.sessions))
    try:
        yield
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        await engine.dispose()


app = FastAPI(title="camera fleet lab", lifespan=lifespan)


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    return (Path(__file__).parent / "dashboard.html").read_text(encoding="utf-8")


@app.get("/health")
async def health():
    async with app.state.engine.connect() as conn:
        await conn.execute(text("SELECT 1"))
    return {"ok": True}


@app.get("/status")
async def status():
    row = await db.latest(app.state.sessions, CAMERA_NAME)
    if row is None:
        raise HTTPException(status_code=503, detail="no probe has completed yet")
    return row


@app.get("/history")
async def history(limit: int = 30):
    return await db.history(app.state.sessions, CAMERA_NAME, max(1, min(limit, 500)))


@app.get("/pool")
async def pool():
    """Connection-pool occupancy, so pool behaviour is observable instead of assumed."""
    p = app.state.engine.pool
    return {"size": p.size(), "checked_out": p.checkedout(), "overflow": p.overflow(), "checked_in": p.checkedin()}
