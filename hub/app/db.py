"""Probe history in MariaDB through SQLAlchemy 2.0 async. The pool is configured on purpose, not left at defaults:

  pool_size / max_overflow : the probe loop and the API handlers share the pool, so it is sized for both with headroom
  pool_pre_ping            : a connection the server closed (restart, idle timeout) is detected and replaced on checkout
                             instead of failing a request with 'MySQL server has gone away'
  pool_recycle             : connections are retired before MariaDB's own idle timeout can cut them mid-use
"""
from __future__ import annotations

import datetime as dt

from sqlalchemy import DateTime, Float, Integer, String, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from .probe import ProbeResult


class Base(DeclarativeBase):
    pass


class Probe(Base):
    __tablename__ = "probes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[dt.datetime] = mapped_column(DateTime, index=True)
    camera: Mapped[str] = mapped_column(String(64), index=True)
    state: Mapped[str] = mapped_column(String(16))
    tunnel_ok: Mapped[int] = mapped_column(Integer)
    tcp_ok: Mapped[int] = mapped_column(Integer)
    tcp_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    rtsp_ok: Mapped[int] = mapped_column(Integer)
    codec: Mapped[str | None] = mapped_column(String(32), nullable=True)
    resolution: Mapped[str | None] = mapped_column(String(16), nullable=True)
    handshake_age_s: Mapped[float | None] = mapped_column(Float, nullable=True)
    error: Mapped[str | None] = mapped_column(String(255), nullable=True)


def make_engine(url: str) -> AsyncEngine:
    return create_async_engine(
        url, pool_size=5, max_overflow=5, pool_pre_ping=True, pool_recycle=1800, pool_timeout=10,
    )


def make_sessions(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


async def save_probe(sessions: async_sessionmaker[AsyncSession], camera: str, r: ProbeResult) -> None:
    res = f"{r.width}x{r.height}" if r.width and r.height else None
    async with sessions() as s:
        s.add(Probe(
            ts=dt.datetime.now(dt.timezone.utc).replace(tzinfo=None), camera=camera, state=r.state,
            tunnel_ok=int(r.tunnel_ok), tcp_ok=int(r.tcp_ok), tcp_ms=r.tcp_ms, rtsp_ok=int(r.rtsp_ok), codec=r.codec, resolution=res,
            handshake_age_s=r.handshake_age_s, error=(r.error or None) and r.error[:255],
        ))
        await s.commit()


def row_to_dict(p: Probe) -> dict:
    return {
        "ts": p.ts.isoformat() + "Z", "camera": p.camera, "state": p.state, "tunnel_ok": bool(p.tunnel_ok),
        "tcp_ok": bool(p.tcp_ok), "tcp_ms": p.tcp_ms,
        "rtsp_ok": bool(p.rtsp_ok), "codec": p.codec, "resolution": p.resolution,
        "handshake_age_s": p.handshake_age_s, "error": p.error,
    }


async def latest(sessions: async_sessionmaker[AsyncSession], camera: str) -> dict | None:
    async with sessions() as s:
        row = (await s.execute(select(Probe).where(Probe.camera == camera).order_by(Probe.id.desc()).limit(1))).scalar_one_or_none()
    return row_to_dict(row) if row else None


async def history(sessions: async_sessionmaker[AsyncSession], camera: str, limit: int) -> list[dict]:
    async with sessions() as s:
        rows = (await s.execute(select(Probe).where(Probe.camera == camera).order_by(Probe.id.desc()).limit(limit))).scalars().all()
    return [row_to_dict(r) for r in rows]
