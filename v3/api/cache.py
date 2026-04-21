"""
api/cache.py
------------
Redis used as a **result mailbox** — not a cache.

Lifecycle of a window entry:
  1. API writes ``pending`` when it accepts the ingest request.
  2. Worker overwrites with ``{label}:{confidence}`` when inference finishes.
  3. CLI polls and reads the final value.
  4. TTL (default 120s) cleans up the entry automatically.

Key scheme:  ``win:<window_id>``
Value scheme: ``"pending"``  or  ``"normal:0.92"``  or  ``"critical:0.87"``

Two clients:
  - ``AsyncResultStore`` — used by the FastAPI gateway (asyncio-native).
  - ``SyncResultStore``  — used by the worker (blocking, simpler).
"""

from __future__ import annotations

import logging
from typing import Optional

import redis.asyncio as aioredis
import redis as syncredis

from shared.config import redis_ as cfg

logger = logging.getLogger(__name__)


def _key(window_id: str) -> str:
    return f"{cfg.key_prefix}{window_id}"


def _encode(label: str, confidence: float) -> str:
    return f"{label}:{confidence:.4f}"


def _decode(raw: str) -> tuple[str, float]:
    """Parse ``"label:confidence"`` → ``(label, confidence)``."""
    if ":" not in raw:
        return raw, 0.0
    label, _, conf_str = raw.partition(":")
    try:
        return label, float(conf_str)
    except ValueError:
        return label, 0.0


# ── Async client (FastAPI) ────────────────────────────────────────────────────

class AsyncResultStore:
    """Non-blocking Redis client for use inside FastAPI coroutines."""

    def __init__(self) -> None:
        self._client: Optional[aioredis.Redis] = None

    async def connect(self) -> None:
        self._client = aioredis.Redis(
            host=cfg.host,
            port=cfg.port,
            db=cfg.db,
            decode_responses=True,
        )
        await self._client.ping()
        logger.info("AsyncResultStore connected to Redis %s:%d", cfg.host, cfg.port)

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()

    async def set_pending(self, window_id: str) -> None:
        """Write the initial 'pending' placeholder."""
        await self._client.set(_key(window_id), cfg.pending_value, ex=cfg.result_ttl)

    async def get_result(self, window_id: str) -> tuple[str, float]:
        """
        Return ``(label, confidence)`` for a window.

        Returns ``("pending", 0.0)`` if the worker hasn't finished yet,
        and ``("unknown", 0.0)`` if the key has expired or never existed.
        """
        try:
            raw = await self._client.get(_key(window_id))
        except Exception as exc:
            logger.warning("Redis GET error for %s: %s", window_id, exc)
            return "unknown", 0.0

        if raw is None:
            return "unknown", 0.0
        if raw == cfg.pending_value:
            return "pending", 0.0
        return _decode(raw)

    async def ping(self) -> bool:
        try:
            return bool(await self._client.ping())
        except Exception:
            return False


# ── Sync client (Worker) ──────────────────────────────────────────────────────

class SyncResultStore:
    """Blocking Redis client for use in the Kafka worker threads."""

    def __init__(self) -> None:
        self._client = syncredis.Redis(
            host=cfg.host,
            port=cfg.port,
            db=cfg.db,
            decode_responses=True,
        )

    def set_result(self, window_id: str, label: str, confidence: float) -> None:
        """Overwrite the pending placeholder with the final classification."""
        try:
            self._client.set(
                _key(window_id),
                _encode(label, confidence),
                ex=cfg.result_ttl,
            )
            logger.debug("Stored result %s → %s (%.4f)", window_id, label, confidence)
        except Exception as exc:
            logger.warning("Redis SET error for %s: %s", window_id, exc)

    def ping(self) -> bool:
        try:
            return bool(self._client.ping())
        except Exception:
            return False
