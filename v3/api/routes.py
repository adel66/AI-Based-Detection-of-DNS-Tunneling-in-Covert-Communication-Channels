"""
api/routes.py
-------------
FastAPI route handlers.

Routes
------
POST /ingest
    Accepts a window feature vector from a CLI agent.
    Writes "pending" to Redis, enqueues to Kafka, returns window_id.

GET /result/{window_id}
    Returns the current classification from Redis.
    Returns {"label": "pending"} until the worker finishes.

GET /health
    Liveness check — confirms Redis and Kafka are reachable.
"""

from __future__ import annotations

import logging
import time
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status

from api.schemas import (
    HealthResponse,
    IngestRequest,
    IngestResponse,
    ResultResponse,
)

logger = logging.getLogger(__name__)
router = APIRouter()


# ── Dependency helpers ────────────────────────────────────────────────────────

def _store(request: Request):
    return request.app.state.store

def _producer(request: Request):
    return request.app.state.producer

def _start_time(request: Request) -> float:
    return request.app.state.start_time


# ── POST /ingest ──────────────────────────────────────────────────────────────

@router.post(
    "/ingest",
    response_model=IngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Submit one 1-second window feature vector for classification",
)
async def ingest_window(
    payload:  IngestRequest,
    store=Depends(_store),
    producer=Depends(_producer),
) -> IngestResponse:
    """
    Accepts a single window from a CLI agent.

    1. Assigns a unique ``window_id`` (UUID4).
    2. Writes ``pending`` to Redis so the CLI can start polling immediately.
    3. Produces the full message to Kafka for worker consumption.
    4. Returns ``{ window_id, status: "queued" }`` — fast, non-blocking.
    """
    window_id = str(uuid.uuid4())
    logger.info(
        "Ingest — agent=%s window=%s→%s queries=%d",
        payload.agent_id,
        payload.window_start.strftime("%H:%M:%S"),
        payload.window_end.strftime("%H:%M:%S"),
        payload.query_count,
    )

    # Write pending marker so the CLI doesn't get "unknown" on first poll
    await store.set_pending(window_id)

    # Enqueue to Kafka (non-blocking from event loop's perspective)
    try:
        await producer.send_window(window_id, payload)
    except Exception as exc:
        logger.error("Kafka produce failed for window %s: %s", window_id, exc)
        # Return accepted anyway — Redis pending is already set.
        # The window is lost to the worker but the CLI will time out gracefully.
        return IngestResponse(window_id=window_id, status="error")

    return IngestResponse(window_id=window_id, status="queued")


# ── GET /result/{window_id} ───────────────────────────────────────────────────

@router.get(
    "/result/{window_id}",
    response_model=ResultResponse,
    summary="Poll the classification result for a submitted window",
)
async def get_result(
    window_id: str,
    store=Depends(_store),
) -> ResultResponse:
    """
    Returns the current Redis entry for ``window_id``.

    Possible responses:
    - ``pending``  → worker hasn't finished yet — CLI should retry
    - ``normal``   → classified as normal traffic
    - ``suspicious`` / ``critical`` → anomaly detected
    - ``unknown``  → TTL expired or window_id never existed
    """
    label, confidence = await store.get_result(window_id)
    return ResultResponse(
        window_id=window_id,
        label=label,
        confidence=confidence,
    )


# ── GET /health ───────────────────────────────────────────────────────────────

@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Liveness check for Redis and Kafka",
)
async def health(
    store=Depends(_store),
    producer=Depends(_producer),
    start_time: float = Depends(_start_time),
) -> HealthResponse:
    redis_ok = await store.ping()
    kafka_ok = producer.ping()
    return HealthResponse(
        status="ok" if (redis_ok and kafka_ok) else "degraded",
        kafka="ok" if kafka_ok else "unreachable",
        redis="ok" if redis_ok else "unreachable",
        uptime_seconds=round(time.time() - start_time, 1),
    )
