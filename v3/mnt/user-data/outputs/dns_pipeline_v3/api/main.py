"""
api/main.py
-----------
FastAPI application factory.

Manages Redis and Kafka connections via the ``lifespan`` context manager
(modern replacement for ``@app.on_event`` hooks).

Run with:
    uvicorn api.main:app --host 0.0.0.0 --port 8000 --workers 2
"""

from __future__ import annotations

import logging
import sys
import time
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api.cache import AsyncResultStore
from api.kafka_producer import WindowKafkaProducer
from api.routes import router
from shared.config import api as api_cfg
from shared.logging_setup import configure_logging

configure_logging("api")
logger = logging.getLogger(__name__)


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup → yield → shutdown."""
    logger.info("API starting up…")

    store    = AsyncResultStore()
    producer = WindowKafkaProducer()

    # Connect to Redis
    try:
        await store.connect()
    except Exception as exc:
        logger.error("Redis unavailable at startup: %s — results will be 'unknown'", exc)

    # Connect to Kafka
    try:
        producer.connect()
    except Exception as exc:
        logger.error("Kafka unavailable at startup: %s — windows will not be queued", exc)

    app.state.store      = store
    app.state.producer   = producer
    app.state.start_time = time.time()

    logger.info("API ready.")
    yield

    logger.info("API shutting down…")
    producer.close()
    await store.close()
    logger.info("API stopped.")


# ── Application factory ───────────────────────────────────────────────────────

def create_app() -> FastAPI:
    app = FastAPI(
        title="DNS Analysis Pipeline",
        description=(
            "Accepts per-second DNS window feature vectors from CLI agents, "
            "queues them through Kafka, classifies via ML workers, and exposes "
            "results through a polling endpoint."
        ),
        version="3.0.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def log_requests(request: Request, call_next):
        response = await call_next(request)
        logger.info("%s %s → %d", request.method, request.url.path, response.status_code)
        return response

    @app.exception_handler(Exception)
    async def global_handler(request: Request, exc: Exception):
        logger.exception("Unhandled error on %s", request.url.path)
        return JSONResponse(status_code=500, content={"detail": "Internal server error."})

    app.include_router(router)
    return app


app = create_app()

if __name__ == "__main__":
    uvicorn.run(
        "api.main:app",
        host=api_cfg.host,
        port=api_cfg.port,
        reload=False,
    )
