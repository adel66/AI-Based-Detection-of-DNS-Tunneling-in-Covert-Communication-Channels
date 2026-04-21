"""
api/kafka_producer.py
---------------------
Wraps ``kafka-python``'s blocking ``KafkaProducer`` for use inside
FastAPI's async context.

Each ``send_window()`` call runs the blocking ``.send().get()`` in a
thread-pool executor so the event loop is never stalled.

Message format on the wire (JSON):
    {
        "window_id":  "<uuid>",
        "agent_id":   "<hostname>",
        "features":   { ... all 16 feature fields ... },
        "window_start": "<ISO datetime>",
        "window_end":   "<ISO datetime>"
    }

The ``window_id`` is the Kafka message key — this routes all messages
from the same window to the same partition, though with window-level
granularity that doesn't matter much.  Agent_id as key would be better
if you want per-agent ordered processing.
"""

from __future__ import annotations

import asyncio
import json
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from kafka import KafkaProducer
from kafka.errors import KafkaError

from api.schemas import IngestRequest
from shared.config import kafka as cfg

logger = logging.getLogger(__name__)

_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="kafka-prod")


class WindowKafkaProducer:
    """
    Async-friendly Kafka producer for ``WindowFeatures`` messages.

    Usage (in FastAPI lifespan):
        producer = WindowKafkaProducer()
        producer.connect()
        ...
        producer.close()
    """

    def __init__(self) -> None:
        self._producer: Optional[KafkaProducer] = None

    def connect(self) -> None:
        """Initialise the underlying Kafka client.  Called once at startup."""
        self._producer = KafkaProducer(
            bootstrap_servers=cfg.bootstrap_servers,
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            key_serializer=lambda k: k.encode("utf-8") if k else None,
            acks=cfg.acks,
            retries=cfg.retries,
            linger_ms=cfg.linger_ms,
            batch_size=cfg.batch_size,
            compression_type="gzip",
            request_timeout_ms=30_000,
        )
        logger.info(
            "KafkaProducer connected → %s (topic=%s)", cfg.bootstrap_servers, cfg.topic
        )

    def close(self) -> None:
        if self._producer:
            self._producer.flush(timeout=10)
            self._producer.close()
            logger.info("KafkaProducer closed.")

    def ping(self) -> bool:
        try:
            return bool(self._producer and self._producer.bootstrap_connected())
        except Exception:
            return False

    # ── async send ────────────────────────────────────────────────────────────

    async def send_window(self, window_id: str, payload: IngestRequest) -> None:
        """
        Serialize and produce one window message to Kafka.

        Runs the blocking send in the thread pool so the event loop stays free.
        Raises ``KafkaError`` on failure — caller decides how to handle it.
        """
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            _executor,
            self._send_sync,
            window_id,
            payload,
        )

    def _send_sync(self, window_id: str, payload: IngestRequest) -> None:
        """Blocking Kafka send — runs inside the thread-pool executor."""
        if not self._producer:
            raise RuntimeError("Producer not connected.")

        message = {
            "window_id":    window_id,
            "agent_id":     payload.agent_id,
            "window_start": payload.window_start.isoformat(),
            "window_end":   payload.window_end.isoformat(),
            "features":     payload.model_dump(
                # Only the 16 numeric feature fields
                include={
                    "query_count", "unique_domain_count", "unique_ratio",
                    "domain_entropy", "mean_per_domain_entropy",
                    "high_entropy_domain_ratio", "mean_qname_length",
                    "std_qname_length", "max_qname_length", "tld_diversity",
                    "suspicious_tld_ratio", "mean_digit_ratio",
                    "mean_vowel_ratio", "inter_query_std",
                }
            ),
        }

        future = self._producer.send(
            cfg.topic,
            key=window_id,
            value=message,
        )
        meta = future.get(timeout=15)
        logger.debug(
            "Produced window_id=%s → topic=%s partition=%d offset=%d",
            window_id, meta.topic, meta.partition, meta.offset,
        )
