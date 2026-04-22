"""
worker/consumer.py
------------------
Kafka consumer — reads window messages, reconstructs the 19-feature
vector in exact training tuple order, runs inference, writes result
to Redis.

Label mapping (matches training):
    0  →  "benign"
    1  →  "malicious"
"""

from __future__ import annotations

import json
import logging
import signal
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from kafka import KafkaConsumer
from kafka.errors import KafkaError, NoBrokersAvailable

from api.cache import SyncResultStore
from model.classifier import BaseClassifier, load_classifier
from shared.config import kafka as kafka_cfg, worker as worker_cfg
from shared.logging_setup import configure_logging

configure_logging("worker")
logger = logging.getLogger(__name__)


# ── Kafka connection with retry ───────────────────────────────────────────────

def _connect_consumer(retries: int = 12, base_delay: float = 3.0) -> KafkaConsumer:
    delay = base_delay
    for attempt in range(1, retries + 1):
        try:
            consumer = KafkaConsumer(
                kafka_cfg.topic,
                bootstrap_servers=kafka_cfg.bootstrap_servers,
                group_id=kafka_cfg.consumer_group,
                value_deserializer=lambda b: json.loads(b.decode("utf-8")),
                auto_offset_reset="earliest",
                enable_auto_commit=False,
                max_poll_records=worker_cfg.max_poll_records,
                session_timeout_ms=45_000,
                heartbeat_interval_ms=10_000,
                fetch_min_bytes=1,
                fetch_max_wait_ms=worker_cfg.poll_timeout_ms,
            )
            logger.info("Connected to Kafka on attempt %d", attempt)
            return consumer
        except NoBrokersAvailable:
            logger.warning("Kafka not reachable (attempt %d/%d) — retrying in %.0fs",
                           attempt, retries, delay)
            time.sleep(delay)
            delay = min(delay * 1.5, 30.0)

    logger.error("Cannot connect to Kafka after %d attempts. Exiting.", retries)
    sys.exit(1)


# ── Feature vector reconstruction ────────────────────────────────────────────

def _build_feature_vector(features: dict) -> list[float]:
    """
    Reconstruct the 19-element feature vector from the JSON message.
    Order matches WindowFeatures.to_vector() and the training tuple exactly.
    """
    def f(key: str) -> float:
        return float(features.get(key, 0.0))

    return [
        f("query_count"),
        f("response_count"),
        f("avg_packet_length"),
        f("std_packet_length"),
        f("avg_entropy"),
        f("max_entropy"),
        f("avg_qname_len"),
        f("max_qname_len"),
        f("avg_digit_ratio"),
        f("avg_special_ratio"),
        f("unique_subdomains"),
        f("unique_qtypes"),
        f("txt_ratio"),
        f("large_resp_ratio"),
        f("avg_ttl"),
        f("avg_max_label_len"),
        f("answer_sum"),
        f("resp_len_avg"),
        f("event_count"),
    ]


# ── Per-message processing ────────────────────────────────────────────────────

def _process_message(
    msg:   dict,
    clf:   BaseClassifier,
    store: SyncResultStore,
) -> tuple[str, str, float]:
    window_id = msg.get("window_id", "unknown")
    try:
        fv              = _build_feature_vector(msg.get("features", {}))
        label, confidence = clf.predict(fv)
        store.set_result(window_id, label, confidence)
        logger.info("window=%s agent=%s label=%s conf=%.4f",
                    window_id[:8], msg.get("agent_id", "?"), label, confidence)
        return window_id, label, confidence
    except Exception as exc:
        logger.error("Inference error for window %s: %s", window_id, exc)
        store.set_result(window_id, "unknown", 0.0)
        return window_id, "unknown", 0.0


# ── Worker ────────────────────────────────────────────────────────────────────

class DNSWindowWorker:
    """Kafka consumer + ML inference worker. Blocks until stopped."""

    def __init__(self) -> None:
        print(">>> INIT START", flush=True)
        self._running  = True
        print(">>> LOADING CLASSIFIER", flush=True)
        self._clf      = load_classifier()
        print(">>> CLASSIFIER LOADED", flush=True)
        print(">>> INIT STORE", flush=True)
        self._store    = SyncResultStore()
        print(">>> STORE READY", flush=True)
        
        self._executor = ThreadPoolExecutor(
            max_workers=worker_cfg.inference_threads,
            thread_name_prefix="inference",
        )
        signal.signal(signal.SIGINT,  self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

    def _handle_signal(self, signum, _frame) -> None:
        logger.info("Signal %d — shutting down.", signum)
        self._running = False

    def run(self) -> None:
        print(">>> ENTERED RUN", flush=True)

        logger.info("Worker starting — topic=%s group=%s threads=%d",
                    kafka_cfg.topic, kafka_cfg.consumer_group, worker_cfg.inference_threads)

        if not self._store.ping():
            logger.warning("Redis unreachable — results will not be stored.")

        consumer = _connect_consumer()
        processed = 0
        errors    = 0
        t_start   = time.time()

        try:
            while self._running:
                poll_result = consumer.poll(timeout_ms=worker_cfg.poll_timeout_ms)
                if not poll_result:
                    continue

                messages = [
                    record.value
                    for records in poll_result.values()
                    for record in records
                    if record.value
                ]
                if not messages:
                    continue

                futures = {
                    self._executor.submit(_process_message, msg, self._clf, self._store): msg
                    for msg in messages
                }
                for future in as_completed(futures):
                    try:
                        future.result()
                        processed += 1
                    except Exception as exc:
                        logger.error("Future error: %s", exc)
                        errors += 1

                consumer.commit()

                elapsed = time.time() - t_start
                rate    = processed / elapsed if elapsed > 0 else 0.0
                logger.info("processed=%d errors=%d rate=%.2f/s", processed, errors, rate)

        except KafkaError as exc:
            logger.error("Kafka error: %s", exc)
        except Exception as exc:
            logger.exception("Worker error: %s", exc)
        finally:
            consumer.close()
            self._executor.shutdown(wait=True)
            logger.info("Worker stopped.")


def main() -> None:
    DNSWindowWorker().run()


if __name__ == "__main__":
    main()