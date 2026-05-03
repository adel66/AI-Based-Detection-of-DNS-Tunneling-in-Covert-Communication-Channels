"""
shared/config.py
----------------
Centralised configuration for every service in the pipeline.

All values are read from environment variables with safe defaults so the
same codebase runs locally, in Docker Compose, and in a multi-node cluster
without any code changes.

Usage
-----
    from shared.config import kafka, redis_, api, worker, cli, log
    print(kafka.bootstrap_servers)
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


# ── helpers ───────────────────────────────────────────────────────────────────

def _str(key: str, default: str) -> str:
    return os.environ.get(key, default)

def _int(key: str, default: int) -> int:
    return int(os.environ.get(key, str(default)))

def _float(key: str, default: float) -> float:
    return float(os.environ.get(key, str(default)))


# ── Kafka ─────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class KafkaConfig:
    bootstrap_servers: str  = field(default_factory=lambda: _str("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"))
    topic:             str  = field(default_factory=lambda: _str("KAFKA_TOPIC",             "dns_windows"))
    consumer_group:    str  = field(default_factory=lambda: _str("KAFKA_CONSUMER_GROUP",    "dns_workers"))

    # Producer tuning — small linger keeps latency low while still batching
    linger_ms:   int = 10
    batch_size:  int = 16_384   # bytes
    retries:     int = 5
    acks:        str = "all"    # wait for full ISR acknowledgement


# ── Redis ─────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class RedisConfig:
    host:          str = field(default_factory=lambda: _str("REDIS_HOST", "localhost"))
    port:          int = field(default_factory=lambda: _int("REDIS_PORT", 6379))
    db:            int = 0
    key_prefix:    str = "win:"     # win:<window_id>
    result_ttl:    int = 120        # seconds — result stays long enough for CLI to poll
    pending_value: str = "pending"  # placeholder written by API immediately on ingest


# ── FastAPI ───────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class APIConfig:
    host:     str = field(default_factory=lambda: _str("API_HOST",     "0.0.0.0"))
    port:     int = field(default_factory=lambda: _int("API_PORT",     8000))
    base_url: str = field(default_factory=lambda: _str("API_BASE_URL", "http://217.65.146.96:8000"))


# ── Worker ────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class WorkerConfig:
    inference_threads: int = field(default_factory=lambda: _int("WORKER_THREADS",      4))
    poll_timeout_ms:   int = field(default_factory=lambda: _int("WORKER_POLL_TIMEOUT", 500))
    max_poll_records:  int = field(default_factory=lambda: _int("WORKER_POLL_RECORDS", 50))
    model_path:        str = field(default_factory=lambda: _str("MODEL_PATH",          "model/dns_ensemble_model.joblib"))


# ── CLI ───────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class CLIConfig:
    window_size_s:  float = 1.0    # aggregation window duration
    poll_interval_s: float = 0.5   # how often CLI polls /result/{id}
    poll_max_wait_s: float = 10.0  # give up polling after this long
    ui_refresh_s:   float = 0.5    # Rich dashboard redraw rate
    max_ui_rows:    int   = 30     # max window rows shown at once


# ── Logging ───────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class LogConfig:
    level:  str = field(default_factory=lambda: _str("LOG_LEVEL", "INFO"))
    fmt:    str = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    file:   str = "dns_pipeline.log"


# ── Singleton instances — import these directly everywhere ────────────────────

kafka   = KafkaConfig()
redis_  = RedisConfig()
api     = APIConfig()
worker  = WorkerConfig()
cli     = CLIConfig()
log     = LogConfig()
