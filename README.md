# 🛡 DNS Analysis Pipeline v3

A production-grade, multi-agent DNS traffic analysis system.

Instead of classifying individual domain names, this system **aggregates all DNS
queries captured in a 1-second window**, computes 16 statistical features over
that window, and sends a single compact tuple to the backend for classification.
This approach detects **behavioural anomalies** — DGA bursts, beaconing patterns,
data exfiltration — that per-domain classification completely misses.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     CLI AGENTS  (many, each runs as root)                   │
│                                                                             │
│  Scapy Sniffer                                                              │
│       │  raw packets                                                        │
│       ▼                                                                     │
│  DNS Parser          normalise qname → DomainEvent                         │
│       │  DomainEvent objects                                                │
│       ▼                                                                     │
│  Window Aggregator   collect for exactly 1 second (clock-aligned)          │
│       │  list[DomainEvent]                                                  │
│       ▼                                                                     │
│  Feature Extractor   compute 16 statistics → WindowFeatures                │
│       │  WindowFeatures                                                     │
│       ▼                                                                     │
│  Window Sender       POST /ingest  → receive window_id                     │
│       │              poll GET /result/{id} every 0.5s                      │
│       ▼                                                                     │
│  Rich Dashboard      one row per second window                              │
└────────────────────────────────────┬────────────────────────────────────────┘
                                     │  HTTP  (1 req/sec per agent)
                                     ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                          FastAPI Gateway  (:8000)                          │
│                                                                            │
│  POST /ingest                                                              │
│    1. Validate WindowFeatures (Pydantic)                                   │
│    2. Assign UUID  →  window_id                                            │
│    3. Redis SET  win:<window_id> = "pending"  (TTL 120s)                  │
│    4. Kafka PRODUCE  →  topic: dns_windows                                 │
│    5. Return 202  { window_id }                                            │
│                                                                            │
│  GET /result/{window_id}                                                   │
│    Redis GET  win:<window_id>  →  "pending" | "normal:0.92" | …           │
│    Return  { label, confidence }                                           │
│                                                                            │
│  GET /health   →  { kafka, redis, uptime }                                │
└────────────────────────────────────┬───────────────────────────────────────┘
                                     │  produce
                                     ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                    Kafka  —  topic: dns_windows  (4 partitions)            │
│                                                                            │
│  Message key = window_id  (UUID, random → even partition spread)          │
│  Message value = { window_id, agent_id, features: {16 floats}, … }        │
└────────────────────────────────────┬───────────────────────────────────────┘
                                     │  consume  (group: dns_workers)
                                     ▼
┌────────────────────────────────────────────────────────────────────────────┐
│              Worker Pool  (docker compose --scale worker=N)                │
│                                                                            │
│  For each window message:                                                  │
│    1. Reconstruct 14-element feature vector                                │
│    2. classifier.predict(vector)  →  (label, confidence)                  │
│    3. Redis SET  win:<window_id>  =  "<label>:<confidence>"  (TTL 120s)   │
│    4. Commit Kafka offset                                                  │
└────────────────────────────────────┬───────────────────────────────────────┘
                                     │  SET / GET
                                     ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                   Redis  —  result mailbox                                 │
│                                                                            │
│  Key:    win:<window_id>                                                   │
│  Value:  "pending"  or  "normal:0.9200"  or  "critical:0.7800"            │
│  TTL:    120 seconds  (auto-cleanup)                                       │
│  Policy: allkeys-lru  (128 MB cap)                                         │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## The 16 Window Features

Every 1-second window is summarised into this fixed-length feature vector:

| # | Feature | What it detects |
|---|---------|----------------|
| 0 | `query_count` | Burst volume |
| 1 | `unique_domain_count` | DGA scatter |
| 2 | `unique_ratio` | Beaconing (low = repetitive) |
| 3 | `domain_entropy` | Randomness across all queried names |
| 4 | `mean_per_domain_entropy` | Per-domain randomness (DGA chars) |
| 5 | `high_entropy_domain_ratio` | Fraction of high-entropy domains |
| 6 | `mean_qname_length` | Exfiltration via long subdomains |
| 7 | `std_qname_length` | Length consistency |
| 8 | `max_qname_length` | Single worst-case exfil domain |
| 9 | `tld_diversity` | TLD scatter |
| 10 | `suspicious_tld_ratio` | Fraction using abused TLDs |
| 11 | `mean_digit_ratio` | DGA digit patterns |
| 12 | `mean_vowel_ratio` | DGA low-vowel patterns |
| 13 | `inter_query_std` | Bot regularity (low std = precise timer) |

---

## Project Structure

```
dns_pipeline_v3/
│
├── cli/
│   ├── main.py          ← orchestration, argument parsing, wiring
│   ├── sniffer.py       ← Scapy UDP/53 capture
│   ├── parser.py        ← domain normalisation → DomainEvent
│   ├── window.py        ← clock-aligned 1s aggregator
│   ├── features.py      ← all 16 statistical computations (pure functions)
│   ├── sender.py        ← HTTP POST /ingest + polling loop
│   └── ui.py            ← Rich live dashboard (one row per window)
│
├── api/
│   ├── main.py          ← FastAPI app factory + lifespan
│   ├── routes.py        ← /ingest, /result/{id}, /health
│   ├── schemas.py       ← Pydantic v2 request/response models
│   ├── cache.py         ← AsyncResultStore (API) + SyncResultStore (worker)
│   └── kafka_producer.py← async Kafka producer (thread-pool wrapped)
│
├── worker/
│   └── consumer.py      ← Kafka consumer loop + thread-pool inference
│
├── model/
│   └── classifier.py    ← HeuristicClassifier + SklearnClassifier + factory
│
├── shared/
│   ├── config.py        ← all env-var config (single source of truth)
│   └── logging_setup.py ← consistent logging across all services
│
├── Dockerfile.api
├── Dockerfile.worker
├── docker-compose.yml
└── requirements.txt
```

---

## Quick Start

### 1. Start the backend stack

```bash
docker compose up --build
```

Wait ~20 seconds for Kafka to elect a leader. You will see:

```
dns_api    | INFO: Application startup complete.
dns_worker | INFO: DNS Window Worker starting — topic=dns_windows
```

### 2. Verify health

```bash
curl http://localhost:8000/health
```

```json
{ "status": "ok", "kafka": "ok", "redis": "ok", "uptime_seconds": 18.4 }
```

### 3. Start the CLI on your capture machine (requires root)

```bash
pip install scapy rich httpx
sudo python -m cli.main --api http://localhost:8000
```

---

## CLI Options

```
sudo python -m cli.main [options]

  --iface,  -i   Network interface (default: all)
  --api,    -a   FastAPI base URL (default: http://localhost:8000)
  --agent        Unique agent ID (default: hostname)
  --window  -w   Window size in seconds (default: 1.0)
  --refresh      UI refresh rate in seconds (default: 0.5)
```

**Examples:**

```bash
# Sniff on eth0, custom API
sudo python -m cli.main --iface eth0 --api http://10.0.0.5:8000

# Give this sensor a meaningful name
sudo python -m cli.main --agent "dmz-sensor-01"

# Wider 2-second windows for low-traffic environments
sudo python -m cli.main --window 2.0
```

---

## Scaling Workers

Each worker replica independently consumes from a Kafka partition.
With 4 partitions (default) you can run up to 4 parallel workers:

```bash
docker compose up --scale worker=4
```

The consumer group (`dns_workers`) ensures each window is processed
by exactly one worker — no duplicate classifications.

---

## API Reference

### `POST /ingest`

Accepts one window's feature vector. Returns immediately.

**Request body** (matches `cli.features.WindowFeatures.to_dict()`):
```json
{
  "window_start": "2025-01-15T12:00:01.000000",
  "window_end":   "2025-01-15T12:00:02.000000",
  "agent_id":     "dmz-sensor-01",
  "query_count":              47,
  "unique_domain_count":      31,
  "unique_ratio":          0.659,
  "domain_entropy":        3.821,
  "mean_per_domain_entropy": 3.12,
  "high_entropy_domain_ratio": 0.19,
  "mean_qname_length":     22.4,
  "std_qname_length":       8.1,
  "max_qname_length":      54.0,
  "tld_diversity":            8,
  "suspicious_tld_ratio":  0.04,
  "mean_digit_ratio":      0.07,
  "mean_vowel_ratio":      0.38,
  "inter_query_std":       0.021
}
```

**Response (202):**
```json
{ "window_id": "a3f7c2d1-...", "status": "queued" }
```

---

### `GET /result/{window_id}`

Poll for the classification result.

**While worker is processing:**
```json
{ "window_id": "a3f7c2d1-...", "label": "pending", "confidence": 0.0 }
```

**After worker finishes:**
```json
{ "window_id": "a3f7c2d1-...", "label": "normal", "confidence": 0.91 }
```

Possible labels: `normal` · `suspicious` · `critical` · `unknown`

---

### `GET /health`

```json
{ "status": "ok", "kafka": "ok", "redis": "ok", "uptime_seconds": 143.7 }
```

---

## Example Dashboard

```
╭───────────────────────────────────────────────────────────────────────────╮
│  🛡  DNS MONITOR v3  │  WINDOW-BASED PIPELINE  │  ● RUNNING               │
│  Agent: dmz-sensor-01   API: http://10.0.0.5:8000   Uptime: 00:04:12     │
│  Windows: 251   ✅ Normal: 238   ⚠  Suspicious: 11   ❌ Critical: 2       │
╰───────────────────────────────────────────────────────────────────────────╯

 Window     Queries   Unique   Entropy   Label            Conf
 ─────────  ────────  ───────  ────────  ───────────────  ──────
 12:04:01        42       29   3.412     ✅ normal         0.89
 12:04:02        51       48   4.821     ⚠  suspicious    0.67
 12:04:03        38       25   3.103     ✅ normal         0.92
 12:04:04       213      209   5.441     ❌ critical       0.94
 12:04:05        44       31   3.287     ✅ normal         0.88
 12:04:06        39       27   3.198     ⏳ pending…       —
```

---

## Plugging in a Real ML Model

Train a scikit-learn model using the 14-feature vector
(`IngestRequest.to_feature_vector()`) and label convention
`0=normal, 1=suspicious, 2=critical`:

```python
import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier

# X: shape (n_samples, 14), y: 0/1/2
clf = RandomForestClassifier(n_estimators=300, class_weight="balanced")
clf.fit(X_train, y_train)

with open("model/model.pkl", "wb") as f:
    pickle.dump(clf, f)
```

Then set the env var before starting the worker:

```bash
MODEL_PATH=model/model.pkl docker compose up worker
```

The worker calls `load_classifier()` at startup which auto-detects the `.pkl`
file. If the file is missing or fails to load it falls back to
`HeuristicClassifier` silently — the system keeps running.

---

## Configuration Reference

All settings live in `shared/config.py` and are overridable via environment variables:

| Variable | Default | Used by |
|---|---|---|
| `KAFKA_BOOTSTRAP_SERVERS` | `localhost:9092` | API, Worker |
| `KAFKA_TOPIC` | `dns_windows` | API, Worker |
| `KAFKA_CONSUMER_GROUP` | `dns_workers` | Worker |
| `REDIS_HOST` | `localhost` | API, Worker |
| `REDIS_PORT` | `6379` | API, Worker |
| `API_HOST` | `0.0.0.0` | API |
| `API_PORT` | `8000` | API |
| `API_BASE_URL` | `http://localhost:8000` | CLI |
| `WORKER_THREADS` | `4` | Worker |
| `MODEL_PATH` | `model/model.pkl` | Worker |
| `LOG_LEVEL` | `INFO` | All |

---

## Limitations

| Limitation | Detail |
|---|---|
| Plain DNS only | No DoH (port 443) or DoT (port 853) support |
| Root required | Scapy needs raw socket access |
| Single Kafka broker | Dev setup — add replicas for production |
| In-memory Redis | Data lost on restart without AOF persistence |
| No auth | API has no authentication — lab environment only |
| Heuristic model | Rule-based fallback; replace with trained ML for accuracy |
