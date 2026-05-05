# AI-Based-Detection-of-DNS-Tunneling-in-Covert-Communication-Channels
Developed a machine learning-based system to detect malicious DNS tunneling activity

 Root Directory (v3)
File	What it does
docker-compose.yml	Defines all services: Zookeeper, Kafka, Redis, API, Worker. Sets up networks, health checks, port mappings.
Dockerfile.api	Builds the FastAPI gateway container. Copies code, installs dependencies, runs uvicorn api.main:app.
Dockerfile.worker	Builds the worker container. Copies code, runs python -m worker.consumer (once we fix the import).
requirements.txt	Python dependencies (FastAPI, Kafka, Redis, Scapy, Rich, etc.).
pyproject.toml / poetry.lock	Alternative dependency management (Poetry). Not used if you use requirements.txt.
README.md	Project documentation.
dns_pipeline.log	Runtime log file (created when you run the CLI).
files.zip / launch.txt	Likely archives or notes – not part of the core code.
📁 api/ – FastAPI Gateway
File	Purpose
main.py	FastAPI app factory. Sets up lifespan (startup/shutdown), includes router, initialises Redis.
routes.py	Defines endpoints: POST /ingest, GET /result/{window_id}, GET /health.
schemas.py	Pydantic models: WindowFeatures (16 metrics), WindowResult (label, confidence).
cache.py	Redis abstraction: AsyncResultStore (for FastAPI async), SyncResultStore (for worker). Handles encoding/decoding of results.
kafka_producer.py	Kafka producer wrapper. Sends WindowFeatures to topic dns_windows. Keyed by agent_id for ordering.
📁 cli/ – Command‑Line Agent (sniffs DNS)
File	Purpose
main.py	Entry point. Parses arguments (--api, --iface, --agent), wires all components together, starts threads, handles Ctrl+C.
sniffer.py	Uses Scapy to capture UDP port 53 packets. Filters for DNS queries (qr == 0). Puts raw packets into a queue.
parser.py	Reads raw packets, extracts domain name (QNAME), creates a DomainEvent with timestamp. Puts into event queue.
window.py	WindowAggregator collects DomainEvents into 1‑second buckets (clock‑aligned). When a window closes, it calls features.py to compute statistics, then puts the feature vector into the send queue.
features.py	Pure functions that compute 16 statistical features from a list of domains: counts, entropy, lengths, TTL, inter‑arrival variance, etc.
sender.py	WindowSender takes feature vectors from the queue, POSTs them to /ingest, gets a window_id, then spawns a daemon thread that polls /result/{id} until classification arrives.
ui.py	Rich‑based live dashboard. Shows a table with one row per window, columns: window ID, timestamp, query count, label, confidence. Updates rows when results come in.
history.py	(Newer file) Likely stores past windows or exports results – not in original plan but harmless.
📁 worker/ – Classification Worker
File	Purpose
consumer.py	Kafka consumer loop. Reads dns_windows topic, submits each feature vector to a thread pool, calls classifier.predict(), writes result to Redis (key window:{uuid}). Commits offsets only after batch completion.
__init__.py	Marks directory as Python package.
📁 model/ – ML & Heuristic Classification
File	Purpose
classifier.py	Loads either a trained model (dns_ensemble_model.joblib) or falls back to a heuristic (rule‑based). Exposes a predict(features) function returning {label, confidence}.
dns_ensemble_model.joblib	Pre‑trained scikit‑learn model (RandomForest / XGBoost). 2.3 MB – the real ML classifier.
(no heuristic.py – logic is inside classifier.py)	
📁 shared/ – Common Utilities
File	Purpose
config.py	Reads environment variables (Kafka, Redis, API, logging). Provides typed config objects used by all components.
logging_setup.py	Configures logging format, level, and output (console + optional file).
📁 mnt/ – Mounted Volume (for Docker)
Used to persist logs or outputs when running inside containers. Not relevant for local development.