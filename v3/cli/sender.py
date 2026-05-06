"""
cli/sender.py
-------------
Sends WindowFeatures to POST /ingest, receives a window_id, then polls
GET /result/{window_id} until the worker classifies the window.

On result:
  - Calls result_callback(window_id, label, confidence)  → updates the UI
  - Calls history_logger.log(features, label, confidence) → writes to file
"""

from __future__ import annotations

import logging
import threading
import time
from queue import Empty, Queue

import httpx

from cli.features import WindowFeatures
from cli.history import HistoryLogger
from shared.config import cli as cli_cfg
from cli.domain_logger import DomainLogger

logger = logging.getLogger(__name__)

_POST_TIMEOUT = 5.0
_POLL_TIMEOUT = 3.0


class WindowSender:
    """
    Parameters
    ----------
    window_queue    : Queue[WindowFeatures]   — filled by WindowAggregator
    result_callback : (window_id, label, confidence) → None  — updates UI
    history_logger  : HistoryLogger           — writes completed rows to file
    api_base_url    : str
    """

    def __init__(
        self,
        window_queue:    Queue,
        result_callback,
        history_logger:  HistoryLogger,
        api_base_url:    str,
    ) -> None:
        self.window_queue    = window_queue
        self.result_callback = result_callback
        self.history_logger  = history_logger
        self._ingest_url     = api_base_url.rstrip("/") + "/ingest"
        self._result_url     = api_base_url.rstrip("/") + "/result"
        self._running        = False
        self._client         = httpx.Client(timeout=_POST_TIMEOUT)
        self.domain_logger = DomainLogger()

        # Keep a reference to features by window_id so the poll thread
        # can hand them to the history logger on completion.
        self._pending: dict[str, tuple[WindowFeatures, list[str]]] = {}
        self._pending_lock = threading.Lock()

    def start(self) -> None:
        self._running = True
        t = threading.Thread(target=self._loop, daemon=True, name="sender")
        t.start()
        logger.info("WindowSender started → %s", self._ingest_url)

    def stop(self) -> None:
        self._running = False
        self._client.close()

    def _loop(self) -> None:
        while self._running:
            try:
                features, domains = self.window_queue.get(timeout=0.5)
            except Empty:
                continue

            window_id = self._send(features)
            if window_id is None:
                continue

            # Store features so the poll thread can log them on completion
            with self._pending_lock:
                self._pending[window_id] = (features, domains)

            # Each window gets its own lightweight poll thread
            t = threading.Thread(
                target=self._poll_result,
                args=(window_id,),
                daemon=True,
                name=f"poll-{window_id[:8]}",
            )
            t.start()

    def _send(self, features: WindowFeatures) -> str | None:
        try:
            resp = self._client.post(self._ingest_url, json=features.to_dict())
            resp.raise_for_status()
            window_id = resp.json()["window_id"]
            logger.debug("Sent window %s (%d queries)", window_id[:8], features.query_count)
            #print("features: "+str(features.to_dict()))
            #print("window_id: "+window_id)
            return window_id
        except httpx.TimeoutException:
            logger.warning("POST /ingest timed out — window dropped.")
        except httpx.HTTPStatusError as exc:
            logger.error("POST /ingest HTTP %d", exc.response.status_code)
        except Exception as exc:
            logger.error("POST /ingest failed: %s", exc)
        return None

    def _poll_result(self, window_id: str) -> None:
        deadline = time.monotonic() + cli_cfg.poll_max_wait_s
        url      = f"{self._result_url}/{window_id}"

        with httpx.Client(timeout=_POLL_TIMEOUT) as client:
            while time.monotonic() < deadline:
                try:
                    resp  = client.get(url)
                    resp.raise_for_status()
                    data  = resp.json()
                    label = data.get("label", "pending")

                    if label != "pending":
                        confidence = float(data.get("confidence", 0.0))
                        self.result_callback(window_id, label, confidence)

                        # Write to history file
                        with self._pending_lock:
                            entry = self._pending.pop(window_id, None)
                        if entry is not None:
                            features, domains = entry
                            self.history_logger.log(features, label, confidence)
                            self.domain_logger.log_window(
                                timestamp=features.window_end,
                                agent_id=features.agent_id,
                                domains=domains,
                                label=label,
                                confidence=confidence,)

                        logger.debug("Result %s → %s (%.2f)", window_id[:8], label, confidence)
                        #print("Result for window %s: %s (confidence %.2f)" % (window_id[:8], label, confidence))
                        #print("--------------------------------------------------------")
                        return

                except httpx.TimeoutException:
                    pass
                except Exception as exc:
                    logger.warning("Poll error for %s: %s", window_id[:8], exc)

                time.sleep(cli_cfg.poll_interval_s)

        # Timed out

        logger.warning("Poll exhausted for %s — marking unknown.", window_id[:8])

        label = "unknown"
        confidence = 0.0

        self.result_callback(window_id, label, confidence)

        with self._pending_lock:
            entry = self._pending.pop(window_id, None)

        if entry:
            features, domains = entry

            try:
                self.history_logger.log(features, label, confidence)

                self.domain_logger.log_window(
            timestamp=features.window_end,
            agent_id=features.agent_id,
            domains=domains,
            label=label,
            confidence=confidence,)

            except Exception as e:
                logger.exception("Failed writing logs for %s: %s", window_id[:8], e)
