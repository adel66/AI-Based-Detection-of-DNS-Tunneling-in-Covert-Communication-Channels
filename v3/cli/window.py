"""
cli/window.py
-------------
Clock-aligned 1-second window aggregator.

Key behaviour
-------------
- Windows are aligned to wall-clock second boundaries so all agents
  produce comparable windows (12:00:01.000, 12:00:02.000, …).
- **Empty windows are silently dropped** — if no DNS packets arrived
  in a second there is nothing to compute, nothing to send, and nothing
  to display.  Only windows with at least one captured query are emitted.
"""

from __future__ import annotations

import logging
import math
import threading
import time
from datetime import datetime
from queue import Empty, Queue

from cli.features import WindowFeatures, compute_features
from cli.parser import DomainEvent
from shared.config import cli as cli_cfg

logger = logging.getLogger(__name__)


class WindowAggregator:
    """
    Reads DomainEvent objects from *event_queue*, groups them into
    fixed 1-second windows, computes features, and pushes non-empty
    WindowFeatures into *window_queue*.

    Parameters
    ----------
    event_queue  : Queue[DomainEvent]   — filled by DNSParser
    window_queue : Queue[WindowFeatures] — consumed by WindowSender
    agent_id     : str                  — embedded in every window
    window_size_s: float                — aggregation duration (default 1.0 s)
    """

    def __init__(
        self,
        event_queue:   Queue,
        window_queue:  Queue,
        agent_id:      str,
        window_size_s: float = cli_cfg.window_size_s,
    ) -> None:
        self.event_queue   = event_queue
        self.window_queue  = window_queue
        self.agent_id      = agent_id
        self.window_size   = window_size_s
        self._running      = False
        self.windows_total = 0   # all ticked windows (including empty)
        self.windows_sent  = 0   # non-empty windows pushed to queue

    def start(self) -> None:
        self._running = True
        t = threading.Thread(target=self._loop, daemon=True, name="aggregator")
        t.start()
        logger.info("WindowAggregator started — window=%.1fs agent=%s",
                    self.window_size, self.agent_id)

    def stop(self) -> None:
        self._running = False

    # ── internal ──────────────────────────────────────────────────────────────

    def _loop(self) -> None:
        while self._running:
            now      = time.time()
            boundary = (math.floor(now / self.window_size) + 1) * self.window_size

            window_start = datetime.fromtimestamp(boundary - self.window_size)
            window_end   = datetime.fromtimestamp(boundary)

            # Sleep until the boundary
            wait = boundary - time.time()
            if wait > 0:
                time.sleep(wait)

            # Drain events that belong to this window
            events: list[DomainEvent] = []
            while True:
                try:
                    event = self.event_queue.get_nowait()
                    if event.timestamp.timestamp() < boundary:
                        events.append(event)
                    else:
                        # Belongs to the next window — put it back
                        self.event_queue.put(event)
                        break
                except Empty:
                    break

            self.windows_total += 1

            # ── Drop empty windows completely ─────────────────────────────────
            if not events:
                logger.debug("Window %s→%s empty — skipped.",
                             window_start.strftime("%H:%M:%S"),
                             window_end.strftime("%H:%M:%S"))
                continue

            features = compute_features(
                events=events,
                window_start=window_start,
                window_end=window_end,
                agent_id=self.agent_id,
            )

            domains = list(set(e.domain for e in events))
            self.window_queue.put((features, domains))
            self.windows_sent += 1
            logger.debug("Window %s→%s — %d events queued.",
                         window_start.strftime("%H:%M:%S"),
                         window_end.strftime("%H:%M:%S"),
                         len(events))
