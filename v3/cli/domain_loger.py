from __future__ import annotations

import threading
from pathlib import Path
from datetime import datetime


class DomainLogger:
    def __init__(self, path: str = "domainlogs.txt") -> None:
        self._path = Path(path)
        self._lock = threading.Lock()

    def log_window(
        self,
        timestamp: datetime,
        agent_id: str,
        domains: list[str],
        label: str,
        confidence: float,
    ) -> None:
        if not domains:
            return

        header = (
            f"=== WINDOW {timestamp.strftime('%Y-%m-%d %H:%M:%S')} "
            f"| agent={agent_id} "
            f"| label={label} ({confidence:.2f}) ===\n"
        )

        with self._lock:
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(header)
                for d in domains:
                    f.write(d + "\n")
                f.write("\n")
