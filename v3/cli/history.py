"""
cli/history.py
--------------
Appends one classified window per line to a TSV file.
Column names match the training DataFrame exactly.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path

from cli.features import WindowFeatures

logger = logging.getLogger(__name__)

_HEADER = "\t".join([
    "window_end", "agent_id", "label", "confidence",
    "query_count", "response_count",
    "avg_packet_length", "std_packet_length",
    "avg_entropy", "max_entropy",
    "avg_qname_len", "max_qname_len",
    "avg_digit_ratio", "avg_special_ratio",
    "unique_subdomains", "unique_qtypes",
    "txt_ratio", "large_resp_ratio",
    "avg_ttl", "avg_max_label_len",
    "answer_sum", "resp_len_avg",
    "event_count",
])


class HistoryLogger:
    def __init__(self, log_path: str = "dns_windows.tsv") -> None:
        self._path = Path(log_path)
        self._lock = threading.Lock()
        if not self._path.exists() or self._path.stat().st_size == 0:
            with open(self._path, "w", encoding="utf-8") as f:
                f.write(_HEADER + "\n")

    def log(self, f: WindowFeatures, label: str, confidence: float) -> None:
        row = "\t".join(str(v) for v in [
            f.window_end.strftime("%Y-%m-%d %H:%M:%S"),
            f.agent_id, label, f"{confidence:.4f}",
            f.query_count, f.response_count,
            f"{f.avg_packet_length:.2f}", f"{f.std_packet_length:.2f}",
            f"{f.avg_entropy:.4f}", f"{f.max_entropy:.4f}",
            f"{f.avg_qname_len:.2f}", f"{f.max_qname_len:.2f}",
            f"{f.avg_digit_ratio:.4f}", f"{f.avg_special_ratio:.4f}",
            f.unique_subdomains, f.unique_qtypes,
            f"{f.txt_ratio:.4f}", f"{f.large_resp_ratio:.4f}",
            f"{f.avg_ttl:.2f}", f"{f.avg_max_label_len:.2f}",
            f.answer_sum, f"{f.resp_len_avg:.2f}",
            f.event_count,
        ])
        with self._lock:
            try:
                with open(self._path, "a", encoding="utf-8") as fh:
                    fh.write(row + "\n")
            except OSError as exc:
                logger.warning("History write failed: %s", exc)