"""
shared/logging_setup.py
-----------------------
Call ``configure_logging()`` once at the entry point of each service.
All modules then just do ``logger = logging.getLogger(__name__)``.
"""

from __future__ import annotations

import logging
import sys

from shared.config import log as log_cfg


def configure_logging(service_name: str = "") -> None:
    """
    Set up root logger with a stdout handler and a rotating file handler.

    Parameters
    ----------
    service_name : str
        Optional label prepended to the log file name for clarity when
        running multiple services on the same host.
    """
    level = getattr(logging, log_cfg.level.upper(), logging.INFO)

    handlers: list[logging.Handler] = [
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_cfg.file, mode="a", encoding="utf-8"),
    ]

    logging.basicConfig(
        level=level,
        format=log_cfg.fmt,
        handlers=handlers,
    )

    # Suppress noisy third-party loggers
    for noisy in ("kafka", "urllib3", "scapy", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    logging.getLogger(__name__).info(
        "Logging configured — service=%s level=%s", service_name or "?", log_cfg.level
    )
