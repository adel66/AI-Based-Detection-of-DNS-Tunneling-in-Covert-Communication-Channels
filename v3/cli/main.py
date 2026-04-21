"""
cli/main.py
-----------
DNS Monitor v3 — entry point.

Pipeline:
    DNSSniffer → DNSParser → WindowAggregator → WindowSender → Dashboard
                                                      ↕ HTTP
                                               FastAPI Gateway

Only non-empty windows (query_count > 0) are sent or displayed.
Full window history is written to dns_windows.tsv.

Usage (requires root):
    sudo python -m cli.main [--iface eth0] [--api http://host:8000]
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
import time
from queue import Queue

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.config import api as api_cfg, cli as cli_cfg
from shared.logging_setup import configure_logging

configure_logging("cli")

import logging
logger = logging.getLogger(__name__)

from cli.sniffer  import DNSSniffer
from cli.parser   import DNSParser
from cli.window   import WindowAggregator
from cli.sender   import WindowSender
from cli.history  import HistoryLogger
from cli.ui       import Dashboard


def _check_root() -> None:
    if os.geteuid() != 0:
        print(
            "\n[ERROR] Root privileges required for packet capture.\n"
            "  Run with: sudo python -m cli.main\n",
            file=sys.stderr,
        )
        sys.exit(1)


def _default_agent_id() -> str:
    return socket.gethostname()


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="dns-monitor",
        description="DNS Monitor v3 — window-based multi-agent pipeline",
    )
    p.add_argument("--iface",  "-i", default=None,                metavar="IF",   help="Network interface (default: all)")
    p.add_argument("--api",    "-a", default=api_cfg.base_url,    metavar="URL",  help=f"API base URL (default: {api_cfg.base_url})")
    p.add_argument("--agent",        default=_default_agent_id(), metavar="ID",   help="Agent identifier (default: hostname)")
    p.add_argument("--window", "-w", default=cli_cfg.window_size_s, type=float,  metavar="S", help="Window size seconds (default: 1.0)")
    p.add_argument("--refresh",      default=cli_cfg.ui_refresh_s,  type=float,  metavar="S", help="UI refresh rate (default: 0.5)")
    p.add_argument("--history",      default="dns_windows.tsv",                  metavar="F", help="History log file (default: dns_windows.tsv)")
    return p.parse_args()


def main() -> None:
    _check_root()
    args = _parse_args()

    logger.info("Starting DNS Monitor — agent=%s iface=%s api=%s",
                args.agent, args.iface or "all", args.api)

    # ── Queues ────────────────────────────────────────────────────────────────
    packet_queue: Queue = Queue(maxsize=5_000)
    event_queue:  Queue = Queue(maxsize=5_000)
    window_queue: Queue = Queue(maxsize=500)

    # ── Components ────────────────────────────────────────────────────────────
    sniffer    = DNSSniffer(packet_queue, iface=args.iface)
    parser     = DNSParser(packet_queue, event_queue)
    aggregator = WindowAggregator(
        event_queue=event_queue,
        window_queue=window_queue,
        agent_id=args.agent,
        window_size_s=args.window,
    )
    history    = HistoryLogger(log_path=args.history)
    dashboard  = Dashboard(
        sniffer_ref=sniffer,
        agent_id=args.agent,
        api_url=args.api,
        refresh_s=args.refresh,
    )

    def _on_result(window_id: str, label: str, confidence: float) -> None:
        dashboard.update_result(window_id, label, confidence)

    sender = WindowSender(
        window_queue=window_queue,
        result_callback=_on_result,
        history_logger=history,
        api_base_url=args.api,
    )

    # Patch sender._send so the dashboard gets the window_id the moment
    # the POST returns — before the poll thread resolves the label.
    _orig_send = sender._send

    def _send_and_register(features):
        window_id = _orig_send(features)
        if window_id:
            dashboard.add_window(features, window_id)
        return window_id

    sender._send = _send_and_register

    # ── Start ─────────────────────────────────────────────────────────────────
    try:
        dashboard.start()
        sniffer.start()
        parser.start()
        aggregator.start()
        sender.start()

        logger.info("All components running.  Press Ctrl+C to stop.")
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        pass

    finally:
        sender.stop()
        aggregator.stop()
        parser.stop()
        sniffer.stop()
        dashboard.stop()
        dashboard.print_summary()


if __name__ == "__main__":
    main()