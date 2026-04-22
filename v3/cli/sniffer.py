"""
cli/sniffer.py
--------------
Captures UDP/53 DNS query packets using Scapy and pushes them into a
shared queue for downstream processing.

Runs in a dedicated daemon thread so it never blocks the main thread.
Requires root privileges.
"""

from __future__ import annotations

import logging
import threading
from queue import Queue

from scapy.all import DNS, DNSQR, sniff

logger = logging.getLogger(__name__)


class DNSSniffer:
    """
    Wraps Scapy's ``sniff()`` in a background daemon thread.

    Parameters
    ----------
    packet_queue : Queue
        Raw Scapy packets are pushed here for the parser to consume.
    iface : str or None
        Network interface name (e.g. ``"eth0"``).  ``None`` = all interfaces.
    """

    def __init__(self, packet_queue: Queue, iface: str | None = None) -> None:
        self.packet_queue  = packet_queue
        self.iface         = iface
        self.packet_count  = 0          # inspected by the UI for stats
        self._stop_event   = threading.Event()

    # ── public API ────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Spawn the capture thread and return immediately."""
        thread = threading.Thread(
            target=self._capture_loop,
            daemon=True,
            name="sniffer",
        )
        thread.start()
        logger.info("Sniffer started — iface=%s", self.iface or "all")

    def stop(self) -> None:
        """Signal the capture thread to exit cleanly."""
        self._stop_event.set()
        logger.info("Sniffer stop requested.")

    # ── internal ──────────────────────────────────────────────────────────────

    def _capture_loop(self) -> None:
        sniff(
            filter="udp port 53",
            prn=self._on_packet,
            store=False,
            iface=self.iface,
            stop_filter=lambda _: self._stop_event.is_set(),
        )

    def _on_packet(self, packet) -> None:
        """
        Scapy callback — called for every packet matching the BPF filter.
        Only DNS query packets (qr == 0) with a question record are enqueued.
        """
        try:
            if packet.haslayer(DNS) and packet[DNS].qr == 0 and packet.haslayer(DNSQR):
                self.packet_count += 1
                self.packet_queue.put(packet)
        except Exception as exc:
            logger.debug("Packet handling error: %s", exc)
