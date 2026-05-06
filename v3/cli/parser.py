"""
cli/parser.py
-------------
Consumes raw Scapy packets, extracts every field needed to reconstruct
the exact per-packet row the model was trained on, and emits DomainEvent
objects into the event queue.

Per-packet fields captured
--------------------------
domain          str   normalised qname (lowercase, no trailing dot)
timestamp       datetime
is_response     bool  DNS qr flag: False=query, True=response
packet_length   int   total wire length of the packet
q_len           int   length of the raw qname string
entropy_val     float Shannon entropy of the qname characters
digit_ratio_val float fraction of digits in qname
special_ratio_val float fraction of non-alphanumeric chars in qname
query_type      int   QTYPE integer (A=1, AAAA=28, TXT=16, MX=15, …)
is_txt          bool  query_type == 16
subdomain       str   everything left of the last two labels
max_label_len   int   length of the longest dot-separated label
ttl             float mean TTL across all answer records (0 if no answers)
answer_count    int   DNS ancount field
response_length int   packet length if is_response else 0
is_large_resp   bool  response_length > 300
"""

from __future__ import annotations

import logging
import math
import threading
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from queue import Empty, Queue

from scapy.all import DNS, DNSQR, DNSRR

logger = logging.getLogger(__name__)

# Matches the training notebook's response_length > 300 feature.
_LARGE_RESP_THRESHOLD = 300


# ── Helper functions (exact match to AI team's implementation) ────────────────

def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    probs  = [v / len(s) for v in counts.values()]
    return -sum(p * math.log2(p) for p in probs)


def digit_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(c.isdigit() for c in s) / len(s)


def special_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(not c.isalnum() for c in s) / len(s)


def max_label_length(s: str) -> int:
    if not s:
        return 0
    return max(len(x) for x in s.split("."))


def extract_subdomain(s: str) -> str:
    parts = s.split(".")
    return ".".join(parts[:-2]) if len(parts) >= 3 else ""


# ── Per-packet data model ─────────────────────────────────────────────────────

@dataclass(slots=True)
class DomainEvent:
    """One captured DNS packet with all fields required by the feature tuple."""
    domain:             str
    timestamp:          datetime
    is_response:        bool
    packet_length:      int
    q_len:              int
    entropy_val:        float
    digit_ratio_val:    float
    special_ratio_val:  float
    query_type:         int
    is_txt:             bool
    subdomain:          str
    max_label_len:      int
    ttl:                float   # mean TTL across answer records, 0 if none
    answer_count:       int
    response_length:    int     # packet_length if response, else 0
    is_large_resp:      bool


# ── Packet extraction ─────────────────────────────────────────────────────────

def _extract_event(packet) -> DomainEvent | None:
    """
    Pull every required field from a Scapy DNS packet.
    Returns None if the packet lacks a DNSQR layer or the qname is empty.
    """
    try:
        if not packet.haslayer(DNS):
            return None

        dns = packet[DNS]
        qr  = bool(dns.qr)   # False = query, True = response

        # qname — need at least a question record
        if not packet.haslayer(DNSQR):
            return None

        raw_qname = packet[DNSQR].qname
        domain    = (
            raw_qname.decode("utf-8", errors="replace")
            if isinstance(raw_qname, bytes) else raw_qname
        ).rstrip(".").lower().strip()

        if not domain:
            return None

        pkt_len  = len(packet)
        q_len    = len(domain)
        q_type   = int(packet[DNSQR].qtype)

        # Answer-record TTL: mean across all RRs in the answer section
        ttl_val      = 0.0
        answer_count = int(dns.ancount)
        if answer_count > 0:
            ttls = []
            try:
                rr = dns.an
                while rr and isinstance(rr, DNSRR):
                    ttls.append(rr.ttl)
                    rr = rr.payload
            except Exception:
                pass
            ttl_val = sum(ttls) / len(ttls) if ttls else 0.0

        resp_len      = pkt_len if qr else 0
        is_large_resp = resp_len > _LARGE_RESP_THRESHOLD

        #print("subdoamin: "+domain)

        return DomainEvent(
            domain=domain,
            timestamp=datetime.now(),
            is_response=qr,
            packet_length=pkt_len,
            q_len=q_len,
            entropy_val=entropy(domain),
            digit_ratio_val=digit_ratio(domain),
            special_ratio_val=special_ratio(domain),
            query_type=q_type,
            is_txt=(q_type == 16),
            subdomain=extract_subdomain(domain),
            max_label_len=max_label_length(domain),
            ttl=ttl_val,
            answer_count=answer_count,
            response_length=resp_len,
            is_large_resp=is_large_resp,
        )

    except Exception as exc:
        logger.debug("Packet extraction error: %s", exc)
        return None


# ── Parser thread ─────────────────────────────────────────────────────────────

class DNSParser:
    """
    Reads raw packets from packet_queue, extracts DomainEvent objects,
    and writes them to event_queue.

    Parameters
    ----------
    packet_queue : Queue   — source, filled by DNSSniffer
    event_queue  : Queue   — sink, consumed by WindowAggregator
    """

    def __init__(self, packet_queue: Queue, event_queue: Queue) -> None:
        self.packet_queue = packet_queue
        self.event_queue  = event_queue
        self._running     = False

    def start(self) -> None:
        self._running = True
        t = threading.Thread(target=self._loop, daemon=True, name="parser")
        t.start()
        logger.info("Parser started.")

    def stop(self) -> None:
        self._running = False

    def _loop(self) -> None:
        while self._running:
            try:
                packet = self.packet_queue.get(timeout=0.3)
            except Empty:
                continue

            event = _extract_event(packet)
            if event is not None:
                self.event_queue.put(event)
                logger.debug("Parsed: %s (resp=%s type=%d)",
                             event.domain, event.is_response, event.query_type)
