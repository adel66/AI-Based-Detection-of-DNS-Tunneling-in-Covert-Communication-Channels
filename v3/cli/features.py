"""
cli/features.py
---------------
Computes the exact 19-feature window tuple the model was trained on.

The feature names, order, and computation logic match the training
notebook exactly.  The only omission is the final "malicious" label
column — that is what the model predicts.

Feature tuple (in order)
------------------------
 0  query_count          int    packets where is_response == False
 1  response_count       int    packets where is_response == True
 2  avg_packet_length    float  mean wire length across all packets
 3  std_packet_length    float  std  wire length across all packets
 4  avg_entropy          float  mean per-packet qname entropy
 5  max_entropy          float  max  per-packet qname entropy
 6  avg_qname_len        float  mean qname character length
 7  max_qname_len        float  max  qname character length
 8  avg_digit_ratio      float  mean digit_ratio(qname)
 9  avg_special_ratio    float  mean special_ratio(qname)
10  unique_subdomains    int    distinct subdomain strings
11  unique_qtypes        int    distinct QTYPE integers
12  txt_ratio            float  is_txt packets / total
13  large_resp_ratio     float  is_large_resp packets / total
14  avg_ttl              float  mean per-packet TTL (0 for queries)
15  avg_max_label_len    float  mean max_label_length(qname)
16  answer_sum           int    sum of ancount across all packets
17  resp_len_avg         float  mean response_length (0 for queries)
18  event_count          int    total packets in window
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, asdict
from datetime import datetime

from cli.parser import DomainEvent


# ── Feature dataclass ─────────────────────────────────────────────────────────

@dataclass
class WindowFeatures:
    """
    Exactly the 19 fields the model was trained on (label excluded).
    Field names match the training DataFrame column names 1-to-1.
    """
    # Window metadata — not part of the model input vector
    window_start: datetime
    window_end:   datetime
    agent_id:     str

    # ── 19 model features ──────────────────────────────────────────────────
    query_count:        int   = 0
    response_count:     int   = 0

    avg_packet_length:  float = 0.0
    std_packet_length:  float = 0.0

    avg_entropy:        float = 0.0
    max_entropy:        float = 0.0

    avg_qname_len:      float = 0.0
    max_qname_len:      float = 0.0

    avg_digit_ratio:    float = 0.0
    avg_special_ratio:  float = 0.0

    unique_subdomains:  int   = 0
    unique_qtypes:      int   = 0

    txt_ratio:          float = 0.0
    large_resp_ratio:   float = 0.0

    avg_ttl:            float = 0.0
    avg_max_label_len:  float = 0.0

    answer_sum:         int   = 0
    resp_len_avg:       float = 0.0

    event_count:        int   = 0

    def to_vector(self) -> list[float]:
        """
        Return the 19 features as an ordered float list.
        Order matches the training tuple exactly.
        """
        return [
            float(self.query_count),
            float(self.response_count),
            self.avg_packet_length,
            self.std_packet_length,
            self.avg_entropy,
            self.max_entropy,
            self.avg_qname_len,
            self.max_qname_len,
            self.avg_digit_ratio,
            self.avg_special_ratio,
            float(self.unique_subdomains),
            float(self.unique_qtypes),
            self.txt_ratio,
            self.large_resp_ratio,
            self.avg_ttl,
            self.avg_max_label_len,
            float(self.answer_sum),
            self.resp_len_avg,
            float(self.event_count),
        ]

    def to_dict(self) -> dict:
        """Serialise to plain dict for JSON payload to the API."""
        d = asdict(self)
        d["window_start"] = self.window_start.isoformat()
        d["window_end"]   = self.window_end.isoformat()
        return d


# ── Aggregation ───────────────────────────────────────────────────────────────

def _mean(values: list) -> float:
    return statistics.mean(values) if values else 0.0

def _std(values: list) -> float:
    return statistics.pstdev(values) if len(values) >= 2 else 0.0

def _max(values: list) -> float:
    return float(max(values)) if values else 0.0


def compute_features(
    events:       list[DomainEvent],
    window_start: datetime,
    window_end:   datetime,
    agent_id:     str,
) -> WindowFeatures:
    """
    Compute the 19-feature tuple from all DomainEvent objects in one window.

    Mirrors the training groupby logic:
        query_count  = (g["is_response"] == 0).sum()
        response_count = (g["is_response"] == 1).sum()
        … etc.

    Parameters
    ----------
    events       : all captured packets in the window (must be non-empty)
    window_start : clock-aligned window start
    window_end   : clock-aligned window end
    agent_id     : identifier of this CLI instance
    """
    if not events:
        # Caller (WindowAggregator) already filters empty windows,
        # but guard here for safety.
        return WindowFeatures(
            window_start=window_start,
            window_end=window_end,
            agent_id=agent_id,
        )

    total = len(events)

    # ── Packet type counts ────────────────────────────────────────────────────
    query_count    = sum(1 for e in events if not e.is_response)
    response_count = sum(1 for e in events if e.is_response)

    # ── Packet length ─────────────────────────────────────────────────────────
    pkt_lengths = [e.packet_length for e in events]
    avg_packet_length = _mean(pkt_lengths)
    std_packet_length = _std(pkt_lengths)

    # ── Entropy ───────────────────────────────────────────────────────────────
    entropies   = [e.entropy_val for e in events]
    avg_entropy = _mean(entropies)
    max_entropy = _max(entropies)

    # ── QNAME length ──────────────────────────────────────────────────────────
    q_lens      = [float(e.q_len) for e in events]
    avg_qname_len = _mean(q_lens)
    max_qname_len = _max(q_lens)

    # ── Character ratios ──────────────────────────────────────────────────────
    avg_digit_ratio   = _mean([e.digit_ratio_val   for e in events])
    avg_special_ratio = _mean([e.special_ratio_val for e in events])

    # ── Diversity counts ──────────────────────────────────────────────────────
    unique_subdomains = len(set(e.subdomain   for e in events))
    unique_qtypes     = len(set(e.query_type  for e in events))

    # ── Ratios ────────────────────────────────────────────────────────────────
    txt_ratio        = sum(1 for e in events if e.is_txt)      / total
    large_resp_ratio = sum(1 for e in events if e.is_large_resp) / total

    # ── TTL / answers ─────────────────────────────────────────────────────────
    avg_ttl          = _mean([e.ttl         for e in events])
    avg_max_label_len= _mean([float(e.max_label_len) for e in events])
    answer_sum       = sum(e.answer_count   for e in events)
    resp_len_avg     = _mean([float(e.response_length) for e in events])

    return WindowFeatures(
        window_start=window_start,
        window_end=window_end,
        agent_id=agent_id,

        query_count=query_count,
        response_count=response_count,

        avg_packet_length=avg_packet_length,
        std_packet_length=std_packet_length,

        avg_entropy=avg_entropy,
        max_entropy=max_entropy,

        avg_qname_len=avg_qname_len,
        max_qname_len=max_qname_len,

        avg_digit_ratio=avg_digit_ratio,
        avg_special_ratio=avg_special_ratio,

        unique_subdomains=unique_subdomains,
        unique_qtypes=unique_qtypes,

        txt_ratio=txt_ratio,
        large_resp_ratio=large_resp_ratio,

        avg_ttl=avg_ttl,
        avg_max_label_len=avg_max_label_len,

        answer_sum=answer_sum,
        resp_len_avg=resp_len_avg,

        event_count=total,
    )