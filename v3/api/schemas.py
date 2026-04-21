"""
api/schemas.py
--------------
Pydantic v2 models for all API request/response payloads.

IngestRequest field names match the training DataFrame column names
exactly so the CLI's WindowFeatures.to_dict() serialises directly
into a valid request body with no transformation needed.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator


# ── Classification labels ──────────────────────────────────────────────────────
# Model outputs: 0 = benign, 1 = malicious

Label = Literal["benign", "malicious", "pending", "unknown"]


# ── POST /ingest ──────────────────────────────────────────────────────────────

class IngestRequest(BaseModel):
    """
    One window's 19-feature tuple as sent by the CLI.
    All feature names match the training notebook column names.
    """

    # Window metadata
    window_start: datetime
    window_end:   datetime
    agent_id:     str = Field(..., min_length=1, max_length=128)

    # ── 19 model features (in training tuple order) ───────────────────────────
    query_count:        int   = Field(0, ge=0)
    response_count:     int   = Field(0, ge=0)

    avg_packet_length:  float = Field(0.0, ge=0.0)
    std_packet_length:  float = Field(0.0, ge=0.0)

    avg_entropy:        float = Field(0.0, ge=0.0)
    max_entropy:        float = Field(0.0, ge=0.0)

    avg_qname_len:      float = Field(0.0, ge=0.0)
    max_qname_len:      float = Field(0.0, ge=0.0)

    avg_digit_ratio:    float = Field(0.0, ge=0.0, le=1.0)
    avg_special_ratio:  float = Field(0.0, ge=0.0, le=1.0)

    unique_subdomains:  int   = Field(0, ge=0)
    unique_qtypes:      int   = Field(0, ge=0)

    txt_ratio:          float = Field(0.0, ge=0.0, le=1.0)
    large_resp_ratio:   float = Field(0.0, ge=0.0, le=1.0)

    avg_ttl:            float = Field(0.0, ge=0.0)
    avg_max_label_len:  float = Field(0.0, ge=0.0)

    answer_sum:         int   = Field(0, ge=0)
    resp_len_avg:       float = Field(0.0, ge=0.0)

    event_count:        int   = Field(0, ge=0)

    @field_validator("window_end")
    @classmethod
    def end_after_start(cls, v: datetime, info) -> datetime:
        start = info.data.get("window_start")
        if start and v <= start:
            raise ValueError("window_end must be after window_start")
        return v

    def to_feature_vector(self) -> list[float]:
        """
        Ordered list of 19 floats matching the training tuple column order.
        Passed directly to model.predict().
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


class IngestResponse(BaseModel):
    window_id: str
    status:    str = "queued"


# ── GET /result/{window_id} ───────────────────────────────────────────────────

class ResultResponse(BaseModel):
    window_id:  str
    label:      Label
    confidence: float = Field(0.0, ge=0.0, le=1.0)


# ── GET /health ───────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status:         str
    kafka:          str
    redis:          str
    uptime_seconds: float