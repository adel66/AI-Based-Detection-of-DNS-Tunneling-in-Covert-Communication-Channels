"""
model/classifier.py
-------------------
Model loading and prediction interface.

Loading priority
----------------
1. DNS_Ensemble_Model  — the primary model (XGBoost + IsolationForest ensemble)
                         loaded from a joblib bundle at MODEL_PATH.
2. HeuristicClassifier — rule-based fallback, always available, no dependencies.

Label convention (matches training data)
-----------------------------------------
    0  →  "benign"
    1  →  "malicious"

The feature vector passed to predict() must be the 19-element list produced by
WindowFeatures.to_vector() / IngestRequest.to_feature_vector(), in the exact
order defined there.  The ensemble model re-orders columns internally via
_ensure_feature_order(X[self.feature_columns]) so column naming is critical.
"""

from __future__ import annotations

import logging
import os
import pickle
from abc import ABC, abstractmethod

from shared.config import worker as worker_cfg

logger = logging.getLogger(__name__)

# Integer → label string (matches training notebook: malicious_traffic 0/1)
_LABEL_MAP: dict[int, str] = {0: "benign", 1: "malicious"}

# The 19 feature column names in the exact order of WindowFeatures.to_vector().
# These names must match the DataFrame columns the ensemble was trained on.
_FEATURE_COLUMNS: list[str] = [
    "query_count",
    "response_count",
    "avg_packet_length",
    "std_packet_length",
    "avg_entropy",
    "max_entropy",
    "avg_qname_len",
    "max_qname_len",
    "avg_digit_ratio",
    "avg_special_ratio",
    "unique_subdomains",
    "unique_qtypes",
    "txt_ratio",
    "large_resp_ratio",
    "avg_ttl",
    "avg_max_label_len",
    "answer_sum",
    "resp_len_avg",
    "event_count",
]


# ── Abstract interface ────────────────────────────────────────────────────────

class BaseClassifier(ABC):

    @abstractmethod
    def predict(self, feature_vector: list[float]) -> tuple[str, float]:
        """
        Classify one window.

        Parameters
        ----------
        feature_vector : list[float]
            19 floats in training tuple order.

        Returns
        -------
        label      : "benign" or "malicious"
        confidence : float 0.0–1.0
        """
        ...


# ── Ensemble model (primary) ──────────────────────────────────────────────────

class DNS_Ensemble_Model:
    """
    XGBoost + IsolationForest weighted ensemble.

    Loaded from a joblib bundle containing:
        xgb_model       — XGBoost classifier
        iso_model       — IsolationForest anomaly detector
        scaler          — fitted StandardScaler
        feature_columns — ordered list of column names (used for alignment)
        weights         — {"xgb": float, "iso": float}
        threshold       — float decision boundary on the ensemble score
    """

    def __init__(self, bundle_path: str) -> None:
        import joblib
        bundle = joblib.load(bundle_path)
        self.xgb             = bundle["xgb_model"]
        self.iso             = bundle["iso_model"]
        self.scaler          = bundle["scaler"]
        self.feature_columns = bundle["feature_columns"]
        self.weights         = bundle["weights"]
        self.threshold       = bundle["threshold"]
        logger.info(
            "Ensemble loaded — threshold=%.4f weights=%s features=%d",
            self.threshold, self.weights, len(self.feature_columns),
        )

    def _ensure_feature_order(self, X):
        """Reorder DataFrame columns to match training order."""
        return X[self.feature_columns]

    @staticmethod
    def _minmax_scale(arr):
        import numpy as np
        arr = np.asarray(arr, dtype=float)
        mn, mx = arr.min(), arr.max()
        if mx - mn == 0:
            return np.zeros_like(arr)
        return (arr - mn) / (mx - mn)

    def predict_score(self, X):
        """Return raw ensemble score (before thresholding)."""
        X        = self._ensure_feature_order(X)
        X_scaled = self.scaler.transform(X)

        xgb_score = self.xgb.predict_proba(X_scaled)[:, 1]

        iso_raw   = self.iso.decision_function(X_scaled)
        iso_score = -iso_raw   # invert: higher = more anomalous

        xgb_score_n = self._minmax_scale(xgb_score)
        iso_score_n = self._minmax_scale(iso_score)

        w_xgb = self.weights["xgb"]
        w_iso  = self.weights["iso"]
        return (w_xgb * xgb_score_n) + (w_iso * iso_score_n)

    def predict(self, X):
        import numpy as np
        scores = self.predict_score(X)
        return (scores >= self.threshold).astype(int)


class EnsembleClassifier(BaseClassifier):
    """
    Wraps DNS_Ensemble_Model to implement the BaseClassifier interface.

    Converts the 19-element feature vector into a named pandas DataFrame
    before calling the ensemble (required by _ensure_feature_order).
    """

    def __init__(self, bundle_path: str) -> None:
        self._model = DNS_Ensemble_Model(bundle_path)

    def predict(self, feature_vector: list[float]) -> tuple[str, float]:
        import pandas as pd
        import numpy as np

        # Build a single-row DataFrame with named columns so the ensemble
        # can reorder via self.feature_columns regardless of our order.
        X = pd.DataFrame([feature_vector], columns=_FEATURE_COLUMNS)

        # Raw score for the single row
        score     = float(self._model.predict_score(X)[0])
        raw_label = int(self._model.predict(X)[0])
        label     = _LABEL_MAP.get(raw_label, "benign")

        # Confidence: distance from threshold, normalised to [0, 1]
        # score is already in [0, 1] range after minmax normalisation
        if raw_label == 1:          # malicious
            confidence = round(min(score, 1.0), 4)
        else:                       # benign
            confidence = round(min(1.0 - score, 1.0), 4)

        logger.debug(
            "Ensemble score=%.4f threshold=%.4f → %s (conf=%.4f)",
            score, self._model.threshold, label, confidence,
        )
        return label, confidence


# ── Heuristic fallback (no external dependencies) ─────────────────────────────

class HeuristicClassifier(BaseClassifier):
    """
    Rule-based classifier using the 19 training features.

    Feature index reference (matches _FEATURE_COLUMNS order):
      0  query_count          10  unique_subdomains
      1  response_count       11  unique_qtypes
      2  avg_packet_length    12  txt_ratio
      3  std_packet_length    13  large_resp_ratio
      4  avg_entropy          14  avg_ttl
      5  max_entropy          15  avg_max_label_len
      6  avg_qname_len        16  answer_sum
      7  max_qname_len        17  resp_len_avg
      8  avg_digit_ratio      18  event_count
      9  avg_special_ratio
    """

    def predict(self, fv: list[float]) -> tuple[str, float]:
        (
            query_count, response_count,
            avg_pkt_len, std_pkt_len,
            avg_entropy, max_entropy,
            avg_qname_len, max_qname_len,
            avg_digit_ratio, avg_special_ratio,
            unique_subdomains, unique_qtypes,
            txt_ratio, large_resp_ratio,
            avg_ttl, avg_max_label_len,
            answer_sum, resp_len_avg,
            event_count,
        ) = fv

        score = 0.0

        # High qname entropy → DGA
        if avg_entropy > 3.8:
            score += 0.30
        elif avg_entropy > 3.2:
            score += 0.15
        if max_entropy > 4.2:
            score += 0.15

        # Long qnames → subdomain tunnelling / exfiltration
        if avg_qname_len > 60:
            score += 0.25
        elif avg_qname_len > 40:
            score += 0.10
        if max_qname_len > 100:
            score += 0.20

        # High digit ratio → DGA
        if avg_digit_ratio > 0.35:
            score += 0.15

        # High special-char ratio → encoding in labels
        if avg_special_ratio > 0.15:
            score += 0.15

        # Large responses → data exfiltration via DNS
        if large_resp_ratio > 0.5:
            score += 0.20
        elif large_resp_ratio > 0.2:
            score += 0.10

        # Many TXT queries → DNS tunnelling
        if txt_ratio > 0.3:
            score += 0.25
        elif txt_ratio > 0.1:
            score += 0.10

        # Many unique subdomains → DGA scatter
        if unique_subdomains > 30:
            score += 0.20
        elif unique_subdomains > 15:
            score += 0.10

        # Very low TTL → fast-flux
        if avg_ttl == 0 and response_count > 0:
            score += 0.15
        elif avg_ttl < 10 and response_count > 0:
            score += 0.08

        # High response size
        if resp_len_avg > 400:
            score += 0.15

        score = min(score, 1.0)

        if score >= 0.40:
            return "malicious", round(score, 4)
        return "benign", round(1.0 - score, 4)


# ── Factory ───────────────────────────────────────────────────────────────────

def load_classifier(model_path: str | None = None) -> BaseClassifier:
    """
    Load the best available classifier in priority order:

    1. EnsembleClassifier  — requires joblib bundle at model_path
    2. HeuristicClassifier — always available, no file needed

    Falls back silently so the system keeps running even if the bundle
    is missing, corrupt, or has incompatible dependencies.

    Parameters
    ----------
    model_path : str or None
        Path to the joblib bundle.  Defaults to worker_cfg.model_path.
    """
    path = model_path or worker_cfg.model_path

    if path and os.path.isfile(path):
        try:
            clf = EnsembleClassifier(path)
            logger.info("Using EnsembleClassifier: %s", path)
            return clf
        except Exception as exc:
            logger.warning(
                "Failed to load ensemble model from '%s': %s — falling back to heuristic.",
                path, exc,
            )

    logger.info("Using HeuristicClassifier (no bundle found at '%s').", path)
    return HeuristicClassifier()