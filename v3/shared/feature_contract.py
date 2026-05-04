"""Shared 19-feature contract used by the API, worker, and model wrapper."""

FEATURE_KEYS: tuple[str, ...] = (
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
)

FEATURE_FIELDS: set[str] = set(FEATURE_KEYS)


def build_feature_vector(features: dict) -> list[float]:
    """Build the ordered 19-feature vector, failing fast on schema drift."""
    missing = [key for key in FEATURE_KEYS if key not in features]
    if missing:
        raise ValueError(f"Missing feature fields: {', '.join(missing)}")

    return [float(features[key]) for key in FEATURE_KEYS]
