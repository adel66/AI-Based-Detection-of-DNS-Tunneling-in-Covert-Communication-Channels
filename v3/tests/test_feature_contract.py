from unittest import TestCase

from shared.feature_contract import FEATURE_FIELDS, FEATURE_KEYS, build_feature_vector


def _sample_features() -> dict:
    return {
        "query_count": 10,
        "response_count": 8,
        "avg_packet_length": 91.2,
        "std_packet_length": 12.4,
        "avg_entropy": 3.7,
        "max_entropy": 4.5,
        "avg_qname_len": 48.1,
        "max_qname_len": 110,
        "avg_digit_ratio": 0.2,
        "avg_special_ratio": 0.08,
        "unique_subdomains": 7,
        "unique_qtypes": 3,
        "txt_ratio": 0.3,
        "large_resp_ratio": 0.1,
        "avg_ttl": 60,
        "avg_max_label_len": 18.2,
        "answer_sum": 9,
        "resp_len_avg": 140.5,
        "event_count": 18,
    }


class FeatureContractTest(TestCase):
    def test_api_and_worker_share_the_same_19_feature_contract(self):
        self.assertEqual(set(FEATURE_KEYS), FEATURE_FIELDS)
        self.assertEqual(len(FEATURE_KEYS), 19)

        features = _sample_features()
        self.assertEqual(set(features), FEATURE_FIELDS)

        vector = build_feature_vector(features)

        self.assertEqual(len(vector), 19)
        self.assertEqual(vector[0], 10)
        self.assertEqual(vector[18], 18)

    def test_worker_rejects_old_or_incomplete_feature_schema(self):
        with self.assertRaisesRegex(ValueError, "Missing feature fields"):
            build_feature_vector(
                {
                    "query_count": 10,
                    "unique_domain_count": 7,
                    "domain_entropy": 3.9,
                    "mean_vowel_ratio": 0.2,
                }
            )
