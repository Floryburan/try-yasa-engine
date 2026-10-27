"""Guard experimental labels and evaluation against misleading success counts."""

import copy
import json
import unittest

from laya_evaluate import HERE, PROMPTS, metrics, same_labels


class EvaluationTests(unittest.TestCase):
    def setUp(self):
        self.cases = json.loads((HERE / "experiments/ctfd_balanced_dev_v1.json").read_text())["cases"]

    def test_all_positive_predictor_has_complete_negative_false_positive_rate(self):
        rows = [{"status": "success", "expected_for_review_only": case["expected"],
                 "verdict": {"is_entrypoint": True, "formation_types": ["decorator", "other"],
                             "entrypoint_kind": "http"}} for case in self.cases]
        result = metrics(rows)
        self.assertEqual((result["tp"], result["fp"], result["tn"], result["fn"]), (4, 4, 0, 0))
        self.assertEqual(result["precision"], 0.5)
        self.assertEqual(result["false_positive_rate_on_decided_negatives"], 1)
        self.assertEqual(result["formation_exact_on_all_gold_positives"], 0)

    def test_unknown_and_transport_errors_are_never_true_negatives(self):
        gold = {"is_entrypoint": False, "formation_types": [], "entrypoint_kind": None}
        result = metrics([{"status": "error", "expected_for_review_only": gold},
                          {"status": "success", "expected_for_review_only": gold,
                           "verdict": {"is_entrypoint": None}}])
        self.assertEqual(result["tn"], 0)
        self.assertEqual((result["unknown"], result["errors"]), (1, 1))
        self.assertIsNone(result["false_positive_rate_on_decided_negatives"])

    def test_labels_and_order_stay_identical_and_neutral_key_substitution_is_rejected(self):
        prompts = {name: json.loads(path.read_text()) for name, path in PROMPTS.items()}
        same_labels(prompts["baseline"], prompts["optimized"])
        changed = copy.deepcopy(prompts["optimized"])
        changed["questions"]["is_entrypoint"]["criteria"]["A"] = changed["questions"]["is_entrypoint"]["criteria"].pop("yes")
        with self.assertRaises(ValueError):
            same_labels(prompts["baseline"], changed)


if __name__ == "__main__":
    unittest.main()
