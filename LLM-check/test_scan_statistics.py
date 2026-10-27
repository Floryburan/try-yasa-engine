"""Usage counts use real attempts, missing telemetry and frozen source scope."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scan_statistics import duration, source_statistics, usage_totals


class ScanStatisticsTests(unittest.TestCase):
    def test_actual_usage_derived_totals_and_missing_fields(self):
        stats = usage_totals([
            {"http_status": 200, "usage": {"input_tokens": 100, "output_tokens": 4}, "elapsed_seconds": .1},
            {"http_status": 200, "usage": {"input_tokens": 50}, "elapsed_seconds": .2},
            {"http_status": 429, "usage": None, "elapsed_seconds": .3},
            {"http_status": None, "usage": None, "elapsed_seconds": .4}])
        self.assertEqual((stats["attempts"], stats["http_successes"], stats["http_errors"], stats["transport_errors"]), (4, 2, 1, 1))
        self.assertEqual((stats["input_tokens"], stats["output_tokens"], stats["total_tokens"]), (150, 4, 104))
        self.assertEqual(stats["responses_missing_output_tokens"], 1)
        self.assertEqual(stats["responses_missing_total_tokens"], 1)
        self.assertEqual(stats["latency_p70_p99_max_ms"], [300, 400, 400])
        self.assertEqual(stats["latency_avg_ms"], 250)

    def test_business_file_counts_require_matching_frozen_index(self):
        with tempfile.TemporaryDirectory() as directory:
            index = Path(directory)
            data = "\n".join(json.dumps(f) for f in (
                {"file": "app.py", "area": "application", "lines": 30},
                {"file": "tests/test_app.py", "area": "tests", "lines": 100})).encode()
            (index / "files.jsonl").write_bytes(data)
            manifest = {"index_directory": str(index), "index_hashes": {"files": hashlib.sha256(data).hexdigest()},
                        "selection": {"area": "application"}}
            stats = source_statistics(manifest, [{"location": {"file": "app.py"}}])
            self.assertEqual((stats["files_in_scope"], stats["source_lines_in_scope"]), (1, 30))
            manifest["index_hashes"]["files"] = "stale"
            self.assertIsNone(source_statistics(manifest, [])["source_lines_in_scope"])

    def test_duration_carries_rounding_into_seconds_and_minutes(self):
        self.assertEqual(duration(9041.485), "150m41s485ms")
        self.assertEqual(duration(59.9999), "1m0s000ms")
        self.assertEqual(usage_totals([])["input_tokens"], 0)


if __name__ == "__main__":
    unittest.main()
