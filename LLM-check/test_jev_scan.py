"""Repository scans keep unknown/error separate and resume partial model work."""

import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.error import HTTPError

from context_graph import fingerprint
from jev_scan import HERE, report_scan
from laya_evaluate import run
from laya_smoke import write_json


class RepositoryScanTests(unittest.TestCase):
    def fixture(self, out):
        prompt = json.loads((HERE / "prompts/entrypoint_compact_v1.json").read_text())
        prepared = []
        for name in ("handler", "helper"):
            payload = {"model": "jev-latest", "state": name, "questions": prompt["questions"]}
            prepared.append({"case_id": name, "function_id": name, "function": "app." + name,
                             "location": {"file": "app.py", "start_line": 1, "end_line": 2},
                             "variant": "jev_compact", "payload": payload, "request_hash": fingerprint(payload)})
        write_json(out / "prepared.json", prepared)
        write_json(out / "manifest.json", {
            "mode": "repository_scan", "provider": "jev", "url": "https://example.test",
            "question_batch_size": 1, "selected_functions": 3, "preparation_errors": 1,
            "selection": {"area": "all", "max_uses": 6}, "experiment_description": "Unlabelled scan"})
        return prepared

    def test_partial_classification_resumes_stages_without_gold_labels(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            self.fixture(out)
            sent = []
            fail_once = [True]

            def open_request(req, timeout):
                payload = json.loads(req.data)
                qids = list(payload["questions"])
                sent.append((payload["state"], qids))
                if qids == ["formation_inheritance"] and fail_once[0]:
                    fail_once[0] = False
                    raise HTTPError(req.full_url, 429, "rate limited", {}, io.BytesIO(b'{}'))
                answers = {}
                for qid, question in payload["questions"].items():
                    choice = ("http" if qid == "entrypoint_kind" else
                              "yes" if payload["state"] == "handler" and qid in {"is_entrypoint", "formation_registration"} else "no")
                    answers[qid] = {"type": "choice", "choice": choice,
                                    "probabilities": {label: float(label == choice) for label in question["criteria"]}}
                return io.BytesIO(json.dumps({"answers": answers, "usage": {"input_tokens": 20, "output_tokens": 2}}).encode())

            opener = SimpleNamespace(open=open_request)
            args = SimpleNamespace(out=out, url="https://example.test", question_batch_size=1, timeout=10)
            with patch("jev_config.read_settings", return_value={"api_key": "test-key"}), \
                 patch("laya_evaluate.request.build_opener", return_value=opener):
                self.assertEqual(run(args), 1)
                self.assertEqual(len(sent), 4)
                self.assertEqual(run(args), 0)
                self.assertEqual(len(sent), 11)
                stats = json.loads((out / "terminal-statistics.json").read_text())
                self.assertEqual(stats["last_invocation"]["usage"]["attempts"], 7)
                self.assertEqual(stats["last_invocation"]["usage"]["input_tokens"], 140)
                self.assertEqual(stats["last_invocation"]["resumed_functions"], 1)
                self.assertEqual(stats["saved_result_usage"]["input_tokens"], 200)
                self.assertEqual(stats["saved_result_usage"]["total_tokens"], 220)
                # Completed functions cause no further network calls.
                self.assertEqual(run(args), 0)
                self.assertEqual(len(sent), 11)
                stats = json.loads((out / "terminal-statistics.json").read_text())
                self.assertEqual(stats["last_invocation"]["usage"]["attempts"], 0)
                self.assertEqual(stats["last_invocation"]["usage"]["input_tokens"], 0)
                self.assertEqual(stats["saved_result_usage"]["total_tokens"], 220)
            summary = json.loads((out / "scan-summary.json").read_text())
            self.assertEqual((summary["entrypoints"], summary["non_entrypoints"]), (1, 1))
            self.assertEqual(summary["preparation_errors"], 1)
            self.assertFalse(summary["has_ground_truth"])
            self.assertNotIn("accuracy", summary)
            self.assertEqual(json.loads((out / "entrypoints.json").read_text())[0]["function_id"], "handler")

    def test_unknown_error_and_unattempted_are_not_negative_predictions(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            self.fixture(out)
            unknown = {"case_id": "handler", "variant": "jev_compact", "status": "success",
                       "function": "app.handler", "verdict": {"is_entrypoint": None}}
            summary = report_scan(out, [unknown])
            self.assertEqual((summary["unknown"], summary["non_entrypoints"], summary["not_attempted_functions"]), (1, 0, 1))
            error = {"case_id": "helper", "variant": "jev_compact", "status": "error", "error": "HTTP 429"}
            summary = report_scan(out, [unknown, error])
            self.assertEqual((summary["request_failed_functions"], summary["non_entrypoints"]), (1, 0))


if __name__ == "__main__":
    unittest.main()
