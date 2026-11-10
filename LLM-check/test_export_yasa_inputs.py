"""The YASA bridge preserves model decisions and rejects stale/incomplete runs."""

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from export_yasa_inputs import export_inputs, sha256


class ExportTests(unittest.TestCase):
    def fixture(self, root):
        ep, src, sink = root / "ep", root / "source", root / "sink"
        ep.mkdir()
        src.mkdir()
        sink.mkdir()
        function = {"id": "f", "name": "handler", "qualified_name": "app.handler", "file": "app.py",
                    "start_line": 1, "start_column": 1, "end_line": 2, "end_column": 12}
        graph = SimpleNamespace(index_hashes={"functions": "frozen"}, repo=root,
                                nodes={"f": function}, tables={"files": [{"file": "app.py", "sha256": "filehash"}]})
        self.write(ep / "manifest.json", {"index_directory": "index", "repository": str(root),
                                          "index_hashes": graph.index_hashes})
        verdict = {"is_entrypoint": True, "formation_types": ["callback", "registration"], "entrypoint_kind": "event"}
        self.write(ep / "prepared.json", [{"case_id": "ep", "function_id": "f", "request_hash": "frozen",
                                           "location": {"file": "app.py", "start_line": 1, "end_line": 2}}])
        self.write(ep / "results.json", [{"case_id": "ep", "function": "app.handler", "status": "success",
                                          "request_hash": "frozen", "verdict": verdict}])
        self.write(src / "manifest.json", {"index_hashes": graph.index_hashes, "cases": [{"case_id": "ep"}],
                                            "jev_predictions_sha256": sha256(ep / "results.json")})
        candidate = {"candidate_id": "c", "owner_id": "f", "owner": "app.handler", "syntax_kind": "parameter",
                     "expression": "request", "location": {"file": "app.py", "start_line": 1,
                     "start_column_utf8": 13, "end_line": 1, "end_column_utf8_exclusive": 20}}
        self.write(src / "prepared.json", [{"request_id": "batch", "case_id": "ep", "request_hash": "source-frozen",
                                             "candidates": [candidate]}])
        self.write(src / "results.json", [{"request_id": "batch", "status": "success", "request_hash": "source-frozen",
            "candidates": [dict(candidate, choice="yes", probabilities={"yes": 0.4, "no": 0.3, "unknown": 0.3},
                                model_confidence=0.1)]}])
        self.write(sink / "manifest.json", {"index_hashes": graph.index_hashes})
        self.write(sink / "results.json", [{"status": "success", "candidate": {"candidate_id": "sink_c", "location": candidate["location"]},
            "verdict": {"is_sink": True, "sink_kind": "other", "sink_answer": {"choice": "yes", "confidence": 0.1},
                        "dangerous_arguments": []}}])
        return ep, src, sink, graph

    @staticmethod
    def write(path, data):
        path.write_text(json.dumps(data))

    def test_preserves_multilabels_probabilities_and_yes_below_half(self):
        with tempfile.TemporaryDirectory() as temp:
            ep, src, sink, graph = self.fixture(Path(temp))
            with patch("export_yasa_inputs.ContextGraph", return_value=graph):
                out = export_inputs(ep, src, sink)
            self.assertEqual(len(out["entrypoints"]), 1)
            self.assertEqual(len(out["sources"]), 1)
            self.assertEqual(out["sources"][0]["probabilities"]["yes"], 0.4)
            self.assertEqual(out["entrypoints"][0]["verdict"]["formation_types"], ["callback", "registration"])
            self.assertTrue(out["entrypoints"][0]["skip_decorators"])
            self.assertEqual(out["schema"], "yasa-llm-input/v2")
            self.assertEqual(out["sinks"][0]["verdict"]["sink_answer"]["confidence"], 0.1)
            self.assertEqual(out["sinks"][0]["verdict"]["dangerous_arguments"], [])

    def test_no_and_unknown_are_not_imported_as_sources(self):
        with tempfile.TemporaryDirectory() as temp:
            ep, src, sink, graph = self.fixture(Path(temp))
            for choice in ("no", "unknown"):
                rows = json.loads((src / "results.json").read_text())
                rows[0]["candidates"][0]["choice"] = choice
                self.write(src / "results.json", rows)
                with patch("export_yasa_inputs.ContextGraph", return_value=graph):
                    self.assertEqual(export_inputs(ep, src, sink)["sources"], [])

    def test_incomplete_source_run_is_an_error_not_a_negative(self):
        with tempfile.TemporaryDirectory() as temp:
            ep, src, sink, graph = self.fixture(Path(temp))
            self.write(src / "results.json", [])
            with patch("export_yasa_inputs.ContextGraph", return_value=graph):
                with self.assertRaisesRegex(ValueError, "unattempted"):
                    export_inputs(ep, src, sink)

    def test_rejects_changed_entrypoint_results_or_candidate_locations(self):
        with tempfile.TemporaryDirectory() as temp:
            ep, src, sink, graph = self.fixture(Path(temp))
            rows = json.loads((src / "results.json").read_text())
            rows[0]["candidates"][0]["location"]["start_line"] = 99
            self.write(src / "results.json", rows)
            with patch("export_yasa_inputs.ContextGraph", return_value=graph):
                with self.assertRaisesRegex(ValueError, "position changed"):
                    export_inputs(ep, src, sink)
            (ep / "results.json").write_text((ep / "results.json").read_text() + "\n")
            with patch("export_yasa_inputs.ContextGraph", return_value=graph):
                with self.assertRaisesRegex(ValueError, "different entrypoint predictions"):
                    export_inputs(ep, src, sink)


if __name__ == "__main__":
    unittest.main()
