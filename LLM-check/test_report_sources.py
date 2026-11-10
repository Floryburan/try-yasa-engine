"""Ensure report extraction uses explicit source evidence and retains links."""

import ast
import tempfile
import unittest
from pathlib import Path

from extract_report_sources import SourceReader, explicit_source, extract


def step(uri, line=1, first=14, last=19, expression="value", tag="SOURCE"):
    return {"location": {"physicalLocation": {"artifactLocation": {"uri": uri},
        "region": {"startLine": line, "endLine": line, "startColumn": first, "endColumn": last,
                   "snippet": {"text": f"  {line}: {tag}: def endpoint(value):\n", "affectedNodeName": expression}}}}}


def finding(steps, name="endpoint"):
    return {"entrypoint": {"filePath": "/app.py", "functionName": name, "type": "functionCall"},
            "sinkInfo": {"sinkRule": "open", "sinkAttribute": ["PythonPathTraversal"]},
            "codeFlows": [{"threadFlows": [{"locations": steps}]}]}


class ReportSourceTests(unittest.TestCase):
    def test_only_explicit_source_markers_are_accepted(self):
        self.assertIsNone(explicit_source(step("file:///app.py", tag="CALL")))
        self.assertIsNone(explicit_source({"location": {"physicalLocation": {"region": {"snippet": {
            "text": '  1: CALL: print("SOURCE: user text")'}}}}}))
        self.assertEqual(explicit_source(step("file:///app.py")), "yasa_source_trace_tag")
        self.assertEqual(explicit_source({"kinds": ["source"]}), "structured_kind")

    def test_same_source_is_deduplicated_but_each_finding_and_entrypoint_is_retained(self):
        with tempfile.TemporaryDirectory() as folder:
            repo = Path(folder)
            (repo / "app.py").write_text("def endpoint(value):\n    return value\n")
            s = step("file:///app.py")
            document = {"runs": [{"results": [finding([step("file:///app.py", tag="CALL"), s]), finding([s], "another")]}]}
            sources, occurrences, findings, unresolved, eps, threads = extract(document, repo, "reporthash")
        self.assertEqual((len(sources), len(occurrences), len(findings), len(eps), threads), (1, 2, 2, 2, 2))
        self.assertFalse(unresolved)
        self.assertEqual(sources[0]["finding_count"], 2)
        self.assertEqual(sources[0]["reported_entrypoint_count"], 2)
        self.assertEqual(occurrences[0]["step_index"], 1)
        self.assertEqual(sources[0]["enclosing_function"], "app.endpoint")
        self.assertEqual(sources[0]["source_expression_text"], "value")
        self.assertEqual(sources[0]["syntax_kind"], "parameter")
        self.assertIsNone(sources[0]["matched_source_rule"])

    def test_first_trace_step_is_never_silently_used_as_source(self):
        with tempfile.TemporaryDirectory() as folder:
            data = extract({"runs": [{"results": [finding([step("file:///app.py", tag="CALL")])]}]}, Path(folder), "r")
        self.assertEqual(len(data[0]), 0)
        self.assertEqual(len(data[3]), 1)
        self.assertEqual(data[2][0]["source_ids"], [])

    def test_different_source_ranges_are_not_merged(self):
        with tempfile.TemporaryDirectory() as folder:
            data = extract({"runs": [{"results": [finding([step("file:///app.py"), step("file:///app.py", first=25, last=30)])]}]}, Path(folder), "r")
        self.assertEqual(len(data[0]), 2)
        self.assertEqual(len(data[2][0]["source_ids"]), 2)
        self.assertTrue(all(s["source_resolution"] == "unresolved_file" for s in data[0]))

    def test_paths_stay_within_repo_and_uri_encoding_is_decoded(self):
        with tempfile.TemporaryDirectory() as folder:
            repo = Path(folder)
            (repo / "my file.py").write_text("pass\n")
            reader = SourceReader(repo)
            self.assertEqual(reader.resolve_file("file:///my%20file.py"), "my file.py")
            self.assertIsNone(reader.resolve_file("file:///../../etc/passwd"))
            self.assertIsNone(reader.resolve_file("https://example.com/my%20file.py"))

    def test_utf8_columns_and_enclosing_class_method_are_preserved(self):
        with tempfile.TemporaryDirectory() as folder:
            repo = Path(folder)
            text = 'class Handler:\n    def get(self):\n        value = "中文"; read_input()\n'
            (repo / "app.py").write_text(text)
            call = next(n for n in ast.walk(ast.parse(text)) if isinstance(n, ast.Call))
            loc = {"reported_uri": "file:///app.py", "start_line": call.lineno, "end_line": call.end_lineno,
                   "start_column": call.col_offset + 1, "end_column": call.end_col_offset + 1}
            value = SourceReader(repo).enrich(loc)
        self.assertEqual(value["source_expression_text"], "read_input()")
        self.assertEqual(value["enclosing_function"], "app.Handler.get")
        self.assertEqual(value["syntax_kind"], "call_return_value")


if __name__ == "__main__":
    unittest.main()
