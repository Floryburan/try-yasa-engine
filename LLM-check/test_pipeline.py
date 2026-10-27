"""Offline tests for scoped chain extraction, API validation, and resumable runs."""

import argparse
import io
import json
import os
import tempfile
import unittest
from collections import defaultdict
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

from context_graph import ContextGraph, json_text
from entrypoint_check import run
from model_api import ModelClient, ModelError, make_request, read_config, validate_verdict


def context(name="handler"):
    return {"schema_version": 1, "function_id": "function:" + name,
            "target": {"id": "function:" + name, "name": name, "qualified_name": "app." + name,
                       "file": "app.py", "start_line": 1, "end_line": 2},
            "nodes": [], "edges": [], "unresolved": [],
            "coverage": {"full_runtime_chain_proven": False}}


def verdict(ctx, decision=True):
    return {"is_entrypoint": decision, "entrypoint_kinds": ["http"] if decision else [],
            "formation_types": ["registration"] if decision else [], "confidence": 0.8,
            "reason": "测试响应", "evidence": [{"record_id": ctx["target"]["id"], "explanation": "测试证据"}] if decision else [],
            "missing_information": []}


def response(value):
    return io.BytesIO(json.dumps(value).encode())


class ScopedResolutionTests(unittest.TestCase):
    def setUp(self):
        self.graph = ContextGraph.__new__(ContextGraph)
        self.graph.nodes = {}
        self.graph.symbols = defaultdict(list)
        self.graph.members = defaultdict(list)
        self.graph.files = {"a.py": {"module": "a"}, "b.py": {"module": "b"}}
        self.graph.file_modules = {"a.py": "module:a.py", "b.py": "module:b.py"}
        self.add("module:a.py", "module", "a.py", name="a", module="a")
        self.add("module:b.py", "module", "b.py", name="b", module="b")
        self.add("function:a_handler", "functions", "a.py", name="handler")
        self.add("function:b_handler", "functions", "b.py", name="handler")

    def add(self, node_id, record_type, file, scope_id=None, **extra):
        row = dict(id=node_id, record_type=record_type, file=file, scope_id=scope_id, start_line=1, **extra)
        self.graph.nodes[node_id] = row
        name = extra.get("name") or extra.get("local_name")
        if name and record_type != "module":
            self.graph.symbols[(file, scope_id, name)].append(node_id)
        return row

    def test_same_name_in_other_module_does_not_create_edge(self):
        ids, _, _ = self.graph.resolve("handler", "a.py", None)
        self.assertEqual(ids, ["function:a_handler"])

    def test_import_alias_resolves_only_imported_module(self):
        self.add("import:h", "imports", "a.py", local_name="h", imported_name="handler",
                 module="b", absolute_module="b", target_files=["b.py"])
        ids, via, _ = self.graph.resolve("h", "a.py", None)
        self.assertEqual(ids, ["function:b_handler"])
        self.assertIn("import:h", via)

    def test_parameter_shadows_module_function(self):
        self.add("function:outer", "functions", "a.py", name="outer", parameters=[{"name": "handler"}])
        self.add("parameter:outer:handler", "parameter", "a.py", "function:outer", name="handler")
        ids, _, _ = self.graph.resolve("handler", "a.py", "function:outer", 10)
        self.assertEqual(ids, ["parameter:outer:handler"])

    def test_method_does_not_see_bare_class_local_name(self):
        self.add("class:C", "classes", "a.py", name="C")
        self.add("function:C_handler", "functions", "a.py", "class:C", name="handler")
        self.add("function:C_run", "functions", "a.py", "class:C", name="run", kind="method")
        ids, _, _ = self.graph.resolve("handler", "a.py", "function:C_run", 10)
        self.assertEqual(ids, ["function:a_handler"])

    def test_local_assignment_after_call_still_shadows_global(self):
        self.add("function:outer", "functions", "a.py", name="outer")
        row = self.add("assignment:late", "assignments", "a.py", "function:outer", name="handler")
        row["start_line"] = 20
        ids, _, reason = self.graph.resolve("handler", "a.py", "function:outer", 10)
        self.assertEqual(ids, [])
        self.assertEqual(reason, "local_binding_not_initialized")

    def test_dynamic_expression_is_reported_not_guessed(self):
        ids, _, reason = self.graph.resolve("registry[name]", "a.py", None)
        self.assertEqual(ids, [])
        self.assertEqual(reason, "dynamic_expression")

    def test_dotted_module_alias_keeps_full_module_identity(self):
        self.graph.files["pkg/mod.py"] = {"module": "pkg.mod"}
        self.graph.file_modules["pkg/mod.py"] = "module:pkg/mod.py"
        self.add("module:pkg/mod.py", "module", "pkg/mod.py", name="mod", module="pkg.mod")
        self.add("function:mod_handler", "functions", "pkg/mod.py", name="handler")
        self.add("import:m", "imports", "a.py", local_name="m", imported_name=None,
                 module="pkg.mod", absolute_module="pkg.mod", target_files=["pkg/mod.py"])
        ids, _, _ = self.graph.resolve("m.handler", "a.py", None)
        self.assertEqual(ids, ["function:mod_handler"])

    def test_unknown_parameter_callee_is_reference_not_resolved_call(self):
        g = self.graph
        g.outgoing, g.incoming, g.edges = defaultdict(list), defaultdict(list), {}
        self.add("function:outer", "functions", "a.py", name="outer")
        self.add("parameter:f", "parameter", "a.py", "function:outer", name="f")
        self.add("call:f", "calls", "a.py", "function:outer")
        g.link_reference("call:f", "f", "calls", "call:f")
        self.assertEqual(g.outgoing['call:f'][0]['relation'], 'callee_reference')

    def test_context_budget_and_no_dangling_graph_edges(self):
        g = self.graph
        g.summary = {"commit": "test"}
        g.tables = {"functions": []}
        g.outgoing, g.incoming = defaultdict(list), defaultdict(list)
        g.edges, g.unresolved = {}, defaultdict(list)
        target = g.nodes["function:a_handler"]
        target.update(source="def handler():\n    pass\n", qualified_name="a.handler")
        g.tables["functions"].append(target)
        for n in range(20):
            row = self.add("call:" + str(n), "calls", "a.py", "function:a_handler", source="x" * 1000)
            g.edge(row["id"], target["id"], "executed_within", row["id"])
        for budget in range(4000, 4200, 7):
            result = g.context(target, max_depth=3, max_nodes=10, max_chars=budget, source_chars=500)
            self.assertLessEqual(len(json_text(result)), budget)
            self.assertTrue(result["coverage"]["budget_exhausted"])
            ids = {target["id"]} | {r["id"] for r in result["nodes"]}
            for edge in result["edges"]:
                self.assertIn(edge["source"], ids)
                self.assertIn(edge["target"], ids)
                self.assertIn(edge["evidence_id"], ids)


class VerdictTests(unittest.TestCase):
    def test_reject_invented_evidence(self):
        ctx = context()
        value = verdict(ctx)
        value["evidence"][0]["record_id"] = "function:invented"
        with self.assertRaises(ModelError):
            validate_verdict(value, ctx)

    def test_uncertainty_is_distinct_from_negative(self):
        ctx = context()
        value = verdict(ctx, None)
        self.assertIsNone(validate_verdict(value, ctx)["is_entrypoint"])

    def test_positive_requires_evidence_and_types(self):
        ctx = context()
        value = verdict(ctx)
        value["evidence"] = []
        with self.assertRaises(ModelError):
            validate_verdict(value, ctx)

    def test_reject_numeric_boolean_and_nan_confidence(self):
        for field, invalid in (("is_entrypoint", 1), ("confidence", float("nan"))):
            ctx = context()
            value = verdict(ctx)
            value[field] = invalid
            with self.assertRaises(ModelError):
                validate_verdict(value, ctx)


class APIPipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.config_file = self.directory / "config.json"
        self.config_file.write_text(json.dumps({"api_url": "http://127.0.0.1:9123/v1/chat/completions", "model": "test-model", "retries": 0}))
        self.env = patch.dict(os.environ, {"LLM_API_KEY": "unit-test-secret", "LLM_API_URL": "", "LLM_MODEL": ""})
        self.env.start()
        self.requests = []

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def mock_http(self, req, **kwargs):
        self.requests.append(req)
        payload = json.loads(req.data)
        ctx = json.loads(payload["messages"][1]["content"])
        result = {"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(verdict(ctx))}}],
                  "usage": {"total_tokens": 10}}
        return response(result)

    def args(self, contexts, dry_run=False):
        path = self.directory / "contexts.jsonl"
        path.write_text("".join(json_text(c) + "\n" for c in contexts))
        return argparse.Namespace(config=self.config_file, contexts=path, out=self.directory / "predictions.jsonl",
                                  workers=2, function=[], limit=None, dry_run=dry_run, no_resume=False)

    def invoke(self, args):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return run(args)

    def test_http_payload_concurrent_results_and_resume(self):
        args = self.args([context("one"), context("two")])
        with patch("model_api.request.urlopen", side_effect=self.mock_http):
            self.assertEqual(self.invoke(args), 0)
            self.assertEqual(self.invoke(args), 0)
        self.assertEqual(len(self.requests), 2)
        self.assertEqual(self.requests[0].get_header("Authorization"), "Bearer unit-test-secret")
        text = args.out.read_text()
        self.assertNotIn("unit-test-secret", text)
        self.assertEqual(len(text.splitlines()), 2)
        summary = json.loads(args.out.with_suffix(".summary.json").read_text())
        self.assertEqual(summary["results"]["resumed"], 2)

    def test_model_change_invalidates_cached_results(self):
        args = self.args([context()])
        with patch("model_api.request.urlopen", side_effect=self.mock_http):
            self.invoke(args)
            config = json.loads(self.config_file.read_text())
            config["model"] = "another-model"
            self.config_file.write_text(json.dumps(config))
            self.invoke(args)
        self.assertEqual(len(self.requests), 2)

    def test_resume_recovers_incomplete_final_write(self):
        args = self.args([context("one")])
        with patch("model_api.request.urlopen", side_effect=self.mock_http):
            self.invoke(args)
            with args.out.open("ab") as stream:
                stream.write(b'{"status":')
            args = self.args([context("one"), context("two")])
            self.assertEqual(self.invoke(args), 0)
        self.assertTrue(args.out.with_suffix(".jsonl.incomplete-tail").exists())
        self.assertEqual(len(args.out.read_text().splitlines()), 2)

    def test_dry_run_cannot_overwrite_model_results(self):
        args = self.args([context()])
        with patch("model_api.request.urlopen", side_effect=self.mock_http):
            self.invoke(args)
        args.dry_run = True
        with self.assertRaises(ValueError):
            self.invoke(args)

    def test_dry_run_makes_no_request_and_needs_no_key(self):
        args = self.args([context()], dry_run=True)
        with patch.dict(os.environ, {"LLM_API_KEY": ""}), patch("model_api.request.urlopen", side_effect=AssertionError("network forbidden")):
            self.assertEqual(self.invoke(args), 0)
        self.assertEqual(json.loads(args.out.read_text())["status"], "dry_run")

    def test_error_is_not_negative_and_is_retried_on_resume(self):
        args = self.args([context()])
        with patch("model_api.request.urlopen", return_value=response({"choices": []})):
            self.assertEqual(self.invoke(args), 1)
        error_row = json.loads(args.out.read_text())
        self.assertEqual(error_row["status"], "error")
        self.assertNotIn("verdict", error_row)
        with patch("model_api.request.urlopen", side_effect=self.mock_http):
            self.assertEqual(self.invoke(args), 0)
        self.assertEqual(len(self.requests), 1)

    def test_retry_429_and_fail_fast_for_401(self):
        config = read_config(self.config_file)
        config["retries"] = 1
        client = ModelClient(config)
        ctx = context()
        good = {"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(verdict(ctx))}}]}
        with patch("model_api.request.urlopen", side_effect=[HTTPError(config["api_url"], 429, "rate limited", {}, None), response(good)]), patch("model_api.time.sleep"):
            self.assertEqual(client.classify(ctx, make_request(ctx, config))["attempts"], 2)
        with patch("model_api.request.urlopen", side_effect=HTTPError(config["api_url"], 401, "secret echoed by server", {}, None)) as http:
            with self.assertRaisesRegex(ModelError, "HTTP 401"):
                client.classify(ctx, make_request(ctx, config))
            self.assertEqual(http.call_count, 1)


if __name__ == "__main__":
    unittest.main()
