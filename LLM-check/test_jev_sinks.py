"""Call-site context, sink roles, checkpoints and failure semantics."""

import ast
import hashlib
import io
import json
import tempfile
import unittest
from collections import defaultdict
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from context_graph import ContextGraph
from jev_sinks import PIPELINE, classify, digest, plan_hash, prepare, questions_for, run
from sink_context import SinkContext, dotted

HERE = Path(__file__).resolve().parent
PROMPT = json.loads((HERE / "prompts/sink_jev_v1.json").read_text())


def graph_fixture(root, text):
    (root / "app.py").write_text(text, encoding="utf-8")
    tree = ast.parse(text)
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    graph = ContextGraph.__new__(ContextGraph)
    graph.repo, graph.index_dir, graph.summary, graph.index_hashes = root, root / "index", {"commit": "fixture"}, {}
    file = {"file": "app.py", "area": "application", "module": "app", "lines": len(text.splitlines()),
            "sha256": hashlib.sha256(text.encode()).hexdigest()}
    graph.files, graph.file_modules = {"app.py": file}, {"app.py": "module:app.py"}
    graph.nodes = {"module:app.py": dict(file, id="module:app.py", record_type="module")}
    graph.symbols, graph.members = defaultdict(list), defaultdict(list)
    graph.incoming, graph.outgoing = defaultdict(list), defaultdict(list)
    graph.tables = {key: [] for key in ("functions", "classes", "imports", "calls", "assignments")}
    graph.tables["files"] = [file]
    definitions = {}

    def scope(node):
        child, node = node, parents.get(node)
        while node:
            if node in definitions and child in node.body:
                return definitions[node]["id"]
            child, node = node, parents.get(node)
        return None

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        table = "classes" if isinstance(node, ast.ClassDef) else "functions"
        outer = scope(node)
        row = {"id": node.name + ":" + str(node.lineno), "name": node.name, "qualified_name": "app." + node.name,
               "record_type": table, "scope_id": outer, "file": "app.py", "area": "application",
               "start_line": node.lineno, "end_line": node.end_lineno, "origin": "source_definition",
               "source": ast.get_source_segment(text, node), "decorators": []}
        if table == "functions":
            row["kind"] = "method" if outer and graph.nodes[outer]["record_type"] == "classes" else "function"
        definitions[node] = row
        graph.nodes[row["id"]] = row
        graph.tables[table].append(row)
        graph.symbols[("app.py", outer, node.name)].append(row["id"])
        if outer:
            graph.members[(outer, node.name)].append(row["id"])
        if table == "functions":
            params = node.args.posonlyargs + node.args.args + node.args.kwonlyargs + [p for p in (node.args.vararg, node.args.kwarg) if p]
            for param in params:
                parameter_id = "param:" + row["id"] + ":" + param.arg
                graph.nodes[parameter_id] = {"id": parameter_id, "name": param.arg, "record_type": "parameter",
                                             "scope_id": row["id"], "file": "app.py", "start_line": param.lineno}
                graph.symbols[("app.py", row["id"], param.arg)].append(parameter_id)
    assignment_nodes = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                local = alias.asname or (alias.name if isinstance(node, ast.ImportFrom) else alias.name.split(".")[0])
                row = {"id": "import:" + local + ":" + str(node.lineno), "record_type": "imports", "local_name": local,
                       "file": "app.py", "scope_id": scope(node), "start_line": node.lineno, "end_line": node.end_lineno,
                       "module": node.module if isinstance(node, ast.ImportFrom) else alias.name,
                       "imported_name": alias.name if isinstance(node, ast.ImportFrom) else None, "target_files": []}
                graph.nodes[row["id"]] = row
                graph.tables["imports"].append(row)
                graph.symbols[("app.py", row["scope_id"], local)].append(row["id"])
        if isinstance(node, ast.Assign):
            for target in node.targets:
                name = dotted(target)
                if not name:
                    continue
                row = {"id": "assign:" + name + ":" + str(node.lineno), "record_type": "assignments", "target": name,
                       "scope_id": scope(node), "file": "app.py", "start_line": node.lineno, "end_line": node.end_lineno}
                graph.nodes[row["id"]] = row
                graph.tables["assignments"].append(row)
                graph.symbols[("app.py", row["scope_id"], name)].append(row["id"])
                assignment_nodes[row["id"]] = node

    def uast(node):
        if isinstance(node, ast.Name):
            return {"type": "Identifier", "name": node.id}
        if isinstance(node, ast.Attribute):
            return {"type": "MemberAccess", "object": uast(node.value), "property": {"type": "Identifier", "name": node.attr}}
        return {"type": "Literal"}
    graph.ast_node = lambda row: {"right": uast(assignment_nodes[row["id"]].value)}
    # Real exported index rows get record_type only in graph.nodes.
    for table in ('functions', 'classes'):
        graph.tables[table] = [{k: v for k, v in row.items() if k != 'record_type'} for row in graph.tables[table]]
    return graph


class SinkContextTests(unittest.TestCase):
    def test_large_function_keeps_exact_call_options_and_bindings_without_whole_body(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            text = "import subprocess as sp\ndef handler(data):\n    cmd = data\n"
            text += "".join("    irrelevant_{} = {}\n".format(i, i) for i in range(400))
            text += "    return sp.run(cmd, shell=True, timeout=5)\n"
            builder = SinkContext(graph_fixture(root, text), max_state_chars=5000)
            call = next(c for c in builder.inventory() if c["callee"] == "sp.run")
            context = builder.build(call, PROMPT)
            self.assertIn('sp.run(cmd, shell=True, timeout=5)', context["state"])
            self.assertIn('import subprocess as sp', context["state"])
            self.assertIn('cmd = data', context["state"])
            self.assertNotIn('irrelevant_399', context["state"])
            self.assertLessEqual(len(context["state"]), 5000)
            self.assertTrue(context["coverage"]["target_call_complete"])
            self.assertFalse(context["coverage"]["whole_function_included"])
            self.assertEqual([a["name"] for a in call["arguments"]], [None, 'shell', 'timeout', None])

    def test_local_wrapper_implementation_and_imports_are_visible(self):
        with tempfile.TemporaryDirectory() as temp:
            graph = graph_fixture(Path(temp), 'import os\ndef launch(cmd):\n    os.system(cmd)\ndef handler(data):\n    launch(data)\n')
            builder = SinkContext(graph)
            call = next(c for c in builder.inventory() if c["callee"] == 'launch')
            context = builder.build(call, PROMPT)
            self.assertIn('def launch(cmd):', context["state"])
            self.assertIn('os.system(cmd)', context["state"])
            self.assertTrue(any(b["role"] == 'local_callee_complete' for b in context["blocks"]))
            self.assertIn('import os', context["state"])

    def test_shadowing_and_lambda_do_not_pull_in_same_named_global_import(self):
        with tempfile.TemporaryDirectory() as temp:
            graph = graph_fixture(Path(temp), 'from dangerous import open\ndef handler(open):\n    open("x")\n    return lambda open: open("y")\n')
            builder = SinkContext(graph)
            calls = [c for c in builder.inventory() if c["callee"] == 'open']
            self.assertEqual(len(calls), 2)
            for call in calls:
                context = builder.build(call, PROMPT)
                self.assertNotIn('from dangerous import open', context["state"])
            self.assertTrue(any(r["reason"] == 'lambda_parameter' for r in builder.build(calls[1], PROMPT)["unresolved"]))

    def test_defaults_execute_in_outer_scope_and_ast_positions_deduplicate(self):
        with tempfile.TemporaryDirectory() as temp:
            graph = graph_fixture(Path(temp), 'def handler(value=build()):\n    return str(value)\n')
            graph.tables["calls"] = [{"id": "synthetic1"}, {"id": "synthetic2"}]
            builder = SinkContext(graph)
            calls = builder.inventory()
            self.assertEqual(len(calls), 2)
            default = next(c for c in calls if c["callee"] == 'build')
            self.assertIsNone(default["scope_id"])
            self.assertTrue(default["owner"].endswith('.<module>'))
            self.assertEqual(len({c["candidate_id"] for c in calls}), 2)

    def test_unicode_offsets_starred_arguments_and_oversize_are_explicit(self):
        with tempfile.TemporaryDirectory() as temp:
            text = 'def handler(parts, options):\n    label = "你好"; call(*parts, shell=True, **options)\n'
            builder = SinkContext(graph_fixture(Path(temp), text), max_state_chars=1)
            call = builder.inventory()[0]
            self.assertEqual(call['location']['start_column_utf8'], len(text.splitlines()[1].split('call(')[0].encode()) + 1)
            self.assertEqual([a['kind'] for a in call['arguments']], ['starred', 'keyword', 'keyword_expansion'])
            context = builder.build(call, PROMPT)
            self.assertTrue(context['coverage']['character_budget_exceeded'])
            self.assertIn(call['expression'], context['state'])
            self.assertTrue(all(b['required'] for b in context['blocks']))

    def test_reparsed_file_keeps_control_context_and_lambda_scope(self):
        with tempfile.TemporaryDirectory() as temp:
            graph = graph_fixture(Path(temp), 'from dangerous import open\ndef handler(flag):\n    if flag:\n        return lambda open: open("x")\n')
            builder = SinkContext(graph)
            call = builder.inventory()[0]
            builder.compact.syntax.cache_clear()  # Simulate file eviction in a repository scan.
            context = builder.build(call, PROMPT)
            self.assertIn('if flag:', context['state'])
            self.assertNotIn('from dangerous import open', context['state'])
            self.assertTrue(any(r['reason'] == 'lambda_parameter' for r in context['unresolved']))

    def test_real_source_alias_recovers_import_when_old_uast_spelling_is_wrong(self):
        with tempfile.TemporaryDirectory() as temp:
            graph = graph_fixture(Path(temp), 'from subprocess import run as execute\ndef handler(cmd):\n    execute(cmd, shell=True)\n')
            row = graph.tables['imports'][0]
            graph.symbols[('app.py', None, 'execute')].clear()
            row['local_name'] = 'run'
            graph.symbols[('app.py', None, 'run')].append(row['id'])
            builder = SinkContext(graph)
            context = builder.build(builder.inventory()[0], PROMPT)
            self.assertIn('from subprocess import run as execute', context['state'])
            self.assertTrue(any(r['via'] for r in context['resolutions'] if r['reference'] == 'execute'))


class SinkRunTests(unittest.TestCase):
    def fixture(self, root, count=1, budget=16000):
        text = 'import os\n' + ''.join('def handler{}(cmd):\n    os.system(cmd)\n'.format(i) for i in range(count))
        graph = graph_fixture(root, text)
        args = SimpleNamespace(out=root / 'out', jev_run=None, index=root / 'index', repo=root,
            env_file=root / '.env', area='application', function=[], candidate=[], limit=None,
            max_state_chars=budget, max_dependencies=10, dependency_depth=2, max_callees=2,
            max_callee_lines=100, max_uses=2, question_batch_size=8, workers=1, retries=0, timeout=10)
        settings = {'base_url': 'https://api.example.test', 'model': 'jev-test', 'api_key': 'test-private-key'}
        with patch('jev_sinks.ContextGraph', return_value=graph), patch('jev_sinks.read_settings', return_value=settings), redirect_stdout(io.StringIO()):
            self.assertEqual(prepare(args), 0)
        return args, settings

    @staticmethod
    def raw(item, choice='yes'):
        answers = {}
        for qid, question in item['payload']['questions'].items():
            selected = ('command_execution' if qid == 'sink_kind' else 'no' if qid == 'role_receiver' else choice)
            n = len(question['criteria'])
            probabilities = {key: (0.4 if key == selected else 0.6 / (n - 1)) for key in question['criteria']}
            answers[qid] = {'type': 'choice', 'choice': selected, 'probabilities': probabilities, 'confidence': 0.1}
        return {'answers': answers, 'model': 'jev-test', 'usage': {'input_tokens': 30, 'output_tokens': 5}}

    def test_preserves_low_probability_yes_roles_and_raw_verified_resume(self):
        with tempfile.TemporaryDirectory() as temp:
            args, settings = self.fixture(Path(temp))
            calls = []
            def api(item, *unused):
                calls.append(item)
                raw = self.raw(item)
                record = {k: item[k] for k in ('request_id', 'case_id', 'function', 'request_hash')}
                record.update(status='success', usage=raw['usage'], model='jev-test', elapsed_seconds=0.1)
                return record, raw, [{'status': 'success', 'http_status': 200, 'elapsed_seconds': 0.1, 'usage': raw['usage']}]
            with patch('jev_sinks.read_settings', return_value=settings), patch('jev_sinks.api_request', side_effect=api), redirect_stdout(io.StringIO()):
                self.assertEqual(run(args), 0)
                self.assertEqual(len(calls), 2)
                rows = json.loads((args.out / 'results.json').read_text())
                self.assertTrue(rows[0]['verdict']['is_sink'])
                self.assertEqual(rows[0]['verdict']['sink_answer']['probabilities']['yes'], 0.4)
                self.assertEqual([a['selector'] for a in rows[0]['verdict']['dangerous_arguments']], ['positional_0'])
                # A derived result is not authoritative; replay the raw answers.
                rows[0]['verdict']['is_sink'] = False
                (args.out / 'results.json').write_text(json.dumps(rows))
                self.assertEqual(run(args), 0)
                self.assertEqual(len(calls), 2)
                self.assertTrue(json.loads((args.out / 'results.json').read_text())[0]['verdict']['is_sink'])
                summary = json.loads((args.out / 'summary.json').read_text())
                self.assertEqual(summary['last_invocation']['http_attempts'], 0)
                self.assertEqual(summary['saved_total_tokens'], 70)
                # Corrupt raw file: matching case ID alone is not a valid cache.
                raw_path = next((args.out / 'responses').glob('*detect.json'))
                raw_path.write_text('{}')
                self.assertEqual(run(args), 0)
                self.assertEqual(len(calls), 3)
            for path in args.out.rglob('*.json'):
                self.assertNotIn('test-private-key', path.read_text())

    def test_unknown_does_not_trigger_classification_and_oversize_never_calls_api(self):
        with tempfile.TemporaryDirectory() as temp:
            args, settings = self.fixture(Path(temp))
            def api(item, *unused):
                raw = self.raw(item, 'unknown')
                return {'status': 'success', 'request_hash': item['request_hash']}, raw, []
            with patch('jev_sinks.read_settings', return_value=settings), patch('jev_sinks.api_request', side_effect=api) as transport, redirect_stdout(io.StringIO()):
                self.assertEqual(run(args), 0)
                self.assertEqual(transport.call_count, 1)
                self.assertIsNone(json.loads((args.out / 'results.json').read_text())[0]['verdict']['is_sink'])
        with tempfile.TemporaryDirectory() as temp:
            args, settings = self.fixture(Path(temp), budget=1)
            with patch('jev_sinks.read_settings', return_value=settings), patch('jev_sinks.api_request') as transport, redirect_stdout(io.StringIO()):
                self.assertEqual(run(args), 1)
                self.assertEqual(transport.call_count, 0)
                self.assertEqual(json.loads((args.out / 'results.json').read_text())[0]['status'], 'blocked_oversized')

    def test_service_restriction_stops_remaining_candidates(self):
        with tempfile.TemporaryDirectory() as temp:
            args, settings = self.fixture(Path(temp), count=3)
            def api(item, *unused):
                return {'status': 'error', 'request_hash': item['request_hash'], 'error': 'HTTP 451'}, None, [
                    {'status': 'error', 'http_status': 451, 'elapsed_seconds': 0.1}]
            with patch('jev_sinks.read_settings', return_value=settings), patch('jev_sinks.api_request', side_effect=api) as transport, redirect_stdout(io.StringIO()):
                self.assertEqual(run(args), 1)
                self.assertEqual(transport.call_count, 1)
            summary = json.loads((args.out / 'summary.json').read_text())
            self.assertEqual(summary['failed'], 1)
            self.assertEqual(summary['not_attempted'], 2)

    def test_real_transport_rejects_reported_truncation(self):
        with tempfile.TemporaryDirectory() as temp:
            args, settings = self.fixture(Path(temp))
            class Opener:
                def open(self, request, timeout):
                    raw = SinkRunTests.raw({'payload': json.loads(request.data)})
                    raw['usage']['truncated'] = True
                    return io.BytesIO(json.dumps(raw).encode())
            with patch('jev_sinks.read_settings', return_value=settings), \
                    patch('jev_source_scan.request.build_opener', return_value=Opener()), redirect_stdout(io.StringIO()):
                self.assertEqual(run(args), 1)
            row = json.loads((args.out / 'results.json').read_text())[0]
            self.assertEqual(row['status'], 'error')
            self.assertNotIn('verdict', row)
            self.assertIn('truncated', row['error'])


if __name__ == '__main__':
    unittest.main()
