"""Check source provenance, profile union and source experiment checkpoints."""

import ast
import io
import json
import tempfile
import unittest
from collections import defaultdict
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from context_graph import fingerprint
from laya_smoke import write_json
from laya_sources import prepare, run
from source_context import SourceContext, enumerate_candidates


class SourceContextTests(unittest.TestCase):
    def fixture(self, repo):
        source = ('def wrap(fn):\n    return fn\n'
                  'def read_payload(request):\n    return request.get_json()\n'
                  'def register(fn):\n    return fn\n'
                  '@wrap\ndef handler(request: "Request"):\n'
                  '    data = read_payload(request)\n'
                  '    def ignored():\n        return request.secret\n'
                  '    return data["value"]\n'
                  'register(handler)\n')
        (repo / 'app.py').write_text(source)
        tree = ast.parse(source)
        nodes = {}
        for node in tree.body:
            if not isinstance(node, ast.FunctionDef):
                continue
            first = min([node.lineno] + [d.lineno for d in node.decorator_list])
            nodes[node.name] = dict(id=node.name, record_type='functions', file='app.py',
                scope_id=None, area='application', name=node.name, qualified_name='app.' + node.name,
                start_line=node.lineno, end_line=node.end_lineno,
                source=''.join(source.splitlines(keepends=True)[first - 1:node.end_lineno]))
        nodes['use'] = dict(id='use', record_type='calls', file='app.py', scope_id=None,
                            area='application', start_line=13, end_line=13, source='register(handler)')
        incoming, outgoing = defaultdict(list), defaultdict(list)
        incoming['handler'].append(dict(source='use', target='handler', relation='argument_reference'))
        outgoing['use'].append(dict(source='use', target='register', relation='calls'))
        def resolve(name, file, scope, line=None):
            return ([name], [], 'resolved') if name in nodes else ([], [], 'external_or_dynamic')
        graph = SimpleNamespace(repo=repo, nodes=nodes, incoming=incoming, outgoing=outgoing,
                                resolve=resolve, members=defaultdict(list))
        return SourceContext(graph), nodes['handler']

    def test_multilabel_profiles_union_deduplicate_and_keep_generic_helpers(self):
        with tempfile.TemporaryDirectory() as directory:
            builder, target = self.fixture(Path(directory))
            context = builder.build(target, ['registration', 'callback', 'decorator'])
            self.assertIn('read_payload', context['helper_ids'])
            registrar = [b for b in context['blocks'] if b.get('record_id') == 'register']
            self.assertEqual(len(registrar), 1)
            self.assertEqual(set(registrar[0]['profiles']), {'registration', 'callback'})
            self.assertTrue(any(b.get('record_id') == 'wrap' for b in context['blocks']))
            positions = [(b['file'], line) for b in context['blocks']
                         for line in range(b['start_line'], b['end_line'] + 1)]
            self.assertEqual(len(positions), len(set(positions)))
            self.assertEqual(len(context['candidates']), len({c['candidate_id'] for c in context['candidates']}))

    def test_exact_parameter_and_call_positions_exclude_nested_bodies(self):
        with tempfile.TemporaryDirectory() as directory:
            builder, target = self.fixture(Path(directory))
            candidates = enumerate_candidates(builder.compact, target)
            param = next(c for c in candidates if c['syntax_kind'] == 'parameter')
            self.assertEqual(param['expression'], 'request')
            self.assertEqual(param['location']['end_column_utf8_exclusive'] - param['location']['start_column_utf8'], 7)
            self.assertNotIn('request.secret', {c['expression'] for c in candidates})
            self.assertIn('data["value"]', {c['expression'] for c in candidates})
            helper = enumerate_candidates(builder.compact, builder.graph.nodes['read_payload'])
            self.assertIn('request.get_json()', {c['expression'] for c in helper})
            self.assertNotIn('request.get_json', {c['expression'] for c in helper})
            self.assertTrue(all('choice' not in c and 'source_probability' not in c for c in candidates))

    def test_empty_labels_still_expand_and_candidate_omissions_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            builder, target = self.fixture(Path(directory))
            builder.max_candidates = 2
            context = builder.build(target, [])
            self.assertEqual(context['profiles'], {'generic': 'generic input evidence'})
            self.assertIn('read_payload', context['helper_ids'])
            self.assertEqual(len(context['candidates']), 2)
            self.assertGreater(len(context['omitted_candidates']), 0)
            self.assertEqual(next(b['source'] for b in context['blocks'] if b['role'] == 'target'), target['source'])

    def test_token_budget_removes_helper_candidates_but_preserves_complete_target(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            builder, target = self.fixture(repo)
            graph = builder.graph
            graph.index_hashes, graph.summary, graph.index_dir = {}, {'commit': 'test'}, repo / 'index'
            jev = repo / 'jev'
            write_json(jev / 'manifest.json', {'index_directory': str(graph.index_dir),
                'repository': str(repo), 'index_hashes': {}, 'repository_commit': 'test'})
            write_json(jev / 'prepared.json', [{'case_id': 'fn', 'function_id': 'handler',
                'definition_identity': ['app.py', 'handler'], 'definition_alias_ids': ['handler'],
                'request_hash': 'frozen', 'payload': {'state': 'saved Jev input'}}])
            write_json(jev / 'results.json', [{'case_id': 'fn', 'function': 'app.handler', 'status': 'success',
                'request_hash': 'frozen', 'verdict': {'is_entrypoint': True, 'formation_types': [], 'entrypoint_kind': 'http'}}])
            args = SimpleNamespace(out=repo / 'out', jev_run=jev, function=['app.handler'], limit=8,
                max_helpers=6, max_helper_lines=100, max_candidates=64, batch_size=4,
                max_len=512, model='multilingual', url='http://127.0.0.1:8001', tokenizer=repo / 'tokenizer')
            def budget(payload, tokenizer):
                if 'def read_payload(' in payload['state']:
                    raise ValueError('Input would be truncated or options collapsed: candidate')
                return {qid: {'sequence_tokens': 500} for qid in payload['questions']}
            with patch('laya_sources.ContextGraph', return_value=graph), \
                    patch('laya_sources.token_audit', side_effect=budget), redirect_stdout(io.StringIO()):
                self.assertEqual(prepare(args), 0)
            context = json.loads((args.out / 'contexts/fn.json').read_text())
            self.assertGreater(len(context['omitted_token_blocks']), 0)
            self.assertTrue(all(c['owner_id'] == 'handler' for c in context['selected_candidates']))
            requests = json.loads((args.out / 'prepared.json').read_text())
            self.assertTrue(all(target['source'].rstrip() in r['payload']['state'] for r in requests))
            self.assertFalse(json.loads((args.out / 'manifest.json').read_text())['ground_truth_used'])


class SourceRunTests(unittest.TestCase):
    def test_model_choice_is_preserved_and_resume_reuses_verified_raw_response(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            url = 'http://127.0.0.1:8001'
            payload = {'state': 'target', 'questions': {'c': {'type': 'choice',
                       'criteria': {'yes': 'source', 'no': 'internal', 'unknown': 'missing'}}}}
            item = {'request_id': 'r', 'case_id': 'fn', 'function': 'app.handler',
                    'payload': payload, 'request_hash': fingerprint({'url': url, 'payload': payload}),
                    'candidates': [{'candidate_id': 'c', 'expression': 'data.get("k")',
                                    'location': {'file': 'app.py', 'start_line': 2, 'start_column_utf8': 1}}]}
            write_json(out / 'prepared.json', [item])
            write_json(out / 'preparation-errors.json', [])
            write_json(out / 'manifest.json', {'mode': 'formation_guided_source_pilot_v1', 'url': url,
                'tokenizer': 'unused', 'selected_entrypoints': 1, 'prepared_entrypoints': 1,
                'cases': [{'omitted_candidates': 0}]})
            raw = {'answers': {'c': {'type': 'choice', 'choice': 'unknown',
                   'probabilities': {'yes': 0.2, 'no': 0.1, 'unknown': 0.7}, 'confidence': 0.27}}}
            class FakeOpener:
                posts = 0
                def open(self, req, timeout):
                    if req.full_url.endswith('/health'):
                        return io.BytesIO(b'{"status":"ok"}')
                    self.posts += 1
                    return io.BytesIO(json.dumps(raw).encode())
            opener = FakeOpener()
            args = SimpleNamespace(out=out, timeout=10)
            with patch('laya_sources.request.build_opener', return_value=opener), \
                    patch('laya_sources.token_audit', return_value={}), redirect_stdout(io.StringIO()):
                self.assertEqual(run(args), 0)
                self.assertEqual(run(args), 0)
            self.assertEqual(opener.posts, 1)
            result = json.loads((out / 'candidate-results.json').read_text())[0]
            self.assertEqual(result['choice'], 'unknown')
            self.assertEqual(result['source_probability'], 0.2)
            self.assertEqual(result['model_confidence'], 0.27)
            self.assertEqual(json.loads((out / 'possible-sources.json').read_text()), [])
            self.assertEqual(json.loads((out / 'last-invocation.json').read_text())['requests_reused'], 1)
            # Changing the raw checkpoint invalidates reuse, even when request
            # hashes still match; keep the actual fresh model answer unchanged.
            raw_path = out / 'responses/r.json'
            tampered = json.loads(raw_path.read_text())
            tampered['answers']['c']['choice'] = 'yes'
            write_json(raw_path, tampered)
            with patch('laya_sources.request.build_opener', return_value=opener), \
                    patch('laya_sources.token_audit', return_value={}), redirect_stdout(io.StringIO()):
                self.assertEqual(run(args), 0)
            self.assertEqual(opener.posts, 2)
            # Editing a prepared request invalidates its frozen hash.
            item['payload']['state'] = 'changed'
            write_json(out / 'prepared.json', [item])
            with patch('laya_sources.request.build_opener', return_value=opener), redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(ValueError, 'Prepared payload changed'):
                    run(args)


if __name__ == '__main__':
    unittest.main()
