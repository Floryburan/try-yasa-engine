"""Source references use syntax/bindings, and metrics keep unknown out of TN."""

import ast
import json
import tempfile
import unittest
from collections import defaultdict
from pathlib import Path
from types import SimpleNamespace

from build_source_reference import SourceReference, export_inventory
from evaluate_source_reference import report_source_match, score
from laya_smoke import write_json
from source_context import enumerate_candidates


class SourceReferenceTests(unittest.TestCase):
    def fixture(self, root, carrier=False):
        text = ('from flask import request as rq\n'
                '@web.route("/<int:item>")\n'
                'def endpoint(item, request):\n'
                '    data = rq.get_json()\n'
                '    query = rq.args.get("q")\n'
                '    value = data["x"]\n'
                '    other = request.get_json()\n'
                '    return str(value)\n')
        (root / 'app.py').write_text(text)
        fn = dict(id='f', record_type='functions', name='endpoint', qualified_name='app.endpoint',
            file='app.py', scope_id=None, start_line=3, end_line=8, area='application', source=''.join(text.splitlines(keepends=True)[1:]))
        imported = dict(id='import', record_type='imports', file='app.py', start_line=1, end_line=1,
                        module='flask', absolute_module='flask', imported_name='request', local_name='rq')
        def resolve(name, file, scope, line=None):
            return ([], ['import'], 'external') if name == 'rq' else ([], [], 'unresolved')
        graph = SimpleNamespace(repo=root, nodes={'f': fn, 'import': imported}, resolve=resolve,
                                members=defaultdict(list), incoming=defaultdict(list), outgoing=defaultdict(list))
        ep = {'function_id': 'f', 'is_entrypoint': True,
              'subtypes': ['challenge_plugin_method' if carrier else 'flask_route'], 'evidence': []}
        ref = SourceReference(graph, [ep])
        cs = enumerate_candidates(ref.builder, fn)
        return ref, cs

    def test_alias_import_route_binding_and_local_propagation_are_distinguished(self):
        with tempfile.TemporaryDirectory() as directory:
            ref, cs = self.fixture(Path(directory))
            rows = {c['expression']: ref.judge(c) for c in cs}
            self.assertTrue(rows['item']['is_source'])
            self.assertTrue(rows['rq.get_json()']['is_source'])
            self.assertTrue(rows['rq.args']['is_source'])
            self.assertTrue(rows['rq.args.get("q")']['is_source'])
            self.assertFalse(rows['data["x"]']['is_source'])
            self.assertFalse(rows['str(value)']['is_source'])
            self.assertIsNone(rows['request']['is_source'])
            self.assertIsNone(rows['request.get_json()']['is_source'])

    def test_request_carrier_policy_difference_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            ref, cs = self.fixture(Path(directory), carrier=True)
            rows = {c['expression']: ref.judge(c) for c in cs}
            self.assertTrue(rows['request']['is_source'])
            self.assertFalse(rows['request.get_json()']['is_source'])
            self.assertTrue(rows['request.get_json()']['request_read_policy_is_source'])

    def test_inventory_strips_predictions_and_does_not_require_results_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = {'candidate_id': 'c', 'owner_id': 'f', 'owner': 'app.f', 'syntax_kind': 'parameter',
                         'expression': 'x', 'location': {'file': 'app.py', 'start_line': 1}}
            write_json(root / 'run/manifest.json', {'repository': 'repo', 'repository_commit': 'commit',
                'index_directory': 'index', 'index_hashes': {}})
            write_json(root / 'run/prepared.json', [{'case_id': 'fn', 'function': 'app.f',
                'jev_verdict': {'is_entrypoint': True}, 'candidates': [candidate]}])
            rows = export_inventory(root / 'run', root / 'inventory')
            self.assertEqual(rows, [candidate])
            saved = (root / 'inventory/candidates.jsonl').read_text()
            self.assertNotIn('jev_verdict', saved)
            self.assertNotIn('probabilities', saved)
            self.assertFalse(json.loads((root / 'inventory/manifest.json').read_text())['source_verdicts_read'])


class SourceMetricTests(unittest.TestCase):
    def test_unknown_reference_excluded_and_model_unknown_not_counted_as_tn(self):
        rows = [{'is_source': True, 'prediction': 'yes'}, {'is_source': True, 'prediction': 'no'},
                {'is_source': True, 'prediction': 'unknown'}, {'is_source': False, 'prediction': 'no'},
                {'is_source': False, 'prediction': 'yes'}, {'is_source': False, 'prediction': 'unknown'},
                {'is_source': None, 'prediction': 'yes'}]
        m = score(rows)
        self.assertEqual((m['tp'], m['fp'], m['fn_decided'], m['tn']), (1, 1, 1, 1))
        self.assertEqual(m['reference_unknown_excluded'], 1)
        self.assertAlmostEqual(m['accuracy'], 2 / 6)
        self.assertAlmostEqual(m['precision'], 1 / 2)
        self.assertAlmostEqual(m['recall'], 1 / 3)
        self.assertAlmostEqual(m['f1'], 0.4)
        self.assertAlmostEqual(m['balanced_accuracy'], 1 / 3)
        self.assertEqual(m['predicted_yes_with_unknown_reference'], 1)

    def test_yasa_unlisted_positions_do_not_become_false_positives_or_tn(self):
        loc = {'file': 'app.py', 'start_line': 1, 'end_line': 1, 'start_column_utf8': 3, 'end_column_utf8_exclusive': 4}
        c = {'candidate': {'candidate_id': 'c', 'location': loc}, 'prediction': 'yes'}
        source = {'source_id': 's', 'file': 'app.py', 'start_line': 1, 'end_line': 1,
                  'start_column': 3, 'end_column': 4, 'source_expression_text': 'x', 'finding_count': 1}
        m = report_source_match([source], {'c': c})
        self.assertEqual(m['counts'], {'yes': 1})
        self.assertIsNone(m['accuracy'])
        self.assertIsNone(m['precision'])


if __name__ == '__main__':
    unittest.main()
