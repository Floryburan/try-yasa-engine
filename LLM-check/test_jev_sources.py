"""Jev replays frozen source evidence without credentials or Laya outputs."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.error import HTTPError

from context_graph import fingerprint
from jev_sources import prepare
from laya_smoke import write_json
from laya_sources import read, run


class JevSourceTests(unittest.TestCase):
    def fixture(self, root, count=1):
        source, out = root / 'source', root / 'jev'
        url = 'http://127.0.0.1:8001'
        payload = {'model': 'multilingual', 'max_len': 3072, 'head_max_len': 256, 'state': 'COMPLETE SOURCE',
                   'questions': {'c': {'type': 'choice', 'instructions': 'Exact original question',
                                      'criteria': {'unknown': 'missing', 'yes': 'external', 'no': 'internal'}}}}
        items = [{'request_id': 'r' + str(i), 'case_id': 'fn', 'function': 'app.handler',
                  'payload': payload, 'token_audit': {'c': {'sequence_tokens': 99}},
                  'request_hash': fingerprint({'url': url, 'payload': payload}),
                  'candidates': [{'candidate_id': 'c', 'owner': 'app.handler', 'expression': 'request.args',
                                  'location': {'file': 'app.py', 'start_line': 1, 'start_column_utf8': 1}}]}
                 for i in range(count)]
        write_json(source / 'prepared.json', items)
        write_json(source / 'manifest.json', {'mode': 'formation_guided_source_pilot_v1',
            'url': url, 'model': 'multilingual', 'selected_entrypoints': 1, 'prepared_entrypoints': 1,
            'cases': [{'omitted_candidates': 0}]})
        write_json(source / 'preparation-errors.json', [])
        write_json(source / 'contexts/fn.json', {'target': 'complete source evidence'})
        # The old output is not an input to this replay.
        write_json(source / 'results.json', {'never_copy': 'old model answer'})
        args = SimpleNamespace(out=out, source_run=source, env_file=root / '.env', timeout=10)
        settings = {'api_key': 'test-private-key', 'base_url': 'https://api.typesafe.ai', 'model': 'jev-latest'}
        with patch('jev_sources.read_settings', return_value=settings), redirect_stdout(io.StringIO()):
            prepare(args)
        return args, settings, payload

    def test_exact_replay_and_jev_transport_without_laya_tokenizer_or_health(self):
        with tempfile.TemporaryDirectory() as directory:
            args, settings, original = self.fixture(Path(directory))
            item = read(args.out / 'prepared.json')[0]
            self.assertEqual(item['payload']['state'], original['state'])
            self.assertEqual(item['payload']['questions'], original['questions'])
            self.assertEqual(list(item['payload']['questions']['c']['criteria']), ['unknown', 'yes', 'no'])
            self.assertEqual(set(item['payload']), {'model', 'state', 'questions'})
            self.assertNotIn('token_audit', item)
            self.assertFalse((args.out / 'results.json').exists())
            self.assertEqual(read(args.out / 'contexts/fn.json'), {'target': 'complete source evidence'})
            class Opener:
                requests = []
                def open(self, req, timeout):
                    self.requests.append(req)
                    return io.BytesIO(json.dumps({'model': 'jev-test', 'answers': {'c': {'type': 'choice',
                        'choice': 'no', 'probabilities': {'yes': 0.1, 'no': 0.8, 'unknown': 0.1},
                        'confidence': 0.7}}, 'usage': {'input_tokens': 77, 'output_tokens': 10}}).encode())
            opener = Opener()
            with patch('laya_sources.read_settings', return_value=settings), \
                    patch('laya_sources.request.build_opener', return_value=opener), \
                    patch('laya_sources.token_audit', side_effect=AssertionError('No Laya audit on Jev')), \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(run(args), 0)
                self.assertEqual(run(args), 0)
            self.assertEqual(len(opener.requests), 1)
            self.assertEqual(opener.requests[0].full_url, 'https://api.typesafe.ai/v1/systemone')
            self.assertEqual(opener.requests[0].get_header('Authorization'), 'Bearer test-private-key')
            self.assertEqual(read(args.out / 'candidate-results.json')[0]['choice'], 'no')
            self.assertIn('# Jev source', (args.out / 'RESULTS.md').read_text())
            for file in args.out.rglob('*.json'):
                self.assertNotIn('test-private-key', file.read_text())

    def test_access_error_stops_requests_and_redacts_key(self):
        with tempfile.TemporaryDirectory() as directory:
            args, settings, _ = self.fixture(Path(directory), count=2)
            class Denied:
                calls = 0
                def open(self, req, timeout):
                    self.calls += 1
                    raise HTTPError(req.full_url, 403, 'denied', {}, io.BytesIO(b'blocked test-private-key'))
            opener = Denied()
            with patch('laya_sources.read_settings', return_value=settings), \
                    patch('laya_sources.request.build_opener', return_value=opener), \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(run(args), 1)
            self.assertEqual(opener.calls, 1)
            self.assertNotIn('test-private-key', (args.out / 'results.json').read_text())
            self.assertIn('[REDACTED]', (args.out / 'results.json').read_text())
            self.assertEqual(read(args.out / 'summary.json')['requests_not_attempted'], 1)


if __name__ == '__main__':
    unittest.main()
