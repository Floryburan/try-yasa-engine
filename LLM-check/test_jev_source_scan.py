"""Whole-entrypoint source scans preserve candidates and concurrent checkpoints."""

import io
import json
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError

from jev_source_scan import batch_payload, run_repository
from laya_sources import read
import test_jev_sources as jev_fixtures
import test_source_context as source_fixtures


class SourceBatchTests(unittest.TestCase):
    def test_no_candidate_cap_and_missing_assignment_span_is_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            builder, target = source_fixtures.SourceContextTests().fixture(Path(directory))
            builder.max_candidates = None
            builder.graph.nodes['data'] = {'id': 'data', 'record_type': 'assignments', 'area': 'application',
                'file': 'app.py', 'start_line': None, 'end_line': None, 'source': ''}
            context = builder.build(target, ['configuration'])
            self.assertGreater(len(context['candidates']), 2)
            self.assertEqual(context['omitted_candidates'], [])
            self.assertTrue(any(g['reason'] == 'missing_or_invalid_source_span' for g in context['unresolved']))

    def test_small_budget_keeps_candidate_owner_body_and_target(self):
        with tempfile.TemporaryDirectory() as directory:
            builder, target = source_fixtures.SourceContextTests().fixture(Path(directory))
            context = builder.build(target, ['registration', 'callback', 'decorator'])
            helper = next(c for c in context['candidates'] if c['owner_id'] == 'read_payload')
            prompt = {'definition': 'Test source boundary', 'criteria': {'yes': 'external', 'no': 'internal', 'unknown': 'missing'}}
            payload, coverage = batch_payload(builder, context, [helper], prompt, 'http', {'model': 'jev'}, max_chars=1)
            self.assertIn(target['source'].rstrip(), payload['state'])
            self.assertIn('def read_payload(request):', payload['state'])
            self.assertIn('return request.get_json()', payload['state'])
            self.assertTrue(coverage['character_budget_exceeded'])
            self.assertTrue(coverage['candidate_owners_complete'])
            self.assertGreater(coverage['optional_blocks_omitted'], 0)
            self.assertNotIn('max_len', payload)


class ConcurrentSourceTests(unittest.TestCase):
    def test_transport_retry_and_verified_resume_without_duplicate_requests(self):
        with tempfile.TemporaryDirectory() as directory:
            args, settings, _ = jev_fixtures.JevSourceTests().fixture(Path(directory), count=4)
            args.workers, args.retries = 2, 1
            lock = threading.Lock()
            class Opener:
                calls = 0
                def open(self, req, timeout):
                    with lock:
                        self.calls += 1
                        call = self.calls
                    if call == 1:
                        raise URLError('temporary connection failure')
                    return io.BytesIO(json.dumps({'model': 'jev-test', 'answers': {'c': {'type': 'choice',
                        'choice': 'yes', 'probabilities': {'yes': 0.8, 'no': 0.1, 'unknown': 0.1}, 'confidence': 0.7}},
                        'usage': {'input_tokens': 20, 'output_tokens': 10}}).encode())
            opener = Opener()
            with patch('jev_source_scan.read_settings', return_value=settings), \
                    patch('jev_source_scan.request.build_opener', return_value=opener), \
                    patch('jev_source_scan.time.sleep'), redirect_stdout(io.StringIO()):
                self.assertEqual(run_repository(args), 0)
                self.assertEqual(run_repository(args), 0)
            self.assertEqual(opener.calls, 5)
            self.assertEqual(len(read(args.out / 'results.json')), 4)
            invocation = read(args.out / 'last-invocation.json')
            self.assertEqual(invocation['requests_attempted'], 0)
            self.assertEqual(invocation['requests_reused'], 4)
            events = [json.loads(line) for path in (args.out / 'usage-events').glob('*.jsonl') for line in path.read_text().splitlines()]
            self.assertEqual(len(events), 5)
            self.assertEqual(sum(e['status'] == 'error' for e in events), 1)
            self.assertEqual(read(args.out / 'summary.json')['unique_source_positions'], 1)
            self.assertEqual(len(read(args.out / 'unique-sources.json')), 1)
            self.assertEqual(read(args.out / 'unique-sources.json')[0]['choice_counts'], {'yes': 4})
            for path in args.out.rglob('*.json*'):
                self.assertNotIn('test-private-key', path.read_text())


if __name__ == '__main__':
    unittest.main()
