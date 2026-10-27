"""Preserve target evidence while removing duplicates and unknown truncation claims."""

import ast
import json
import tempfile
import unittest
from collections import defaultdict
from pathlib import Path
from types import SimpleNamespace

from compact_context import CompactContext
from input_length_audit import response_audit


class CompactInputTests(unittest.TestCase):
    def test_outer_dependencies_are_kept_without_duplicate_target_or_sibling(self):
        source = ('def install(app, prefix):\n'
                  '    prefix = prefix.strip("/")\n'
                  '    def handler(name):\n'
                  '        return send(prefix, name)\n'
                  '    rule = prefix + "/<name>"\n'
                  '    app.add_url_rule(rule, view_func=handler)\n'
                  '    def unused():\n'
                  '        return "irrelevant sibling"\n')
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "app.py").write_text(source)
            target = {"id": "target", "record_type": "functions", "file": "app.py", "name": "handler",
                      "qualified_name": "app.install.handler", "scope_id": "outer", "start_line": 3,
                      "end_line": 4, "source": "".join(source.splitlines(keepends=True)[2:4])}
            use = {"id": "use", "record_type": "calls", "area": "application", "file": "app.py",
                   "start_line": 6, "end_line": 6, "source": 'app.add_url_rule(rule, view_func=handler)'}
            incoming = defaultdict(list, {"target": [{"source": "use", "target": "target", "relation": "argument_reference"}]})
            graph = SimpleNamespace(repo=repo, nodes={"target": target, "use": use}, incoming=incoming,
                                    resolve=lambda *args: ([], [], "unresolved"))
            context = CompactContext(graph).build(target)
            self.assertEqual(context["state"].count(target["source"].rstrip()), 1)
            self.assertIn('prefix = prefix.strip("/")', context["state"])
            self.assertIn('rule = prefix + "/<name>"', context["state"])
            self.assertNotIn("irrelevant sibling", context["state"])
            positions = [(b["file"], line) for b in context["blocks"] for line in range(b["start_line"], b["end_line"] + 1)]
            self.assertEqual(len(positions), len(set(positions)))

    def test_missing_truncation_flag_is_unknown_even_with_usage(self):
        payload = {"state": "code", "questions": {}}
        wire = json.dumps(payload).encode()
        result = response_audit({"usage": {"input_tokens": 123}}, payload, wire)
        self.assertEqual(result["provider_reported_input_tokens"], 123)
        self.assertEqual(result["server_truncation_status"], "not_reported")
        self.assertFalse(result["client_state_truncated"])

    def test_explicit_truncation_and_no_truncation_are_distinguished(self):
        payload = {"state": "code"}
        a = response_audit({"usage": {"truncated": True, "state_tokens_dropped": 4}}, payload, b"body")
        b = response_audit({"usage": {"truncated": False, "state_tokens_dropped": 0}}, payload, b"body")
        self.assertEqual(a["server_truncation_status"], "reported_truncation")
        self.assertEqual(b["server_truncation_status"], "reported_no_truncation")


if __name__ == "__main__":
    unittest.main()
