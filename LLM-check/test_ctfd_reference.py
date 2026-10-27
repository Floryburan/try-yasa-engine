"""Check reference coverage, source evidence and difficult target distinctions."""

import hashlib
import json
import unittest
from pathlib import Path

from build_ctfd_reference import FORMATIONS, KINDS

HERE=Path(__file__).resolve().parent
DATA=HERE/"annotations/ctfd-application-v1"


class ReferenceDatasetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows=json.loads((DATA/"annotations.json").read_text())
        cls.manifest=json.loads((DATA/"manifest.json").read_text())
        cls.repo=Path(cls.manifest["repository"])

    def target(self,name):
        rows=[r for r in self.rows if r["function"]==name]
        self.assertEqual(len(rows),1,name)
        return rows[0]

    def test_exhaustive_unique_coverage_of_the_frozen_application_scope(self):
        indexed=[json.loads(l) for l in (HERE.parent/"artifacts/ctfd-uast/index/functions.jsonl").open()]
        expected={r["id"] for r in indexed if r.get("area")=="application" and r.get("origin")=="source_definition"}
        self.assertEqual(len(self.rows),847)
        self.assertEqual({r["function_id"] for r in self.rows},expected)
        self.assertEqual(len({r["case_id"] for r in self.rows}),847)
        self.assertEqual(len({tuple(r["definition_identity"]) for r in self.rows}),847)

    def test_evidence_matches_actual_source_and_all_labels_are_legal(self):
        sources={}
        for row in self.rows:
            self.assertIs(type(row["is_entrypoint"]),bool if row["is_entrypoint"] is not None else type(None))
            self.assertTrue(set(row["formation_types"])<=set(FORMATIONS))
            self.assertEqual(len(row["formation_types"]),len(set(row["formation_types"])))
            self.assertTrue(row["reason"])
            self.assertFalse(row["independent_human_review"])
            self.assertTrue(row["needs_independent_review"])
            if row["is_entrypoint"] is True:
                self.assertIn(row["entrypoint_kind"],KINDS)
                self.assertTrue(row["formation_types"])
                self.assertTrue(any(e["role"]!="target_definition" for e in row["evidence"]))
                self.assertFalse("other" in row["formation_types"] and len(row["formation_types"])>1)
            else:
                self.assertEqual(row["formation_types"],[])
                self.assertIsNone(row["entrypoint_kind"])
            for ev in row["evidence"]:
                if ev["file"] not in sources:
                    sources[ev["file"]]=(self.repo/ev["file"]).read_text(encoding="utf-8").splitlines(keepends=True)
                expected="".join(sources[ev["file"]][ev["start_line"]-1:ev["end_line"]])
                self.assertEqual(ev["source"],expected)
                self.assertEqual(ev["sha256"],hashlib.sha256(expected.encode()).hexdigest())

    def test_handler_registration_helper_and_decorator_wrapper_are_distinct(self):
        handler=self.target("CTFd.plugins.register_plugin_assets_directory.assets_handler")
        helper=self.target("CTFd.plugins.register_plugin_assets_directory")
        wrapper=self.target("CTFd.utils.decorators.authed_only.authed_only_wrapper")
        self.assertIs(handler["is_entrypoint"],True)
        self.assertEqual(handler["formation_types"],["registration"])
        self.assertIs(helper["is_entrypoint"],False)
        self.assertIs(wrapper["is_entrypoint"],False)
        self.assertEqual(self.target("CTFd.views.notifications")["formation_types"],["decorator"])

    def test_configured_strategy_and_its_internal_helper_are_distinct(self):
        self.assertIs(self.target("CTFd.utils.social.SolveSocialShare.asset")["is_entrypoint"],True)
        self.assertIs(self.target("CTFd.plugins.dynamic_challenges.DynamicValueChallenge.update")["is_entrypoint"],True)
        self.assertIs(self.target("CTFd.plugins.dynamic_challenges.DynamicValueChallenge.calculate_value")["is_entrypoint"],False)
        self.assertIs(self.target("CTFd.utils.helpers.markup")["is_entrypoint"],False)
        self.assertIs(self.target("CTFd.utils.formatters.safe_format")["is_entrypoint"],False)
        self.assertIsNone(self.target("CTFd.utils.exports.serializers.JSONEncoder.default")["is_entrypoint"])


if __name__=="__main__":
    unittest.main()
