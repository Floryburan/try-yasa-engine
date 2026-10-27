"""Independent coverage, evidence and Django dispatch checks for the reference."""

import ast
import hashlib
import json
import unittest
from pathlib import Path

from build_ctfd_reference import FORMATIONS, KINDS

HERE = Path(__file__).resolve().parent
DATA = HERE / "annotations/django-helpdesk-application-v1"


class HelpdeskReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = json.loads((DATA / "annotations.json").read_text())
        cls.manifest = json.loads((DATA / "manifest.json").read_text())
        cls.repo = Path(cls.manifest["repository"])
        cls.by_name = {r["function"]: r for r in cls.rows}

    def target(self, name):
        return self.by_name["helpdesk." + name]

    def test_all_source_functions_covered_once_independently_of_uast(self):
        actual = set()
        for file in (self.repo / "src/helpdesk").rglob("*.py"):
            tree = ast.parse(file.read_text(encoding="utf-8-sig"))
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    actual.add((file.relative_to(self.repo).as_posix(), node.lineno, node.end_lineno))
        annotated = {(r["file"], r["start_line"], r["end_line"]) for r in self.rows}
        self.assertEqual(actual, annotated)
        self.assertEqual(len(self.rows), len(actual))
        self.assertEqual(len({r["case_id"] for r in self.rows}), len(actual))
        self.assertEqual(len({tuple(r["definition_identity"]) for r in self.rows}), len(actual))
        self.assertTrue(all(r["function"].startswith("helpdesk.") for r in self.rows))

    def test_labels_and_every_source_evidence_hash(self):
        for row in self.rows:
            self.assertTrue(row["reason"])
            self.assertFalse(row["independent_human_review"])
            self.assertTrue(row["needs_independent_review"])
            self.assertLessEqual(set(row["formation_types"]), set(FORMATIONS))
            if row["is_entrypoint"] is True:
                self.assertIn(row["entrypoint_kind"], KINDS)
                self.assertTrue(row["bindings"])
                self.assertTrue(any(e["role"] != "target_definition" for e in row["evidence"]))
                self.assertFalse("other" in row["formation_types"] and len(row["formation_types"]) > 1)
            else:
                self.assertEqual(row["formation_types"], [])
                self.assertIsNone(row["entrypoint_kind"])
            for ev in row["evidence"]:
                lines = (self.repo / ev["file"]).read_text(encoding="utf-8").splitlines(keepends=True)
                self.assertGreaterEqual(ev["start_line"], 1)
                self.assertLessEqual(ev["end_line"], len(lines))
                source = "".join(lines[ev["start_line"] - 1:ev["end_line"]])
                self.assertEqual(source, ev["source"])
                self.assertEqual(hashlib.sha256(source.encode()).hexdigest(), ev["sha256"])
            definition = next(e for e in row["evidence"] if e["role"] == "target_definition")
            self.assertEqual(row["source_sha256"], definition["sha256"])
        for file, digest in self.manifest["files_sha256"].items():
            self.assertEqual(hashlib.sha256((self.repo / file).read_bytes()).hexdigest(), digest)
        self.assertEqual(hashlib.sha256((DATA / "annotations.json").read_bytes()).hexdigest(), self.manifest["annotations_sha256"])
        self.assertEqual(hashlib.sha256((DATA / "POLICY.md").read_bytes()).hexdigest(), self.manifest["policy_sha256"])
        self.assertEqual(hashlib.sha256((HERE / "build_helpdesk_reference.py").read_bytes()).hexdigest(), self.manifest["builder_sha256"])

    def test_framework_hook_and_direct_helper_are_distinguished(self):
        for name in ("views.public.ViewTicket.get", "views.public.BaseCreateTicketView.get_form_kwargs",
                     "views.permissions.MustBeStaffMixin.test_func", "views.api.TicketViewSet.get_queryset",
                     "webhooks.notify_followup_webhooks_receiver", "tasks.helpdesk_process_email",
                     "serializers.UserSerializer.validate", "models.CustomFieldManager.get_queryset",
                     "forms.MultipleTicketSelectForm.clean_tickets", "email.process_email"):
            self.assertIs(self.target(name)["is_entrypoint"], True, name)
        for name in ("views.public.ViewTicket.get_next_url", "views.api.FollowUpAttachmentViewSet.accessible_followups",
                     "webhooks.notify_followup_webhooks", "user.HelpdeskUser.can_access_ticket",
                     "decorators.protect_view._wrapped_view", "email.process_queue", "models.Attachment.attachment_path",
                     "templatetags.bootstrap5_form.apply_classes"):
            self.assertIs(self.target(name)["is_entrypoint"], False, name)
        self.assertEqual(self.target("views.staff.dashboard")["formation_types"], ["registration"])
        self.assertEqual(self.target("models.FollowUpAttachment.attachment_path")["formation_types"],
                         ["inheritance", "interface_implementation", "callback"])

    def test_every_url_binding_resolved_or_explicitly_external(self):
        inventory = json.loads((DATA / "dispatch_inventory.json").read_text())
        url_entries = [r for r in inventory if r["registration"] in {"path", "re_path", "router.register"}]
        tree = ast.parse((self.repo / "src/helpdesk/urls.py").read_text())
        expected = {n.lineno for n in ast.walk(tree) if isinstance(n, ast.Call)
                    and ast.unparse(n.func) in {"path", "re_path", "router.register"}}
        self.assertEqual({r["start_line"] for r in url_entries}, expected)
        positive_ids = {r["function_id"] for r in self.rows if r["is_entrypoint"] is True}
        for item in url_entries:
            self.assertNotEqual(item["resolution"], "unresolved")
            self.assertLessEqual(set(item["target_function_ids"]), positive_ids)
            if item["resolution"] == "local_source_definitions":
                self.assertTrue(item["target_function_ids"])
        user_router = next(r for r in url_entries if r["expression"] == "CreateUserView")
        self.assertEqual(user_router["resolution"], "external_inherited_actions")
        self.assertFalse(user_router["target_function_ids"])

    def test_used_base_hooks_keep_super_chains_and_definition_dedup(self):
        # These concrete subclass overrides retain the included base hook.
        for name in ("views.public.BaseCreateTicketView.get_initial", "views.public.BaseCreateTicketView.get_form_kwargs",
                     "views.public.CreateTicketIframeView.dispatch", "views.public.CreateTicketIframeView.form_valid",
                     "views.staff.CreateTicketView.get_initial", "views.staff.UpdateTicketView.get_initial",
                     "views.staff.CreateTicketView.get_form_kwargs", "views.staff.UpdateTicketView.get_form_kwargs"):
            row = self.target(name)
            self.assertIs(row["is_entrypoint"], True)
            tree = ast.parse((self.repo / row["file"]).read_text())
            node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.lineno == row["start_line"])
            self.assertTrue(any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "super" for n in ast.walk(node)), name)
        base = self.target("views.abstract_views.AbstractCreateTicketMixin.get_initial")
        self.assertGreater(len(base["bindings"]), 1)
        self.assertEqual(sum(r["function_id"] == base["function_id"] for r in self.rows), 1)

    def test_migrations_and_unknown_boundaries_are_separate(self):
        migrations = [r for r in self.rows if r["scope_partition"] == "migrations"]
        self.assertEqual(len(migrations), 16)
        self.assertEqual(sum(r["is_entrypoint"] is True for r in migrations), 13)
        self.assertIsNone(self.target("forms.PublicTicketForm.__init__")["is_entrypoint"])
        self.assertIsNone(self.target("serializers.BaseTicketSerializer.__init__")["is_entrypoint"])
        self.assertTrue(all(r["candidate_formation_types"] for r in self.rows if r["is_entrypoint"] is None))
        scope = json.loads((DATA / "scope_inventory.json").read_text())
        self.assertEqual(sum(r["functions"] for r in scope if r["in_scope"]), len(self.rows))
        self.assertEqual(sum(r["functions"] for r in scope if r["partition"] == "tests"), 674)


if __name__ == "__main__":
    unittest.main()
