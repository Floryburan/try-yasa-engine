"""Definition identity and receiver evidence do not depend on framework heuristics."""

import ast
import tempfile
import unittest
from collections import defaultdict
from pathlib import Path
from types import SimpleNamespace

from compact_context import CompactContext
from function_identity import deduplicate_definitions
from context_graph import ContextGraph


class DefinitionIdentityTests(unittest.TestCase):
    def test_selector_merges_before_limit_and_preserves_alias_lookup(self):
        base = {"id": "a", "file": "app.py", "name": "get", "qualified_name": "app.View.get",
                "start_line": 2, "end_line": 3, "origin": "source_definition", "area": "application", "source": "body"}
        graph = ContextGraph.__new__(ContextGraph)
        graph.tables = {"functions": [base, dict(base, id="clone"), dict(base, id="other", start_line=5)]}
        selected = graph.select_functions(limit=2)
        self.assertEqual(len(selected), 2)
        self.assertEqual(graph.select_functions(names=["clone"])[0]["definition_alias_ids"], ["a", "clone"])

    def test_merge_same_definition_keep_property_accessors_and_other_files(self):
        base = {"id": "a", "file": "app.py", "name": "get", "qualified_name": "app.View.get",
                "start_line": 2, "end_line": 3, "source": "def get(self):\n    pass"}
        rows = [base, dict(base, id="clone"), dict(base, id="setter", start_line=6, end_line=7),
                dict(base, id="other", file="other.py")]
        result = deduplicate_definitions(rows)
        self.assertEqual(len(result), 3)
        self.assertEqual(result[0]["definition_alias_ids"], ["a", "clone"])
        with self.assertRaisesRegex(ValueError, "Conflicting source"):
            deduplicate_definitions([base, dict(base, id="bad", source="different")])


class BindingEvidenceTests(unittest.TestCase):
    def fixture(self, repo):
        sources = {"base.py": "class Base:\n    def get(self):\n        return 'body'\n",
                   "child.py": ('from base import Base\n'
                                'class User(Base):\n    pass\n'
                                'class Admin(Base):\n    pass\n'
                                'class Override(Base):\n    def get(self):\n        return "own"\n'
                                'class Leaf(Override):\n    pass\n'
                                'user = User()\nadmin = Admin()\nalias = user\n'
                                'register("/u", alias.get)\nregister("/a", admin.get)\n'
                                'register("/bad", Override.get)\n')}
        for file, source in sources.items():
            (repo / file).write_text(source)
        nodes, tables = {}, defaultdict(list)
        incoming, outgoing = defaultdict(list), defaultdict(list)

        def row(node_id, file, kind, first, last, **extra):
            item = dict(id=node_id, file=file, record_type=kind, area="application", scope_id=None,
                        start_line=first, end_line=last,
                        source="".join(sources[file].splitlines(keepends=True)[first-1:last]), **extra)
            nodes[node_id] = item
            tables[kind].append(item)
            return item

        row("Base", "base.py", "classes", 1, 3, name="Base", qualified_name="base.Base")
        target = row("get", "base.py", "functions", 2, 3, name="get", qualified_name="base.Base.get")
        target.update(scope_id="Base", kind="method")
        row("User", "child.py", "classes", 2, 3, name="User", qualified_name="child.User")
        row("Admin", "child.py", "classes", 4, 5, name="Admin", qualified_name="child.Admin")
        row("Override", "child.py", "classes", 6, 8, name="Override", qualified_name="child.Override")
        override = row("override_get", "child.py", "functions", 7, 8, name="get", qualified_name="child.Override.get")
        override.update(scope_id="Override", kind="method")
        row("Leaf", "child.py", "classes", 9, 10, name="Leaf", qualified_name="child.Leaf")
        row("base_import", "child.py", "imports", 1, 1, module="base", imported_name="Base", local_name="Base")
        for name, line in (("user", 11), ("admin", 12), ("alias", 13)):
            row(name, "child.py", "assignments", line, line, target=name)
        for name, line in (("user_ctor", 11), ("admin_ctor", 12), ("use_user", 14), ("use_admin", 15)):
            row(name, "child.py", "calls", line, line)

        def edge(source, target_id, relation):
            item = {"source": source, "target": target_id, "relation": relation}
            incoming[target_id].append(item)
            outgoing[source].append(item)

        for child, parent in (("User", "Base"), ("Admin", "Base"), ("Override", "Base"), ("Leaf", "Override")):
            edge(child, parent, "inherits")
        edge("user_ctor", "User", "calls")
        edge("admin_ctor", "Admin", "calls")
        edge("user_ctor", "user", "initializes_binding")
        edge("admin_ctor", "admin", "initializes_binding")
        edge("alias", "user", "alias_of")
        edge("use_user", "alias", "binding_evidence")
        edge("use_admin", "admin", "receiver_reference")

        def resolve(name, file, scope, line=None):
            return (["Base"], ["base_import"], "resolved") if name == "Base" and file == "child.py" else ([], [], "unresolved")
        return SimpleNamespace(repo=repo, nodes=nodes, tables=tables, incoming=incoming,
                               outgoing=outgoing, resolve=resolve), target

    def test_two_receivers_aliases_and_overrides_keep_one_target(self):
        with tempfile.TemporaryDirectory() as directory:
            graph, target = self.fixture(Path(directory))
            context = CompactContext(graph, reference_areas=None).build(target)
            evidence = context["binding_context"]
            self.assertEqual({r["class_id"] for r in evidence["receivers"]}, {"Base", "User", "Admin"})
            self.assertEqual(evidence["overridden_branches"], ["Override"])
            self.assertIn('register("/u", alias.get)', context["state"])
            self.assertIn('register("/a", admin.get)', context["state"])
            self.assertIn('alias = user', context["state"])
            self.assertIn('from base import Base', context["state"])
            self.assertNotIn('"/bad"', context["state"])
            self.assertEqual(context["state"].count(target["source"].rstrip()), 1)
            self.assertEqual(sum(b["role"] == "target" for b in context["blocks"]), 1)
            positions = [(b["file"], n) for b in context["blocks"] for n in range(b["start_line"], b["end_line"] + 1)]
            self.assertEqual(len(positions), len(set(positions)))
            self.assertEqual(context["coverage"]["inherited_receivers_selected"], 2)

    def test_budget_omissions_are_explicit_and_body_remains_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            graph, target = self.fixture(Path(directory))
            context = CompactContext(graph, max_binding_classes=2, max_binding_sites=1).build(target)
            self.assertEqual(context["coverage"]["binding_classes_omitted"], 1)
            self.assertGreater(context["coverage"]["binding_sites_omitted"], 0)
            self.assertIn("Additional binding evidence omitted", context["state"])
            self.assertTrue(context["coverage"]["target_complete"])

    def test_receiver_class_fields_and_instance_configuration_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            graph, target = self.fixture(repo)
            (repo / "base.py").write_text("class Base:\n    def get(self):\n        return self.prefix\n")
            target["source"] = "    def get(self):\n        return self.prefix\n"
            text = (repo / "child.py").read_text()
            lines = text.splitlines(keepends=True)
            lines[2], lines[4] = '    prefix = "/u"\n', '    prefix = "/a"\n'
            lines.append('user.prefix = "/custom"\n')
            (repo / "child.py").write_text("".join(lines))
            for node_id, scope_id, line in (("user_prefix", "User", 3), ("admin_prefix", "Admin", 5), ("custom_prefix", None, 17)):
                row = {"id": node_id, "scope_id": scope_id, "record_type": "assignments", "area": "application",
                       "file": "child.py", "start_line": line, "end_line": line, "source": lines[line - 1],
                       "target": "prefix" if scope_id else "user.prefix"}
                graph.nodes[node_id] = row
                graph.tables["assignments"].append({k: v for k, v in row.items() if k != "record_type"})
            graph.incoming["user"].append({"source": "custom_prefix", "target": "user", "relation": "assigned_receiver"})
            context = CompactContext(graph).build(target)
            self.assertIn('prefix = "/u"', context["state"])
            self.assertIn('prefix = "/a"', context["state"])
            self.assertIn('user.prefix = "/custom"', context["state"])


if __name__ == "__main__":
    unittest.main()
