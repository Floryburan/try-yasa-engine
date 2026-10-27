"""Keep graph evidence associated with the actual target and bound hub expansion."""

import unittest

from yasa_callgraph_context import YasaCallGraph


def node(name, file=None, line=10):
    return {"id": name, "fullName": name,
            "funcDef": {"name": "handler", "loc": {"sourcefile": file, "start": {"line": line}}} if file else ""}


def edge(source, target):
    return {"id": source + "->" + target, "sourceNodeId": source, "targetNodeId": target,
            "callSite": {"loc": {"sourcefile": "/repo/a.py", "start": {"line": 20}}}}


class CallGraphContextTests(unittest.TestCase):
    def test_same_name_in_other_file_never_matches_target(self):
        graph = {"nodes": {"a": node("a", "/repo/a.py"), "b": node("b", "/repo/b.py")}, "edges": {}}
        context = YasaCallGraph(graph, "/repo")
        self.assertEqual(context.match({"file": "a.py", "start_line": 10}), ["a"])
        with self.assertRaises(ValueError):
            context.neighborhood({"file": "missing.py", "start_line": 10, "name": "handler"})

    def test_external_hub_does_not_import_unrelated_functions(self):
        graph = {"nodes": {"a": node("a", "/repo/a.py"), "b": node("b", "/repo/b.py"), "hub": node("hub")},
                 "edges": {"ha": edge("hub", "a"), "bh": edge("b", "hub")}}
        result = YasaCallGraph(graph, "/repo").neighborhood({"file": "a.py", "start_line": 10})
        self.assertEqual(set(result["nodes"]), {"a", "hub"})
        self.assertEqual(result["coverage"]["direct_incoming_edges"], 1)

    def test_budget_reports_missing_direct_edges(self):
        graph = {"nodes": {"a": node("a", "/repo/a.py"), "b": node("b"), "c": node("c")},
                 "edges": {"ab": edge("a", "b"), "ac": edge("a", "c")}}
        result = YasaCallGraph(graph, "/repo").neighborhood({"file": "a.py", "start_line": 10}, max_edges=1)
        self.assertEqual(len(result["edges"]), 1)
        self.assertEqual(result["coverage"]["omitted_direct_edges"], 1)


if __name__ == "__main__":
    unittest.main()
