"""Collect static receiver/inheritance/instance evidence without classifying entrypoints."""

import ast
import textwrap
from collections import defaultdict, deque


class BindingContext:
    def __init__(self, graph, max_classes=12, max_sites=24, reference_areas=("application",)):
        self.graph = graph
        self.max_classes, self.max_sites, self.reference_areas = max_classes, max_sites, reference_areas
        self.children = defaultdict(list)
        self.shadows = defaultdict(set)
        self.class_assignments = defaultdict(list)
        for row in getattr(graph, "tables", {}).get("classes", []):
            for edge in graph.outgoing[row["id"]]:
                if edge["relation"] == "inherits" and graph.nodes[edge["target"]]["record_type"] == "classes":
                    self.children[edge["target"]].append(row["id"])
        for row in getattr(graph, "tables", {}).get("functions", []):
            if row.get("scope_id"):
                self.shadows[row["scope_id"]].add(row["name"])
        for row in getattr(graph, "tables", {}).get("assignments", []):
            if row.get("scope_id") and row.get("target", "").isidentifier():
                self.shadows[row["scope_id"]].add(row["target"])
                self.class_assignments[row["scope_id"]].append(graph.nodes[row["id"]])

    def in_scope(self, row):
        return self.reference_areas is None or row.get("area") in self.reference_areas

    def method_reference(self, row, name):
        try:
            tree = ast.parse(textwrap.dedent(row.get("source", "")))
        except SyntaxError:
            return False
        return any(isinstance(n, ast.Attribute) and n.attr == name for n in ast.walk(tree))

    def build(self, target):
        graph = self.graph
        owner = graph.nodes.get(target.get("scope_id"), {})
        if owner.get("record_type") != "classes":
            return {"receivers": [], "sites": [], "class_candidates": 0, "sites_candidates": 0,
                    "classes_omitted": 0, "sites_omitted": 0, "overridden_branches": []}
        queue, visited, candidates, overridden = deque([(owner["id"], [owner["id"]])]), set(), [], []
        while queue:
            class_id, path = queue.popleft()
            if class_id in visited:
                continue
            visited.add(class_id)
            cls = graph.nodes[class_id]
            if class_id != owner["id"] and target["name"] in self.shadows[class_id]:
                overridden.append(class_id)
                continue
            if not self.in_scope(cls):
                continue
            candidates.append({"class_id": class_id, "qualified_name": cls["qualified_name"],
                               "inheritance_path": path,
                               "relation": "declaring_class" if len(path) == 1 else "inherited_candidate"})
            for child in sorted(self.children[class_id]):
                queue.append((child, path + [child]))
        receivers = candidates[:self.max_classes]
        receiver_attributes = set()
        try:
            tree = ast.parse(textwrap.dedent(target["source"]))
            definition = next(n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)))
            parameters = definition.args.posonlyargs + definition.args.args
            receiver_name = parameters[0].arg if parameters else None
            receiver_attributes = {n.attr for n in ast.walk(definition) if isinstance(n, ast.Attribute)
                                   and isinstance(n.value, ast.Name) and n.value.id == receiver_name}
        except (SyntaxError, StopIteration):
            pass
        # Keep different receiver contexts even if their source use is identical;
        # source rendering itself is deduplicated later by file and line.
        per_receiver = []
        for receiver in receivers:
            class_id = receiver["class_id"]
            sites = {}

            def add(row, relation, instance_binding=None):
                if row.get("record_type") not in {"calls", "assignments"} or not self.in_scope(row):
                    return
                key = (row["id"], relation, instance_binding)
                sites[key] = {"record_id": row["id"], "class_id": class_id, "relation": relation,
                              "instance_binding_id": instance_binding}

            for edge in graph.outgoing[class_id]:
                if edge["relation"] == "decorated_by":
                    add(graph.nodes[edge["target"]], "class_decorator")
            remaining_attributes = set(receiver_attributes)
            for ancestor in reversed(receiver["inheritance_path"]):
                assignments = self.class_assignments[ancestor]
                for assignment in assignments:
                    if assignment["target"] in remaining_attributes:
                        add(assignment, "receiver_attribute_binding")
                remaining_attributes.difference_update(a["target"] for a in assignments)
            for edge in graph.incoming[class_id]:
                source = graph.nodes[edge["source"]]
                relation = edge["relation"]
                if relation == "receiver_reference" and not self.method_reference(source, target["name"]):
                    # Keep class factories used as another call's argument or
                    # assigned to a binding; omit unrelated sibling-method calls.
                    if "/arguments/" not in source.get("ast_path", "") and not any(
                        e["relation"] == "initializes_binding" for e in graph.outgoing[source["id"]]):
                        continue
                if relation in {"calls", "argument_reference", "alias_of", "value_reference", "receiver_reference"}:
                    add(source, "constructor_call" if relation == "calls" else "class_" + relation)
                if relation != "calls":
                    continue
                for initialized in graph.outgoing[source["id"]]:
                    if initialized["relation"] != "initializes_binding":
                        continue
                    binding = graph.nodes[initialized["target"]]
                    add(binding, "instance_binding", binding["id"])
                    aliases, seen_bindings = deque([binding["id"]]), set()
                    while aliases:
                        binding_id = aliases.popleft()
                        if binding_id in seen_bindings:
                            continue
                        seen_bindings.add(binding_id)
                        for reference in graph.incoming[binding_id]:
                            site = graph.nodes[reference["source"]]
                            if reference["relation"] == "alias_of" and self.in_scope(site):
                                add(site, "instance_alias", binding_id)
                                aliases.append(site["id"])
                            elif reference["relation"] == "assigned_receiver" and site.get("target", "").rsplit(".", 1)[-1] in receiver_attributes:
                                add(site, "instance_attribute_assignment", binding_id)
                            elif reference["relation"] in {"binding_evidence", "receiver_reference"} and self.method_reference(site, target["name"]):
                                add(site, "bound_method_reference", binding_id)
            ordered = sorted(sites.values(), key=lambda s: (
                s["relation"] not in {"bound_method_reference", "receiver_attribute_binding", "class_argument_reference", "class_alias_of", "class_value_reference", "class_decorator"},
                graph.nodes[s["record_id"]]["file"], graph.nodes[s["record_id"]]["start_line"], s["relation"]))
            per_receiver.append(ordered)
        # Round-robin prevents a heavily referenced first class from hiding all
        # evidence for the other receiver classes.
        ordered_sites = []
        for position in range(max((len(s) for s in per_receiver), default=0)):
            for sites in per_receiver:
                if position < len(sites):
                    ordered_sites.append(sites[position])
        return {"receivers": receivers, "sites": ordered_sites[:self.max_sites],
                "class_candidates": len(candidates), "sites_candidates": len(ordered_sites),
                "classes_omitted": len(candidates) - len(receivers),
                "sites_omitted": len(ordered_sites) - min(len(ordered_sites), self.max_sites),
                "overridden_branches": overridden,
                "limitations": "Static receiver candidates only; Python MRO, dynamic factories and dispatch are not proven."}
