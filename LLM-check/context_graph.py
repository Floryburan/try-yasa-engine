"""Build auditable, bounded function contexts from the YASA UAST index.

This is a conservative syntactic graph, not a Python interpreter or a complete
points-to analysis. No framework-specific entrypoint recognizer is used here.
"""

import hashlib
import heapq
import json
import re
from collections import defaultdict
from functools import lru_cache
from pathlib import Path
from function_identity import deduplicate_definitions


def json_text(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def fingerprint(value):
    return hashlib.sha256(json_text(value).encode("utf-8")).hexdigest()


def name_of(node):
    if not isinstance(node, dict):
        return ""
    if node.get("type") == "Identifier":
        return node.get("name", "")
    if node.get("type") == "MemberAccess" and not node.get("computed"):
        left, right = name_of(node.get("object")), name_of(node.get("property"))
        return left + "." + right if left and right else ""
    return ""


def references(node):
    """Extract expression references, excluding keyword labels/member property names."""
    if isinstance(node, list):
        for child in node:
            yield from references(child)
    elif isinstance(node, dict):
        if node.get("type") == "VariableDeclaration":
            yield from references(node.get("init"))
        elif node.get("type") in {"Identifier", "MemberAccess"} and name_of(node):
            yield name_of(node)
        else:
            for key, child in node.items():
                if key not in {"loc", "_meta", "parent"}:
                    yield from references(child)


class ContextGraph:
    def __init__(self, index_dir, repo=None, verify_sources=True):
        self.index_dir = Path(index_dir).resolve()
        self.artifact_dir = self.index_dir.parent
        self.summary = json.loads((self.index_dir / "summary.json").read_text())
        self.repo = Path(repo or self.summary["repository"]).resolve()
        self.tables = {}
        self.index_hashes = {}
        for table in ("files", "functions", "classes", "imports", "calls", "assignments"):
            content = (self.index_dir / (table + ".jsonl")).read_bytes()
            self.index_hashes[table] = hashlib.sha256(content).hexdigest()
            self.tables[table] = [json.loads(line) for line in content.decode("utf-8").splitlines() if line.strip()]
        self.nodes = {}
        self.symbols = defaultdict(list)
        self.members = defaultdict(list)
        self.outgoing, self.incoming = defaultdict(list), defaultdict(list)
        self.edges = {}
        self.unresolved = defaultdict(list)
        self.by_scope = defaultdict(list)
        self.files = {row["file"]: row for row in self.tables["files"]}
        self.file_modules = {}
        for row in self.tables["files"]:
            if verify_sources:
                actual = hashlib.sha256((self.repo / row["file"]).read_bytes()).hexdigest()
                if actual != row["sha256"]:
                    raise ValueError("Source changed since UAST export: " + row["file"])
            node_id = "module:" + row["file"]
            self.file_modules[row["file"]] = node_id
            self.nodes[node_id] = dict(row, id=node_id, record_type="module")
        for table in ("functions", "classes", "imports", "calls", "assignments"):
            for row in self.tables[table]:
                self.nodes[row["id"]] = dict(row, record_type=table)
                self.by_scope[row.get("scope_id") or self.file_modules[row["file"]]].append(row["id"])
                binding = row.get("name") if table in {"functions", "classes"} else row.get("local_name")
                if table == "assignments" and re.fullmatch(r"[A-Za-z_]\w*", row["target"]):
                    binding = row["target"]
                if binding:
                    self.symbols[(row["file"], row.get("scope_id"), binding)].append(row["id"])
                if table == "functions" and row.get("kind") == "method":
                    self.members[(row.get("scope_id"), row["name"])].append(row["id"])
        for function in self.tables["functions"]:
            for param in function.get("parameters", []):
                name = param["name"]
                if name:
                    param_id = "parameter:" + function["id"] + ":" + name
                    self.nodes[param_id] = dict(param, id=param_id, record_type="parameter",
                                                file=function["file"], scope_id=function["id"],
                                                start_line=function["start_line"])
                    self.symbols[(function["file"], function["id"], name)].append(param_id)
        self._build()

    @lru_cache(maxsize=24)
    def ast_tree(self, ast_file):
        path = (self.artifact_dir / ast_file).resolve()
        # An index may reference only exported ASTs within its artifact directory.
        path.relative_to(self.artifact_dir)
        return json.loads(path.read_text())

    def ast_node(self, row):
        node = self.ast_tree(row["ast_file"])
        for part in row["ast_path"].split("/")[1:]:
            key = part.replace("~1", "/").replace("~0", "~")
            node = node[int(key)] if isinstance(node, list) else node[key]
        if (node.get("_meta") or {}).get("nodehash") != row.get("nodehash"):
            raise ValueError("UAST/index mismatch: " + row["id"])
        return node

    def edge(self, source, target, relation, evidence=None, certainty="syntactic"):
        if not source or not target or source == target:
            return
        key = (source, target, relation, evidence)
        if key in self.edges:
            return
        row = {"source": source, "target": target, "relation": relation,
               "evidence_id": evidence, "certainty": certainty}
        self.edges[key] = row
        self.outgoing[source].append(row)
        self.incoming[target].append(row)

    def scopes(self, scope_id):
        first = True
        while scope_id:
            row = self.nodes[scope_id]
            # Python unqualified names inside methods do not use class locals.
            if first or row["record_type"] != "classes":
                yield scope_id
            first = False
            scope_id = row.get("scope_id")
        yield None

    def resolve(self, name, file, scope_id, line=None, seen=None):
        """Return local identities + import/alias evidence, never global name matches."""
        if not name or not re.fullmatch(r"[A-Za-z_]\w*(\.[A-Za-z_]\w*)*", name):
            return [], [], "dynamic_expression"
        seen = set() if seen is None else set(seen)
        key = (name, file, scope_id)
        if key in seen:
            return [], [], "cyclic_alias_or_import"
        seen.add(key)
        root, *attrs = name.split(".")
        candidates = []
        for scope in self.scopes(scope_id):
            bindings = self.symbols.get((file, scope, root), [])
            if bindings:
                # Local assignments later in a function still shadow module globals.
                candidates = [i for i in bindings if line is None or scope is None
                              or (self.nodes[i].get("start_line") or 0) <= line
                              or self.nodes[i]["record_type"] == "parameter"]
                if not candidates:
                    return [], [], "local_binding_not_initialized"
                break
        identities, via = [], []
        reason = "name_not_resolved"
        for node_id in candidates:
            row = self.nodes[node_id]
            kind = row["record_type"]
            if kind == "parameter" and root in {"self", "cls"}:
                function = self.nodes[row["scope_id"]]
                if function.get("kind") == "method":
                    identities.append(function["scope_id"])
                    via.append(node_id)
                    continue
            if kind == "imports":
                via.append(node_id)
                reason = "external_or_unresolved_import"
                for target in row.get("target_files", []):
                    module = self.files[target]["module"]
                    imported = row.get("imported_name")
                    absolute = row.get("absolute_module", row["module"])
                    if imported and module != absolute + "." + imported:
                        found, path, why = self.resolve(imported, target, None, seen=seen)
                        identities.extend(found)
                        via.extend(path)
                        reason = why
                    else:
                        identities.append(self.file_modules[target])
                        # 'import package.sub' binds package, not package.sub.
                        if not imported and row.get("local_name") == absolute.split(".")[0] and "." in absolute:
                            root_module = absolute.split(".")[0]
                            root_files = [f for f, item in self.files.items() if item["module"] == root_module]
                            if root_files:
                                identities[-1] = self.file_modules[root_files[0]]
            elif kind == "assignments":
                via.append(node_id)
                alias = name_of(self.ast_node(row).get("right"))
                if alias and alias != root:
                    found, path, why = self.resolve(alias, file, row.get("scope_id"), row.get("start_line"), seen)
                    identities.extend(found or [node_id])
                    via.extend(path)
                    reason = why
                else:
                    identities.append(node_id)
            else:
                identities.append(node_id)
        for attr in attrs:
            next_ids = []
            for node_id in identities:
                row = self.nodes[node_id]
                if row["record_type"] == "module":
                    found, path, why = self.resolve(attr, row["file"], None, seen=seen)
                    next_ids.extend(found)
                    via.extend(path)
                    reason = why
                    if not found:
                        expected = row["module"] + "." + attr
                        next_ids.extend(self.file_modules[f] for f, item in self.files.items() if item["module"] == expected)
                elif row["record_type"] == "classes":
                    next_ids.extend(self.members.get((node_id, attr), []))
            identities = next_ids
            if not identities:
                reason = "attribute_or_receiver_type_unresolved"
        identities, via = list(dict.fromkeys(identities)), list(dict.fromkeys(via))
        return identities, via, "resolved" if identities else reason

    def link_reference(self, owner, name, relation, evidence):
        row = self.nodes[owner]
        targets, via, reason = self.resolve(name, row["file"], row.get("scope_id"), row.get("start_line"))
        certainty = "candidate" if len(targets) > 1 else "syntactic"
        for target in targets:
            actual_relation = relation
            if relation == "calls" and self.nodes[target]["record_type"] not in {"functions", "classes"}:
                actual_relation = "callee_reference"
            self.edge(owner, target, actual_relation, evidence, certainty)
        for binding in via:
            self.edge(owner, binding, "binding_evidence", evidence)
        return targets, reason

    def _build(self):
        for table in ("functions", "classes"):
            for row in self.tables[table]:
                if row.get("scope_id"):
                    self.edge(row["id"], row["scope_id"], "enclosed_by", row["id"])
                for decorator in row.get("decorators", []):
                    self.link_reference(row["id"], decorator["name"], "decorator_definition", row["id"])
                if table == "classes":
                    for base in row.get("bases", []):
                        targets, reason = self.link_reference(row["id"], base["name"], "inherits", row["id"])
                        if not targets:
                            self.unresolved[row["id"]].append({"expression": base["expression"], "reason": reason, "role": "base_class"})
        # Initializer calls are linked to their resulting binding (Blueprint/Namespace etc.).
        calls_by_path = {(r["file"], r["ast_path"]): r for r in self.tables["calls"]}
        for row in self.tables["assignments"]:
            initializer = calls_by_path.get((row["file"], row["ast_path"] + "/right"))
            if initializer:
                self.edge(initializer["id"], row["id"], "initializes_binding", row["id"])
            if row.get("scope_id"):
                self.edge(row["id"], row["scope_id"], "assigned_within", row["id"])
            if "." in row["target"]:
                self.link_reference(row["id"], row["target"].rsplit(".", 1)[0], "assigned_receiver", row["id"])
            alias = name_of(self.ast_node(row).get("right"))
            if alias:
                self.link_reference(row["id"], alias, "alias_of", row["id"])
            else:
                # Functions/classes also escape through dictionaries, lists and
                # other initializer expressions, not only plain-name aliases.
                for ref in sorted(set(references(self.ast_node(row).get("right")))):
                    self.link_reference(row["id"], ref, "value_reference", row["id"])
        for row in self.tables["calls"]:
            node_id = row["id"]
            if row.get("scope_id"):
                self.edge(node_id, row["scope_id"], "executed_within", node_id)
            if row.get("decorated_target_id"):
                self.edge(row["decorated_target_id"], node_id, "decorated_by", node_id)
            targets, reason = self.link_reference(node_id, row["callee"], "calls", node_id)
            callable_targets = [target for target in targets if self.nodes[target]["record_type"] in {"functions", "classes"}]
            if not callable_targets:
                self.unresolved[node_id].append({"expression": row["callee"], "reason": reason if not targets else "callable_value_not_resolved", "role": "callee"})
            if "." in row["callee"]:
                receiver = row["callee"].rsplit(".", 1)[0]
                self.link_reference(node_id, receiver, "receiver_reference", node_id)
            ast = self.ast_node(row)
            args = ast.get("arguments") or []
            for position, argument in enumerate(args):
                for ref in sorted(set(references(argument))):
                    self.link_reference(node_id, ref, "argument_reference", node_id)
                # Retain actual-to-formal evidence for calls to registration helpers.
                for target in callable_targets:
                    function = self.nodes[target]
                    if function["record_type"] != "functions":
                        continue
                    parameters = function.get("parameters", [])
                    if function.get("kind") == "method" and row["callee"].startswith(("self.", "cls.")):
                        parameters = parameters[1:]
                    if argument.get("type") == "VariableDeclaration":
                        arg_name = name_of(argument.get("id"))
                    else:
                        arg_name = parameters[position]["name"] if position < len(parameters) else None
                    parameter_id = "parameter:" + target + ":" + str(arg_name)
                    if parameter_id in self.nodes:
                        self.edge(node_id, parameter_id, "supplies_parameter", node_id,
                                  "candidate" if len(callable_targets) > 1 else "syntactic")
        # Include imported definitions and re-exports as evidence, without merging modules.
        for row in self.tables["imports"]:
            targets, via, _ = self.resolve(row["local_name"], row["file"], row.get("scope_id"), row.get("start_line"))
            for target in targets:
                self.edge(row["id"], target, "imports_binding", row["id"])
            for target in via:
                self.edge(row["id"], target, "reexport_evidence", row["id"])

    def select_functions(self, area="application", include_lambdas=False, names=(), limit=None):
        rows = [row for row in self.tables["functions"]
                if row.get("origin") == "source_definition" or (include_lambdas and row.get("origin") == "lambda")]
        if area != "all":
            rows = [row for row in rows if row.get("area") == area]
        rows.sort(key=lambda r: (r["file"], r["start_line"] or 0, r["id"]))
        rows = deduplicate_definitions(rows)
        if names:
            rows = [row for row in rows if any(name in {row["name"], row["qualified_name"], *row["definition_alias_ids"]} for name in names)]
        return rows if limit is None else rows[:limit]

    def neighbor_edges(self, node_id, expand_functions, upstream_functions, target_area):
        row = self.nodes[node_id]
        for edge in self.outgoing[node_id]:
            yield edge, edge["target"]
        for edge in self.incoming[node_id]:
            relation = edge["relation"]
            if target_area == "application" and self.nodes[edge["source"]].get("area") in {"tests", "migrations"}:
                continue
            # Parent/module hubs must not pull unrelated siblings into the context.
            if relation in {"enclosed_by", "assigned_within"}:
                continue
            if relation in {"decorator_definition", "imports_binding", "reexport_evidence"}:
                continue
            if row["record_type"] == "functions" and node_id not in upstream_functions and relation in {"calls", "argument_reference"}:
                continue
            if relation == "executed_within" and node_id not in expand_functions:
                continue
            # For shared receivers trace initialization and passing as an argument,
            # rather than every endpoint registered on the same Blueprint/Namespace.
            if relation in {"receiver_reference", "binding_evidence"} and row["record_type"] in {"assignments", "imports", "parameter"}:
                continue
            yield edge, edge["source"]

    def context(self, target, max_depth=10, max_nodes=100, max_chars=60000, source_chars=6000):
        if max_depth < 0 or max_nodes < 1 or max_chars < 4000 or source_chars < 200:
            raise ValueError("Invalid context limits (max_chars >= 4000, source_chars >= 200)")
        target_id = target["id"]
        distances = {}
        expand_functions = {target_id}
        upstream_functions = {target_id}
        queue = [(0.0, 0, target_id, True, True)]
        omitted = {"depth": set(), "nodes": set(), "chars": set()}
        while queue:
            cost, depth, node_id, expand_body, trace_upstream = heapq.heappop(queue)
            if node_id in distances:
                continue
            if len(distances) >= max_nodes:
                omitted["nodes"].add(node_id)
                omitted["nodes"].update(item[2] for item in queue if item[2] not in distances)
                break
            distances[node_id] = depth
            if expand_body:
                expand_functions.add(node_id)
            if trace_upstream:
                upstream_functions.add(node_id)
            for edge, neighbor in self.neighbor_edges(node_id, expand_functions, upstream_functions, target.get("area")):
                if neighbor in distances:
                    continue
                if depth >= max_depth:
                    omitted["depth"].add(neighbor)
                else:
                    relation = edge["relation"]
                    # Preserve outward registration chains before broad function-body
                    # expansion. A long handler must not consume all nodes before its
                    # class/Blueprint/Namespace registration evidence can be reached.
                    step = {"enclosed_by": 0.1, "decorated_by": 0.1,
                            "binding_evidence": 0.2, "receiver_reference": 0.2,
                            "argument_reference": 0.3, "initializes_binding": 0.2,
                            "imports_binding": 0.2, "reexport_evidence": 0.2,
                            "alias_of": 0.2, "supplies_parameter": 0.4,
                            "inherits": 0.3, "decorator_definition": 2.0}.get(relation, 0.8)
                    if relation in {"imports_binding", "reexport_evidence"} and self.nodes[neighbor]["record_type"] == "functions":
                        step = 2.0
                    if relation == "argument_reference" and edge["source"] == node_id and self.nodes[node_id].get("region") == "decorator":
                        # Decorator arguments can reference large documentation/schema
                        # models. Follow the decorator receiver's registration chain
                        # before expanding those supporting object graphs.
                        step = 2.0
                    if relation == "executed_within" and edge["target"] == node_id:
                        step = 4.0
                    expand = edge["target"] == neighbor and relation in {"calls", "decorator_definition"}
                    upstream = edge["target"] == neighbor and relation in {"executed_within", "enclosed_by"}
                    heapq.heappush(queue, (cost + step, depth + 1, neighbor, expand, upstream))
        context = {"schema_version": 1, "function_id": target_id,
                   "repository_commit": self.summary.get("commit"),
                   "target": None, "nodes": [], "edges": [], "unresolved": [],
                   "coverage": {"full_runtime_chain_proven": False, "budget_exhausted": False, "max_depth": max_depth,
                                "max_nodes": max_nodes, "max_context_chars": max_chars,
                                "source_chars_per_node": source_chars,
                                "limitations": ["Static lexical/import/alias matching; dynamic calls, instance attributes and configuration may remain unresolved.",
                                                "Candidate edges and same-scope rebindings are not proven runtime targets.",
                                                "A syntactic argument reference alone does not prove callback registration."]}}
        for node_id, distance in distances.items():
            original = self.nodes[node_id]
            row = dict(original, distance=distance)
            if row["record_type"] == "classes":
                # Keep bases and decorators, but avoid duplicating every sibling method.
                row["methods"] = [{"id": r["id"], "name": r["name"], "start_line": r["start_line"]}
                                  for r in self.tables["functions"] if r.get("scope_id") == node_id]
            text = row.get("source", "")
            # Keep the complete target body whenever it fits half the budget;
            # --source-chars limits supporting definitions rather than the target.
            limit = max_chars // 2 if node_id == target_id else source_chars
            if row["record_type"] == "classes":
                limit = min(limit, 1400)
            if len(text) > limit:
                row["source"] = text[:limit]
                row["omitted_source_chars"] = len(text) - limit
            if row["record_type"] == "calls":
                row["arguments"] = [dict(arg, source=arg["source"][:1200],
                                         omitted_source_chars=max(0, len(arg["source"]) - 1200))
                                    for arg in row.get("arguments", [])]
            if node_id == target_id:
                context["target"] = row
            else:
                context["nodes"].append(row)
        def refresh():
            kept = {target_id} | {r["id"] for r in context["nodes"]}
            context["edges"] = [edge for node_id in sorted(kept) for edge in self.outgoing[node_id] if edge["target"] in kept
                                and (edge["evidence_id"] is None or edge["evidence_id"] in kept)]
            context["unresolved"] = [dict(issue, record_id=node_id) for node_id in sorted(kept)
                                     for issue in self.unresolved[node_id]]
            context["coverage"].update(included_nodes=len(kept),
                omitted_by_budget={key: len(ids - kept) for key, ids in omitted.items()},
                sources_truncated=sum(bool(r.get("omitted_source_chars")) or any(a.get("omitted_source_chars") for a in r.get("arguments", []))
                                      for r in [context["target"], *context["nodes"]]))
            context["coverage"]["budget_exhausted"] = any(context["coverage"]["omitted_by_budget"].values()) or bool(context["coverage"]["sources_truncated"])
        refresh()
        while len(json_text(context)) > max_chars and context["nodes"]:
            omitted["chars"].add(context["nodes"].pop()["id"])
            refresh()
        if len(json_text(context)) > max_chars:
            raise ValueError("Target metadata exceeds context budget: " + target_id)
        # Enforce the advertised serialized size including all coverage metadata.
        if len(json_text(context)) > max_chars:
            raise ValueError("Context exceeds budget; increase --max-context-chars")
        return context

    def stats(self):
        return {"nodes": len(self.nodes), "edges": len(self.edges),
                "index_hashes": self.index_hashes,
                "relations": dict(sorted((kind, sum(e["relation"] == kind for e in self.edges.values()))
                                         for kind in {e["relation"] for e in self.edges.values()}))}
