"""Bounded, auditable Python call-site contexts; not a taint slice or full PDG."""

import ast

from compact_context import CompactContext, bound_names
from context_graph import fingerprint


SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)


def span(file, node):
    return {"file": file, "start_line": node.lineno, "start_column_utf8": node.col_offset + 1,
            "end_line": node.end_lineno, "end_column_utf8_exclusive": node.end_col_offset + 1}


def dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return base + "." + node.attr if base else ""
    return ""


def references(node):
    result = set()
    for item in ast.walk(node):
        if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Load):
            result.add(item.id)
        elif isinstance(item, ast.Attribute) and isinstance(item.ctx, ast.Load) and dotted(item):
            result.add(dotted(item))
    return result


class SinkContext:
    def __init__(self, graph, max_state_chars=16000, max_dependencies=10, dependency_depth=2,
                 max_callees=2, max_callee_lines=100, max_uses=2):
        self.graph = graph
        self.compact = CompactContext(graph)
        self.max_state_chars, self.max_dependencies = max_state_chars, max_dependencies
        self.dependency_depth = dependency_depth
        self.max_callees, self.max_callee_lines, self.max_uses = max_callees, max_callee_lines, max_uses
        self.definitions = {}
        self._call_tree, self._call_nodes = None, {}
        self._imports = {}
        for table in ("functions", "classes"):
            for row in graph.tables[table]:
                key = (row["file"], row.get("start_line"), row.get("name"))
                if row.get("origin", "source_definition") == "source_definition":
                    self.definitions.setdefault(key, graph.nodes[row["id"]])

    def source_imports(self, file):
        if file in self._imports:
            return self._imports[file]
        _, tree, parents = self.compact.syntax(file)
        result = {}
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Import, ast.ImportFrom)):
                continue
            scope_id = self.scope(file, node, parents)
            for alias in node.names:
                local = alias.asname or (alias.name if isinstance(node, ast.ImportFrom) else alias.name.split(".")[0])
                matches = [r for r in self.graph.tables["imports"] if r["file"] == file and r.get("scope_id") == scope_id
                           and node.lineno <= r["start_line"] <= node.end_lineno
                           and (r.get("imported_name") == alias.name if isinstance(node, ast.ImportFrom) else r.get("module") == alias.name)]
                result.setdefault((scope_id, local), []).append((node.lineno, node.end_lineno, matches))
        self._imports[file] = result
        return result

    def resolve(self, name, file, scope_id, line):
        """Honor source-level 'as' bindings even when an old UAST index lost them.

        Keep this adapter local to sink retrieval; frozen entrypoint/source
        experiments and the original ContextGraph are not changed.
        """
        root, separator, attrs = name.partition(".")
        imports = self.source_imports(file)
        for scope in self.graph.scopes(scope_id):
            raw = self.graph.symbols.get((file, scope, root), [])
            if any(self.graph.nodes[i]["record_type"] != "imports" for i in raw):
                return (*self.graph.resolve(name, file, scope_id, line), [])
            bindings = imports.get((scope, root), [])
            if bindings:
                ids, via, spans = [], [], []
                reason = "source_import_binding_unresolved"
                for first, last, rows in bindings:
                    if scope is not None and first > line:
                        continue
                    spans.append((file, first, last))
                    for row in rows:
                        # Look up the original UAST spelling, but present the real
                        # source import statement and alias to the model.
                        reference = row["local_name"] + (separator + attrs if separator else "")
                        found, path, reason = self.graph.resolve(reference, file, scope, line)
                        ids.extend(found)
                        via.extend([row["id"]] + path)
                return list(dict.fromkeys(ids)), list(dict.fromkeys(via)), reason, spans
            if raw:
                return [], [], "uast_import_alias_disagrees_with_source", []
        return (*self.graph.resolve(name, file, scope_id, line), [])

    def owner(self, file, node, parents):
        child, current = node, parents.get(node)
        while current is not None:
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                # Defaults, annotations, bases and decorators execute in the outer
                # scope. Only descendants of the body's statements bind locally.
                if child in current.body:
                    row = self.definitions.get((file, current.lineno, current.name))
                    if row:
                        return row, current
            child, current = current, parents.get(current)
        return self.graph.nodes[self.graph.file_modules[file]], None

    def scope(self, file, node, parents):
        row, _ = self.owner(file, node, parents)
        return row["id"] if row["record_type"] in {"functions", "classes"} else None

    def inventory(self, area="application", functions=(), candidate_ids=(), limit=None):
        result = []
        selected_files = None
        if functions:
            selected_files = {r["file"] for r in self.definitions.values() if r.get("qualified_name") in functions}
            selected_files.update(f for f, r in self.graph.files.items() if r["module"] + ".<module>" in functions)
        for file in sorted(self.graph.files):
            if selected_files is not None and file not in selected_files:
                continue
            if area != "all" and self.graph.files[file]["area"] != area:
                continue
            lines, tree, parents = self.compact.syntax(file)
            text = "".join(lines)
            for node in sorted((n for n in ast.walk(tree) if isinstance(n, ast.Call)),
                               key=lambda n: (n.lineno, n.col_offset, n.end_lineno, n.end_col_offset)):
                owner, owner_node = self.owner(file, node, parents)
                location = span(file, node)
                candidate_id = "sink_" + fingerprint(location)[:24]
                args = []
                for i, arg in enumerate(node.args):
                    args.append({"selector": "positional_" + str(i), "kind": "starred" if isinstance(arg, ast.Starred) else "positional",
                                 "source_index": i, "name": None, "expression": ast.get_source_segment(text, arg),
                                 "location": span(file, arg)})
                for i, arg in enumerate(node.keywords):
                    args.append({"selector": "keyword_" + str(i), "kind": "keyword" if arg.arg else "keyword_expansion",
                                 "source_index": i, "name": arg.arg, "expression": ast.get_source_segment(text, arg.value),
                                 "location": span(file, arg.value)})
                if isinstance(node.func, ast.Attribute):
                    args.append({"selector": "receiver", "kind": "receiver", "name": None,
                                 "expression": ast.get_source_segment(text, node.func.value),
                                 "location": span(file, node.func.value)})
                item = {"candidate_id": candidate_id, "location": location, "area": self.graph.files[file]["area"],
                        "owner_id": owner["id"], "owner": owner.get("qualified_name", self.graph.files[file]["module"] + ".<module>"),
                        "scope_id": self.scope(file, node, parents), "callee": ast.get_source_segment(text, node.func),
                        "callee_reference": dotted(node.func), "expression": ast.get_source_segment(text, node), "arguments": args}
                if functions and item["owner"] not in functions:
                    continue
                if candidate_ids and candidate_id not in candidate_ids:
                    continue
                result.append(item)
        # The source AST is the inventory: repeated UAST decorator/synthetic views
        # do not introduce extra model targets for the same physical call site.
        ids = [row["candidate_id"] for row in result]
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate physical call position")
        if functions and set(functions) - {r["owner"] for r in result}:
            raise ValueError("Selected function has no call candidates")
        if candidate_ids and set(candidate_ids) - set(ids):
            raise ValueError("Selected candidate is not in the requested scope")
        return result[:limit] if limit else result

    def build(self, candidate, prompt):
        file = candidate["location"]["file"]
        lines, tree, parents = self.compact.syntax(file)
        text = "".join(lines)
        if self._call_tree is not tree:
            self._call_tree = tree
            self._call_nodes = {(n.lineno, n.col_offset + 1, n.end_lineno, n.end_col_offset + 1): n
                                for n in ast.walk(tree) if isinstance(n, ast.Call)}
        loc = candidate["location"]
        node = self._call_nodes[(loc["start_line"], loc["start_column_utf8"], loc["end_line"], loc["end_column_utf8_exclusive"])]
        owner, owner_node = self.owner(file, node, parents)
        if owner["id"] != candidate["owner_id"] or ast.get_source_segment(text, node) != candidate["expression"]:
            raise ValueError("Call definition changed since inventory: " + candidate["candidate_id"])
        blocks, omitted, unresolved, resolutions = [], [], [], []
        covered = set()

        def add(file, first, last, role, priority, source=None, required=False):
            if not isinstance(first, int) or not isinstance(last, int) or first < 1 or last < first:
                unresolved.append({"role": role, "file": file, "reason": "missing_source_span"})
                return
            key = (file, first, last, source)
            if key in covered:
                return
            covered.add(key)
            src = source if source is not None else "".join(self.compact.syntax(file)[0][first - 1:last])
            blocks.append({"file": file, "start_line": first, "end_line": last, "role": role,
                           "priority": priority, "required": required, "source": src})

        def header(file, definition, role, priority, required=False):
            last = max(definition.lineno, min(n.lineno for n in definition.body) - 1)
            add(file, definition.lineno, last, role, priority, required=required)

        add(file, node.lineno, node.end_lineno, "target_call", 0, candidate["expression"], True)
        if owner_node:
            header(file, owner_node, "owner_signature", 1, True)
        current = parents.get(node)
        while current and not isinstance(current, (ast.Module,) + SCOPES):
            if isinstance(current, ast.stmt) and not isinstance(current, (ast.If, ast.For, ast.AsyncFor, ast.While,
                                                                         ast.With, ast.AsyncWith, ast.Try)):
                add(file, current.lineno, current.end_lineno, "enclosing_statement", 10)
                break
            current = parents.get(current)
        current = parents.get(node)
        while current and not isinstance(current, ast.Module):
            if isinstance(current, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith, ast.Try)):
                body = current.body
                if body:
                    add(file, current.lineno, max(current.lineno, body[0].lineno - 1), "enclosing_control", 20)
            elif isinstance(current, ast.ClassDef):
                header(file, current, "owner_class", 18)
            current = parents.get(current)

        needed = references(node)
        dependency_nodes, chosen = [], set()
        for _ in range(self.dependency_depth):
            newly_needed = set()
            matches = []
            for item in ast.walk(tree):
                if not isinstance(item, (ast.Assign, ast.AnnAssign, ast.AugAssign)) or item in chosen:
                    continue
                if item.end_lineno > node.lineno or self.scope(file, item, parents) != candidate["scope_id"]:
                    continue
                targets = item.targets if isinstance(item, ast.Assign) else [item.target]
                bound = bound_names(item) | {dotted(t) for t in targets if dotted(t)}
                if bound & needed:
                    matches.append(item)
            matches.sort(key=lambda n: (-n.lineno, n.col_offset))
            for item in matches:
                chosen.add(item)
                if len(dependency_nodes) >= self.max_dependencies:
                    omitted.append({"role": "argument_binding", "file": file, "start_line": item.lineno,
                                    "end_line": item.end_lineno, "reason": "dependency_statement_limit"})
                    continue
                dependency_nodes.append(item)
                newly_needed.update(references(item.value))
                add(file, item.lineno, item.end_lineno, "argument_binding", 22)
            needed.update(newly_needed)
        # Record unresolved lexical lambda bindings, rather than confusing a
        # lambda parameter with an imported global carrying the same name.
        lambda_names = set()
        current = parents.get(node)
        while current is not None and current is not owner_node:
            if isinstance(current, ast.Lambda):
                lambda_names.update(a.arg for a in current.args.posonlyargs + current.args.args + current.args.kwonlyargs)
                lambda_names.update(a.arg for a in (current.args.vararg, current.args.kwarg) if a)
            current = parents.get(current)
        evidence, identities = set(), []
        for name in sorted(needed, key=lambda n: (n != candidate["callee_reference"], n)):
            if name.split(".")[0] in lambda_names:
                unresolved.append({"reference": name, "reason": "lambda_parameter"})
                continue
            ids, via, reason, import_spans = self.resolve(name, file, candidate["scope_id"], node.lineno)
            for import_file, first, last in import_spans:
                add(import_file, first, last, "source_import_binding", 5)
            resolutions.append({"reference": name, "identities": ids, "via": via, "reason": reason})
            evidence.update(ids + via)
            if name == candidate["callee_reference"]:
                identities.extend(ids)
            if not ids:
                unresolved.append({"reference": name, "reason": reason})
        for record_id in sorted(evidence):
            row = self.graph.nodes[record_id]
            if row["record_type"] == "imports":
                _, module, _ = self.compact.syntax(row["file"])
                for statement in ast.walk(module):
                    if isinstance(statement, (ast.Import, ast.ImportFrom)) and statement.lineno <= row["start_line"] <= statement.end_lineno:
                        # Keep the real, complete import statement; no synthesized
                        # explanation that could misrepresent alias binding.
                        add(row["file"], statement.lineno, statement.end_lineno, "import_binding", 5)
                        break
            elif row["record_type"] == "assignments" and record_id in evidence:
                add(row["file"], row.get("start_line"), row.get("end_line"), "resolved_binding", 24)
        callees = []
        for record_id in dict.fromkeys(identities):
            row = self.graph.nodes[record_id]
            if row["record_type"] != "functions":
                continue
            if len(callees) >= self.max_callees:
                omitted.append({"role": "local_callee", "record_id": record_id, "reason": "callee_count_limit"})
                continue
            callees.append(record_id)
            definition = self.compact.definition(row)
            if definition.end_lineno - definition.lineno + 1 <= self.max_callee_lines:
                first = min([definition.lineno] + [d.lineno for d in definition.decorator_list])
                add(row["file"], first, definition.end_lineno, "local_callee_complete", 25)
            else:
                header(row["file"], definition, "local_callee_signature", 25)
                omitted.append({"role": "local_callee_body", "record_id": record_id, "reason": "callee_line_limit"})
            for reference in references(definition):
                _, via, _, import_spans = self.resolve(reference, row["file"], row["id"], row["end_line"])
                for import_file, first, last in import_spans:
                    add(import_file, first, last, "callee_import", 26)
                for import_id in via:
                    imported = self.graph.nodes[import_id]
                    if imported["record_type"] == "imports":
                        add(imported["file"], imported.get("start_line"), imported.get("end_line"), "callee_import", 26)
        uses = []
        for edge in self.graph.incoming[candidate["owner_id"]]:
            if edge["relation"] != "calls":
                continue
            row = self.graph.nodes[edge["source"]]
            if row["record_type"] == "calls" and (candidate["area"] == "all" or row.get("area") == candidate["area"]):
                uses.append(row)
        for row in sorted(uses, key=lambda r: (r["file"], r["start_line"]))[:self.max_uses]:
            add(row["file"], row["start_line"], row["end_line"], "direct_caller", 40)
        if len(uses) > self.max_uses:
            omitted.append({"role": "direct_caller", "count": len(uses) - self.max_uses, "reason": "direct_use_limit"})
        context = {"candidate": candidate, "resolutions": resolutions, "unresolved": unresolved,
                   "blocks": [], "omitted": omitted,
                   "coverage": {"target_call_complete": True, "whole_function_included": False,
                                "full_runtime_chain_proven": False, "is_backward_taint_slice": False,
                                "token_limit_claimed": False, "direct_use_candidates": len(uses)}}
        import json
        metadata = {k: candidate[k] for k in ("candidate_id", "owner", "location", "callee", "arguments")}
        prefix = prompt["definition"] + "\n\nTarget call C:\n" + json.dumps(metadata, ensure_ascii=False, indent=2)
        prefix += "\n\nEvidence is bounded static context. Omitted bindings/bodies and dynamic calls are not proof of absence.\n"
        callee_resolutions = [r for r in resolutions if r["reference"] == candidate["callee_reference"]]
        prefix += "Callee resolution: " + json.dumps(callee_resolutions or [{"reference": candidate["callee"],
            "reason": "dynamic_or_unresolved_callee"}], ensure_ascii=False) + "\n"
        if unresolved:
            prefix += "Unresolved references (first 8): " + json.dumps(unresolved[:8], ensure_ascii=False) + "\n"

        def render(selected):
            return prefix + "".join("\n[{} {}:{}-{}]\n{}\n".format(b["role"], b["file"], b["start_line"],
                b["end_line"], b["source"].rstrip()) for b in selected)

        selected = []
        for block in sorted(blocks, key=lambda b: (not b["required"], b["priority"], b["file"], b["start_line"])):
            if block["required"] or len(render(selected + [block])) <= self.max_state_chars:
                selected.append(block)
            else:
                context["omitted"].append({k: block[k] for k in ("file", "start_line", "end_line", "role")}
                                          | {"reason": "state_character_budget"})
        context["blocks"] = selected
        note = "\nContext omissions: {}. Unresolved references: {}. Missing evidence may require unknown.\n".format(
            len(context["omitted"]), len(unresolved))
        # Reserve the disclosure itself; never silently drop the complete target.
        while len(render(selected) + note) > self.max_state_chars and any(not b["required"] for b in selected):
            last = next(b for b in reversed(selected) if not b["required"])
            selected.remove(last)
            context["omitted"].append({k: last[k] for k in ("file", "start_line", "end_line", "role")}
                                      | {"reason": "disclosure_character_budget"})
            note = "\nContext omissions: {}. Unresolved references: {}. Missing evidence may require unknown.\n".format(len(context["omitted"]), len(unresolved))
        context["state"] = render(selected) + note
        context["coverage"].update(state_characters=len(context["state"]),
                                   state_utf8_bytes=len(context["state"].encode("utf-8")),
                                   character_budget_exceeded=len(context["state"]) > self.max_state_chars,
                                   blocks_selected=len(selected), blocks_omitted=len(context["omitted"]))
        return context
