"""Formation-guided Python evidence retrieval and unlabelled source candidates."""

import ast
from compact_context import CompactContext, loaded_names, start_line
from context_graph import fingerprint


PROFILES = {
    "registration": "direct registration sites and local registrar implementations",
    "inheritance": "local bases, overridden contracts and receiver initialization",
    "interface_implementation": "local interface contracts and receiver initialization",
    "configuration": "local referenced assignments and handler binding values",
    "callback": "callback registration sites and local registrar implementations",
    "decorator": "local decorator implementations and their import bindings",
    "other": "generic local input and call evidence",
}


def own_nodes(function):
    """Body of this function, excluding nested definitions and decorator evaluation."""
    def walk(node):
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            return
        for child in ast.iter_child_nodes(node):
            yield from walk(child)
    for statement in function.body:
        yield from walk(statement)


def enumerate_candidates(builder, row):
    node = builder.definition(row)
    lines, _, _ = builder.syntax(row["file"])
    text = "".join(lines)
    body = list(own_nodes(node))
    parents = {child: parent for parent in body for child in ast.iter_child_nodes(parent)}
    items = [(p, "parameter") for p in
             list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs)
             + ([node.args.vararg] if node.args.vararg else [])
             + ([node.args.kwarg] if node.args.kwarg else [])]
    for item in body:
        if isinstance(item, ast.Call):
            items.append((item, "call_return"))
        elif isinstance(item, (ast.Attribute, ast.Subscript)) and isinstance(item.ctx, ast.Load):
            # A method's callable attribute is not its return value. The Call has
            # its own candidate; input carriers in its receiver remain visible.
            parent = parents.get(item)
            if not (isinstance(parent, ast.Call) and parent.func is item):
                items.append((item, "attribute_read" if isinstance(item, ast.Attribute) else "subscript_read"))
    result = []
    for item, kind in items:
        expression = item.arg if isinstance(item, ast.arg) else ast.get_source_segment(text, item)
        # ast.arg spans include the annotation; candidate is the bound name only.
        end_line = item.lineno if isinstance(item, ast.arg) else item.end_lineno
        end_col = item.col_offset + len(item.arg.encode()) if isinstance(item, ast.arg) else item.end_col_offset
        location = {"file": row["file"], "start_line": item.lineno,
                    "start_column_utf8": item.col_offset + 1, "end_line": end_line,
                    "end_column_utf8_exclusive": end_col + 1}
        result.append({"candidate_id": "c_" + fingerprint([location, kind])[:16],
                       "owner_id": row["id"], "owner": row["qualified_name"],
                       "syntax_kind": kind, "expression": expression, "location": location})
    return sorted(result, key=lambda c: (c["location"]["start_line"], c["location"]["start_column_utf8"], c["syntax_kind"]))


class SourceContext:
    def __init__(self, graph, max_helpers=6, max_helper_lines=100, max_candidates=64):
        self.graph = graph
        self.compact = CompactContext(graph)
        self.max_helpers, self.max_helper_lines = max_helpers, max_helper_lines
        self.max_candidates = max_candidates

    def build(self, target, formation_types):
        base = self.compact.build(target)
        requested = list(dict.fromkeys(formation_types))
        profiles = requested or ["generic"]
        blocks = [dict(b, profiles=["baseline"]) for b in base["blocks"]]
        proposals = {}
        gaps, omitted = [], []

        def propose(row, reason, whole=False):
            if row["id"] == target["id"] or row.get("area") != "application":
                return
            if row["record_type"] not in {"functions", "classes", "assignments", "imports"}:
                return
            first, last = row["start_line"], row["end_line"]
            if type(first) is not int or type(last) is not int or first < 1 or last < first:
                gaps.append({"record_id": row["id"], "profile": reason, "reason": "missing_or_invalid_source_span"})
                return
            if row["record_type"] in {"functions", "classes"}:
                node = self.compact.definition(row)
                first = start_line(node)
                last = node.end_lineno if whole else min(start_line(n) for n in node.body) - 1
                last = max(last, node.lineno)
            key = (row["file"], first, last)
            item = proposals.setdefault(key, {"row": row, "first": first, "last": last,
                                              "profiles": [], "whole": whole})
            if reason not in item["profiles"]:
                item["profiles"].append(reason)

        def resolve_expr(expr, owner, reason, whole=True):
            name = ast.unparse(expr)
            ids, via, why = self.graph.resolve(name, owner["file"], owner["id"], getattr(expr, "lineno", owner["start_line"]))
            for node_id in via:
                evidence = self.graph.nodes[node_id]
                if evidence["record_type"] == "imports":
                    propose(evidence, reason)
            for node_id in ids:
                propose(self.graph.nodes[node_id], reason, whole=whole)
            if not ids:
                gaps.append({"owner": owner["qualified_name"], "expression": name,
                             "profile": reason, "reason": why})
            return ids

        node = self.compact.definition(target)
        # Generic local callees are always inspected, even if Jev supplied no
        # formation or an incorrect one. Only one statically resolved hop.
        for call in (n for n in own_nodes(node) if isinstance(n, ast.Call)):
            resolve_expr(call.func, target, "generic_callee")
        if "configuration" in requested:
            for name in sorted(loaded_names(node)):
                ids, via, _ = self.graph.resolve(name, target["file"], target["id"], target["end_line"])
                for node_id in ids + via:
                    row = self.graph.nodes[node_id]
                    if row["record_type"] in {"assignments", "imports"}:
                        propose(row, "configuration")
        if "decorator" in requested:
            for expr in node.decorator_list:
                resolve_expr(expr.func if isinstance(expr, ast.Call) else expr, target, "decorator")
        for profile in (p for p in ("registration", "callback") if p in requested):
            for block in base["blocks"]:
                row = self.graph.nodes.get(block.get("record_id"), {})
                if block["role"] not in {"direct_use", "binding_site"} or row.get("record_type") != "calls":
                    continue
                for edge in self.graph.outgoing[row["id"]]:
                    if edge["relation"] == "calls":
                        propose(self.graph.nodes[edge["target"]], profile, whole=True)
        owner = self.graph.nodes.get(target.get("scope_id"), {})
        for profile in (p for p in ("inheritance", "interface_implementation") if p in requested):
            if owner.get("record_type") != "classes":
                gaps.append({"profile": profile, "reason": "target_has_no_owning_class"})
                continue
            queue, seen = [owner], set()
            while queue:
                cls = queue.pop(0)
                if cls["id"] in seen:
                    continue
                seen.add(cls["id"])
                propose(cls, profile)
                for name in (target["name"], "__init__"):
                    for mid in self.graph.members.get((cls["id"], name), []):
                        propose(self.graph.nodes[mid], profile, whole=True)
                for parent in self.compact.definition(cls).bases:
                    for bid in resolve_expr(parent, cls, profile, whole=False):
                        base_cls = self.graph.nodes[bid]
                        if base_cls["record_type"] == "classes":
                            queue.append(base_cls)

        covered = {(b["file"], n) for b in blocks for n in range(b["start_line"], b["end_line"] + 1)}
        helpers = []
        ordered = sorted(proposals.values(), key=lambda p: (p["profiles"] == ["generic_callee"],
                         p["last"] - p["first"], p["row"]["file"], p["first"]))
        for item in ordered:
            row, first, last = item["row"], item["first"], item["last"]
            is_helper = row["record_type"] == "functions" and item["whole"]
            if last - first + 1 > self.max_helper_lines or (is_helper and len(helpers) >= self.max_helpers):
                omitted.append({"record_id": row["id"], "profiles": item["profiles"], "reason": "support_budget"})
                continue
            lines, _, _ = self.compact.syntax(row["file"])
            positions = {(row["file"], n) for n in range(first, last + 1)}
            if is_helper:
                helpers.append(row)
            # Merge evidence reasons even if a span is already in the baseline.
            for block in blocks:
                if block["file"] == row["file"] and not (block["end_line"] < first or block["start_line"] > last):
                    block["profiles"] = sorted(set(block["profiles"] + item["profiles"]))
            pending = sorted(n for f, n in positions - covered)
            while pending:
                begin = end = pending.pop(0)
                while pending and pending[0] == end + 1:
                    end = pending.pop(0)
                blocks.append({"file": row["file"], "start_line": begin, "end_line": end,
                               "role": "source_support", "source": "".join(lines[begin - 1:end]),
                               "record_id": row["id"], "profiles": sorted(item["profiles"])})
            covered.update(positions)
        # Recurse zero further hops. Supporting functions get imports so calls
        # such as request.get_json retain their actual import provenance.
        for helper in helpers:
            for name in sorted(loaded_names(self.compact.definition(helper))):
                _, via, _ = self.graph.resolve(name, helper["file"], helper["id"], helper["end_line"])
                for node_id in via:
                    row = self.graph.nodes[node_id]
                    if row["record_type"] != "imports":
                        continue
                    first, last = row["start_line"], row["end_line"]
                    if any((row["file"], n) in covered for n in range(first, last + 1)):
                        continue
                    lines, _, _ = self.compact.syntax(row["file"])
                    blocks.append({"file": row["file"], "start_line": first, "end_line": last,
                                   "role": "helper_import", "source": "".join(lines[first - 1:last]),
                                   "record_id": node_id, "profiles": ["generic_callee"]})
                    covered.update((row["file"], n) for n in range(first, last + 1))
        candidates = [c for row in [target] + helpers for c in enumerate_candidates(self.compact, row)]
        # Same location reached by multiple profiles is judged once per entrypoint.
        unique = {c["candidate_id"]: c for c in candidates}
        candidates = list(unique.values())
        return {"target": {k: target[k] for k in ("id", "file", "qualified_name", "source")},
                "formation_types": requested, "profiles": {p: PROFILES.get(p, "generic input evidence") for p in profiles},
                "blocks": blocks, "candidates": candidates[:self.max_candidates],
                "omitted_candidates": candidates[self.max_candidates:] if self.max_candidates is not None else [], "omitted_support": omitted,
                "unresolved": gaps, "baseline_coverage": base["coverage"],
                "helper_ids": [h["id"] for h in helpers], "helper_depth": 1,
                "full_runtime_chain_proven": False}


def render_context(context, blocks, candidates, definition, kind):
    text = [definition, "", "Target T: " + context["target"]["qualified_name"],
            "Jev predictions (unverified): formation=" + ",".join(context["formation_types"]) + "; kind=" + str(kind),
            "Static evidence only; missing external library bodies and dynamic links remain unresolved."]
    for block in blocks:
        text += ["", "[{} {}:{}-{}; profiles={}]".format(block["role"], block["file"],
                 block["start_line"], block["end_line"], ",".join(block["profiles"])), block["source"].rstrip()]
    text += ["", "Candidates (exact syntax positions; expressions below may be abbreviated):"]
    for c in candidates:
        loc = c["location"]
        expression = " ".join(c["expression"].split())
        text.append("{}: {} {}:{}:{} owner={} expression={}".format(c["candidate_id"], c["syntax_kind"],
                    loc["file"], loc["start_line"], loc["start_column_utf8"], c["owner"],
                    expression[:180] + (" ... [see full code]" if len(expression) > 180 else "")))
    text.append("Coverage gaps: unresolved links={}, omitted support={}, omitted candidates={}.".format(
        len(context["unresolved"]), len(context["omitted_support"]), len(context["omitted_candidates"])))
    return "\n".join(text)
