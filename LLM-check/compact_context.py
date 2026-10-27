"""Source-only contexts: target, direct uses, and narrowly selected surrounding code."""

import ast
import textwrap
from functools import lru_cache
from binding_context import BindingContext


def start_line(node):
    return min([node.lineno] + [d.lineno for d in getattr(node, "decorator_list", [])])


def loaded_names(node):
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}


def bound_names(node):
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return set()
    result = set()
    def visit(item):
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            return
        if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Store):
            result.add(item.id)
        for child in ast.iter_child_nodes(item):
            visit(child)
    visit(node)
    return result


def names_in_text(source):
    try:
        return loaded_names(ast.parse(textwrap.dedent(source)))
    except SyntaxError:
        return set()


class CompactContext:
    def __init__(self, graph, max_uses=6, reference_areas=("application",), max_binding_classes=12, max_binding_sites=24):
        self.graph, self.max_uses = graph, max_uses
        self.reference_areas = reference_areas
        self.bindings = BindingContext(graph, max_binding_classes, max_binding_sites, reference_areas)

    @lru_cache(maxsize=32)
    def syntax(self, file):
        text = (self.graph.repo / file).read_text(encoding="utf-8")
        tree = ast.parse(text, filename=file)
        parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
        return text.splitlines(keepends=True), tree, parents

    def definition(self, row):
        _, tree, _ = self.syntax(row["file"])
        kinds = (ast.FunctionDef, ast.AsyncFunctionDef) if row["record_type"] == "functions" else (ast.ClassDef,)
        matches = [n for n in ast.walk(tree) if isinstance(n, kinds)
                   and n.lineno == row["start_line"] and n.name == row["name"]]
        if len(matches) != 1:
            raise ValueError("Cannot locate exact Python definition: " + row["id"])
        return matches[0]

    def build(self, target):
        target_node = self.definition(target)
        target_start, target_end = start_line(target_node), target_node.end_lineno
        lines, tree, parents = self.syntax(target["file"])
        if "".join(lines[target_start - 1:target_end]).rstrip() != target["source"].rstrip():
            raise ValueError("Indexed target does not match source: " + target["id"])
        uses = {}
        target_edges = [edge for node_id in target.get("definition_alias_ids", [target["id"]])
                        for edge in self.graph.incoming[node_id]]
        for edge in target_edges:
            if edge["relation"] not in {"calls", "argument_reference", "alias_of", "value_reference"}:
                continue
            row = self.graph.nodes[edge["source"]]
            if row["record_type"] not in {"calls", "assignments"}:
                continue
            if self.reference_areas is not None and row.get("area") not in self.reference_areas:
                continue
            if row["file"] == target["file"] and target_start <= row["start_line"] <= row["end_line"] <= target_end:
                continue  # Already visible inside the complete target.
            uses[row["id"]] = dict(row, reference_kind=edge["relation"])
        # Prefer direct calls over their enclosing argument expressions at the same site.
        calls = [r for r in uses.values() if r["reference_kind"] == "calls"]
        sites = [r for r in uses.values() if r["reference_kind"] == "calls" or not any(
            c["file"] == r["file"] and r["start_line"] <= c["start_line"] <= c["end_line"] <= r["end_line"] for c in calls)]
        sites.sort(key=lambda r: (0 if r["reference_kind"] == "argument_reference" else 1, r["file"], r["start_line"], r["id"]))
        selected_uses = sites[:self.max_uses]
        blocks = []
        covered = set()
        def add(file, first, last, role, record_id=None):
            source_lines, _, _ = self.syntax(file)
            pending = [line for line in range(first, last + 1) if (file, line) not in covered]
            while pending:
                begin = end = pending.pop(0)
                while pending and pending[0] == end + 1:
                    end = pending.pop(0)
                text = "".join(source_lines[begin - 1:end])
                blocks.append({"file": file, "start_line": begin, "end_line": end,
                               "role": role, "source": text, "record_id": record_id})
                covered.update((file, line) for line in range(begin, end + 1))
        add(target["file"], target_start, target_end, "target", target["id"])
        for row in selected_uses:
            add(row["file"], row["start_line"], row["end_line"], "direct_use", row["id"])

        # Recover only headers and local statements needed by T or its direct uses.
        structural = set()
        for decorator in target_node.decorator_list:
            structural.update(loaded_names(decorator))
        owner = parents.get(target_node)
        ancestors = []
        while owner is not None and not isinstance(owner, ast.Module):
            ancestors.append(owner)
            if isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                first_body = min(start_line(n) for n in owner.body)
                add(target["file"], start_line(owner), max(owner.lineno, first_body - 1), "outer_header")
                if isinstance(owner, ast.ClassDef):
                    for expr in owner.decorator_list + owner.bases:
                        structural.update(loaded_names(expr))
            elif hasattr(owner, "body") and isinstance(owner.body, list) and owner.body:
                # Keep controlling if/with/for headers around nested definitions.
                add(target["file"], owner.lineno, max(owner.lineno, start_line(owner.body[0]) - 1), "outer_control")
            owner = parents.get(owner)
        needed = loaded_names(target_node)
        for use in selected_uses:
            needed.update(names_in_text(use["source"]))
            structural.update(names_in_text(use["source"]))
        for ancestor in ancestors:
            if not isinstance(ancestor, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            chosen = set()
            changed = True
            while changed:
                changed = False
                for statement in ancestor.body:
                    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        continue
                    includes_use = any(u["file"] == target["file"] and statement.lineno <= u["start_line"] <= statement.end_lineno for u in selected_uses)
                    if statement not in chosen and (includes_use or bound_names(statement) & needed):
                        chosen.add(statement)
                        needed.update(loaded_names(statement))
                        changed = True
            for statement in sorted(chosen, key=lambda n: n.lineno):
                add(target["file"], statement.lineno, statement.end_lineno, "outer_implementation")

        binding_context = self.bindings.build(target)
        extra_imports = {}
        omitted_binding_statements = 0

        def imports_for(names, row):
            for name in sorted(names):
                ids, via, _ = self.graph.resolve(name, row["file"], row.get("scope_id"), row.get("start_line"))
                for node_id in ids + via:
                    item = self.graph.nodes[node_id]
                    if item["record_type"] == "imports":
                        extra_imports[node_id] = item

        def header(row, role):
            node = self.definition(row)
            first_body = min(start_line(n) for n in node.body)
            add(row["file"], start_line(node), max(node.lineno, first_body - 1), role, row["id"])
            expressions = list(node.decorator_list) + (list(node.bases) if isinstance(node, ast.ClassDef) else [])
            for expr in expressions:
                imports_for(loaded_names(expr), row)

        # Add every selected receiver's inheritance path as headers, not full class
        # bodies. A child class is evidence about T; it is not another target.
        for receiver in binding_context["receivers"]:
            for class_id in receiver["inheritance_path"]:
                header(self.graph.nodes[class_id], "receiver_class")
        for evidence in binding_context["sites"]:
            row = self.graph.nodes[evidence["record_id"]]
            add(row["file"], row["start_line"], row["end_line"], "binding_site", row["id"])
            imports_for(names_in_text(row["source"]), row)
            _, module, parent_map = self.syntax(row["file"])
            containers = [n for n in ast.walk(module) if isinstance(n, ast.stmt)
                          and n.lineno <= row["start_line"] <= row["end_line"] <= n.end_lineno]
            if not containers:
                continue
            current = min(containers, key=lambda n: (n.end_lineno - n.lineno, -n.lineno))
            site_names = names_in_text(row["source"])
            scopes = []
            parent = parent_map.get(current)
            while parent is not None:
                if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    first_body = min(start_line(n) for n in parent.body)
                    add(row["file"], start_line(parent), max(parent.lineno, first_body - 1), "binding_scope")
                    scopes.append(parent)
                elif isinstance(parent, ast.Module):
                    scopes.append(parent)
                parent = parent_map.get(parent)
            for scope in scopes:
                chosen = set()
                changed = True
                while changed:
                    changed = False
                    for statement in scope.body:
                        if statement in chosen or isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                            continue
                        if bound_names(statement) & site_names:
                            chosen.add(statement)
                            site_names.update(loaded_names(statement))
                            changed = True
                for index, statement in enumerate(sorted(chosen, key=lambda n: n.lineno)):
                    if index >= 8 or statement.end_lineno - statement.lineno >= 60:
                        omitted_binding_statements += 1
                        continue
                    add(row["file"], statement.lineno, statement.end_lineno, "binding_dependency")
                    imports_for(loaded_names(statement), dict(row, start_line=statement.lineno))

        # Import bindings for referenced names; module initializers only for structural
        # names (decorator receivers, bases and direct-use arguments), not all callees.
        names = sorted(needed | structural, key=lambda n: (n not in structural, n))
        imports, assignments = dict(extra_imports), {}
        for name in names:
            ids, via, _ = self.graph.resolve(name, target["file"], target["id"], target["end_line"])
            for node_id in ids + via:
                row = self.graph.nodes[node_id]
                if row["record_type"] == "imports":
                    imports[node_id] = row
                elif name in structural and row["record_type"] == "assignments" and row.get("scope_id") is None:
                    assignments[node_id] = row
        for row in assignments.values():
            add(row["file"], row["start_line"], row["end_line"], "binding")
            for name in names_in_text(row["source"]):
                _, via, _ = self.graph.resolve(name, row["file"], row.get("scope_id"), row["start_line"])
                for node_id in via:
                    if self.graph.nodes[node_id]["record_type"] == "imports":
                        imports[node_id] = self.graph.nodes[node_id]
        import_groups = {}
        for row in imports.values():
            _, module, _ = self.syntax(row["file"])
            statements = [n for n in ast.walk(module) if isinstance(n, (ast.Import, ast.ImportFrom))
                          and n.lineno <= row["start_line"] <= n.end_lineno]
            if statements:
                statement = min(statements, key=lambda n: n.end_lineno - n.lineno)
                key = (row["file"], statement.lineno, statement.end_lineno)
                group = import_groups.setdefault(key, {"node": statement, "rows": []})
                group["rows"].append(row)
        for (file, first, last), group in import_groups.items():
            if all((file, line) in covered for line in range(first, last + 1)):
                continue
            statement = group["node"]
            requested = {row.get("imported_name") or row.get("module") for row in group["rows"]}
            local_names = {row.get("local_name") for row in group["rows"]}
            aliases = [a for a in statement.names if a.name in requested or (a.asname or a.name.split(".")[0]) in local_names]
            if not aliases:
                raise ValueError("Cannot select imported aliases faithfully")
            selected = ", ".join(a.name + (" as " + a.asname if a.asname else "") for a in aliases)
            prefix = ("from " + "." * statement.level + (statement.module or "") + " import ") if isinstance(statement, ast.ImportFrom) else "import "
            source_lines, _, _ = self.syntax(file)
            blocks.append({"file": file, "start_line": first, "end_line": last,
                           "role": "import_binding", "source": prefix + selected + "\n",
                           "source_kind": "selected_import_aliases", "original_source": "".join(source_lines[first - 1:last])})
            covered.update((file, line) for line in range(first, last + 1))

        text = ["Target T: " + target["qualified_name"]]
        if binding_context["receivers"]:
            text += ["", "Receiver bindings are static candidates, not entrypoint verdicts; T remains the sole target."]
            for receiver in binding_context["receivers"]:
                names = [self.graph.nodes[i]["qualified_name"] for i in receiver["inheritance_path"]]
                text.append("Receiver: {} [{}]; inheritance path: {}".format(
                    receiver["qualified_name"], receiver["relation"], " -> ".join(names)))
            text.append("Python MRO and runtime dispatch are not proven by these bindings.")
        for block in blocks:
            text += ["", "[{} {}:{}-{}]".format(block["role"], block["file"], block["start_line"], block["end_line"]), block["source"].rstrip("\n")]
        if len(sites) > len(selected_uses):
            text += ["", "Additional direct use sites omitted: " + str(len(sites) - len(selected_uses))]
        if binding_context["classes_omitted"] or binding_context["sites_omitted"] or omitted_binding_statements:
            text += ["", "Additional binding evidence omitted: classes={}, sites={}, dependency statements={}".format(
                binding_context["classes_omitted"], binding_context["sites_omitted"], omitted_binding_statements)]
        return {"state": "\n".join(text) + "\n", "blocks": blocks, "binding_context": binding_context,
                "coverage": {"target_complete": True, "unique_source_lines": len(covered),
                             "direct_use_candidates": len(sites), "direct_uses_selected": len(selected_uses),
                             "direct_uses_omitted": len(sites) - len(selected_uses), "graph_edges_in_input": 0,
                             "binding_class_candidates": binding_context["class_candidates"],
                             "binding_classes_selected": len(binding_context["receivers"]),
                             "inherited_receivers_selected": sum(r["relation"] == "inherited_candidate" for r in binding_context["receivers"]),
                             "binding_classes_omitted": binding_context["classes_omitted"],
                             "binding_site_candidates": binding_context["sites_candidates"],
                             "binding_sites_selected": len(binding_context["sites"]),
                             "binding_sites_omitted": binding_context["sites_omitted"],
                             "binding_dependency_statements_omitted": omitted_binding_statements,
                             "selection": "direct references and dependency-selected surrounding statements; not a full runtime chain"}}
