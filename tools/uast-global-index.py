#!/usr/bin/env python3
"""Index YASA Python UAST exports; do not infer entrypoints or execute source."""

import argparse
import hashlib
import json
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


def children(value):
    if isinstance(value, list):
        yield from value
    elif isinstance(value, dict):
        for key, child in value.items():
            if key not in {"loc", "parent", "_meta"}:
                yield child


def identifiers(value):
    """Syntactic names, not resolved references; member property names are excluded."""
    if isinstance(value, dict):
        if value.get("type") == "VariableDeclaration":
            # Keyword arguments are represented as declarations (view_func=handler).
            yield from identifiers(value.get("init"))
            return
        if value.get("type") == "Identifier":
            if value.get("name"):
                yield value["name"]
            return
        if value.get("type") == "MemberAccess":
            yield from identifiers(value.get("object"))
            if value.get("computed"):
                yield from identifiers(value.get("property"))
            return
    for child in children(value):
        yield from identifiers(child)


def expression_name(node):
    if not isinstance(node, dict):
        return ""
    kind = node.get("type")
    if kind == "Identifier":
        return node.get("name", "")
    if kind == "Literal":
        return str(node.get("value", ""))
    if kind == "MemberAccess" and not node.get("computed"):
        return ".".join(filter(None, [expression_name(node.get("object")), expression_name(node.get("property"))]))
    return ""


def location(node):
    loc = node.get("loc") or {}
    start, end = loc.get("start") or {}, loc.get("end") or {}
    return {"start_line": start.get("line"), "start_column": start.get("column"),
            "end_line": end.get("line"), "end_column": end.get("column")}


def area(file):
    first = Path(file).parts[0]
    return {"CTFd": "application", "tests": "tests", "migrations": "migrations"}.get(first, "scripts_or_other")


class GlobalIndex:
    def __init__(self, repo, ast_dir, source_roots=(), application_roots=()):
        self.repo, self.ast_dir = repo, ast_dir
        self.source_roots = sorted((Path(p) for p in source_roots), key=lambda p: -len(p.parts))
        self.application_roots = tuple(Path(p) for p in application_roots)
        self.tables = {name: [] for name in ("files", "functions", "classes", "imports", "calls", "assignments")}
        self.lookup = {name: defaultdict(list) for name in (
            "functions_by_name", "classes_by_name", "calls_by_callee", "calls_by_argument_name", "importers_by_file")}
        self.modules = defaultdict(list)
        self.node_types = Counter()
        self.sources = {}
        self.ast_files = {}
        self.diagnostics = []

    def source(self, node):
        loc = location(node)
        first, last = loc["start_line"], loc["end_line"]
        if not first or not last:
            return ""
        lines = self.lines[first - 1:last]
        if not lines:
            return ""
        # Python's parser reports UTF-8 byte columns, one-based in this UAST.
        encoded = [line.encode("utf-8") for line in lines]
        if loc["end_column"]:
            encoded[-1] = encoded[-1][:loc["end_column"] - 1]
        if loc["start_column"]:
            encoded[0] = encoded[0][loc["start_column"] - 1:]
        return b"".join(encoded).decode("utf-8", errors="replace")

    def base(self, node, kind, scope, ast_path):
        loc = location(node)
        token = f"{self.file}:{kind}:{ast_path}"
        return {"id": f"{kind}:{hashlib.sha256(token.encode()).hexdigest()[:20]}",
                "file": self.file, "area": self.area(self.file), **loc,
                "scope_id": scope[-1]["id"] if scope else None,
                "in_synthetic_scope": any(item.get("origin") == "parser_generated" for item in scope),
                "nodehash": (node.get("_meta") or {}).get("nodehash"),
                "ast_file": self.ast_files[self.file], "ast_path": ast_path}

    def scope_names(self, scope):
        return ".".join(item["name"] for item in scope)

    def visit(self, value, scope=(), ast_path="", region="body", decorated_target=None):
        if isinstance(value, list):
            for index, node in enumerate(value):
                self.visit(node, scope, f"{ast_path}/{index}", region, decorated_target)
            return
        if not isinstance(value, dict):
            return
        kind = value.get("type")
        if kind:
            self.node_types[kind] += 1
        if kind in {"FunctionDefinition", "ClassDefinition"}:
            table = "functions" if kind == "FunctionDefinition" else "classes"
            row = self.base(value, table[:-1] if table == "functions" else "class", scope, ast_path)
            name = expression_name(value.get("id")) or value.get("name") or "<anonymous>"
            decorators = (value.get("_meta") or {}).get("decorators") or []
            row.update(name=name, qualified_name=".".join(filter(None, [self.module, self.scope_names(scope), name])),
                       lexical_name=".".join(filter(None, [self.scope_names(scope), name])),
                       decorators=[{"expression": self.source(d), "name": expression_name(d.get("callee", d)),
                                    **location(d)} for d in decorators])
            declaration_start = min([row["start_line"] or 1] + [location(d)["start_line"] or row["start_line"] or 1 for d in decorators])
            row["source_start_line"] = declaration_start
            row["source"] = "".join(self.lines[declaration_start - 1:row["end_line"]])
            if table == "functions":
                fragment = self.source(value).lstrip()
                row["origin"] = ("lambda" if fragment.startswith("lambda") else
                                 "source_definition" if fragment.startswith(("def ", "async def ")) else
                                 "parser_generated")
                row["kind"] = ("lambda" if row["origin"] == "lambda" else
                               "method" if scope and scope[-1]["kind"] == "class" else "function")
                row["enclosing_class_id"] = next((item["id"] for item in reversed(scope) if item["kind"] == "class"), None)
                row["is_async"] = bool((value.get("_meta") or {}).get("isAsync"))
                row["parameters"] = [{"name": expression_name(p.get("id")),
                                      "kind": (p.get("_meta") or {}).get("parameterKind"),
                                      "source": self.source(p)} for p in value.get("parameters") or []]
            else:
                row["bases"] = [{"expression": self.source(b) or expression_name(b),
                                  "name": expression_name(b)} for b in value.get("supers") or []]
            self.tables[table].append(row)
            self.lookup[f"{table}_by_name"][name].append(row["id"])
            own_scope = (*scope, {"id": row["id"], "name": name, "origin": row.get("origin"),
                                 "kind": "class" if table == "classes" else "function"})
            # Decorators, defaults and bases are evaluated in the enclosing scope.
            self.visit(decorators, scope, f"{ast_path}/_meta/decorators", "decorator", row["id"])
            for key, child in value.items():
                if key not in {"loc", "parent", "_meta"}:
                    self.visit(child, own_scope if key == "body" else scope, f"{ast_path}/{key}",
                               "body" if key == "body" else "definition", None)
            return
        if kind == "ImportExpression":
            row = self.base(value, "import", scope, ast_path)
            module = expression_name(value.get("from"))
            imported = expression_name(value.get("imported"))
            local = expression_name(value.get("local"))
            row.update(module=module or imported, imported_name=imported if module else None,
                       local_name=local or (imported if module else imported.split(".")[0]),
                       source=self.source(value), resolution="unresolved", target_files=[])
            self.tables["imports"].append(row)
        elif kind in {"CallExpression", "NewExpression"}:
            row = self.base(value, "call", scope, ast_path)
            arguments = [{"source": self.source(a), "identifiers": sorted(set(identifiers(a)))}
                         for a in value.get("arguments") or []]
            callee_node = value.get("callee") or value.get("constructor") or {}
            callee = expression_name(callee_node) or self.source(callee_node)
            row.update(callee=callee, source=self.source(value), arguments=arguments,
                       region=region, decorated_target_id=decorated_target,
                       argument_names=sorted({name for arg in arguments for name in arg["identifiers"]}))
            self.tables["calls"].append(row)
            self.lookup["calls_by_callee"][callee].append(row["id"])
            for name in row["argument_names"]:
                self.lookup["calls_by_argument_name"][name].append(row["id"])
        elif kind == "AssignmentExpression":
            row = self.base(value, "assignment", scope, ast_path)
            row.update(target=self.source(value.get("left") or {}) or expression_name(value.get("left")),
                       value=self.source(value.get("right") or {}), operator=value.get("operator"),
                       source=self.source(value))
            self.tables["assignments"].append(row)
        for key, child in value.items():
            if key not in {"loc", "parent", "_meta"}:
                self.visit(child, scope, f"{ast_path}/{key}", region, decorated_target)
        # Keep calls/expressions embedded in metadata such as annotations.
        meta = value.get("_meta") or {}
        for key, child in meta.items():
            if isinstance(child, (dict, list)):
                self.visit(child, scope, f"{ast_path}/_meta/{key}", region, decorated_target)

    def area(self, file):
        path = Path(file)
        if any(path == root or root in path.parents for root in self.application_roots):
            return "application"
        return area(file)

    def module_name(self, file):
        path = Path(file)
        for root in self.source_roots:
            if root in path.parents:
                path = path.relative_to(root)
                break
        parts = list(path.with_suffix("").parts)
        if parts[-1] == "__init__":
            parts.pop()
        return ".".join(parts)

    def load(self):
        for relative in sorted(json.loads((self.ast_dir / "astList.json").read_text())):
            ast_file = self.ast_dir / relative
            tree = json.loads(ast_file.read_text())
            source = Path(tree.get("loc", {}).get("sourcefile", ""))
            if not source.is_absolute():
                source = self.repo / source
            file = source.resolve().relative_to(self.repo).as_posix()
            if file in self.sources:
                raise ValueError(f"Duplicate UAST for {file}")
            self.sources[file] = source.read_text(encoding="utf-8-sig")
            self.ast_files[file] = ast_file.relative_to(self.ast_dir.parent).as_posix()
            self.modules[self.module_name(file)].append(file)
        source_files = {p.relative_to(self.repo).as_posix() for p in self.repo.rglob("*.py")
                        if not any(part in {".git", ".venv", "node_modules", "__pycache__"} for part in p.relative_to(self.repo).parts)}
        missing = sorted(source_files - self.sources.keys())
        extra = sorted(self.sources.keys() - source_files)
        if missing or extra:
            raise ValueError(f"UAST coverage mismatch: missing={missing}, unexpected={extra}")
        for self.file in sorted(self.sources):
            self.module = self.module_name(self.file)
            self.lines = self.sources[self.file].splitlines(keepends=True)
            tree = json.loads((self.ast_dir.parent / self.ast_files[self.file]).read_text())
            if tree.get("type") != "CompileUnit":
                raise ValueError(f"Invalid UAST root in {self.file}")
            self.tables["files"].append({"file": self.file, "module": self.module, "area": self.area(self.file),
                                         "lines": len(self.lines), "ast_file": self.ast_files[self.file],
                                         "sha256": hashlib.sha256((self.repo / self.file).read_bytes()).hexdigest()})
            self.visit(tree)
        self.resolve_imports()

    def resolve_imports(self):
        for row in self.tables["imports"]:
            module = row["module"]
            if module.startswith("."):
                level = len(module) - len(module.lstrip("."))
                package = self.module_name(row["file"]).split(".")
                if Path(row["file"]).name != "__init__.py":
                    package = package[:-1]
                if level > len(package):
                    self.diagnostics.append({"import_id": row["id"], "message": "relative import escapes repository package"})
                    continue
                prefix = package[:len(package) - level + 1]
                module = ".".join(prefix + ([module.lstrip(".")] if module.lstrip(".") else []))
            candidates = [module]
            if row["imported_name"] and row["imported_name"] != "*":
                candidates.insert(0, f"{module}.{row['imported_name']}")
            targets = next((self.modules[name] for name in candidates if name in self.modules), [])
            row["absolute_module"] = module
            row["target_files"] = targets
            row["resolution"] = "repository_module" if targets else "external_or_unresolved"
            # Module matching does not prove which function an imported alias denotes.
            for file in targets:
                self.lookup["importers_by_file"][file].append(row["id"])

    def write(self, out):
        out.mkdir(parents=True, exist_ok=True)
        for name, rows in self.tables.items():
            with (out / f"{name}.jsonl").open("w", encoding="utf-8") as stream:
                for row in rows:
                    stream.write(json.dumps(row, ensure_ascii=False) + "\n")
        (out / "lookup.json").write_text(json.dumps(self.lookup, ensure_ascii=False, indent=2) + "\n")
        git = subprocess.run(["git", "-C", str(self.repo), "rev-parse", "HEAD"], capture_output=True, text=True)
        summary = {"schema_version": 1, "created_at": datetime.now(timezone.utc).isoformat(),
                   "source_roots": [str(p) for p in self.source_roots],
                   "application_roots": [str(p) for p in self.application_roots],
                   "repository": str(self.repo), "commit": git.stdout.strip() if git.returncode == 0 else None,
                   "ast_directory": str(self.ast_dir), "coverage": {"parsed": len(self.sources), "missing": []},
                   "counts": {name: len(rows) for name, rows in self.tables.items()},
                   "function_origins": dict(Counter(row["origin"] for row in self.tables["functions"])),
                   "counts_by_area": {group: dict(Counter(row["area"] for row in rows)) for group, rows in self.tables.items()},
                   "node_types": dict(self.node_types.most_common()),
                   "import_resolution": dict(Counter(row["resolution"] for row in self.tables["imports"])),
                   "diagnostics": self.diagnostics,
                   "limitations": ["Syntactic UAST index, not a resolved call graph or entrypoint verdict.",
                                   "Import matching uses repository paths; dynamic imports and re-exports need further analysis.",
                                   "Argument name lookups can include same-name symbols from unrelated scopes; verify file and scope.",
                                   ("Configured package roots define application scope, including nested migrations."
                                    if self.application_roots else "Tests and migration functions are included and labelled separately.")]}
        (out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
        print(json.dumps({"coverage": summary["coverage"], "counts": summary["counts"],
                          "import_resolution": summary["import_resolution"]}, ensure_ascii=False, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--ast-dir", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--source-root", action="append", default=[], help="Repository-relative Python import root (repeatable)")
    parser.add_argument("--application-root", action="append", default=[], help="Repository-relative application package (repeatable; includes migrations)")
    args = parser.parse_args()
    for value in args.source_root + args.application_root:
        if Path(value).is_absolute() or ".." in Path(value).parts:
            parser.error("Roots must be repository-relative paths without '..'")
    index = GlobalIndex(args.repo.resolve(), args.ast_dir.resolve(), args.source_root, args.application_root)
    index.load()
    index.write(args.out.resolve())


if __name__ == "__main__":
    main()
