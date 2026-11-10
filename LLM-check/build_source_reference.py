#!/usr/bin/env python3
"""Build a source-only static reference; never read source predictions or scores."""

import argparse
import ast
import csv
import hashlib
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from context_graph import ContextGraph, fingerprint
from laya_smoke import write_json
from source_context import SourceContext, enumerate_candidates, own_nodes

HERE = Path(__file__).resolve().parent
DATA_FIELDS = {"args", "form", "json", "data", "files", "headers", "cookies", "values", "environ",
               "query_string", "path", "full_path", "url", "base_url", "url_root", "host", "host_url",
               "remote_addr", "remote_user", "referrer", "method", "authorization", "content_type",
               "content_length", "mimetype", "access_route", "user_agent", "view_args"}
REQUEST_METADATA = {"endpoint", "url_rule", "blueprint", "blueprints", "routing_exception"}
REQUEST_APIS = {"get_json", "get_data"}
DB_READS = {"execute", "all", "first", "one", "one_or_none", "scalar", "scalars", "get", "count", "paginate",
            "fetchone", "fetchall", "fetchmany", "scalar_one", "scalar_one_or_none"}
WRITES = {"set", "add", "add_all", "delete", "remove", "commit", "flush", "rollback", "update", "insert",
          "write", "writelines", "send", "sendall", "put", "publish"}
BUILTINS = {"str", "int", "float", "bool", "bytes", "bytearray", "dict", "list", "tuple", "set", "frozenset",
            "len", "range", "enumerate", "zip", "sorted", "reversed", "sum", "min", "max", "any", "all", "abs",
            "round", "print", "repr", "isinstance", "issubclass", "getattr", "hasattr", "setattr", "delattr",
            "type", "id", "super", "map", "filter", "iter", "next", "callable", "ord", "chr", "hex", "format"}
SAFE_MODULES = {"flask", "werkzeug", "marshmallow", "flask_restx", "sqlalchemy", "alembic", "datetime", "time",
                "json", "math", "re", "decimal", "collections", "functools", "itertools", "operator", "uuid",
                "hashlib", "hmac", "base64", "binascii", "html", "markupsafe", "jinja2", "click", "itsdangerous",
                "logging", "posixpath", "ntpath", "pathlib", "typing", "warnings", "dataclasses", "random"}


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def lines_json(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=False) + "\n")


def export_inventory(run, out):
    """Read frozen *inputs* only; discard entrypoint model labels and all scores."""
    manifest = read(run / "manifest.json")
    inputs = read(run / "prepared.json")
    unique, pairs = {}, []
    for item in inputs:
        for c in item["candidates"]:
            clean = {k: c[k] for k in ("candidate_id", "owner_id", "owner", "syntax_kind", "expression", "location")}
            if c["candidate_id"] in unique and clean != unique[c["candidate_id"]]:
                raise ValueError("Conflicting candidate identity")
            unique[c["candidate_id"]] = clean
            pairs.append({"case_id": item["case_id"], "entrypoint": item["function"], "candidate_id": c["candidate_id"]})
    lines_json(out / "candidates.jsonl", sorted(unique.values(), key=lambda c: c["candidate_id"]))
    lines_json(out / "pairs.jsonl", pairs)
    write_json(out / "manifest.json", {"repository": manifest["repository"], "repository_commit": manifest["repository_commit"],
        "index_directory": manifest["index_directory"], "index_hashes": manifest["index_hashes"],
        "source_run": str(run.resolve()), "source_prepared_sha256": hashlib.sha256((run / "prepared.json").read_bytes()).hexdigest(),
        "unique_candidates": len(unique), "candidate_pairs": len(pairs), "source_verdicts_read": False,
        "scope_note": "Candidate scope is conditional on the preceding Jev entrypoint scan; source judgments/scores excluded."})
    return list(unique.values())


class SourceReference:
    def __init__(self, graph, entrypoint_reference):
        self.graph = graph
        self.builder = SourceContext(graph).compact
        self.ep = {r["function_id"]: r for r in entrypoint_reference}
        self.cache, self.local_cache, self.param_cache = {}, {}, {}

    def function(self, owner):
        return self.builder.definition(self.graph.nodes[owner])

    def evidence(self, file, first, last=None, role="source_syntax"):
        lines, _, _ = self.builder.syntax(file)
        last = first if last is None else last
        text = "".join(lines[first - 1:last])
        return {"file": file, "start_line": first, "end_line": last, "role": role, "source": text,
                "sha256": hashlib.sha256(text.encode()).hexdigest()}

    def params(self, owner):
        if owner in self.param_cache:
            return self.param_cache[owner]
        row, node = self.graph.nodes[owner], self.function(owner)
        ep = self.ep.get(owner, {})
        types = set(ep.get("subtypes", []))
        routes, cli = set(), set()
        _, _, parents = self.builder.syntax(row["file"])
        parent = parents.get(node)
        decorations = list(node.decorator_list) + (list(parent.decorator_list) if isinstance(parent, ast.ClassDef) else [])
        for decorator in decorations:
            if not isinstance(decorator, ast.Call):
                continue
            text = ast.unparse(decorator.func)
            if text.endswith(".route") and decorator.args and isinstance(decorator.args[0], ast.Constant) and isinstance(decorator.args[0].value, str):
                routes.update(re.findall(r"<(?:[^:<>]+:)?([A-Za-z_]\w*)>", decorator.args[0].value))
            if text in {"click.argument", "click.option"}:
                strings = [a.value for a in decorator.args if isinstance(a, ast.Constant) and isinstance(a.value, str)]
                if text.endswith("argument") and strings:
                    cli.add(strings[0].replace("-", "_"))
                elif strings:
                    dest = next((s for s in strings if not s.startswith("-")), None)
                    dest = dest or next((s[2:].split("/")[0].replace("-", "_") for s in strings if s.startswith("--")), None)
                    if dest:
                        cli.add(dest)
        if "registered_asset_handler" in types and node.name == "assets_handler":
            # Explicit CTFd source-reviewed add_url_rule(rule=.../<path:path>, view_func=assets_handler).
            routes.add("path")
        proof = {"route": routes, "cli": cli,
                 "carrier": {"request"} if types & {"challenge_plugin_method", "flask_session_interface"} else set(),
                 "types": types, "ep": ep}
        self.param_cache[owner] = proof
        return proof

    def locals(self, owner):
        if owner not in self.local_cache:
            values = defaultdict(list)
            for node in own_nodes(self.function(owner)):
                if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)) and getattr(node, "value", None) is not None:
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for target in targets:
                        if isinstance(target, ast.Name):
                            values[target.id].append((node.lineno, node.value))
                elif isinstance(node, (ast.With, ast.AsyncWith)):
                    for item in node.items:
                        if isinstance(item.optional_vars, ast.Name):
                            values[item.optional_vars.id].append((node.lineno, item.context_expr))
            self.local_cache[owner] = values
        return self.local_cache[owner]

    def import_symbol(self, name, owner, line):
        row = self.graph.nodes[owner]
        ids, via, _ = self.graph.resolve(name, row["file"], owner, line)
        symbols = []
        for nid in ids + via:
            r = self.graph.nodes[nid]
            if r["record_type"] == "imports":
                module = r.get("absolute_module", r.get("module", ""))
                imported = r.get("imported_name")
                symbols.append((module + "." + imported if imported else module, r))
        return symbols, ids

    def domain(self, node, owner, line, seen=None):
        seen = set() if seen is None else set(seen)
        if isinstance(node, ast.Name):
            if node.id in seen:
                return "unknown"
            seen.add(node.id)
            fn = self.function(owner)
            names = {a.arg for a in list(fn.args.posonlyargs) + list(fn.args.args) + list(fn.args.kwonlyargs)
                     + ([fn.args.vararg] if fn.args.vararg else []) + ([fn.args.kwarg] if fn.args.kwarg else [])}
            if node.id in names:
                if node.id in self.params(owner)["carrier"]:
                    return "request_parameter"
                if node.id in {"request", "req"}:
                    return "unproved_request_parameter"
                return "local_value"
            values = [value for first, value in self.locals(owner).get(node.id, []) if first < line]
            if values:
                ds = {self.domain(value, owner, getattr(value, "lineno", line), seen) for value in values}
                if ds <= {"request_global", "request_parameter"} and len(ds) == 1:
                    return next(iter(ds))
                if ds == {"open_file"}:
                    return "open_file"
                # Once a request data field, DB/network result or transformation
                # is assigned to an application local, its later use is propagation.
                return "local_value"
            symbols, ids = self.import_symbol(node.id, owner, line)
            for symbol, _ in symbols:
                if symbol == "flask.request":
                    return "request_global"
                if symbol == "flask.session":
                    return "session"
                if symbol in {"flask.current_app", "flask.Flask"}:
                    return "app"
                if symbol in {"os.environ", "os.getenv"}:
                    return "environment"
                if symbol.startswith(("requests", "urllib.request", "socket", "redis", "boto")):
                    return "network"
                if symbol.startswith("CTFd.cache"):
                    return "cache"
                if symbol.startswith("CTFd.models"):
                    return "database" if symbol.endswith(".db") else "model"
                if symbol.startswith("os"):
                    return "os_module"
            if symbols:
                return "module:" + symbols[-1][0]
            if ids and all(self.graph.nodes[i]["record_type"] in {"functions", "classes"} for i in ids):
                return "internal_callable"
            if node.id in BUILTINS or node.id in {"True", "False", "None"} or node.id.endswith(("Error", "Exception")):
                return "builtin"
            return "unknown"
        if isinstance(node, ast.Attribute):
            base = self.domain(node.value, owner, line, seen)
            if base.startswith("module:flask") and node.attr == "request":
                return "request_global"
            if base == "os_module" and node.attr in {"environ", "getenv"}:
                return "environment"
            if node.attr == "config":
                return "config"
            if base.startswith("request_") or base == "unproved_request_parameter":
                if node.attr in DATA_FIELDS or node.attr in {"stream", "input_stream"}:
                    return "request_data:" + base
                return "local_value"
            if base in {"database", "model"}:
                return "database" if base == "database" or node.attr == "query" else "local_value"
            if base.startswith("module:"):
                return base + "." + node.attr
            return base if base in {"network", "cache", "config", "environment", "session", "open_file"} else "local_value"
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == "open":
                return "open_file"
            if isinstance(node.func, ast.Attribute) and self.domain(node.func.value, owner, line, seen) == "database":
                if node.func.attr not in DB_READS | WRITES:
                    return "database"
            return "local_value"
        return "local_value"

    def locate(self, candidate):
        owner = candidate["owner_id"]
        if owner not in self.cache:
            row = self.graph.nodes[owner]
            expected = {c["candidate_id"]: c for c in enumerate_candidates(self.builder, row)}
            self.cache[owner] = expected
        if self.cache[owner].get(candidate["candidate_id"]) != candidate:
            raise ValueError("Candidate does not match source syntax: " + candidate["candidate_id"])
        loc = candidate["location"]
        types = {"parameter": ast.arg, "call_return": ast.Call, "attribute_read": ast.Attribute, "subscript_read": ast.Subscript}
        matches = [n for n in ast.walk(self.function(owner)) if isinstance(n, types[candidate["syntax_kind"]])
                   and n.lineno == loc["start_line"] and n.col_offset + 1 == loc["start_column_utf8"]
                   and (isinstance(n, ast.arg) or (n.end_lineno == loc["end_line"]
                        and n.end_col_offset + 1 == loc["end_column_utf8_exclusive"]))]
        if len(matches) != 1:
            raise ValueError("Non-unique syntax position")
        return matches[0]

    def judge(self, candidate):
        node = self.locate(candidate)
        owner, loc = candidate["owner_id"], candidate["location"]
        proof = self.params(owner)
        evidence = [self.evidence(loc["file"], loc["start_line"], loc["end_line"])]
        def result(label, category, reason, input_access=None):
            return dict(candidate, is_source=label, category=category, reason=reason,
                        request_read_policy_is_source=label if input_access is None else input_access,
                        evidence=evidence, annotation_origin="agent_static_review_with_explicit_source_rules",
                        independent_human_review=False, review_status="agent_first_pass")
        if isinstance(node, ast.arg):
            if node.arg in {"self", "cls"}:
                return result(False, "receiver", "Python 接收对象参数不是外部数据起点。")
            if node.arg in proof["route"] and proof["ep"].get("is_entrypoint") is True:
                evidence.extend(proof["ep"].get("evidence", [])[1:3])
                return result(True, "route_parameter", "独立入口参考及源码路由占位符将该形参绑定到 URL 路径。")
            if node.arg in proof["cli"] and proof["ep"].get("is_entrypoint") is True:
                evidence.extend(proof["ep"].get("evidence", [])[1:3])
                return result(True, "cli_parameter", "源码 Click argument/option 将该参数绑定到命令行输入。")
            if node.arg in proof["carrier"] and proof["ep"].get("is_entrypoint") is True:
                evidence.extend(proof["ep"].get("evidence", [])[1:3])
                return result(True, "request_carrier", "独立框架/插件契约将外部请求对象传入此形参。")
            if node.arg in {"request", "req"} and proof["ep"].get("is_entrypoint") is False:
                return result(False, "internal_parameter", "独立入口参考判为内部函数；该参数只是调用时的数据传递。")
            if node.arg in {"request", "req"} or proof["ep"].get("is_entrypoint") is None:
                return result(None, "unproved_parameter_origin", "缺少可靠的外部数据参数绑定证明。")
            if proof["types"] & {"application_factory", "configured_event_manager"} and node.arg not in {"app", "response", "session"}:
                return result(None, "deployment_or_event_parameter", "部署参数/事件通道的外部控制边界未确认。")
            return result(False, "internal_or_runtime_parameter", "未由 URL/CLI/请求承载契约绑定；普通应用参数或运行时对象，不是新外部数据读取。")
        # A direct request data API can have two explicit reference readings:
        # origin-only (primary, already supplied carrier => propagation), and
        # request-read-sites (secondary, mark every direct request API read).
        request_domain = None
        if isinstance(node, ast.Attribute) and node.attr in DATA_FIELDS:
            request_domain = self.domain(node.value, owner, node.lineno)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            base = self.domain(node.func.value, owner, node.lineno)
            if node.func.attr in REQUEST_APIS and base in {"request_global", "request_parameter", "unproved_request_parameter"}:
                request_domain = base
            elif base.startswith("request_data:") and node.func.attr in {"get", "getlist", "to_dict", "read", "readline", "readlines"}:
                request_domain = base.split(":", 1)[1]
        elif isinstance(node, ast.Subscript):
            base = self.domain(node.value, owner, node.lineno)
            if base.startswith("request_data:"):
                request_domain = base.split(":", 1)[1]
        if request_domain == "request_global":
            return result(True, "framework_request_read", "从实际导入的 Flask request 直接获取请求数据或字段值。")
        if request_domain == "request_parameter":
            return result(False, "request_carrier_read", "严格起点口径：请求对象已由入口形参引入；此处为承载对象的后续读取。", input_access=True)
        if request_domain == "unproved_request_parameter":
            return result(None, "unproved_request_read", "对象的请求类型/传入绑定不能充分证明。")
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            base_node = node.value
            base = self.domain(base_node, owner, node.lineno)
            if isinstance(node, ast.Subscript) and base in {"config", "environment", "session"}:
                return result(None, "unproved_persisted_or_environment_read", "配置、环境或会话读取的控制者/信任边界未确认。")
            if base == "request_global" and isinstance(node, ast.Attribute) and node.attr not in REQUEST_METADATA:
                return result(None, "unreviewed_request_attribute", "该 Request 属性未包含在明确的数据/运行时元数据口径中。")
            if base == "unknown":
                return result(None, "unresolved_attribute_receiver", "属性/下标接收对象来源未解析。")
            return result(False, "application_value_or_metadata", "应用中已有对象、SQL 表达式/列、容器元素或运行时元数据的读取，不是新输入边界。")
        if isinstance(node, ast.Call):
            method = node.func.attr if isinstance(node.func, ast.Attribute) else None
            receiver = self.domain(node.func.value, owner, node.lineno) if isinstance(node.func, ast.Attribute) else None
            full = ast.unparse(node.func)
            if method in WRITES:
                return result(False, "write_or_side_effect", "写入/更新/输出操作不是外部数据读取起点。")
            if receiver in {"config", "environment", "session", "cache"} and method in {"get", "getlist", "pop", "items", "values", "keys"}:
                return result(None, "unproved_storage_read", "配置/环境/会话/缓存读边界未确认。")
            if receiver == "database" and method in DB_READS:
                return result(None, "unproved_database_read", "数据库读取的外部可控性未确认，不能当作确定正例或负例。")
            if receiver == "network" or receiver == "open_file" and method in {"read", "readline", "readlines", "readinto"}:
                return result(None, "unproved_external_io", "网络/文件数据的外部控制边界未确认。")
            if isinstance(node.func, ast.Name) and node.func.id == "open":
                mode = node.args[1].value if len(node.args) > 1 and isinstance(node.args[1], ast.Constant) else None
                for kw in node.keywords:
                    if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                        mode = kw.value.value
                if isinstance(mode, str) and "r" not in mode and "+" not in mode and any(c in mode for c in "wax"):
                    return result(False, "write_only_file", "明确以只写模式打开文件。")
                return result(None, "unproved_file_origin", "文件读取路径/控制者未确认。")
            symbols, ids = self.import_symbol(full, owner, node.lineno)
            if any(self.graph.nodes[i]["record_type"] in {"functions", "classes"} for i in ids):
                return result(False, "internal_call", "调用仓库内部实现；边界若位于实现内部，应标记内部读取，而不是再次标记包装调用。")
            domain = self.domain(node.func, owner, node.lineno)
            if domain in {"network", "environment"}:
                return result(None, "unproved_external_io", "外部 I/O 或环境值的控制者未确认。")
            if domain == "builtin" or receiver in {"local_value", "database", "model", "app", "request_global", "request_parameter"}:
                return result(False, "processing_or_query_construction", "内建处理、应用值变换、运行时操作或查询构建，不是新外部输入读取。")
            if domain.startswith("module:") and domain[7:].split(".")[0] in SAFE_MODULES:
                return result(False, "library_processing", "已确认的格式化、框架输出、序列化、校验、查询构建或标准库计算。")
            return result(None, "unresolved_call_origin", "调用实现/接收对象未解析，不能证明数据首次进入的位置。")
        raise ValueError("Unsupported candidate syntax")


POLICY = """# CTFd source 静态参考口径 v1

这是 AI 辅助静态参考标注，无独立人工复核，不是人工确认的漏洞/攻击者可控性真值。
参考构建器只读取候选库存、仓库源码、UAST 和已有独立入口静态参考；不读取 source 模型答案、概率、置信度或 YASA source 清单。
候选库存来自本轮扫描输入，因此这是给定候选集、给定上一阶段入口选择的条件评测；不能据此评估遗漏入口、未展开辅助函数或其他语法位置的召回。

主口径 origin-only：URL 路径绑定形参、Click 输入参数、已证明框架/插件请求承载形参，以及实际导入 Flask request 的直接数据读取视为 source。
承载参数本身已是 source 时，它的后续 form/get_json 等读取在主口径视为传播；普通应用本地值的变换和内部包装调用也不再次算新 source。
直接 Flask request 容器和其字段读取 API 均可作为框架获取不同值的边界位置，按精确 AST 位置分别记录；本地变量缓存后的取值按传播处理。
辅助口径 request-read-sites：仅将已证明请求承载形参上的直接请求 API 读取额外视为 source，用于展示口径敏感性；不挑选分数更高的口径替代主口径。
数据库、配置、会话、环境、缓存、网络和文件读取在控制者未知时为 unknown；未解析调用/接收者也是 unknown，绝不默认当负例。
内部类/函数调用按物理输入来源定位，不因返回值可能携带污点而成为新的 source。若输入读取在内部未展开，属于覆盖缺口。
接收对象 self/cls、已有对象的属性/下标、运行时路由元数据、写操作、输出/序列化/处理、SQL 查询构建不是新的外部输入边界。

保留 yes/no/unknown，未知参考单列并排除二元分数；模型 unknown 保留，在全体已定参考分母下作为未正确完成，而不改成 no。
主表按入口-候选配对计算；位置级仅在同一位置的原始模型答案一致时给单一预测，不投票修改冲突。
Accuracy 受非 source 占多数影响，必须同时报告 Precision、Recall、F1、Balanced Accuracy、参考覆盖率和模型 unknown。
YASA 报告 source 使用更宽污点建模口径且只覆盖告警路径；只能单独计算匹配覆盖，不能用剩余候选构造 TN/FP。
"""


def build(args):
    if args.out.exists():
        raise ValueError("Choose a fresh reference output directory")
    inventory = args.inventory
    meta = read(inventory / "manifest.json")
    graph = ContextGraph(Path(meta["index_directory"]), Path(meta["repository"]))
    if graph.index_hashes != meta["index_hashes"] or graph.summary.get("commit") != meta["repository_commit"]:
        raise ValueError("Inventory and source index differ")
    annotations = read(args.entrypoint_reference / "annotations.json")
    entry_manifest = read(args.entrypoint_reference / "manifest.json")
    if entry_manifest["index_hashes"] != graph.index_hashes or entry_manifest["repository_commit"] != graph.summary.get("commit"):
        raise ValueError("Entrypoint static reference uses another source revision")
    ref = SourceReference(graph, annotations)
    candidates = [json.loads(line) for line in (inventory / "candidates.jsonl").read_text().splitlines()]
    rows = []
    for i, c in enumerate(candidates, 1):
        rows.append(ref.judge(c))
        if i % 1000 == 0 or i == len(candidates):
            print("[SOURCE-REFERENCE] {}/{}; labels={}".format(i, len(candidates), dict(Counter(
                "yes" if r["is_source"] is True else "no" if r["is_source"] is False else "unknown" for r in rows))), flush=True)
    lines_json(args.out / "annotations.jsonl", rows)
    counts = Counter("yes" if r["is_source"] is True else "no" if r["is_source"] is False else "unknown" for r in rows)
    write_json(args.out / "summary.json", {"unique_candidates": len(rows), "labels": dict(counts),
        "categories": dict(Counter(r["category"] for r in rows)), "independent_human_review": False})
    (args.out / "POLICY.md").write_text(POLICY, encoding="utf-8")
    write_json(args.out / "manifest.json", dict(meta, created_at=datetime.now(timezone.utc).isoformat(),
        policy="source-origin-only-static-v1", annotation_origin="agent_static_review_with_explicit_source_rules",
        independent_human_review=False, source_predictions_read=False, inventory_sha256=hashlib.sha256((inventory / "candidates.jsonl").read_bytes()).hexdigest(),
        entrypoint_reference_sha256=hashlib.sha256((args.entrypoint_reference / "annotations.json").read_bytes()).hexdigest(),
        annotations_sha256=hashlib.sha256((args.out / "annotations.jsonl").read_bytes()).hexdigest(),
        policy_sha256=hashlib.sha256(POLICY.encode()).hexdigest(), implementation_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()))
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("command", choices=("inventory", "build"))
    p.add_argument("--run", type=Path, default=HERE / "runs/jev-sources-ctfd-application-v1")
    p.add_argument("--inventory", type=Path, default=HERE / "annotations/ctfd-source-inventory-v1")
    p.add_argument("--entrypoint-reference", type=Path, default=HERE / "annotations/ctfd-application-v1")
    p.add_argument("--out", required=True, type=Path)
    args = p.parse_args()
    if args.command == "inventory":
        if args.out.exists():
            raise ValueError("Choose a fresh inventory output directory")
        rows = export_inventory(args.run, args.out)
        print("Exported {} unlabelled candidate positions".format(len(rows)))
        return 0
    return build(args)


if __name__ == "__main__":
    raise SystemExit(main())
