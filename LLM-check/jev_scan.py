#!/usr/bin/env python3
"""Prepare and run repository-wide, per-function Jev entrypoint classification."""

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from compact_context import CompactContext
from context_graph import ContextGraph, fingerprint
from input_length_audit import summarize_input_audits
from jev_config import DEFAULT_ENV_FILE, read_settings
from laya_evaluate import run, same_labels
from laya_smoke import write_json
from scan_statistics import source_statistics, terminal_statistics

HERE = Path(__file__).resolve().parent


def positive(value):
    value = int(value)
    if value < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return value


def prepare(args):
    if (args.out / "manifest.json").exists() or (args.out / "prepared.json").exists():
        raise ValueError("Output already exists; choose a fresh --out")
    settings = read_settings(args.env_file)
    prompt = json.loads((HERE / "prompts/entrypoint_compact_v1.json").read_text())
    same_labels(json.loads((HERE / "prompts/entrypoint_laya_v1.json").read_text()), prompt)
    graph = ContextGraph(args.index, args.repo)
    functions = graph.select_functions(args.area, names=args.function, limit=args.limit)
    if not functions:
        raise ValueError("No functions matched the selection")
    # Keep all reference areas for a literal whole-repository scan. Business-only
    # runs exclude test/migration usage; other selections keep their own usage.
    builder = CompactContext(graph, args.max_uses, None if args.area == "all" else (args.area,),
                             args.max_binding_classes, args.max_binding_sites)
    prepared, failures, audits = [], [], []
    print("Building compact contexts for {} functions; no API calls.".format(len(functions)), flush=True)
    for number, function in enumerate(functions, 1):
        target = dict(graph.nodes[function["id"]], definition_identity=function["definition_identity"],
                      definition_alias_ids=function["definition_alias_ids"])
        case_id = "fn_" + fingerprint(target["definition_identity"])[:24]
        try:
            context = builder.build(target)
        except (ValueError, SyntaxError, OSError, KeyError) as exc:
            failures.append({"function_id": target["id"], "function": target["qualified_name"],
                             "file": target["file"], "error": str(exc)})
            continue
        payload = {"model": settings["model"], "state": prompt["definition"] + "\n\n" + context["state"],
                   "questions": prompt["questions"]}
        digest = fingerprint({"url": settings["base_url"], "payload": payload,
                              "pipeline": "entrypoint_then_classify-v1", "question_batch_size": args.question_batch_size})
        row = {"case_id": case_id, "function_id": target["id"], "function": target["qualified_name"],
               "definition_identity": target["definition_identity"], "definition_alias_ids": target["definition_alias_ids"],
               "location": {key: target.get(key) for key in ("file", "start_line", "end_line", "area")},
               "variant": "jev_compact", "payload": payload, "request_hash": digest}
        prepared.append(row)
        write_json(args.out / "contexts" / (case_id + ".json"), context)
        write_json(args.out / "jev_compact/request-plans" / (case_id + ".json"), payload)
        text_path = args.out / "state-text" / (case_id + ".txt")
        text_path.parent.mkdir(parents=True, exist_ok=True)
        text_path.write_text(payload["state"], encoding="utf-8")
        audits.append(dict(case_id=case_id, function=target["qualified_name"],
                           state_characters=len(payload["state"]), **context["coverage"]))
        if number % 50 == 0 or number == len(functions):
            print("Prepared {}/{}; extraction errors {}".format(number, len(functions), len(failures)), flush=True)
    classifications = (len(prompt["questions"]) - 2 + args.question_batch_size) // args.question_batch_size
    indexed_in_area = [f for f in graph.tables["functions"] if args.area == "all" or f.get("area") == args.area]
    manifest = {"mode": "repository_scan", "provider": "jev", "created_at": datetime.now(timezone.utc).isoformat(),
                "url": settings["base_url"], "model": settings["model"], "env_file": str(args.env_file.resolve()),
                "api_key_env": "TYPESAFE_API_KEY", "pipeline": "entrypoint_then_classify-v1",
                "question_batch_size": args.question_batch_size, "prompts": {"jev_compact": prompt},
                "repository": str(graph.repo), "repository_commit": graph.summary.get("commit"),
                "index_directory": str(graph.index_dir),
                "index_hashes": graph.index_hashes,
                "implementation_hashes": {name: fingerprint((HERE / name).read_text())
                                          for name in ("compact_context.py", "binding_context.py", "function_identity.py", "context_graph.py", "jev_scan.py")},
                "selection": {"area": args.area, "functions": args.function, "limit": args.limit,
                              "max_uses": args.max_uses, "origin": "source_definition",
                              "max_binding_classes": args.max_binding_classes, "max_binding_sites": args.max_binding_sites},
                "definition_aliases_merged": sum(len(f["definition_alias_ids"]) - 1 for f in functions),
                "functions_with_binding_sites": sum(a["binding_sites_selected"] > 0 for a in audits),
                "functions_with_inherited_receivers": sum(a["inherited_receivers_selected"] > 0 for a in audits),
                "excluded_origins_in_area": dict(Counter(f.get("origin", "unknown") for f in indexed_in_area
                                                        if f.get("origin") != "source_definition")),
                "selected_functions": len(functions), "prepared_functions": len(prepared),
                "preparation_errors": len(failures),
                "requests_if_no_entrypoints": len(prepared),
                "requests_if_all_entrypoints": len(prepared) * (1 + classifications),
                "classification_requests_per_positive": classifications,
                "experiment_description": "全仓逐函数精简上下文；模型独立判断入口并分类；没有人工真值，不报告准确率。",
                "limitations": ["No rule-based candidate prefilter; all selected source function definitions are sent.",
                                "Lambda expressions, parser-generated functions and module-level execution are excluded.",
                                "Direct references are statically resolved and capped; this is not a complete runtime chain.",
                                "Jev actual token counts come only from provider usage; there is no Laya tokenizer requirement."]}
    manifest["source_statistics"] = source_statistics(manifest, prepared)
    write_json(args.out / "prepared.json", prepared)
    write_json(args.out / "preparation-errors.json", failures)
    write_json(args.out / "input-preparation-audit.json", audits)
    write_json(args.out / "manifest.json", manifest)
    report_scan(args.out, [])
    print(json.dumps({key: manifest[key] for key in ("selected_functions", "prepared_functions", "preparation_errors",
                     "requests_if_no_entrypoints", "requests_if_all_entrypoints")}, ensure_ascii=False), flush=True)
    return int(bool(failures))


def report_scan(out, rows):
    manifest = json.loads((out / "manifest.json").read_text())
    prepared = json.loads((out / "prepared.json").read_text())
    identity = {p["case_id"]: p for p in prepared}
    complete = [r for r in rows if r["status"] == "success"]
    entrypoints = [r for r in complete if r["verdict"]["is_entrypoint"] is True]
    def located(row):
        item = identity[row["case_id"]]
        return dict(row, function_id=item["function_id"], location=item["location"])
    summary = {"selected_functions": manifest["selected_functions"], "prepared_functions": len(prepared),
               "preparation_errors": manifest["preparation_errors"], "attempted_functions": len(rows),
               "successful_functions": len(complete), "entrypoints": len(entrypoints),
               "non_entrypoints": sum(r["verdict"]["is_entrypoint"] is False for r in complete),
               "unknown": sum(r["verdict"]["is_entrypoint"] is None for r in complete),
               "request_failed_functions": sum(r["status"] != "success" for r in rows),
               "not_attempted_functions": len(prepared) - len(rows),
               "formation_counts": dict(Counter(t for r in entrypoints for t in r["verdict"]["formation_types"])),
               "kind_counts": dict(Counter(r["verdict"]["entrypoint_kind"] for r in entrypoints)),
               "has_ground_truth": False}
    for key in ("definition_aliases_merged", "functions_with_binding_sites", "functions_with_inherited_receivers"):
        if key in manifest:
            summary[key] = manifest[key]
    terminal_text = terminal_statistics(out, manifest, prepared, rows, summary)
    write_json(out / "scan-summary.json", summary)
    write_json(out / "entrypoints.json", [located(r) for r in entrypoints])
    write_json(out / "review-needed.json", [located(r) for r in rows if r["status"] != "success"
               or r["verdict"]["is_entrypoint"] is None or r["verdict"].get("consistency_issues")])
    write_json(out / "actual-input-audit.json", summarize_input_audits(rows))
    lines = ["# Jev 全仓逐函数扫描", "", manifest["experiment_description"], "",
             "选择范围：`{}`；lambda、解析器生成函数和模块顶层执行不在本轮范围。".format(manifest["selection"]["area"]),
             "直接引用最多保留 {} 处；没有引用不表示已经证明是非入口。".format(manifest["selection"]["max_uses"]), "",
             "| 项目 | 数量 |", "|---|---:|"]
    lines += ["| {} | {} |".format(key, value) for key, value in summary.items()
              if type(value) is int]
    lines += ["", "没有人工真值，因此不计算准确率、召回率或误报率。unknown、提取失败和请求失败均单独保留。",
              "`entrypoints.json` 为模型判定的入口，`review-needed.json` 为不确定、失败或标签矛盾的结果。",
              "`preparation-errors.json` 保存没有成功构建上下文的函数，不把它们当成非入口。",
              "重新运行同一目录会跳过成功函数，并复用请求与回复哈希匹配的成功阶段。", "",
              "| 函数 | 位置 | 形成方式 | 用途 |", "|---|---|---|---|"]
    for row in entrypoints:
        item, verdict = identity[row["case_id"]], row["verdict"]
        lines.append("| `{}` | {}:{} | {} | {} |".format(row["function"], item["location"]["file"],
                     item["location"]["start_line"], ", ".join(verdict["formation_types"]), verdict["entrypoint_kind"]))
    lines += ["", "## 运行与用量统计", "", "```text", terminal_text, "```", "",
              "Source lines 是所选范围的物理行数，含空行和注释。Saved tokens 是当前保存回复的用量，",
              "不等于账户历史总消耗；last invocation 只统计最近一次 run 的真实网络请求，不包含缓存复用。",
              "缺失的服务端 token 字段明确标为 partial；请求失败可能没有 usage，不能据此认定没有计费。",
              "旧版本未记录的运行耗时不会通过文件时间或函数耗时相加冒充。"]
    (out / "RESULTS.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "run", "summarize"))
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--index", type=Path, default=HERE.parent / "artifacts/ctfd-uast/index")
    parser.add_argument("--repo", type=Path)
    parser.add_argument("--env-file", type=Path, default=DEFAULT_ENV_FILE)
    parser.add_argument("--area", choices=("application", "tests", "migrations", "scripts_or_other", "all"), default="application")
    parser.add_argument("--function", action="append", default=[])
    parser.add_argument("--limit", type=positive, help="Limit functions during prepare; freeze a separate pilot run")
    parser.add_argument("--max-uses", type=positive, default=6)
    parser.add_argument("--max-binding-classes", type=positive, default=12)
    parser.add_argument("--max-binding-sites", type=positive, default=24)
    parser.add_argument("--question-batch-size", type=positive, default=1,
                        help="1 matches the eight-case experiment; 8 batches all classification questions")
    parser.add_argument("--timeout", type=positive, default=180)
    args = parser.parse_args()
    if args.command == "prepare":
        return prepare(args)
    manifest = json.loads((args.out / "manifest.json").read_text())
    if manifest.get("mode") != "repository_scan" or manifest.get("provider") != "jev":
        raise ValueError("Not a prepared Jev repository scan")
    if args.command == "summarize":
        path = args.out / "results.json"
        summary = report_scan(args.out, json.loads(path.read_text()) if path.exists() else [])
        return 0
    settings = read_settings(args.env_file, require_key=True)
    if settings["base_url"] != manifest["url"] or settings["model"] != manifest["model"]:
        raise ValueError("Model/API root changed; prepare a fresh scan")
    args.url, args.question_batch_size = manifest["url"], manifest["question_batch_size"]
    return run(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError) as exc:
        raise SystemExit("ERROR: " + str(exc))
