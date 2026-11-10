#!/usr/bin/env python3
"""Summarize a YASA scan using frozen model inputs, optionally waiting for it."""

import argparse
import csv
import hashlib
import json
import os
import re
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from extract_report_sources import extract


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temp.replace(path)


def csv_table(path, columns, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def source_key(location, imported=False):
    if imported:
        return (location["file"], location["start_line"], location["start_column_utf8"],
                location["end_line"], location["end_column_utf8_exclusive"])
    return (location.get("file"), location.get("start_line"), location.get("start_column"),
            location.get("end_line"), location.get("end_column"))


def summarize(args, inputs):
    log = args.log.read_text(encoding="utf-8", errors="replace")
    starts = re.findall(r"Execute entrypoint \((\d+)/(\d+)\): ([^\n]+)", log)
    completions = re.findall(r"\[symbolInterpret\] Find (\d+) findings, cost: (\d+)ms", log)
    diag = read(args.report / "llm-input-diagnostics.json") if (args.report / "llm-input-diagnostics.json").exists() else {}
    done = "Execution completed" in log and (args.report / "scan_summary.json").exists()
    state = {"status": "completed" if done else "running", "updated_at": datetime.now(timezone.utc).isoformat(),
             "input_file": str(args.input.resolve()), "report_directory": str(args.report.resolve()),
             "log": str(args.log.resolve()), "entrypoints_imported": len(inputs["entrypoints"]),
             "entrypoints_started": len(starts), "entrypoints_completed_in_log": len(completions),
             "current_entrypoint": starts[-1][2] if starts else None,
             "finding_events_in_log": sum(int(n) for n, _ in completions),
             "model_api_requests": 0,
             **{key: diag.get(key) for key in ("entrypoints_bound", "entrypoints_unmatched",
                "source_decisions_imported", "source_decisions_ast_matched", "source_decisions_executed",
                "source_decisions_marked", "source_mark_events", "sink_detection", "sinks_imported",
                "sinks_ast_matched", "sinks_executed", "sinks_without_selected_arguments",
                "sink_arguments_checked", "sink_arguments_unresolved", "sink_finding_events")}}
    if not done:
        if args.pid:
            try:
                os.kill(args.pid, 0)
            except ProcessLookupError:
                state["status"] = "stopped_without_final_report"
            except PermissionError:
                pass
        write(args.out / "status.json", state)
        return state
    scan = read(args.report / "scan_summary.json")
    raw = (args.report / "report.sarif").read_bytes()
    document = json.loads(raw)
    sources, occurrences, findings, unresolved, _, _ = extract(document, args.repo, hashlib.sha256(raw).hexdigest())
    by_source = {s["source_id"]: s for s in sources}
    raw_results = [result for run in document["runs"] for result in run.get("results", [])]
    by_index = {(run_index, result_index): result for run_index, run in enumerate(document["runs"])
                for result_index, result in enumerate(run.get("results", []))}
    original_sources = {(s["case_id"], source_key(s["location"], True)) for s in inputs["sources"]}
    entries = {e["case_id"]: e for e in inputs["entrypoints"]}
    links = []
    for occurrence in occurrences:
        raw_result = by_index[(occurrence["run_index"], occurrence["result_index"])]
        case_id = (raw_result.get("entrypoint") or {}).get("llmCaseId")
        source = by_source[occurrence["source_id"]]
        sink = occurrence["sink"]
        llm_sink = (raw_result.get("sinkInfo") or {}).get("llm") or {}
        sink_argument = llm_sink.get("argument") or {}
        sink_verdict = llm_sink.get("verdict") or {}
        links.append({"finding_id": occurrence["finding_id"], "case_id": case_id,
                      "entrypoint": entries.get(case_id, {}).get("function"),
                      "source_file": source["file"], "source_line": source["start_line"],
                      "source_expression": source["expression"],
                      "source_matches_imported_decision": (case_id, source_key(source)) in original_sources,
                      "sink_file": sink["file"], "sink_line": sink["start_line"],
                      "sink_rule": occurrence["sink_info"].get("sinkRule"),
                      "sink_attributes": ";".join(occurrence["sink_info"].get("sinkAttribute") or []),
                      "llm_sink_id": llm_sink.get("candidate_id"), "llm_sink_kind": sink_verdict.get("sink_kind"),
                      "llm_sink_confidence": (sink_verdict.get("sink_answer") or {}).get("confidence"),
                      "sink_argument_selector": sink_argument.get("selector"),
                      "sink_argument_expression": sink_argument.get("expression"),
                      "sink_argument_confidence": (sink_argument.get("answer") or {}).get("confidence")})
    csv_table(args.out / "source-to-sink.csv", ["finding_id", "case_id", "entrypoint", "source_file", "source_line",
              "source_expression", "source_matches_imported_decision", "sink_file", "sink_line", "sink_rule", "sink_attributes",
              "llm_sink_id", "llm_sink_kind", "llm_sink_confidence", "sink_argument_selector",
              "sink_argument_expression", "sink_argument_confidence"], links)
    unused = [{"case_id": s["source"]["case_id"], "entrypoint": entries[s["source"]["case_id"]]["function"],
               "syntax_kind": s["source"]["syntax_kind"], "file": s["source"]["location"]["file"],
               "line": s["source"]["location"]["start_line"], "expression": s["source"]["expression"],
               "ast_matched": s["astMatched"], "visits": s["visits"], "marks": s["marks"]}
              for s in diag["sources"] if s["marks"] == 0]
    csv_table(args.out / "untriggered-sources.csv", ["case_id", "entrypoint", "syntax_kind", "file", "line",
              "expression", "ast_matched", "visits", "marks"], unused)
    sink_types = Counter(attribute for result in raw_results
                         for attribute in (result.get("sinkInfo") or {}).get("sinkAttribute", []))
    state.update(findings=len(findings), findings_with_explicit_source=sum(bool(f["source_ids"]) for f in findings),
                 source_positions_in_findings=len(sources), source_occurrences_in_findings=len(occurrences),
                 source_links_matching_import=sum(link["source_matches_imported_decision"] for link in links),
                 source_links_not_matching_import=sum(not link["source_matches_imported_decision"] for link in links),
                 findings_with_unimported_entrypoint=sum((r.get("entrypoint") or {}).get("llmCaseId") not in entries for r in raw_results),
                 threads_without_explicit_source=len(unresolved), sink_attribute_counts=dict(sink_types),
                 scan_statistics={k: v for k, v in scan.items() if k != "ruleConfig"},
                 report_sha256=hashlib.sha256(raw).hexdigest(),
                 source_files_unchanged=all(hashlib.sha256((args.repo / f["file"]).read_bytes()).hexdigest() == f["sha256"]
                                            for f in inputs["files"]))
    if "sinks" in inputs:
        imported_sink_ids = {s["candidate_id"] for s in inputs["sinks"]}
        state["findings_with_unimported_sink"] = sum(
            ((r.get("sinkInfo") or {}).get("llm") or {}).get("candidate_id") not in imported_sink_ids
            for r in raw_results)
    if (len(completions) != len(entries) or state["source_links_not_matching_import"] or
            state["findings_with_unimported_entrypoint"] or not state["source_files_unchanged"]):
        state["status"] = "completed_with_verification_issues"
    write(args.out / "summary.json", state)
    write(args.out / "status.json", state)
    write(args.out / "findings.json", findings)
    write(args.out / "sources-in-findings.json", sources)
    lines = ["# Jev 入口/source → YASA 污点检测", "", f"状态：{state['status']}。", "",
             f"处理入口 {len(completions)}/{len(entries)}；导入 source 判断 {len(inputs['sources'])} 条，实际标记 {state['source_decisions_marked']} 条。",
             f"YASA 告警 {len(findings)} 条，其中含明确 SOURCE 的 {state['findings_with_explicit_source']} 条；告警路径涉及 {len(sources)} 个 source 位置。",
             f"耗时 {scan.get('totalTimeMs', 0) / 1000:.1f} 秒；模型 API 调用 0 次。", "",
             f"原始报告：`{args.report.resolve() / 'report.sarif'}`。", "",
             "- `source-to-sink.csv`：入口、source、sink 的逐告警关系和导入位置核对。",
             "- `untriggered-sources.csv`：模型选 yes 但引擎尚未成功标记的位置。",
             "- `summary.json`：完整统计和验证结果。", "",
             "告警不是经人工确认的真实漏洞；没有告警也不能据此判定入口安全。未触发 source 不作为负例。",
             "入口默认跳过装饰器；原有入口/source 标记被替换，YASA 传播、sink 和净化匹配继续执行。", ""]
    if "sinks" in inputs:
        lines[-2] = "入口/source/sink 均来自导入的 Jev 判断；原有入口/source/sink 规则关闭，YASA 负责传播。"
        lines += [f"导入 sink {state['sinks_imported']} 个，UAST 匹配 {state['sinks_ast_matched']} 个，执行到 {state['sinks_executed']} 个。",
                  f"未选危险参数 {state['sinks_without_selected_arguments']} 个；实际检查参数 {state['sink_arguments_checked']} 个；参数绑定未解析 {state['sink_arguments_unresolved']} 个。",
                  "告警按原始模型分类输出，保留 sink/参数置信度；未选参数不使用原生规则补选。",
                  "传播命中不等于已确认漏洞，尤其不等于证明绕过了输入校验或权限检查。", ""]
    (args.out / "SUMMARY.md").write_text("\n".join(lines), encoding="utf-8")
    return state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("input", "report", "log", "repo", "out"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--watch", action="store_true")
    parser.add_argument("--pid", type=int)
    args = parser.parse_args()
    inputs = read(args.input)
    while True:
        try:
            state = summarize(args, inputs)
        except (json.JSONDecodeError, FileNotFoundError):
            if not args.watch:
                raise
            time.sleep(2)
            continue
        print(json.dumps({key: state.get(key) for key in ("status", "entrypoints_completed_in_log", "findings",
                         "source_decisions_marked")}, ensure_ascii=False), flush=True)
        if not args.watch or state["status"] != "running":
            return int(state["status"] not in {"running", "completed"})
        time.sleep(30)


if __name__ == "__main__":
    raise SystemExit(main())
