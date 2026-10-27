#!/usr/bin/env python3
"""Prepare auditable UAST examples and query a Laya /v1/systemone service."""

import argparse
import json
import math
import os
import time
from functools import lru_cache
from datetime import datetime, timezone
from pathlib import Path
from urllib import request, error

from context_graph import ContextGraph, fingerprint

HERE = Path(__file__).resolve().parent
FIELDS = ("id", "record_type", "file", "start_line", "qualified_name", "source",
          "omitted_source_chars", "module", "absolute_module", "imported_name", "local_name")


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def compact_record(row, is_target=False):
    record = {key: row[key] for key in FIELDS if key in row}
    # Keep the complete target. Supporting definitions explicitly record any clipping.
    cap = None if is_target else (400 if row["record_type"] == "classes" else 1600)
    if cap and len(record.get("source", "")) > cap:
        record["omitted_source_chars"] = (record.get("omitted_source_chars", 0)
                                          + len(record["source"]) - cap)
        record["source"] = record["source"][:cap]
    return record


@lru_cache(maxsize=2)
def audit_tokenizer(tokenizer_path):
    from transformers import AutoTokenizer
    return AutoTokenizer.from_pretrained(str(tokenizer_path), local_files_only=True)


def token_audit(payload, tokenizer_path):
    # Uses the installed server's formatter and tokenizer; does not load model weights.
    from laya.common import build_head, build_sequence, render_options
    tok = audit_tokenizer(tokenizer_path)
    rows = {}
    for qid, q in payload["questions"].items():
        internal = {"t": q["type"], "ins": q["instructions"], "crit": q["criteria"]}
        ids, markers, options, truncation = build_sequence(
            tok, payload["state"], internal, max_len=payload["max_len"],
            head_max_len=payload["head_max_len"], return_stats=True,
            return_truncation_stats=True)
        head_ids, head_markers, _ = build_head(tok, internal, payload["head_max_len"])
        instruction_text = (internal["t"] + " question: " + internal["ins"]).replace(tok.mask_token, " ")
        instruction_tokens = len(tok(instruction_text, add_special_tokens=False)["input_ids"])
        instruction_dropped = max(0, instruction_tokens - (head_markers[0] - 2))
        option_dropped = []
        for i, option in enumerate(render_options(internal)):
            full = len(tok(" " + option.replace(tok.mask_token, " "), add_special_tokens=False)["input_ids"])
            end = head_markers[i + 1] if i + 1 < len(head_markers) else len(head_ids) - 1
            used = end - head_markers[i] - 1
            option_dropped.append(max(0, full - used))
        if (truncation["truncated"] or instruction_dropped or any(option_dropped)
                or options["options_distinct"] != len(q["criteria"])):
            raise ValueError("Input would be truncated or options collapsed: " + qid)
        rows[qid] = dict(truncation, sequence_tokens=len(ids), option_stats=options,
                        instruction_tokens_dropped=instruction_dropped, option_tokens_dropped=option_dropped)
    return rows


def render_state(state):
    lines = [state["task_definition"], "", "以下为待分析数据，T 是目标函数。"]
    for row in [state["target"]] + state["related_records"]:
        lines += ["", "[{}] {} {}:{} {}".format(
            row["id"], row["record_type"], row["file"], row.get("start_line", ""),
            row.get("qualified_name", "")), row.get("source", "")]
        if row["record_type"] == "imports":
            lines.append("导入绑定：来源={}; 导入={}; 本地名={}".format(
                row.get("absolute_module", row.get("module")),
                row.get("imported_name"), row.get("local_name")))
        if row.get("omitted_source_chars"):
            lines.append("[辅助源码后续省略 {} 字符]".format(row["omitted_source_chars"]))
    lines += ["", "UAST 静态关系（不能视为已证明的运行时调用）："]
    for edge in state["uast_relationships"]:
        lines.append("{} --{}--> {} [{}; evidence={}]".format(
            edge["source"], edge["relation"], edge["target"], edge["certainty"], edge["evidence"]))
    lines += ["", "未解析信息：", json.dumps(state["unresolved"], ensure_ascii=False),
              "覆盖范围：目标函数全文保留；辅助记录为人工选取，部分辅助源码省略；不证明完整运行时链路。"]
    return "\n".join(lines)


def prepare(args):
    prompt = json.loads(args.prompt.read_text(encoding="utf-8"))
    manifest = json.loads(args.cases.read_text(encoding="utf-8"))
    contexts = {}
    for line in args.contexts.open(encoding="utf-8"):
        row = json.loads(line)
        contexts[row["target"]["qualified_name"]] = row
    graph = ContextGraph(args.index)
    prepared = []
    for case in manifest["cases"]:
        original = contexts[case["function"]]
        target = original["target"]
        if target.get("omitted_source_chars"):
            raise ValueError("Target body was clipped: " + case["function"])
        supporting = {n["id"]: n for n in original["nodes"][:case["supporting_prefix"]]}
        for table, file, line in case["supplement"]:
            matches = [row for row in graph.tables[table]
                       if row["file"] == file and row.get("start_line") == line]
            if not matches:
                raise ValueError("Missing UAST selection: " + str((table, file, line)))
            for row in matches:
                supporting[row["id"]] = graph.nodes[row["id"]]
        known = set(supporting) | {target["id"]}
        edges = [e for e in graph.edges.values() if e["source"] in known and e["target"] in known
                 and (e["evidence_id"] is None or e["evidence_id"] in known)]
        # Short evidence IDs reduce repeated hash tokens without changing graph identities.
        labels = {target["id"]: "T"}
        labels.update({node_id: "E" + str(i) for i, node_id in enumerate(supporting, 1)})
        records = [compact_record(n) for n in supporting.values()]
        for record in records:
            record["id"] = labels[record["id"]]
        compact_target = compact_record(target, is_target=True)
        compact_target["id"] = "T"
        state = {
            "task_definition": prompt["definition"],
            "target": compact_target,
            "related_records": records,
            "uast_relationships": [dict(source=labels[e["source"]], target=labels[e["target"]],
                                        relation=e["relation"], certainty=e["certainty"],
                                        evidence=labels.get(e["evidence_id"])) for e in edges],
            "unresolved": [dict(issue, record_id=labels[node_id]) for node_id in sorted(known)
                           for issue in graph.unresolved[node_id]],
            "coverage": {"selection": "human_selected_UAST_records_for_four_example_smoke_test",
                         "target_body_complete": True, "full_runtime_chain_proven": False,
                         "source_context_coverage": original["coverage"],
                         "omitted_from_original_context": len(original["nodes"])
                         - sum(n["id"] in supporting for n in original["nodes"])}
        }
        payload = {"model": args.model, "state": render_state(state), "questions": prompt["questions"],
                   "max_len": 8192, "head_max_len": 512}
        row = {"case_id": case["id"], "function": case["function"], "payload": payload,
               "prompt_version": prompt["version"], "repository_commit": original["repository_commit"],
               "request_hash": fingerprint(payload), "expected_for_review_only": case["expected"],
               "evidence_id_mapping": {label: node_id for node_id, label in labels.items()},
               "token_audit": token_audit(payload, args.tokenizer)}
        prepared.append(row)
        write_json(args.out / "contexts" / (case["id"] + ".json"), state)
        write_json(args.out / "requests" / (case["id"] + ".json"), payload)
        print("Prepared {}: {} ({} state tokens)".format(
            case["id"], case["function"], max(x["state_tokens"] for x in row["token_audit"].values())), flush=True)
    write_json(args.out / "prepared.json", prepared)
    write_json(args.out / "prompt.json", prompt)
    write_json(args.out / "manifest.json", {
        "created_at": datetime.now(timezone.utc).isoformat(), "cases": manifest,
        "contexts": str(args.contexts.resolve()), "index_hashes": graph.index_hashes,
        "protocol": "/v1/systemone", "model": args.model,
        "note": "Expected labels are stored outside payloads and never transmitted. No entrypoint checker is used."})


def validate_answers(raw, questions):
    if raw.get("usage", {}).get("truncated") or raw.get("usage", {}).get("state_tokens_dropped", 0):
        raise ValueError("Server truncated the state; not a valid full-context trial")
    answers = raw.get("answers")
    if not isinstance(answers, dict) or set(answers) != set(questions):
        raise ValueError("Missing or unexpected answer IDs")
    for qid, q in questions.items():
        answer = answers[qid]
        if answer.get("type") != "choice" or answer.get("choice") not in q["criteria"]:
            raise ValueError("Invalid answer choice: " + qid)
        probabilities = answer.get("probabilities")
        if not isinstance(probabilities, dict) or set(probabilities) != set(q["criteria"]):
            raise ValueError("Invalid probability labels: " + qid)
        values = list(probabilities.values())
        if any(type(p) not in (float, int) or not math.isfinite(p) or not 0 <= p <= 1 for p in values):
            raise ValueError("Invalid probability values: " + qid)
        if abs(sum(values) - 1) > 0.02:
            raise ValueError("Probabilities do not sum to one: " + qid)
    return answers


def validate_response(raw, payload):
    answers = validate_answers(raw, payload["questions"])
    decision = answers["is_entrypoint"]["choice"]
    formations = [qid[len("formation_"):] for qid, answer in answers.items()
                  if qid.startswith("formation_") and answer["choice"] == "yes"]
    issues = []
    kind = answers["entrypoint_kind"]["choice"]
    if decision == "yes" and kind == "none":
        issues.append("入口判断为 yes，但触发场景选了 none。")
    if decision == "no" and (formations or kind not in {"none", "unknown"}):
        issues.append("入口判断为 no，但独立分类问题给出了入口类别。")
    if "other" in formations and len(formations) > 1:
        issues.append("other 定义为六类之外的机制，但模型同时选择了已列出的机制。")
    return {"is_entrypoint": {"yes": True, "no": False, "unknown": None}[decision],
            "formation_types": formations if decision == "yes" else [],
            "entrypoint_kind": answers["entrypoint_kind"]["choice"] if decision == "yes" else None,
            "raw_formation_choices": {qid[len("formation_"):]: a["choice"] for qid, a in answers.items()
                                      if qid.startswith("formation_")},
            "entrypoint_probabilities": answers["is_entrypoint"]["probabilities"],
            "consistency_issues": issues}


def run(args):
    prepared = json.loads((args.out / "prepared.json").read_text(encoding="utf-8"))
    headers = {"Content-Type": "application/json"}
    if os.getenv("LAYA_API_KEY"):
        headers["Authorization"] = "Bearer " + os.environ["LAYA_API_KEY"]
    opener = request.build_opener(request.ProxyHandler({}))
    with opener.open(request.Request(args.url.rstrip("/") + "/health", headers=headers), timeout=10) as response:
        write_json(args.out / "service-health.json", json.load(response))
    results = []
    for item in prepared:
        payload = item["payload"]
        result = {key: item[key] for key in ("case_id", "function", "request_hash", "expected_for_review_only")}
        started = time.monotonic()
        try:
            req = request.Request(args.url.rstrip("/") + "/v1/systemone", headers=headers,
                                  data=json.dumps(payload, ensure_ascii=False).encode("utf-8"), method="POST")
            with opener.open(req, timeout=args.timeout) as response:
                raw = json.load(response)
            write_json(args.out / "responses" / (item["case_id"] + ".json"), raw)
            result.update(status="success", verdict=validate_response(raw, payload), usage=raw.get("usage"))
        except error.HTTPError as exc:
            result.update(status="error", error="HTTP " + str(exc.code), response_body=exc.read(4096).decode("utf-8", "replace"))
        except (error.URLError, OSError, ValueError, KeyError, TypeError) as exc:
            result.update(status="error", error=str(exc))
        result["elapsed_seconds"] = round(time.monotonic() - started, 3)
        results.append(result)
        write_json(args.out / "results.json", results)
        print(json.dumps(result, ensure_ascii=False), flush=True)
    write_report(args.out, results)
    return int(any(r["status"] != "success" for r in results))


def write_report(out, results):
    lines = ["# CTFd 四个样例的 Laya 实验", "",
             "实际接口：`/v1/systemone`。输入为人工选取的 UAST 源码与静态关系；目标函数全文保留。",
             "人工预期标签没有发送给模型。各形成方式独立提问，最终分类只在入口判断为 yes 时采用。",
             "模型给出选项及概率，不生成推理解释；下表不添加人工代写的模型理由。", "",
             "| 函数 | 模型入口判断 | 模型形成方式 | 场景 | 入口 yes 概率 | 人工预期 |",
             "|---|---|---|---|---|---|"]
    for row in results:
        if row["status"] != "success":
            lines.append("| `{}` | 请求/校验错误 | {} | | | |".format(row["function"], row["error"]))
            continue
        v = row["verdict"]
        lines.append("| `{}` | {} | {} | {} | {:.4f} | {} |".format(
            row["function"], v["is_entrypoint"], ", ".join(v["formation_types"]),
            v["entrypoint_kind"], v["entrypoint_probabilities"]["yes"],
            ", ".join(row["expected_for_review_only"]["required_formations"])))
    lines += ["", "只有四个已知正样例，不能衡量误报率或整体准确率；尚未覆盖接口实现和配置绑定样例。",
              "`requests/` 是实际请求；`responses/` 是原始回复；`prepared.json` 记录 token 检查、人工预期与请求指纹。",
              "概率是模型输出，不是已验证的正确率；这次实验没有调用 YASA 入口 checker。", ""]
    for row in results:
        for issue in row.get("verdict", {}).get("consistency_issues", []):
            lines.append("- `{}`：{}".format(row["case_id"], issue))
    (out / "RESULTS.md").write_text("\n".join(lines), encoding="utf-8")


def summarize(args):
    prepared = {row["case_id"]: row for row in json.loads((args.out / "prepared.json").read_text())}
    results = json.loads((args.out / "results.json").read_text())
    for row in results:
        if row["status"] == "success":
            raw = json.loads((args.out / "responses" / (row["case_id"] + ".json")).read_text())
            row["verdict"] = validate_response(raw, prepared[row["case_id"]]["payload"])
    write_json(args.out / "results.json", results)
    write_report(args.out, results)
    health_path = args.out / "service-health-after.json"
    if health_path.exists():
        health = json.loads(health_path.read_text())
        report = args.out / "RESULTS.md"
        with report.open("a", encoding="utf-8") as stream:
            stream.write("\n运行后设备：`" + str(health.get("device")) + "`。")
            for name, fallback in health.get("cpu_fallbacks", {}).items():
                stream.write("`{}` 累计 CPU 回退 {} 次。".format(name, fallback.get("count", 0)))
            stream.write("详细状态及回退原因见 `service-health-after.json`。\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "run", "summarize"))
    parser.add_argument("--out", type=Path, default=HERE / "runs/laya-four-v1")
    parser.add_argument("--prompt", type=Path, default=HERE / "prompts/entrypoint_laya_v1.json")
    parser.add_argument("--cases", type=Path, default=HERE / "experiments/ctfd_four_cases.json")
    parser.add_argument("--contexts", type=Path, default=HERE / "runs/ctfd/contexts.jsonl")
    parser.add_argument("--index", type=Path, default=HERE.parent / "artifacts/ctfd-uast/index")
    parser.add_argument("--tokenizer", type=Path, default=Path("/data/models/laya-multilingual/tokenizer"))
    parser.add_argument("--url", default="http://127.0.0.1:8001")
    parser.add_argument("--model", default="multilingual")
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    if args.command == "prepare":
        prepare(args)
        return 0
    if args.command == "summarize":
        summarize(args)
        return 0
    return run(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, error.URLError) as exc:
        raise SystemExit("ERROR: " + str(exc))
