#!/usr/bin/env python3
"""Compare fixed-label Laya prompts on manually reviewed positive/negative examples."""

import argparse
import json
import os
import random
import time
from pathlib import Path
from urllib import request, error

from context_graph import ContextGraph, fingerprint
from laya_smoke import (compact_record, render_state, token_audit, validate_answers,
                        validate_response, write_json)
from input_length_audit import response_audit, summarize_input_audits
from jev_config import api_headers, api_url

HERE = Path(__file__).resolve().parent
PROMPTS = {"baseline": HERE / "prompts/entrypoint_laya_v1.json",
           "optimized": HERE / "prompts/entrypoint_laya_v2.json"}


def same_labels(baseline, candidate):
    if set(baseline["questions"]) != set(candidate["questions"]):
        raise ValueError("Question IDs changed")
    for qid, question in baseline["questions"].items():
        other = candidate["questions"][qid]
        if question["type"] != other["type"] or list(question["criteria"]) != list(other["criteria"]):
            raise ValueError("Output labels or their order changed: " + qid)


def prepare(args):
    if (args.out / "prepared.json").exists():
        raise ValueError("Prepared experiment exists; use a new --out to preserve it")
    prompts = {name: json.loads(path.read_text(encoding="utf-8")) for name, path in PROMPTS.items()}
    same_labels(prompts["baseline"], prompts["optimized"])
    dataset = json.loads(args.cases.read_text(encoding="utf-8"))
    contexts = {}
    for line in (HERE / "runs/ctfd/contexts.jsonl").open(encoding="utf-8"):
        row = json.loads(line)
        contexts[row["target"]["qualified_name"]] = row
    graph = ContextGraph(HERE.parent / "artifacts/ctfd-uast/index")
    cases = list(dataset["cases"])
    random.Random(26).shuffle(cases)
    prepared = []
    for case in cases:
        original = contexts[case["function"]]
        target = graph.nodes[original["target"]["id"]]
        selected = {row["id"]: graph.nodes[row["id"]]
                    for row in original["nodes"][:case["supporting_prefix"]]}
        for table, file, line in case["supplement"]:
            matches = [row for row in graph.tables[table] if row["file"] == file and row.get("start_line") == line]
            if not matches:
                raise ValueError("Missing selection: " + str((table, file, line)))
            selected.update({row["id"]: graph.nodes[row["id"]] for row in matches})
        selected.pop(target["id"], None)
        labels = {target["id"]: "T"}
        labels.update({node_id: "E" + str(i) for i, node_id in enumerate(selected, 1)})
        records = [compact_record(target, is_target=True)] + [compact_record(row) for row in selected.values()]
        for row in records:
            row["id"] = labels[row["id"]]
        scope = graph.nodes.get(target.get("scope_id"))
        identity = {"qualified_name": target["qualified_name"], "python_kind": target["kind"],
                    "lexical_owner": scope.get("qualified_name", scope.get("name")) if scope else "module",
                    "owner_record_type": scope["record_type"] if scope else "module"}
        state = {"task_definition": "", "target": records[0], "related_records": records[1:],
                 "uast_relationships": [dict(source=labels[e["source"]], target=labels[e["target"]],
                                             relation=e["relation"], certainty=e["certainty"], evidence=labels.get(e["evidence_id"]))
                                        for e in graph.edges.values() if e["source"] in labels and e["target"] in labels
                                        and (e["evidence_id"] is None or e["evidence_id"] in labels)],
                 "unresolved": [dict(issue, record_id=labels[node_id]) for node_id in labels
                                for issue in graph.unresolved[node_id]]}
        evidence = ("TARGET IDENTITY (from UAST, not an entrypoint verdict):\n" + json.dumps(identity, ensure_ascii=False)
                    + "\n" + render_state(state))
        # Identical evidence across prompt variants. No expected verdict/review is included.
        write_json(args.out / "contexts" / (case["id"] + ".json"),
                   dict(state, target_identity=identity, evidence_id_mapping={v: k for k, v in labels.items()}))
        for variant, prompt in prompts.items():
            payload = {"model": "multilingual", "state": prompt["definition"] + "\n\n" + evidence,
                       "questions": prompt["questions"], "max_len": 8192, "head_max_len": 512}
            audit = token_audit(payload, Path("/data/models/laya-multilingual/tokenizer"))
            item = {"variant": variant, "case_id": case["id"], "function": case["function"],
                    "expected_for_review_only": case["expected"], "review": case["review"],
                    "payload": payload, "evidence_hash": fingerprint(evidence),
                    "request_hash": fingerprint({"url": args.url, "payload": payload,
                                                 "pipeline": "entrypoint_then_classify-v1",
                                                 "question_batch_size": args.question_batch_size}),
                    "token_audit": audit}
            prepared.append(item)
            write_json(args.out / variant / "request-plans" / (case["id"] + ".json"), payload)
            print("Prepared {} {}: {} tokens".format(variant, case["id"], max(a["sequence_tokens"] for a in audit.values())), flush=True)
    write_json(args.out / "prepared.json", prepared)
    write_json(args.out / "manifest.json", {
        "dataset": dataset, "repository_commit": graph.summary.get("commit"), "index_hashes": graph.index_hashes,
        "url": args.url, "model": "multilingual", "prompts": prompts, "seed": 26,
        "pipeline": "entrypoint_then_classify-v1", "question_batch_size": args.question_batch_size,
        "limitations": "Manually selected development examples/context. No independent test accuracy claim. Interface/configuration have no positive examples.",
        "labels_unchanged": True})


def metrics(results):
    counts = {key: 0 for key in ("tp", "tn", "fp", "fn", "unknown", "errors")}
    formation_tp = formation_fp = formation_fn = exact = kind_correct = positives = 0
    for row in results:
        gold = row["expected_for_review_only"]
        positives += int(gold["is_entrypoint"])
        if row["status"] != "success":
            counts["errors"] += 1
            continue
        verdict = row["verdict"]
        predicted = verdict["is_entrypoint"]
        if predicted is None:
            counts["unknown"] += 1
            continue
        counts[("tp" if gold["is_entrypoint"] else "fp") if predicted else
               ("fn" if gold["is_entrypoint"] else "tn")] += 1
        expected_set, predicted_set = set(gold["formation_types"]), set(verdict["formation_types"])
        formation_tp += len(expected_set & predicted_set)
        formation_fp += len(predicted_set - expected_set)
        formation_fn += len(expected_set - predicted_set)
        if gold["is_entrypoint"]:
            exact += int(predicted is True and expected_set == predicted_set)
            kind_correct += int(predicted is True and verdict["entrypoint_kind"] == gold["entrypoint_kind"])
    def ratio(a, b):
        return round(a / b, 4) if b else None
    decided = sum(counts[k] for k in ("tp", "tn", "fp", "fn"))
    return dict(counts, total=len(results), decided=decided,
                precision=ratio(counts["tp"], counts["tp"] + counts["fp"]),
                recall_on_all_gold_positives=ratio(counts["tp"], positives),
                false_positive_rate_on_decided_negatives=ratio(counts["fp"], counts["fp"] + counts["tn"]),
                decision_accuracy=ratio(counts["tp"] + counts["tn"], decided),
                formation_exact_on_all_gold_positives=ratio(exact, positives),
                kind_accuracy_on_all_gold_positives=ratio(kind_correct, positives),
                formation_counts_on_decided={"tp": formation_tp, "fp": formation_fp, "fn": formation_fn},
                formation_micro_precision_on_decided=ratio(formation_tp, formation_tp + formation_fp),
                formation_micro_recall_on_decided=ratio(formation_tp, formation_tp + formation_fn))


def report(out, rows):
    if (out / "manifest.json").exists():
        manifest = json.loads((out / "manifest.json").read_text())
        if manifest.get("mode") == "repository_scan":
            from jev_scan import report_scan
            return report_scan(out, rows)
    variant_names = list(dict.fromkeys(row["variant"] for row in rows))
    variants = {name: [row for row in rows if row["variant"] == name] for name in variant_names}
    scores = {name: metrics(items) for name, items in variants.items()}
    write_json(out / "metrics.json", scores)
    manifest = json.loads((out / "manifest.json").read_text()) if (out / "manifest.json").exists() else {}
    description = manifest.get("experiment_description", "4 个正样本、4 个负样本；两版提示词使用相同静态证据和两阶段流程。所有输出标签及其顺序保持不变。")
    lines = ["# 固定标签、正负样本的 Laya 开发实验", "",
             description,
             "模型先判断入口；仅当模型回答 yes 才请求形成方式和场景。没有阈值替代、规则纠正或人工代判。",
             "原始回答全部保存，人工预期与模型请求分开存放。unknown 和请求错误单独计数。", "",
             "| 版本 | TP | TN | FP | FN | unknown | 错误 | 入口精确率 | 负样本误报率 | 正样本形成方式完全匹配 |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for name, m in scores.items():
        lines.append("| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |".format(
            name, m["tp"], m["tn"], m["fp"], m["fn"], m["unknown"], m["errors"],
            m["precision"], m["false_positive_rate_on_decided_negatives"], m["formation_exact_on_all_gold_positives"]))
    lines += ["", "| 版本 | 函数 | 人工入口 | 模型入口 | 人工形成方式 | 模型形成方式 | 模型场景 |",
              "|---|---|---|---|---|---|---|"]
    for row in rows:
        gold, v = row["expected_for_review_only"], row.get("verdict", {})
        lines.append("| {} | `{}` | {} | {} | {} | {} | {} |".format(
            row["variant"], row["function"], gold["is_entrypoint"], v.get("is_entrypoint", row.get("error", "error")),
            ", ".join(gold["formation_types"]), ", ".join(v.get("formation_types", [])), v.get("entrypoint_kind")))
    lines += ["", "这是人工选取的开发样本，不代表全仓准确率；接口实现和配置绑定还没有正样本。",
              "负样本的空类别列表表示模型判为非入口后分类阶段未执行，不是模型逐项回答了 no。",
              "与历史首轮结果相比，上下文和流程也已变化；本轮 baseline/optimized 之间才是同证据对比。", ""]
    if "callgraph_sha256" in manifest:
        lines[-2] = "本轮仅比较增加调用图证据的效果；完整图已导出，模型接收的是有预算限制的局部视图。"
    elif len(variant_names) == 1:
        lines[-2] = "本轮只有一个输入版本；与历史结果比较时，需考虑输入内容和提示词均已精简，不能单独归因于其中一项。"
    length_audit = summarize_input_audits(rows)
    if length_audit["responses_audited"] or manifest.get("provider") == "jev":
        write_json(out / "actual-input-audit.json", length_audit)
        length_message = ("真实请求输入 token 范围（服务端 usage）：{}–{}。".format(
            length_audit["actual_input_token_min"], length_audit["actual_input_token_max"])
            if length_audit["actual_input_token_min"] is not None else "服务端没有返回实际输入 token 数；实际长度与服务端截断状态尚未核实。")
        lines += ["", length_message,
                  "截断遥测：`" + json.dumps(length_audit["truncation_status_counts"], ensure_ascii=False) + "`。",
                  "not_reported 表示服务端未明确报告，不能写成已确认未截断。", ""]
    (out / "RESULTS.md").write_text("\n".join(lines), encoding="utf-8")


def run(args):
    manifest = json.loads((args.out / "manifest.json").read_text())
    if manifest.get("mode") != "repository_scan":
        return _run(args)
    from scan_statistics import ScanStatistics
    prepared = json.loads((args.out / "prepared.json").read_text())
    stats = ScanStatistics(args.out, len(prepared))
    args.scan_statistics = stats
    try:
        return _run(args)
    except BaseException as exc:
        stats.finish("interrupted" if isinstance(exc, KeyboardInterrupt) else "failed")
        path = args.out / "results.json"
        report(args.out, json.loads(path.read_text()) if path.exists() else [])
        raise


def _run(args):
    prepared = json.loads((args.out / "prepared.json").read_text())
    manifest = json.loads((args.out / "manifest.json").read_text())
    if args.url != manifest["url"] or args.question_batch_size != manifest["question_batch_size"]:
        raise ValueError("Run URL/batch size must match the prepared manifest")
    # Remote Jev requests should honor the same proxy settings as curl.
    # Keep local Laya traffic direct, even when the shell defines a proxy.
    opener = (request.build_opener() if manifest.get("provider") == "jev"
              else request.build_opener(request.ProxyHandler({})))
    headers = {"Content-Type": "application/json"}
    api_key = os.getenv("LAYA_API_KEY", "")
    if manifest.get("provider") == "jev":
        from jev_config import DEFAULT_ENV_FILE, read_settings
        api_key = read_settings(getattr(args, "env_file", manifest.get("env_file", DEFAULT_ENV_FILE)), require_key=True)["api_key"]
    if api_key:
        headers["Authorization"] = "Bearer " + api_key
    if manifest.get("provider") == "jev":
        headers = api_headers(api_key)
    inference_url = api_url(args.url) if manifest.get("provider") == "jev" else args.url + "/v1/systemone"
    def health(name):
        if manifest.get("provider") == "jev":
            return  # /health is a local Laya endpoint, not a Jev API contract.
        with opener.open(request.Request(args.url + "/health", headers=headers), timeout=10) as response:
            write_json(args.out / name, json.load(response))
    health("service-health-before.json")
    results_path = args.out / "results.json"
    old = json.loads(results_path.read_text()) if results_path.exists() else []
    cached = {(r["variant"], r["case_id"], r["request_hash"]): r for r in old if r["status"] == "success"}
    results = []
    stats = getattr(args, "scan_statistics", None)
    for item in prepared:
        key = (item["variant"], item["case_id"], item["request_hash"])
        if key in cached:
            results.append(cached[key])
            if stats:
                stats.record["resumed_functions"] += 1
            continue
        row = {key: item[key] for key in ("variant", "case_id", "function", "request_hash", "expected_for_review_only") if key in item}
        started = time.monotonic()
        stages = []
        def ask(qids, stage_id):
            payload = dict(item["payload"], questions={qid: item["payload"]["questions"][qid] for qid in qids})
            root = args.out / item["variant"]
            filename = item["case_id"] + "-" + stage_id + ".json"
            write_json(root / "requests" / filename, payload)
            wire = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            wire_path = root / "wire-requests" / filename
            wire_path.parent.mkdir(parents=True, exist_ok=True)
            wire_path.write_bytes(wire)
            response_path = root / "responses" / filename
            checkpoint_path = root / "checkpoints" / filename
            digest = fingerprint({"url": args.url, "payload": payload})
            raw = None
            if manifest.get("mode") == "repository_scan" and checkpoint_path.exists() and response_path.exists():
                checkpoint = json.loads(checkpoint_path.read_text())
                candidate = json.loads(response_path.read_text())
                if checkpoint.get("request_hash") == digest and checkpoint.get("response_hash") == fingerprint(candidate):
                    validate_answers(candidate, payload["questions"])
                    raw = candidate
            reused = raw is not None
            if raw is None:
                req = request.Request(inference_url, headers=headers,
                                      data=wire, method="POST")
                request_started = time.monotonic()
                http_status = None
                try:
                    with opener.open(req, timeout=args.timeout) as response:
                        http_status = getattr(response, "status", 200)
                        raw = json.load(response)
                except error.HTTPError as exc:
                    http_status = exc.code
                    raise
                finally:
                    if stats:
                        stats.request(item["case_id"], stage_id, digest, time.monotonic() - request_started,
                                      http_status, raw.get("usage") if isinstance(raw, dict) else None)
            write_json(root / "responses" / filename, raw)
            stages.append({"stage_id": stage_id, "questions": qids, "usage": raw.get("usage"),
                           "input_audit": response_audit(raw, payload, wire), "reused_checkpoint": reused})
            validate_answers(raw, payload["questions"])
            if manifest.get("mode") == "repository_scan":
                write_json(checkpoint_path, {"request_hash": digest, "response_hash": fingerprint(raw)})
            return raw["answers"]
        try:
            answers = ask(["is_entrypoint"], "entrypoint")
            choice = answers["is_entrypoint"]["choice"]
            if choice == "yes":
                qids = [qid for qid in item["payload"]["questions"] if qid != "is_entrypoint"]
                for i in range(0, len(qids), args.question_batch_size):
                    answers.update(ask(qids[i:i + args.question_batch_size], "classify-" + str(i)))
                verdict = validate_response({"answers": answers}, item["payload"])
            else:
                verdict = {"is_entrypoint": False if choice == "no" else None,
                           "formation_types": [], "entrypoint_kind": None, "raw_formation_choices": {},
                           "entrypoint_probabilities": answers["is_entrypoint"]["probabilities"], "consistency_issues": []}
            row.update(status="success", verdict=verdict, stages=stages,
                       classification_executed=(choice == "yes"))
        except error.HTTPError as exc:
            body = exc.read(2048).decode("utf-8", "replace")
            if api_key:
                body = body.replace(api_key, "[REDACTED]")
            row.update(status="error", error="HTTP " + str(exc.code),
                       response_body=body, stages=stages)
        except (error.URLError, OSError, ValueError, KeyError, TypeError) as exc:
            row.update(status="error", error=str(exc), stages=stages)
        row["elapsed_seconds"] = round(time.monotonic() - started, 3)
        results.append(row)
        write_json(results_path, results)
        if stats:
            stats.progress(results)
        print(json.dumps({key: row.get(key) for key in
                          ("variant", "case_id", "function", "status", "verdict", "error", "elapsed_seconds")},
                         ensure_ascii=False), flush=True)
        if row.get("error") in {"HTTP 401", "HTTP 402", "HTTP 403", "HTTP 451"}:
            print("Stopped on a service-wide authentication/access restriction; remaining cases were not requested.", flush=True)
            break
    write_json(results_path, results)
    health("service-health-after.json")
    if stats:
        stats.finish("completed" if len(results) == len(prepared) and all(r["status"] == "success" for r in results)
                     else "finished_with_errors")
    report(args.out, results)
    return int(any(row["status"] != "success" for row in results))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "run", "summarize"))
    parser.add_argument("--out", type=Path, default=HERE / "runs/laya-balanced-dev-v1")
    parser.add_argument("--cases", type=Path, default=HERE / "experiments/ctfd_balanced_dev_v1.json")
    parser.add_argument("--url", default="http://127.0.0.1:8001")
    parser.add_argument("--question-batch-size", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    if args.question_batch_size < 1:
        raise ValueError("question-batch-size must be positive")
    if args.command == "prepare":
        prepare(args)
        return 0
    if args.command == "summarize":
        report(args.out, json.loads((args.out / "results.json").read_text()))
        return 0
    return run(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, error.URLError) as exc:
        raise SystemExit("ERROR: " + str(exc))
