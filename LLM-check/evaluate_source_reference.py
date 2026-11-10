#!/usr/bin/env python3
"""Evaluate saved source decisions against a frozen, explicitly scoped reference."""

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from context_graph import fingerprint
from laya_smoke import validate_answers, write_json

HERE = Path(__file__).resolve().parent


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def ratio(n, d):
    return n / d if d else None


def score(rows, label_field="is_source"):
    known = [r for r in rows if type(r[label_field]) is bool]
    excluded = [r for r in rows if type(r[label_field]) is not bool]
    tp = sum(r[label_field] is True and r["prediction"] == "yes" for r in known)
    fp = sum(r[label_field] is False and r["prediction"] == "yes" for r in known)
    fn = sum(r[label_field] is True and r["prediction"] == "no" for r in known)
    tn = sum(r[label_field] is False and r["prediction"] == "no" for r in known)
    unresolved_positive = sum(r[label_field] is True and r["prediction"] not in {"yes", "no"} for r in known)
    unresolved_negative = sum(r[label_field] is False and r["prediction"] not in {"yes", "no"} for r in known)
    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn + unresolved_positive)
    specificity = ratio(tn, tn + fp + unresolved_negative)
    f1 = 2 * precision * recall / (precision + recall) if precision is not None and recall is not None and precision + recall else 0.0
    return {"total": len(rows), "reference_known": len(known), "reference_unknown_excluded": len(excluded),
            "reference_coverage": ratio(len(known), len(rows)), "reference_positive": sum(r[label_field] is True for r in known),
            "reference_negative": sum(r[label_field] is False for r in known), "tp": tp, "fp": fp, "fn_decided": fn, "tn": tn,
            "unresolved_positive": unresolved_positive, "unresolved_negative": unresolved_negative,
            "prediction_statuses": dict(Counter(r["prediction"] for r in rows)),
            "accuracy": ratio(tp + tn, len(known)), "precision": precision, "recall": recall, "f1": f1,
            "specificity": specificity, "balanced_accuracy": (recall + specificity) / 2 if recall is not None and specificity is not None else None,
            "decided_accuracy": ratio(tp + tn, tp + fp + fn + tn), "decided_recall": ratio(tp, tp + fn),
            "all_negative_accuracy_baseline": ratio(sum(r[label_field] is False for r in known), len(known)),
            "predicted_yes_with_known_reference": tp + fp,
            "predicted_yes_with_unknown_reference": sum(r["prediction"] == "yes" for r in excluded),
            "predicted_yes_reference_coverage": ratio(tp + fp, sum(r["prediction"] == "yes" for r in rows))}


def save_csv(path, rows):
    fields = ("candidate_id", "case_id", "entrypoint", "owner", "file", "line", "column", "syntax_kind", "expression",
              "reference", "prediction", "category", "reason", "source_probability", "model_confidence")
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            c = row["candidate"]
            writer.writerow({"candidate_id": c["candidate_id"], "case_id": row.get("case_id"), "entrypoint": row.get("entrypoint"),
                "owner": c["owner"], "file": c["location"]["file"], "line": c["location"]["start_line"],
                "column": c["location"]["start_column_utf8"], "syntax_kind": c["syntax_kind"], "expression": c["expression"],
                "reference": {True: "yes", False: "no", None: "unknown"}[row["is_source"]], "prediction": row["prediction"],
                "category": row["category"], "reason": row["reason"], "source_probability": row.get("source_probability"),
                "model_confidence": row.get("model_confidence")})


def report_source_match(source, candidates):
    """Only exact reported-position coverage; unlisted locations are unlabelled."""
    matches = []
    for source_row in source:
        exact = [c for c in candidates.values() if c["candidate"]["location"] == {
            "file": source_row["file"], "start_line": source_row["start_line"], "end_line": source_row["end_line"],
            "start_column_utf8": source_row["start_column"], "end_column_utf8_exclusive": source_row["end_column"]}]
        status = "not_in_candidate_inventory"
        if exact:
            decisions = {r["prediction"] for r in exact}
            status = "yes" if "yes" in decisions else "no" if decisions == {"no"} else "unresolved"
        matches.append({"source_id": source_row["source_id"], "file": source_row["file"], "line": source_row["start_line"],
                        "expression": source_row["source_expression_text"], "status": status,
                        "candidate_ids": [c["candidate"]["candidate_id"] for c in exact],
                        "finding_count": source_row["finding_count"]})
    counts = Counter(r["status"] for r in matches)
    return {"reported_sources": len(matches), "counts": dict(counts),
            "reported_position_reproduction_rate": ratio(counts["yes"], len(matches)), "matches": matches,
            "precision": None, "accuracy": None,
            "note": "YASA finding-path sources are not exhaustive positive/negative ground truth; this is exact-position reproduction only."}


def evaluate(args):
    if args.out.exists():
        raise ValueError("Choose a fresh evaluation output directory")
    ref_manifest = read(args.reference / "manifest.json")
    manifest = read(args.run / "manifest.json")
    if (sha(args.reference / "annotations.jsonl") != ref_manifest["annotations_sha256"]
            or sha(args.reference / "POLICY.md") != ref_manifest["policy_sha256"]):
        raise ValueError("Frozen source reference changed")
    if ref_manifest["source_prepared_sha256"] != sha(args.run / "prepared.json"):
        raise ValueError("Reference inventory and evaluated source inputs differ")
    if ref_manifest["repository_commit"] != manifest["repository_commit"] or ref_manifest["index_hashes"] != manifest["index_hashes"]:
        raise ValueError("Source revisions differ")
    reference = {r["candidate_id"]: r for r in map(json.loads, (args.reference / "annotations.jsonl").read_text().splitlines())}
    prepared, saved = read(args.run / "prepared.json"), read(args.run / "results.json")
    results = {r["request_id"]: r for r in saved}
    rows, seen = [], set()
    for item in prepared:
        if item["request_hash"] != fingerprint({"url": manifest["url"], "payload": item["payload"]}):
            raise ValueError("Prepared source request changed")
        result = results.get(item["request_id"])
        answers = {}
        if result and result["status"] == "success":
            raw_path = args.run / "responses" / (item["request_id"] + ".json")
            if result["request_hash"] != item["request_hash"] or result["response_sha256"] != sha(raw_path):
                raise ValueError("Result/checkpoint hash mismatch")
            answers = validate_answers(read(raw_path), item["payload"]["questions"])
        for c in item["candidates"]:
            ref = reference[c["candidate_id"]]
            for field in ("candidate_id", "owner_id", "owner", "syntax_kind", "expression", "location"):
                if ref[field] != c[field]:
                    raise ValueError("Reference candidate identity mismatch")
            pair = (item["case_id"], c["candidate_id"])
            if pair in seen:
                raise ValueError("Duplicate candidate-entrypoint pair")
            seen.add(pair)
            prediction = answers[c["candidate_id"]]["choice"] if answers else "failed" if result else "not_attempted"
            rows.append({"candidate": c, "case_id": item["case_id"], "entrypoint": item["function"],
                         "is_source": ref["is_source"], "request_read_policy_is_source": ref["request_read_policy_is_source"],
                         "prediction": prediction, "category": ref["category"], "reason": ref["reason"],
                         "source_probability": answers[c["candidate_id"]]["probabilities"]["yes"] if answers else None,
                         "model_confidence": answers[c["candidate_id"]].get("confidence") if answers else None})
    grouped = defaultdict(list)
    for row in rows:
        grouped[row["candidate"]["candidate_id"]].append(row)
    consistent, union = [], []
    for cid, members in grouped.items():
        decisions = {m["prediction"] for m in members}
        base = dict(members[0])
        base["prediction"] = next(iter(decisions)) if len(decisions) == 1 else "context_conflict"
        consistent.append(base)
        union.append(dict(base, prediction="yes" if "yes" in decisions else base["prediction"]))
    metrics = {"pair_origin_only": score(rows), "unique_origin_only_consistent": score(consistent),
               "unique_origin_only_any_yes_detection": score(union),
               "pair_request_read_sites_sensitivity": score(rows, "request_read_policy_is_source"),
               "unique_request_read_sites_sensitivity": score(union, "request_read_policy_is_source"),
               "by_syntax_kind": {kind: score([r for r in union if r["candidate"]["syntax_kind"] == kind])
                                  for kind in sorted({r["candidate"]["syntax_kind"] for r in rows})},
               "reference_is_ai_assisted_static": True, "independent_human_review": False,
               "whole_repository_recall_claimed": False,
               "model_answers_modified": False}
    args.out.mkdir(parents=True)
    save_csv(args.out / "all-candidate-pairs.csv", rows)
    save_csv(args.out / "unique-positions.csv", union)
    save_csv(args.out / "false-positives.csv", [r for r in union if r["is_source"] is False and r["prediction"] == "yes"])
    save_csv(args.out / "false-negatives.csv", [r for r in union if r["is_source"] is True and r["prediction"] != "yes"])
    save_csv(args.out / "excluded-reference-unknown.csv", [r for r in union if r["is_source"] is None])
    write_json(args.out / "metrics.json", metrics)
    if args.yasa_sources.exists():
        comparison = report_source_match(read(args.yasa_sources), {r["candidate"]["candidate_id"]: r for r in union})
        write_json(args.out / "yasa-reported-source-coverage.json", comparison)
    primary = metrics["unique_origin_only_any_yes_detection"]
    alternate = metrics["unique_request_read_sites_sensitivity"]
    pct = lambda value: "N/A" if value is None else "{:.2f}%".format(value * 100)
    lines = ["# CTFd Jev source 参考评测", "", "这是候选集上的 AI 辅助静态参考评测，无独立人工复核，不是已验证的全仓真实准确率。",
             "参考构建只读取源码、无标签候选库存及独立入口静态参考；没有读取 source 预测/概率或 YASA 报告。",
             "候选集受前一阶段入口选择和一层辅助扩展影响，不能评估未进入候选集的真实 source。", "",
             "主口径：外部输入起点；已作为 source 的请求承载形参，其后续读取属于传播。",
             "位置级检测：任一入口下原始答案为 yes 即表示模型发现该位置；不对原始入口级判断做投票或改标签。", "",
             "| 指标 | 主口径，去重位置 |", "|---|---:|"]
    for key in ("accuracy", "precision", "recall", "f1", "balanced_accuracy", "specificity", "all_negative_accuracy_baseline", "reference_coverage", "predicted_yes_reference_coverage"):
        lines.append("| {} | {} |".format(key, pct(primary[key])))
    lines += ["", "```text"]
    for key in ("total", "reference_known", "reference_unknown_excluded", "reference_positive", "reference_negative", "tp", "fp", "fn_decided", "tn", "unresolved_positive", "unresolved_negative"):
        lines.append("{:<34}: {}".format(key, primary[key]))
    lines += ["```", "", "参考 unknown 排除于二元评分，但单列保留；模型 unknown/失败不能冒充 TN，在主 Accuracy/Recall 分母保留。",
              "Precision 只针对参考已定的模型 yes；参考未知的模型 yes 不擅自判为 FP，也不能认为已验证正确。", "",
              "## 口径敏感性", "", "若把请求承载形参上的每次直接请求 API 读取也算 source，指标变化如下：", "",
              "| 指标 | 请求读取位置口径 |", "|---|---:|"]
    for key in ("accuracy", "precision", "recall", "f1", "balanced_accuracy"):
        lines.append("| {} | {} |".format(key, pct(alternate[key])))
    lines += ["", "两个口径在参考标注之前定义，不按评测分数挑选。更换口径的行可在参考 annotations 的 request_read_policy_is_source 查到。",
              "完整配对级、语法类别分组和冲突统计见 metrics.json；FP/FN 与参考 unknown 分别保存 CSV。",
              "YASA 报告对照仅是告警路径 source 的精确位置重现率，见 yasa-reported-source-coverage.json；不把其余位置算成负例。"]
    (args.out / "REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    write_json(args.out / "manifest.json", {"created_at": datetime.now(timezone.utc).isoformat(), "source_run": str(args.run.resolve()),
        "reference": str(args.reference.resolve()), "reference_annotations_sha256": sha(args.reference / "annotations.jsonl"),
        "reference_policy_sha256": sha(args.reference / "POLICY.md"), "source_results_sha256": sha(args.run / "results.json"),
        "source_prepared_sha256": sha(args.run / "prepared.json"), "implementation_sha256": sha(Path(__file__)),
        "api_called": False, "independent_human_review": False})
    print(json.dumps(metrics, ensure_ascii=False, indent=2))
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--run", type=Path, default=HERE / "runs/jev-sources-ctfd-application-v1")
    p.add_argument("--reference", type=Path, default=HERE / "annotations/ctfd-sources-static-v1")
    p.add_argument("--yasa-sources", type=Path, default=HERE / "source-extractions/ctfd-yasa-manual-v1/sources.json")
    p.add_argument("--out", type=Path, required=True)
    return evaluate(p.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
