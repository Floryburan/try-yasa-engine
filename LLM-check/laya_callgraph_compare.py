#!/usr/bin/env python3
"""Freeze an input ablation: same prompt, with or without YASA call graph edges."""

import argparse
import hashlib
import json
from pathlib import Path

from context_graph import fingerprint
from laya_smoke import token_audit, write_json
from yasa_callgraph_context import YasaCallGraph

HERE = Path(__file__).resolve().parent


def prepare(args):
    if (args.out / "prepared.json").exists():
        raise ValueError("Output already prepared; use a fresh --out")
    base_manifest = json.loads((args.baseline / "manifest.json").read_text())
    base = [row for row in json.loads((args.baseline / "prepared.json").read_text()) if row["variant"] == "optimized"]
    export = json.loads((args.graph.parent.parent / "command.json").read_text())
    if export["repository_commit"] != base_manifest["repository_commit"]:
        raise ValueError("Call graph and baseline repository commits differ")
    files_index = HERE.parent / "artifacts/ctfd-uast/index/files.jsonl"
    if hashlib.sha256(files_index.read_bytes()).hexdigest() != base_manifest["index_hashes"]["files"]:
        raise ValueError("UAST file index differs from the frozen baseline")
    checked_files = 0
    for line in files_index.open(encoding="utf-8"):
        record = json.loads(line)
        actual = hashlib.sha256((Path(export["repository"]) / record["file"]).read_bytes()).hexdigest()
        if actual != record["sha256"]:
            raise ValueError("Source differs from the baseline UAST: " + record["file"])
        checked_files += 1
    graph_sha = hashlib.sha256(args.graph.read_bytes()).hexdigest()
    graph = YasaCallGraph(json.loads(args.graph.read_text()), export["repository"])
    prompt = base_manifest["prompts"]["optimized"]
    prepared, coverage = [], []
    for item in base:
        context = json.loads((args.baseline / "contexts" / (item["case_id"] + ".json")).read_text())
        target = context["target"]
        max_edges = 24
        while True:
            subgraph = graph.neighborhood(target, max_edges=max_edges)
            addition = graph.render(subgraph)
            payload = dict(item["payload"], state=item["payload"]["state"] + "\n\n" + addition)
            try:
                audit = token_audit(payload, Path("/data/models/laya-multilingual/tokenizer"))
                break
            except ValueError:
                max_edges -= 4
                if max_edges < 4:
                    raise
        write_json(args.out / "callgraph-views" / (item["case_id"] + ".json"), subgraph)
        coverage.append(dict(case_id=item["case_id"], function=item["function"], **subgraph["coverage"],
                             selected_nodes=len(subgraph["nodes"]), selected_edges=len(subgraph["edges"])))
        for variant in ("uast_only", "uast_plus_yasa_cg"):
            final_payload = payload if variant == "uast_plus_yasa_cg" else item["payload"]
            row = {key: item[key] for key in ("case_id", "function", "expected_for_review_only", "review")}
            row.update(variant=variant, payload=final_payload,
                       token_audit=audit if variant == "uast_plus_yasa_cg" else item["token_audit"],
                       original_evidence_hash=item["evidence_hash"],
                       request_hash=fingerprint({"url": args.url, "payload": final_payload,
                                                 "pipeline": "entrypoint_then_classify-v1", "question_batch_size": 1,
                                                 "callgraph_sha256": graph_sha if variant == "uast_plus_yasa_cg" else None}))
            prepared.append(row)
            write_json(args.out / variant / "request-plans" / (item["case_id"] + ".json"), final_payload)
        print("{}: {} target match(es), {} incoming / {} outgoing, {} selected edges, {} max sequence tokens".format(
            item["case_id"], len(subgraph["target_nodes"]), subgraph["coverage"]["direct_incoming_edges"],
            subgraph["coverage"]["direct_outgoing_edges"], len(subgraph["edges"]),
            max(a["sequence_tokens"] for a in audit.values())), flush=True)
    write_json(args.out / "prepared.json", prepared)
    write_json(args.out / "callgraph-coverage.json", coverage)
    write_json(args.out / "manifest.json", {
        "dataset": base_manifest["dataset"], "repository_commit": export["repository_commit"],
        "url": args.url, "model": "multilingual", "question_batch_size": 1,
        "pipeline": "entrypoint_then_classify-v1", "prompts": {name: prompt for name in ("uast_only", "uast_plus_yasa_cg")},
        "baseline": str(args.baseline.resolve()), "callgraph": str(args.graph.resolve()),
        "verified_source_files": checked_files,
        "callgraph_sha256": graph_sha, "entrypoint_checker_predictions_used": False,
        "experiment_description": "同一批 4 正 4 负样本、相同第二版提示词和两阶段流程；仅增加 YASA 全库静态调用图的目标附近视图。",
        "limitations": "The whole graph is exported, but bounded neighborhoods are sent to the model. Static/library callback approximations are not guaranteed runtime calls. This does not independently test the UAST parser."})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, default=HERE / "runs/laya-balanced-dev-v1")
    parser.add_argument("--graph", type=Path, default=HERE.parent / "artifacts/ctfd-full-callgraph-20261026/report/callgraph.json")
    parser.add_argument("--out", type=Path, default=HERE / "runs/laya-yasa-callgraph-v1")
    parser.add_argument("--url", default="http://127.0.0.1:8001")
    prepare(parser.parse_args())
