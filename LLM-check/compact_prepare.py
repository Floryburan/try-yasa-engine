#!/usr/bin/env python3
"""Freeze a compact source-only entrypoint experiment without API calls."""

import argparse
import json
from pathlib import Path

from compact_context import CompactContext
from context_graph import ContextGraph, fingerprint
from jev_config import DEFAULT_ENV_FILE, read_settings
from laya_evaluate import same_labels
from laya_smoke import token_audit, write_json

HERE = Path(__file__).resolve().parent


def prepare(args):
    if (args.out / "prepared.json").exists():
        raise ValueError("Output already exists; use a new --out")
    settings = read_settings(args.env_file)
    prompt = json.loads((HERE / "prompts/entrypoint_compact_v1.json").read_text())
    baseline_prompt = json.loads((HERE / "prompts/entrypoint_laya_v1.json").read_text())
    same_labels(baseline_prompt, prompt)
    dataset = json.loads((HERE / "experiments/ctfd_balanced_dev_v1.json").read_text())
    graph = ContextGraph(HERE.parent / "artifacts/ctfd-uast/index")
    builder = CompactContext(graph, max_uses=args.max_uses)
    prepared, summary = [], []
    prior = json.loads((HERE / "runs/jev-ctfd-smoke-v1/prepared.json").read_text())
    prior_by_name = {row["function"]: row for row in prior}
    for case in dataset["cases"]:
        matches = [r for r in graph.tables["functions"] if r["qualified_name"] == case["function"]]
        if len(matches) != 1:
            raise ValueError("Ambiguous target function")
        context = builder.build(graph.nodes[matches[0]["id"]])
        state = prompt["definition"] + "\n\n" + context["state"]
        # Exact local formatting check belongs only to this named Laya checkpoint.
        # Jev tokens are obtained later from the actual provider response.
        reference_payload = {"state": state, "questions": prompt["questions"], "max_len": 8192, "head_max_len": 256}
        local_audit = token_audit(reference_payload, Path("/data/models/laya-multilingual/tokenizer"))
        payload = {"model": settings["model"] if args.provider == "jev" else "multilingual",
                   "state": state, "questions": prompt["questions"]}
        if args.provider == "laya":
            payload.update(max_len=8192, head_max_len=256)
        variant = args.provider + "_compact"
        old_chars = len(prior_by_name[case["function"]]["payload"]["state"])
        audit = {"local_reference_checkpoint": "laya-multilingual", "applies_to_jev": False,
                 "exact_local_question_audits": local_audit,
                 "jev_pre_dispatch_exact_tokens": None, "jev_truncation_status": "not_yet_requested"}
        item = {"case_id": case["id"], "function": case["function"], "variant": variant, "payload": payload,
                "expected_for_review_only": case["expected"], "input_length_audit": audit,
                "request_hash": fingerprint({"url": settings["base_url"] if args.provider == "jev" else args.url,
                                             "payload": payload, "pipeline": "entrypoint_then_classify-v1", "question_batch_size": 1})}
        prepared.append(item)
        write_json(args.out / "contexts" / (case["id"] + ".json"), context)
        write_json(args.out / variant / "request-plans" / (case["id"] + ".json"), payload)
        text_path = args.out / "state-text" / (case["id"] + ".txt")
        text_path.parent.mkdir(parents=True, exist_ok=True)
        text_path.write_text(state, encoding="utf-8")
        stats = {"case_id": case["id"], "function": case["function"], "previous_state_characters": old_chars,
                 "compact_state_characters": len(state), "local_reference_max_sequence_tokens": max(v["sequence_tokens"] for v in local_audit.values()),
                 "source_blocks": len(context["blocks"]), **context["coverage"]}
        summary.append(stats)
        print(json.dumps(stats, ensure_ascii=False), flush=True)
    write_json(args.out / "prepared.json", prepared)
    write_json(args.out / "input-preparation-audit.json", summary)
    write_json(args.out / "manifest.json", {
        "provider": args.provider, "url": settings["base_url"] if args.provider == "jev" else args.url,
        "model": settings["model"] if args.provider == "jev" else "multilingual", "env_file": str(args.env_file.resolve()),
        "api_key_env": "TYPESAFE_API_KEY" if args.provider == "jev" else "LAYA_API_KEY", "question_batch_size": 1,
        "pipeline": "entrypoint_then_classify-v1", "dataset": dataset, "repository_commit": graph.summary.get("commit"),
        "index_hashes": graph.index_hashes, "prompts": {args.provider + "_compact": prompt},
        "experiment_description": "精简源码输入：完整目标函数、直接使用位置、必要外层语句与导入；没有图边、长规则或重复源码行。输出标签保持不变。",
        "note": "Local exact token audit uses Laya's tokenizer only. Jev exact input tokens must come from provider usage; absent server truncation fields remain unknown."})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", choices=("jev", "laya"), default="jev")
    parser.add_argument("--out", type=Path, default=HERE / "runs/jev-compact-v1")
    parser.add_argument("--env-file", type=Path, default=DEFAULT_ENV_FILE)
    parser.add_argument("--url", default="http://127.0.0.1:8001")
    parser.add_argument("--max-uses", type=int, default=6)
    args = parser.parse_args()
    if args.max_uses < 1:
        raise SystemExit("max-uses must be positive")
    prepare(args)
