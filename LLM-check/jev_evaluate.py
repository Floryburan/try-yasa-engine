#!/usr/bin/env python3
"""Use the frozen CTFd experiment with the official Jev System One endpoint."""

import argparse
import json
from pathlib import Path

from context_graph import fingerprint
from jev_config import DEFAULT_ENV_FILE, public_settings, read_settings
from laya_evaluate import report, run
from laya_smoke import write_json

HERE = Path(__file__).resolve().parent


def jev_payload(payload, model):
    # Laya-specific token limits and model name must not be forwarded to Jev.
    return {"model": model, "state": payload["state"], "questions": payload["questions"]}


def prepare(args, settings):
    if (args.out / "prepared.json").exists():
        raise ValueError("Prepared experiment exists; use a fresh --out")
    source_manifest = json.loads((args.source_run / "manifest.json").read_text())
    source = [row for row in json.loads((args.source_run / "prepared.json").read_text()) if row["variant"] == args.input_variant]
    if not source:
        raise ValueError("Input variant not found in frozen source experiment")
    prepared = []
    for item in source:
        payload = jev_payload(item["payload"], settings["model"])
        row = {key: item[key] for key in ("case_id", "function", "expected_for_review_only")}
        row.update(variant="jev_" + args.input_variant, payload=payload,
                   request_hash=fingerprint({"url": settings["base_url"], "payload": payload,
                                             "pipeline": "entrypoint_then_classify-v1", "question_batch_size": 1}))
        prepared.append(row)
        write_json(args.out / row["variant"] / "request-plans" / (row["case_id"] + ".json"), payload)
    write_json(args.out / "prepared.json", prepared)
    write_json(args.out / "manifest.json", {
        "provider": "jev", "url": settings["base_url"], "model": settings["model"],
        "env_file": str(args.env_file.resolve()), "api_key_env": "TYPESAFE_API_KEY", "question_batch_size": 1,
        "pipeline": "entrypoint_then_classify-v1", "dataset": source_manifest["dataset"],
        "repository_commit": source_manifest["repository_commit"], "source_run": str(args.source_run.resolve()),
        "prompts": {"jev_" + args.input_variant: source_manifest["prompts"][args.input_variant]},
        "experiment_description": "Jev 接口实验；保留冻结的 4 正 4 负样本、提示词、输入证据和全部输出标签。仅切换模型服务。",
        "note": "No credentials stored. Preparation is offline; Laya tokenizer counts are not claimed as Jev token counts."})
    print(json.dumps({"prepared_cases": len(prepared), "out": str(args.out), "api_called": False}, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check-config", "prepare", "run", "summarize"))
    parser.add_argument("--env-file", type=Path, default=DEFAULT_ENV_FILE)
    parser.add_argument("--out", type=Path, default=HERE / "runs/jev-ctfd-smoke-v1")
    parser.add_argument("--source-run", type=Path, default=HERE / "runs/laya-yasa-callgraph-v1")
    parser.add_argument("--input-variant", choices=("uast_only", "uast_plus_yasa_cg"), default="uast_plus_yasa_cg")
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    if args.command == "check-config":
        print(json.dumps(public_settings(read_settings(args.env_file)), ensure_ascii=False, indent=2))
        return 0
    if args.command == "prepare":
        prepare(args, read_settings(args.env_file))
        return 0
    if args.command == "summarize":
        report(args.out, json.loads((args.out / "results.json").read_text()))
        return 0
    manifest = json.loads((args.out / "manifest.json").read_text())
    if manifest.get("provider") != "jev":
        raise ValueError("This is not a prepared Jev experiment")
    settings = read_settings(args.env_file, require_key=True)
    if settings["base_url"] != manifest["url"] or settings["model"] != manifest["model"]:
        raise ValueError("Model/API root changed; prepare a fresh experiment")
    args.url = manifest["url"]
    args.question_batch_size = manifest["question_batch_size"]
    return run(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError) as exc:
        raise SystemExit("ERROR: " + str(exc))
