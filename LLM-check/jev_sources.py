#!/usr/bin/env python3
"""Replay source inputs or scan all predicted entrypoints with Jev."""

import argparse
import copy
import shutil
from datetime import datetime, timezone
from pathlib import Path

from context_graph import fingerprint
from jev_config import DEFAULT_ENV_FILE, read_settings
from jev_evaluate import jev_payload
from laya_smoke import write_json
from laya_sources import digest, positive, read, run, summarize

HERE = Path(__file__).resolve().parent


def prepare(args):
    if args.out.exists():
        raise ValueError("Choose a fresh --out directory")
    original_manifest = read(args.source_run / "manifest.json")
    if original_manifest.get("mode") != "formation_guided_source_pilot_v1":
        raise ValueError("Not a frozen source pilot")
    settings = read_settings(args.env_file)
    source = read(args.source_run / "prepared.json")
    prepared = []
    verification = []
    for old in source:
        original_hash = fingerprint({"url": original_manifest["url"], "payload": old["payload"]})
        if original_hash != old["request_hash"]:
            raise ValueError("Frozen source request changed: " + old["request_id"])
        item = copy.deepcopy(old)
        item["payload"] = jev_payload(old["payload"], settings["model"])
        item["request_hash"] = fingerprint({"url": settings["base_url"], "payload": item["payload"]})
        item["source_request_hash"] = old["request_hash"]
        item["source_token_audit_for_reference_only"] = item.pop("token_audit", None)
        checks = {"request_id": item["request_id"],
                  "state_identical": item["payload"]["state"] == old["payload"]["state"],
                  "questions_identical": item["payload"]["questions"] == old["payload"]["questions"],
                  "questions_and_option_order_identical":
                      list(item["payload"]["questions"]) == list(old["payload"]["questions"])
                      and all(list(q["criteria"]) == list(old["payload"]["questions"][qid]["criteria"])
                              for qid, q in item["payload"]["questions"].items()),
                  "candidates_identical": item["candidates"] == old["candidates"]}
        if not all(value for key, value in checks.items() if key != "request_id"):
            raise ValueError("Input equivalence check failed")
        verification.append(checks)
        prepared.append(item)
        write_json(args.out / "requests" / (item["request_id"] + ".json"), item["payload"])
    for rel in ("contexts", "prompt.json", "preparation-errors.json", "jev-predictions.snapshot.json"):
        path = args.source_run / rel
        if path.is_dir():
            shutil.copytree(path, args.out / rel)
        elif path.is_file():
            shutil.copy2(path, args.out / rel)
    manifest = copy.deepcopy(original_manifest)
    manifest.update(provider="jev", url=settings["base_url"], model=settings["model"],
                    created_at=datetime.now(timezone.utc).isoformat(),
                    source_run=str(args.source_run.resolve()),
                    source_prepared_sha256=digest(args.source_run / "prepared.json"),
                    source_implementation_hashes=manifest.pop("implementation_hashes", {}),
                    implementation_hashes={n: digest(HERE / n) for n in ("jev_sources.py", "laya_sources.py", "jev_config.py")},
                    token_count_note="Source tokenizer audit is Laya-only; Jev counts come from provider usage.",
                    input_replay="Identical state, questions, choice order and candidates; only model/service controls changed.")
    write_json(args.out / "manifest.json", manifest)
    write_json(args.out / "prepared.json", prepared)
    write_json(args.out / "input-equivalence.json", verification)
    summarize(args.out)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "run", "summarize"))
    parser.add_argument("--out", required=True, type=Path)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--source-run", type=Path)
    selection.add_argument("--jev-run", type=Path, help="Build source inputs for all entrypoints in this repository scan")
    parser.add_argument("--function", action="append", default=[])
    parser.add_argument("--limit", type=positive)
    parser.add_argument("--max-helpers", type=positive, default=2)
    parser.add_argument("--max-helper-lines", type=positive, default=100)
    parser.add_argument("--batch-size", type=positive, default=8)
    parser.add_argument("--max-state-chars", type=positive, default=24000)
    parser.add_argument("--workers", type=positive, default=4)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--env-file", type=Path, default=DEFAULT_ENV_FILE)
    parser.add_argument("--timeout", type=positive, default=180)
    args = parser.parse_args()
    if not 0 <= args.retries <= 5:
        parser.error("--retries must be between 0 and 5")
    if args.command == "prepare":
        if args.jev_run:
            from jev_source_scan import prepare_repository
            return prepare_repository(args)
        args.source_run = args.source_run or HERE / "runs/laya-sources-ctfd-pilot-v2"
        return prepare(args)
    manifest = read(args.out / "manifest.json")
    if manifest.get("provider") != "jev":
        raise ValueError("Not a prepared Jev source experiment")
    if args.command == "summarize":
        summarize(args.out)
        return 0
    if manifest.get("source_scan_mode") == "repository_entrypoints":
        from jev_source_scan import run_repository
        return run_repository(args)
    return run(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError) as exc:
        raise SystemExit("ERROR: " + str(exc))
