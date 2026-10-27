#!/usr/bin/env python3
"""Prepare per-function UAST contexts and classify them through a model API."""

import argparse
import json
import sys
import time
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime, timezone
from pathlib import Path

from context_graph import ContextGraph, fingerprint, json_text
from model_api import ModelClient, ModelError, make_request, read_config, request_hash, validate_verdict


HERE = Path(__file__).resolve().parent
DEFAULT_INDEX = HERE.parent / "artifacts/ctfd-uast/index"
DEFAULT_RUN = HERE / "runs/ctfd"


def positive(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def prepare(args):
    print("Loading UAST index and resolving lexical/import relationships...", flush=True)
    graph = ContextGraph(args.index, args.repo)
    functions = graph.select_functions(args.area, args.include_lambdas, args.function, args.limit)
    if not functions:
        raise ValueError("No functions matched the selection")
    args.out.mkdir(parents=True, exist_ok=True)
    path = args.out / "contexts.jsonl"
    temporary = path.with_suffix(".jsonl.tmp")
    truncated, largest, unresolved = 0, 0, 0
    with temporary.open("w", encoding="utf-8") as stream:
        for number, function in enumerate(functions, 1):
            context = graph.context(function, args.max_depth, args.max_nodes, args.max_context_chars, args.source_chars)
            serialized = json_text(context)
            stream.write(serialized + "\n")
            truncated += bool(context["coverage"]["budget_exhausted"])
            largest = max(largest, len(serialized))
            unresolved += len(context["unresolved"])
            if number % 50 == 0 or number == len(functions):
                print("Prepared {}/{} function contexts".format(number, len(functions)), flush=True)
    temporary.replace(path)
    manifest = {"schema_version": 1, "created_at": datetime.now(timezone.utc).isoformat(),
                "repository": str(graph.repo), "repository_commit": graph.summary.get("commit"),
                "context_graph_sha256": fingerprint((HERE / "context_graph.py").read_text()),
                "selection": {"area": args.area, "include_lambdas": args.include_lambdas, "functions": args.function, "limit": args.limit},
                "functions": len(functions), "contexts_with_truncation": truncated,
                "unresolved_records_in_contexts": unresolved, "largest_context_chars": largest,
                "contexts_file": str(path.resolve()), "graph": graph.stats()}
    write_json(args.out / "manifest.json", manifest)
    print(json.dumps({key: manifest[key] for key in ("functions", "contexts_with_truncation", "largest_context_chars", "contexts_file")}, ensure_ascii=False, indent=2))


def read_contexts(path):
    seen = set()
    with path.open(encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            context = json.loads(line)
            if context.get("schema_version") != 1 or context.get("function_id") != context.get("target", {}).get("id"):
                raise ValueError("Invalid context at line " + str(number))
            function_id = context["function_id"]
            if function_id in seen:
                raise ValueError("Duplicate function context: " + function_id)
            seen.add(function_id)
            yield context


def load_successes(path):
    cached = {}
    if not path.exists():
        return cached
    lines = path.read_bytes().splitlines(keepends=True)
    byte_offset = 0
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            byte_offset += len(line)
            continue
        try:
            row = json.loads(line)
        except (ValueError, UnicodeError):
            if line_number == len(lines) and not line.endswith(b"\n"):
                path.with_suffix(path.suffix + ".incomplete-tail").write_bytes(line)
                with path.open("r+b") as stream:
                    stream.truncate(byte_offset)
                break
            raise ValueError("Output contains invalid JSON at line {}; use a new --out file".format(line_number))
        if row.get("status") == "success":
            cached[(row["function_id"], row["request_hash"])] = row
        byte_offset += len(line)
    # A complete final JSON object without its newline is also a valid partial
    # run. Insert the separator before appending another result.
    if path.stat().st_size and not path.read_bytes().endswith(b"\n"):
        with path.open("ab") as stream:
            stream.write(b"\n")
    return cached


def bounded_results(executor, jobs, workers):
    pending = set()
    exhausted = False
    while pending or not exhausted:
        while not exhausted and len(pending) < workers * 2:
            try:
                pending.add(executor.submit(next(jobs)))
            except StopIteration:
                exhausted = True
        if pending:
            done, pending = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                yield future.result()


def run(args):
    config = read_config(args.config)
    client = None if args.dry_run else ModelClient(config)
    output = args.out
    if output.resolve() == args.contexts.resolve():
        raise ValueError("--out must differ from --contexts")
    if args.dry_run and output.exists():
        previous = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines() if line.strip()]
        if any(row.get("status") != "dry_run" for row in previous):
            raise ValueError("Dry run cannot replace model results; choose a separate preview --out")
    cached = load_successes(output) if not args.dry_run and not args.no_resume else {}
    output.parent.mkdir(parents=True, exist_ok=True)
    stats = Counter()
    decisions = Counter()
    selected = 0
    started = time.monotonic()

    def jobs():
        nonlocal selected
        for context in read_contexts(args.contexts):
            target = context["target"]
            if args.function and not any(name in {target["id"], target["name"], target["qualified_name"]} for name in args.function):
                continue
            if args.limit is not None and selected >= args.limit:
                break
            selected += 1
            payload = make_request(context, config)
            digest = request_hash(payload, config)
            key = (context["function_id"], digest)
            if key in cached:
                validate_verdict(cached[key]["verdict"], context)
                stats["resumed"] += 1
                decisions[str(cached[key]["verdict"]["is_entrypoint"])] += 1
                continue
            def job(context=context, payload=payload, digest=digest):
                target = context["target"]
                result = {"schema_version": 1, "function_id": context["function_id"], "request_hash": digest,
                          "function": {key: target.get(key) for key in ("file", "name", "qualified_name", "start_line", "end_line", "enclosing_class_id")},
                          "model": config["model"], "created_at": datetime.now(timezone.utc).isoformat(),
                          "context_coverage": context["coverage"]}
                if args.dry_run:
                    return dict(result, status="dry_run", payload=payload)
                try:
                    return dict(result, status="success", **client.classify(context, payload))
                except ModelError as exc:
                    return dict(result, status="error", error=str(exc))
            yield job

    # Dry runs replace their preview file; model runs append, allowing partial-run resume.
    with output.open("w" if args.dry_run else "a", encoding="utf-8") as stream:
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            for result in bounded_results(executor, iter(jobs()), args.workers):
                stream.write(json_text(result) + "\n")
                stream.flush()
                stats[result["status"]] += 1
                if result["status"] == "success":
                    decisions[str(result["verdict"]["is_entrypoint"])] += 1
                if result["status"] == "error":
                    print("ERROR {}: {}".format(result["function"]["qualified_name"], result["error"]), file=sys.stderr, flush=True)
                elif sum(stats.values()) % 10 == 0:
                    print("Completed {} requests ({} resumed)".format(sum(stats.values()) - stats["resumed"], stats["resumed"]), flush=True)
    if selected == 0:
        raise ValueError("No contexts matched the selection")
    summary = {"selected": selected, "results": dict(stats), "decisions_including_resumed": dict(decisions),
               "elapsed_seconds": round(time.monotonic() - started, 3), "output": str(output.resolve()),
               "real_api_called": not args.dry_run and bool(stats["success"] or stats["error"])}
    write_json(output.with_suffix(".summary.json"), summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 1 if stats["error"] else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prep = commands.add_parser("prepare", help="Extract function contexts from the UAST index; no model calls")
    prep.add_argument("--index", type=Path, default=DEFAULT_INDEX)
    prep.add_argument("--repo", type=Path, help="Override relocated source repository; source hashes must match")
    prep.add_argument("--out", type=Path, default=DEFAULT_RUN)
    prep.add_argument("--area", choices=("application", "tests", "migrations", "scripts_or_other", "all"), default="application")
    prep.add_argument("--include-lambdas", action="store_true")
    prep.add_argument("--function", action="append", default=[], help="Exact function id, name, or qualified name; repeatable")
    prep.add_argument("--limit", type=positive)
    prep.add_argument("--max-depth", type=positive, default=10)
    prep.add_argument("--max-nodes", type=positive, default=100)
    prep.add_argument("--max-context-chars", type=positive, default=60000)
    prep.add_argument("--source-chars", type=positive, default=6000)
    invoke = commands.add_parser("run", help="One model request per function context, with resumable JSONL results")
    invoke.add_argument("--contexts", type=Path, default=DEFAULT_RUN / "contexts.jsonl")
    invoke.add_argument("--config", type=Path)
    invoke.add_argument("--out", type=Path, required=True)
    invoke.add_argument("--workers", type=positive, default=2)
    invoke.add_argument("--function", action="append", default=[])
    invoke.add_argument("--limit", type=positive)
    invoke.add_argument("--dry-run", action="store_true", help="Write complete request previews; never contact an API")
    invoke.add_argument("--no-resume", action="store_true", help="Append new results even for previously successful identical requests")
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            prepare(args)
            return 0
        return run(args)
    except (ValueError, OSError, KeyError) as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
