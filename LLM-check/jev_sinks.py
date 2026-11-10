#!/usr/bin/env python3
"""Prepare and classify deduplicated Python call sites as potential Jev sinks."""

import argparse
import csv
import hashlib
import json
import threading
import time
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime, timezone
from pathlib import Path

from context_graph import ContextGraph, fingerprint
from jev_config import DEFAULT_ENV_FILE, read_settings
from jev_source_scan import api_request
from laya_smoke import validate_answers, write_json
from sink_context import SinkContext

HERE = Path(__file__).resolve().parent
PIPELINE = "callsite-sink-then-argument-roles-v1"


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def plan_hash(item, manifest):
    return fingerprint({"pipeline": PIPELINE, "url": manifest["url"], "model": manifest["model"],
                        "state": item["state"], "questions": item["questions"],
                        "question_batch_size": manifest["question_batch_size"]})


def questions_for(candidate, prompt):
    questions = {"is_sink": prompt["is_sink"], "sink_kind": prompt["sink_kind"]}
    for arg in candidate["arguments"]:
        questions["role_" + arg["selector"]] = {"type": "choice", "criteria": prompt["argument_criteria"],
            "instructions": "For C's sensitive operation, is selector {} ({}, name={}, source index={}) a dangerous data input? "
                            "Inspect the argument expression in Target C. Starred indexes are source positions, not resolved runtime indexes. "
                            "Select by semantic role even if its current value is a constant; this is not an exploitability decision.".format(
                                arg["selector"], arg["kind"], arg.get("name"), arg.get("source_index"))}
    return questions


def prepare(args):
    if args.out.exists():
        raise ValueError("Choose a fresh --out directory")
    original = read(args.jev_run / "manifest.json") if args.jev_run else None
    index = args.index or (Path(original["index_directory"]) if original else None)
    if index is None:
        raise ValueError("Specify --jev-run or --index")
    print("[JEV-SINK] Loading UAST index and verifying repository source hashes.", flush=True)
    graph = ContextGraph(index, args.repo or (Path(original["repository"]) if original else None))
    if original and graph.index_hashes != original["index_hashes"]:
        raise ValueError("Index changed since the entrypoint experiment")
    settings, prompt = read_settings(args.env_file), read(HERE / "prompts/sink_jev_v1.json")
    builder = SinkContext(graph, args.max_state_chars, args.max_dependencies, args.dependency_depth,
                          args.max_callees, args.max_callee_lines, args.max_uses)
    candidates = builder.inventory(args.area, args.function, args.candidate, args.limit)
    if not candidates:
        raise ValueError("No call sites matched the selection")
    manifest = {"mode": PIPELINE, "provider": "jev", "created_at": datetime.now(timezone.utc).isoformat(),
                "url": settings["base_url"], "model": settings["model"], "repository": str(graph.repo),
                "repository_commit": graph.summary.get("commit"), "index_directory": str(graph.index_dir),
                "index_hashes": graph.index_hashes, "source_files": graph.tables["files"],
                "area": args.area, "selected_candidates": len(candidates), "question_batch_size": args.question_batch_size,
                "context_options": {k: getattr(args, k) for k in ("max_state_chars", "max_dependencies", "dependency_depth",
                    "max_callees", "max_callee_lines", "max_uses")}, "input_budget_unit": "characters, not model tokens",
                "entrypoint_source_predictions_used_in_prompt": False, "ground_truth_used": False,
                "yasa_sink_rules_used_for_selection_or_labels": False,
                "selection": {"functions": args.function, "candidate_ids": args.candidate, "limit": args.limit},
                "implementation_hashes": {n: digest(HERE / n) for n in
                    ("jev_sinks.py", "sink_context.py", "jev_source_scan.py", "context_graph.py", "compact_context.py")},
                "limitations": ["Python ast.Call sites only; implicit operations and other languages are not enumerated.",
                    "All application call sites are eligible, including module/class initialization, decorators and defaults.",
                    "No entrypoint-reachability prefilter: incomplete static links must not silently exclude sinks.",
                    "Context evidence is bounded lexical/static retrieval, not a backward taint slice or complete PDG.",
                    "Missing evidence and oversized mandatory inputs remain explicit errors/unknown, never negative predictions.",
                    "External API usage is reported by the provider; character budgets do not establish service token limits."]}
    prepared, failures = [], []
    print("[JEV-SINK] Building contexts for {} physical call sites; no API calls.".format(len(candidates)), flush=True)
    for number, candidate in enumerate(candidates, 1):
        case_id = candidate["candidate_id"]
        try:
            context = builder.build(candidate, prompt)
            item = {"case_id": case_id, "function": candidate["owner"], "candidate": candidate,
                    "state": context["state"], "questions": questions_for(candidate, prompt),
                    "input_coverage": context["coverage"], "blocked": context["coverage"]["character_budget_exceeded"]}
            item["request_hash"] = plan_hash(item, manifest)
            prepared.append(item)
            write_json(args.out / "contexts" / (case_id + ".json"), context)
            target = args.out / "state-text" / (case_id + ".txt")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(item["state"], encoding="utf-8")
        except (ValueError, KeyError, SyntaxError, OSError, TypeError) as exc:
            failures.append({"case_id": case_id, "candidate": candidate, "error": str(exc)})
        if number % 100 == 0 or number == len(candidates):
            print("[JEV-SINK] Prepared {}/{}; {} errors.".format(number, len(candidates), len(failures)), flush=True)
    manifest.update(prepared_candidates=len(prepared), preparation_errors=len(failures),
                    oversized_candidates=sum(p["blocked"] for p in prepared),
                    files_in_scope=sum(args.area == "all" or f["area"] == args.area for f in graph.files.values()),
                    source_lines_in_scope=sum(f["lines"] for f in graph.files.values() if args.area == "all" or f["area"] == args.area))
    write_json(args.out / "manifest.json", manifest)
    write_json(args.out / "prompt.json", prompt)
    write_json(args.out / "candidates.json", candidates)
    write_json(args.out / "prepared.json", prepared)
    write_json(args.out / "preparation-errors.json", failures)
    summarize(args.out)
    return int(bool(failures))


def decode(item, answers):
    decision = answers["is_sink"]
    positive = decision["choice"] == "yes"
    roles = {a["selector"]: answers["role_" + a["selector"]] for a in item["candidate"]["arguments"]} if positive else {}
    selected = [dict(a, answer=roles[a["selector"]]) for a in item["candidate"]["arguments"]
                if positive and roles[a["selector"]]["choice"] == "yes"]
    issues = []
    if positive and not selected:
        issues.append("sink_yes_without_a_selected_dangerous_argument_or_receiver")
    kind = answers["sink_kind"]["choice"] if positive else None
    if positive and kind == "unknown":
        issues.append("sink_kind_unknown")
    return {"is_sink": {"yes": True, "no": False, "unknown": None}[decision["choice"]],
            "sink_kind": kind, "sink_answer": decision, "sink_kind_answer": answers.get("sink_kind"),
            "argument_answers": roles, "dangerous_arguments": selected, "consistency_issues": issues}


class ServiceRestriction(Exception):
    pass


def classify(item, manifest, args, settings, invocation_id, stop):
    """Each worker owns one candidate; stages checkpoint independently."""
    result = {k: item[k] for k in ("case_id", "function", "candidate", "request_hash")}
    result["stages"] = []
    answers = {}

    def stage(name, questions):
        if stop.is_set():
            raise ServiceRestriction("Service restriction; remaining stages were not requested")
        request_id = item["case_id"] + "_" + name
        payload = {"model": manifest["model"], "state": item["state"], "questions": questions}
        request_hash = fingerprint({"url": manifest["url"], "payload": payload})
        raw_path = args.out / "responses" / (request_id + ".json")
        checkpoint = args.out / "checkpoints" / (request_id + ".json")
        previous = read(checkpoint) if checkpoint.exists() else {}
        raw = None
        if (previous.get("status") == "success" and previous.get("request_hash") == request_hash and raw_path.exists()
                and previous.get("response_sha256") == digest(raw_path)):
            raw = read(raw_path)
            try:
                validate_answers(raw, questions)
            except (ValueError, KeyError, TypeError):
                raw = None
        if raw is not None:
            record = dict(previous, reused=True)
        else:
            write_json(args.out / "requests" / (request_id + ".json"), payload)
            # Reuse the existing validated/retrying HTTP transport, with no source
            # candidates: all sink/argument semantics are decoded here from raw answers.
            request_item = {"request_id": request_id, "case_id": item["case_id"], "function": item["function"],
                            "request_hash": request_hash, "payload": payload, "candidates": []}
            record, raw, events = api_request(request_item, manifest["url"], settings["api_key"], args.timeout, args.retries)
            record.pop("candidates", None)
            record["reused"] = False
            record["input_audit"] = {"state_characters": len(payload["state"]), "state_utf8_bytes": len(payload["state"].encode()),
                                     "client_state_truncated": False, "provider_reported_input_tokens": ((raw or {}).get("usage") or {}).get("input_tokens"),
                                     "server_truncation_status": "not_reported"}
            if raw is not None:
                write_json(raw_path, raw)
                record["response_sha256"] = digest(raw_path)
            write_json(checkpoint, record)
            write_json(args.out / "usage-events" / invocation_id / (request_id + ".json"), events)
            if any(e.get("http_status") in {401, 402, 403, 451} for e in events):
                stop.set()
        result["stages"].append(record)
        if record["status"] != "success":
            raise ServiceRestriction(record.get("error", "API request failed"))
        answers.update(raw["answers"])

    started = time.monotonic()
    try:
        if item["blocked"]:
            result.update(status="blocked_oversized", error="Complete mandatory call/signature exceeds client character budget; not submitted")
            return result
        stage("detect", {"is_sink": item["questions"]["is_sink"]})
        if answers["is_sink"]["choice"] == "yes":
            more = [(key, value) for key, value in item["questions"].items() if key != "is_sink"]
            size = manifest["question_batch_size"]
            for offset in range(0, len(more), size):
                stage("roles_" + str(offset // size), dict(more[offset:offset + size]))
        result.update(status="success", verdict=decode(item, answers))
    except (ServiceRestriction, OSError, ValueError, KeyError, TypeError) as exc:
        result.update(status="error", error=str(exc).replace(settings["api_key"], "[REDACTED]"))
    finally:
        result["elapsed_seconds"] = time.monotonic() - started
    return result


def run(args):
    manifest, prepared = read(args.out / "manifest.json"), read(args.out / "prepared.json")
    settings = read_settings(args.env_file, require_key=True)
    if manifest["mode"] != PIPELINE or settings["base_url"] != manifest["url"] or settings["model"] != manifest["model"]:
        raise ValueError("Service/model/pipeline changed; prepare a fresh run")
    for f in manifest["source_files"]:
        if digest(Path(manifest["repository"]) / f["file"]) != f["sha256"]:
            raise ValueError("Source changed since preparation: " + f["file"])
    for item in prepared:
        if plan_hash(item, manifest) != item["request_hash"]:
            raise ValueError("Prepared input changed: " + item["case_id"])
    old = {r["case_id"]: r for r in read(args.out / "results.json")} if (args.out / "results.json").exists() else {}
    saved = {p["case_id"]: old[p["case_id"]] for p in prepared if p["case_id"] in old
             and old[p["case_id"]].get("request_hash") == p["request_hash"]}
    stop = threading.Event()
    invocation_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
    started, completed, interrupted = time.monotonic(), 0, False
    iterator, active = iter(prepared), {}
    executor = ThreadPoolExecutor(max_workers=args.workers)

    def submit():
        if stop.is_set():
            return
        item = next(iterator, None)
        if item:
            active[executor.submit(classify, item, manifest, args, settings, invocation_id, stop)] = item

    for _ in range(args.workers):
        submit()
    print("[JEV-SINK] {} call sites, {} workers; valid raw-response checkpoints will be reused.".format(len(prepared), args.workers), flush=True)
    try:
        while active:
            done, _ = wait(active, timeout=1, return_when=FIRST_COMPLETED)
            for future in done:
                item = active.pop(future)
                row = future.result()
                saved[item["case_id"]] = row
                completed += 1
                write_json(args.out / "results.json", [saved[p["case_id"]] for p in prepared if p["case_id"] in saved])
                if completed % 20 == 0 or row["status"] != "success" or completed == len(prepared):
                    print("[JEV-SINK] {}/{} complete; latest {}: {}; {:.1f}s".format(completed, len(prepared),
                        item["case_id"], row.get("verdict", {}).get("is_sink", row["status"]), time.monotonic() - started), flush=True)
                submit()
    except KeyboardInterrupt:
        interrupted = True
        stop.set()
    finally:
        executor.shutdown(wait=True, cancel_futures=True)
        invocation = {"invocation_id": invocation_id, "finished_at": datetime.now(timezone.utc).isoformat(),
                      "elapsed_seconds": time.monotonic() - started, "candidates_processed": completed,
                      "status": "interrupted" if interrupted else "completed" if completed == len(prepared)
                                and all(saved.get(p["case_id"], {}).get("status") == "success" for p in prepared) else "finished_with_errors"}
        write_json(args.out / "invocations" / (invocation_id + ".json"), invocation)
        write_json(args.out / "last-invocation.json", invocation)
        summarize(args.out)
    return 130 if interrupted else int(invocation["status"] != "completed")


def summarize(out):
    manifest, prepared = read(out / "manifest.json"), read(out / "prepared.json")
    rows = read(out / "results.json") if (out / "results.json").exists() else []
    good = [r for r in rows if r["status"] == "success"]
    yes = [r for r in good if r["verdict"]["is_sink"] is True]
    invocation = read(out / "last-invocation.json") if (out / "last-invocation.json").exists() else {}
    usage, events, timings = Counter(), [], []
    for path in (out / "usage-events").glob("*/*.json"):
        for event in read(path):
            events.append((path.parent.name, event))
            usage.update({k: v for k, v in (event.get("usage") or {}).items() if k in {"input_tokens", "output_tokens"} and isinstance(v, int)})
            timings.append(event["elapsed_seconds"])
    current = [e for key, e in events if key == invocation.get("invocation_id")]
    last_usage = Counter()
    for e in current:
        last_usage.update({k: v for k, v in (e.get("usage") or {}).items() if k in {"input_tokens", "output_tokens"} and isinstance(v, int)})
    summary = {"language": "python", "scope": manifest["area"], "model": manifest["model"],
               "files_in_scope": manifest["files_in_scope"], "source_lines_in_scope": manifest["source_lines_in_scope"],
               "calls_selected": manifest["selected_candidates"], "calls_prepared": len(prepared), "calls_completed": len(good),
               "sinks": len(yes), "non_sinks": sum(r["verdict"]["is_sink"] is False for r in good),
               "unknown": sum(r["verdict"]["is_sink"] is None for r in good),
               "failed": sum(r["status"] == "error" for r in rows), "oversized_not_submitted": sum(p["blocked"] for p in prepared),
               "preparation_errors": manifest["preparation_errors"], "not_attempted": len(prepared) - len(rows),
               "calls_with_context_omissions": sum(p["input_coverage"]["blocks_omitted"] > 0 for p in prepared),
               "sink_kind_counts": dict(Counter(r["verdict"]["sink_kind"] for r in yes)),
               "selected_argument_roles": sum(len(r["verdict"]["dangerous_arguments"]) for r in yes),
               "consistency_issues": sum(bool(r["verdict"]["consistency_issues"]) for r in good),
               "saved_http_attempts": len(events), "saved_input_tokens": usage["input_tokens"],
               "saved_output_tokens": usage["output_tokens"], "saved_total_tokens": usage["input_tokens"] + usage["output_tokens"],
               "last_invocation": dict(invocation, http_attempts=len(current), input_tokens=last_usage["input_tokens"],
                                       output_tokens=last_usage["output_tokens"]),
               "has_ground_truth": False, "sink_decision_is_vulnerability_verdict": False}
    write_json(out / "summary.json", summary)
    write_json(out / "possible-sinks.json", yes)
    columns = ["candidate_id", "owner", "file", "line", "column", "call", "status", "is_sink", "sink_kind", "sink_probability",
               "model_confidence", "dangerous_selectors", "unknown_selectors", "consistency_issues"]
    flat = []
    for row in rows:
        c, v = row["candidate"], row.get("verdict", {})
        flat.append({"candidate_id": c["candidate_id"], "owner": c["owner"], "file": c["location"]["file"],
            "line": c["location"]["start_line"], "column": c["location"]["start_column_utf8"], "call": c["expression"],
            "status": row["status"], "is_sink": v.get("is_sink"), "sink_kind": v.get("sink_kind"),
            "sink_probability": v.get("sink_answer", {}).get("probabilities", {}).get("yes"),
            "model_confidence": v.get("sink_answer", {}).get("confidence"),
            "dangerous_selectors": ";".join(a["selector"] for a in v.get("dangerous_arguments", [])),
            "unknown_selectors": ";".join(k for k, a in v.get("argument_answers", {}).items() if a["choice"] == "unknown"),
            "consistency_issues": ";".join(v.get("consistency_issues", []))})
    for filename, selected in (("candidate-results.csv", flat), ("possible-sinks.csv", [r for r in flat if r["is_sink"] is True])):
        with (out / filename).open("w", encoding="utf-8-sig", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=columns)
            writer.writeheader()
            writer.writerows(selected)
    lines = ["Language                               : python", "Scan scope                             : " + manifest["area"],
             "Model                                  : " + manifest["model"]]
    for label, key in [("Files in scope", "files_in_scope"), ("Source lines in scope", "source_lines_in_scope"),
                       ("Call sites selected", "calls_selected"), ("Call sites completed", "calls_completed"),
                       ("Potential sinks (model)", "sinks"), ("Non-sinks", "non_sinks"), ("Unknown calls", "unknown"),
                       ("Failed calls", "failed"), ("Oversized calls not submitted", "oversized_not_submitted"),
                       ("Preparation errors", "preparation_errors"), ("Call sites not attempted", "not_attempted"),
                       ("Calls with omitted context", "calls_with_context_omissions"),
                       ("Dangerous argument roles", "selected_argument_roles"), ("Saved HTTP attempts", "saved_http_attempts"),
                       ("Saved input tokens", "saved_input_tokens"), ("Saved output tokens", "saved_output_tokens"),
                       ("Saved total tokens", "saved_total_tokens")]:
        lines.append("{:<39}: {:,}".format(label, summary[key]))
    terminal = "\n".join(lines)
    (out / "statistics.txt").write_text(terminal + "\n", encoding="utf-8")
    (out / "SUMMARY.md").write_text("# Jev 逐调用点 sink 识别\n\n```text\n" + terminal + "\n```\n\n"
        "这是潜在 sink 及危险参数角色的模型判断，不是漏洞结论，也没有准确率真值。\n"
        "state-text/ 保存精简输入，contexts/ 保存选取/裁剪明细，requests/ 和 responses/ 保存实际请求与原始回复。\n"
        "预算以字符计，不代表 Jev 实际 token 上限。目标调用完整；超预算的必需输入不提交，不当作阴性。\n", encoding="utf-8")
    print(terminal, flush=True)
    return summary


def positive(value):
    value = int(value)
    if value < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "run", "summarize"))
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--jev-run", type=Path)
    parser.add_argument("--index", type=Path)
    parser.add_argument("--repo", type=Path)
    parser.add_argument("--area", choices=("application", "tests", "migrations", "scripts_or_other", "all"), default="application")
    parser.add_argument("--function", action="append", default=[])
    parser.add_argument("--candidate", action="append", default=[])
    parser.add_argument("--limit", type=positive)
    parser.add_argument("--max-state-chars", type=positive, default=16000)
    parser.add_argument("--max-dependencies", type=positive, default=10)
    parser.add_argument("--dependency-depth", type=positive, default=2)
    parser.add_argument("--max-callees", type=positive, default=2)
    parser.add_argument("--max-callee-lines", type=positive, default=100)
    parser.add_argument("--max-uses", type=int, default=2)
    parser.add_argument("--question-batch-size", type=positive, default=8)
    parser.add_argument("--workers", type=positive, default=4)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--timeout", type=positive, default=180)
    parser.add_argument("--env-file", type=Path, default=DEFAULT_ENV_FILE)
    args = parser.parse_args()
    if not 0 <= args.retries <= 5 or args.max_uses < 0:
        parser.error("retries must be 0..5 and max-uses must be nonnegative")
    if args.command == "prepare":
        return prepare(args)
    if args.command == "summarize":
        summarize(args.out)
        return 0
    return run(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError) as exc:
        raise SystemExit("ERROR: " + str(exc))
