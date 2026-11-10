"""Repository source preparation and bounded, resumable Jev API execution."""

import hashlib
import json
import time
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from urllib import error, request

from context_graph import ContextGraph, fingerprint
from jev_config import api_headers, api_url, read_settings
from jev_evaluate import jev_payload
from laya_smoke import validate_answers, write_json
from laya_sources import HERE, digest, payload_for, read, summarize
from source_context import SourceContext, start_line


def batch_payload(builder, context, batch, prompt, kind, settings, max_chars):
    """Keep T and each candidate owner complete; trim optional support only."""
    required = set()
    for owner_id in {c["owner_id"] for c in batch}:
        owner = builder.graph.nodes[owner_id]
        node = builder.compact.definition(owner)
        required.update((owner["file"], n) for n in range(start_line(node), node.end_lineno + 1))
    blocks = list(context["blocks"])
    omitted = []
    controls = SimpleNamespace(model=settings["model"], max_len=8192)
    while True:
        payload = jev_payload(payload_for(context, blocks, batch, batch, prompt, kind, controls), settings["model"])
        if len(payload["state"]) <= max_chars:
            break
        optional = [i for i, b in enumerate(blocks) if b["role"] != "target" and not any(
            (b["file"], n) in required for n in range(b["start_line"], b["end_line"] + 1))]
        if not optional:
            break  # Send complete definitions; explicitly flag an oversized input.
        omitted.append(blocks.pop(optional[-1]))
    coverage = {"state_characters": len(payload["state"]), "character_budget_exceeded": len(payload["state"]) > max_chars,
                "optional_blocks_omitted": len(omitted), "selected_block_indexes": [context["blocks"].index(b) for b in blocks],
                "candidate_owners_complete": True, "target_complete": True,
                "token_limit_claimed": False}
    return payload, coverage


def prepare_repository(args):
    if args.out.exists():
        raise ValueError("Choose a fresh --out directory")
    original = read(args.jev_run / "manifest.json")
    plans = {p["case_id"]: p for p in read(args.jev_run / "prepared.json")}
    predictions = read(args.jev_run / "results.json")
    selected = [r for r in predictions if r["status"] == "success" and r["verdict"]["is_entrypoint"] is True]
    if args.function:
        selected = [r for r in selected if r["function"] in args.function]
        if set(args.function) != {r["function"] for r in selected}:
            raise ValueError("Function not found among successful Jev entrypoint predictions")
    if args.limit:
        selected = selected[:args.limit]
    if not selected:
        raise ValueError("No predicted entrypoints selected")
    graph = ContextGraph(Path(original["index_directory"]), Path(original["repository"]))
    if graph.index_hashes != original["index_hashes"] or graph.summary.get("commit") != original["repository_commit"]:
        raise ValueError("Repository index changed since entrypoint scan")
    definitions = {f["id"]: f for f in graph.select_functions(original["selection"]["area"])}
    settings = read_settings(args.env_file)
    builder = SourceContext(graph, args.max_helpers, args.max_helper_lines, max_candidates=None)
    prompt = read(HERE / "prompts/source_laya_v1.json")
    requests, cases, failures = [], [], []
    print("[JEV-SOURCE] Preparing all {} predicted entrypoints; no API calls; candidate count uncapped.".format(len(selected)), flush=True)
    for number, row in enumerate(selected, 1):
        try:
            plan = plans[row["case_id"]]
            function = definitions[plan["function_id"]]
            if (plan["request_hash"] != row["request_hash"] or function["definition_identity"] != plan["definition_identity"]
                    or function["qualified_name"] != row["function"]):
                raise ValueError("Entrypoint prediction/definition identity mismatch")
            target = dict(graph.nodes[plan["function_id"]], definition_identity=plan["definition_identity"],
                          definition_alias_ids=plan["definition_alias_ids"])
            context = builder.build(target, row["verdict"]["formation_types"])
            context["request_coverage"] = []
            function_requests = []
            for offset in range(0, len(context["candidates"]), args.batch_size):
                batch = context["candidates"][offset:offset + args.batch_size]
                rid = row["case_id"] + "_batch_" + str(offset // args.batch_size)
                payload, coverage = batch_payload(builder, context, batch, prompt, row["verdict"]["entrypoint_kind"],
                                                  settings, args.max_state_chars)
                item = {"request_id": rid, "case_id": row["case_id"], "function": row["function"],
                        "jev_verdict": row["verdict"], "candidates": batch, "payload": payload,
                        "request_hash": fingerprint({"url": settings["base_url"], "payload": payload}),
                        "input_coverage": coverage}
                function_requests.append(item)
                context["request_coverage"].append(dict(request_id=rid, **coverage))
            write_json(args.out / "contexts" / (row["case_id"] + ".json"), context)
            for item in function_requests:
                write_json(args.out / "requests" / (item["request_id"] + ".json"), item["payload"])
            requests.extend(function_requests)
            cases.append({"case_id": row["case_id"], "function": row["function"], "location": plan["location"],
                          "jev_verdict": row["verdict"], "candidates": len(context["candidates"]),
                          "target_candidates": sum(c["owner_id"] == target["id"] for c in context["candidates"]),
                          "omitted_candidates": len(context["omitted_candidates"]), "requests": len(function_requests),
                          "omitted_support": len(context["omitted_support"]), "unresolved_links": len(context["unresolved"]),
                          "oversized_requests": sum(c["character_budget_exceeded"] for c in context["request_coverage"]),
                          "requests_with_omitted_blocks": sum(c["optional_blocks_omitted"] > 0 for c in context["request_coverage"]),
                          "baseline_coverage": context["baseline_coverage"]})
        except (ValueError, KeyError, SyntaxError, OSError) as exc:
            failures.append({"case_id": row["case_id"], "function": row["function"], "error": str(exc)})
            print("[JEV-SOURCE] Preparation error {}: {}".format(row["function"], exc), flush=True)
        if number % 20 == 0 or number == len(selected):
            print("[JEV-SOURCE] Prepared {}/{} entrypoints, {} requests, {} candidates, {} errors".format(
                number, len(selected), len(requests), sum(c["candidates"] for c in cases), len(failures)), flush=True)
    manifest = {"mode": "formation_guided_source_pilot_v1", "source_scan_mode": "repository_entrypoints",
                "provider": "jev", "created_at": datetime.now(timezone.utc).isoformat(),
                "url": settings["base_url"], "model": settings["model"], "repository": str(graph.repo),
                "repository_commit": original["repository_commit"], "index_directory": str(graph.index_dir),
                "index_hashes": graph.index_hashes, "jev_run": str(args.jev_run.resolve()),
                "jev_predictions_sha256": digest(args.jev_run / "results.json"),
                "source_statistics": original.get("source_statistics", {}), "selection": original["selection"],
                "entrypoint_functions_scanned": len(predictions), "selected_entrypoints": len(selected),
                "prepared_entrypoints": len(cases), "cases": cases, "batch_size": args.batch_size,
                "max_helpers": args.max_helpers, "max_helper_lines": args.max_helper_lines,
                "max_state_characters": args.max_state_chars, "max_candidates": None, "helper_depth": 1,
                "ground_truth_used": False, "source_report_used": False,
                "implementation_hashes": {n: digest(HERE / n) for n in
                    ("jev_source_scan.py", "jev_sources.py", "source_context.py", "laya_sources.py", "compact_context.py", "binding_context.py")},
                "source_policy": "external_controlled_boundary_origin", "target_body_complete": True,
                "limitations": ["Source coverage is conditional on previous Jev entrypoint predictions in the recorded area.",
                                "Local helper expansion, reference resolution and support evidence remain bounded.",
                                "Candidates cover parameters, call returns, attribute/subscript reads, not arbitrary syntax or module execution.",
                                "Character budgets do not measure Jev tokens; oversized complete targets are submitted and flagged.",
                                "External-control origin policy differs from YASA broad taint-source rules; no source ground truth scoring."]}
    write_json(args.out / "manifest.json", manifest)
    write_json(args.out / "prepared.json", requests)
    write_json(args.out / "preparation-errors.json", failures)
    write_json(args.out / "jev-predictions.snapshot.json", selected)
    write_json(args.out / "prompt.json", prompt)
    summarize(args.out)
    return int(bool(failures))


def api_request(item, url, api_key, timeout, retries):
    """Workers do HTTP only. Main thread writes checkpoints and usage events."""
    started = time.monotonic()
    wire = json.dumps(item["payload"], ensure_ascii=False).encode("utf-8")
    headers = api_headers(api_key)
    opener = request.build_opener()
    result = {k: item[k] for k in ("request_id", "case_id", "function", "request_hash")}
    result["wire_sha256"] = hashlib.sha256(wire).hexdigest()
    events, raw = [], None
    for attempt in range(retries + 1):
        tick, status, retryable = time.monotonic(), None, False
        try:
            req = request.Request(api_url(url), data=wire, headers=headers, method="POST")
            with opener.open(req, timeout=timeout) as response:
                status = getattr(response, "status", 200)
                raw = json.load(response)
            validate_answers(raw, item["payload"]["questions"])
            result.update(status="success", model=raw.get("model"), usage=raw.get("usage"))
        except error.HTTPError as exc:
            status = exc.code
            result.update(status="error", error="HTTP " + str(exc.code),
                          response_body=exc.read(4096).decode("utf-8", "replace").replace(api_key, "[REDACTED]"))
            retryable = status in {408, 429, 500, 502, 503, 504}
        except OSError as exc:
            result.update(status="error", error=str(exc).replace(api_key, "[REDACTED]"))
            retryable = True
        except (ValueError, KeyError, TypeError) as exc:
            result.update(status="error", error=str(exc).replace(api_key, "[REDACTED]"))
        events.append({"request_id": item["request_id"], "attempt": attempt + 1, "http_status": status,
                       "elapsed_seconds": time.monotonic() - tick, "status": result["status"],
                       "error": result.get("error"), "usage": raw.get("usage") if isinstance(raw, dict) else None})
        if result["status"] == "success" or not retryable or attempt == retries:
            break
        time.sleep(min(2 ** attempt, 10))
    result["elapsed_seconds"] = time.monotonic() - started
    result["attempts"] = len(events)
    if result["status"] == "success":
        result.pop("error", None)
        result.pop("response_body", None)
        result["candidates"] = [dict(c, choice=raw["answers"][c["candidate_id"]]["choice"],
            probabilities=raw["answers"][c["candidate_id"]]["probabilities"],
            source_probability=raw["answers"][c["candidate_id"]]["probabilities"]["yes"],
            model_confidence=raw["answers"][c["candidate_id"]].get("confidence"),
            x_jev_confidence=raw["answers"][c["candidate_id"]].get("x_jev_confidence")) for c in item["candidates"]]
    return result, raw, events


def run_repository(args):
    manifest, prepared = read(args.out / "manifest.json"), read(args.out / "prepared.json")
    settings = read_settings(args.env_file, require_key=True)
    if settings["base_url"] != manifest["url"] or settings["model"] != manifest["model"]:
        raise ValueError("Model/API root changed; prepare a fresh run")
    path = args.out / "results.json"
    old = {r["request_id"]: r for r in read(path)} if path.exists() else {}
    valid, pending = {}, []
    for item in prepared:
        if fingerprint({"url": manifest["url"], "payload": item["payload"]}) != item["request_hash"]:
            raise ValueError("Prepared request changed: " + item["request_id"])
        previous = old.get(item["request_id"], {})
        raw_path = args.out / "responses" / (item["request_id"] + ".json")
        if (previous.get("status") == "success" and previous.get("request_hash") == item["request_hash"]
                and raw_path.exists() and previous.get("response_sha256") == digest(raw_path)):
            validate_answers(read(raw_path), item["payload"]["questions"])
            valid[item["request_id"]] = previous
        else:
            pending.append(item)
    # Retain earlier failures until the corresponding fresh completion replaces them.
    saved = {r["request_id"]: old[r["request_id"]] for r in prepared if r["request_id"] in old
             and old[r["request_id"]].get("request_hash") == r["request_hash"]}
    write_json(path, list(saved.values()))
    started = time.monotonic()
    invocation_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
    event_path = args.out / "usage-events" / (invocation_id + ".jsonl")
    event_path.parent.mkdir(parents=True, exist_ok=True)
    completed, attempts, failed, stop, interrupted = 0, 0, 0, False, False
    counts = Counter()
    iterator = iter(pending)
    executor = ThreadPoolExecutor(max_workers=args.workers)
    active = {}
    print("[JEV-SOURCE] {} requests; {} cached; {} pending; {} workers.".format(
        len(prepared), len(valid), len(pending), args.workers), flush=True)
    def submit():
        if stop:
            return
        item = next(iterator, None)
        if item is not None:
            future = executor.submit(api_request, item, manifest["url"], settings["api_key"], args.timeout, args.retries)
            active[future] = item
    for _ in range(args.workers):
        submit()
    try:
        while active:
            done, _ = wait(active, timeout=1, return_when=FIRST_COMPLETED)
            for future in done:
                item = active.pop(future)
                result, raw, events = future.result()
                attempts += len(events)
                completed += 1
                with event_path.open("a", encoding="utf-8") as stream:
                    for event in events:
                        stream.write(json.dumps(event, ensure_ascii=False) + "\n")
                if raw is not None:
                    raw_path = args.out / "responses" / (item["request_id"] + ".json")
                    write_json(raw_path, raw)
                    result["response_sha256"] = digest(raw_path)
                saved[item["request_id"]] = result
                write_json(path, list(saved.values()))
                counts.update(c["choice"] for c in result.get("candidates", []))
                failed += result["status"] != "success"
                if completed % 20 == 0 or result["status"] != "success" or completed == len(pending):
                    print("[JEV-SOURCE] {}/{} requests finished; new sources={}, no={}, unknown={}, failed={}; {:.1f}s".format(
                        completed + len(valid), len(prepared), counts["yes"], counts["no"], counts["unknown"], failed,
                        time.monotonic() - started), flush=True)
                if result.get("error") in {"HTTP 401", "HTTP 402", "HTTP 403", "HTTP 451"}:
                    stop = True
                submit()
    except KeyboardInterrupt:
        interrupted = True
        print("[JEV-SOURCE] Interrupted; saved responses can be resumed.", flush=True)
    finally:
        executor.shutdown(wait=True, cancel_futures=True)
        invocation = {"invocation_id": invocation_id, "finished_at": datetime.now(timezone.utc).isoformat(),
                      "status": "interrupted" if interrupted else ("finished_with_errors" if failed or stop else "completed"),
                      "elapsed_seconds": time.monotonic() - started, "requests_attempted": attempts,
                      "requests_completed": completed, "requests_reused": len(valid), "workers": args.workers}
        write_json(args.out / "invocations" / (invocation_id + ".json"), invocation)
        write_json(args.out / "last-invocation.json", invocation)
        summarize(args.out)
    return 130 if interrupted else int(bool(failed or stop))
