#!/usr/bin/env python3
"""Prepare/run a formation-guided source pilot using saved Jev entrypoints."""

import argparse
import csv
import hashlib
import json
import os
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib import error, request

from context_graph import ContextGraph, fingerprint
from jev_config import DEFAULT_ENV_FILE, api_headers, api_url, read_settings
from laya_smoke import token_audit, validate_answers, write_json
from source_context import SourceContext, render_context, start_line

HERE = Path(__file__).resolve().parent


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def select_examples(rows, plans, limit):
    """Cover predicted formations, then triggers; ties use short saved inputs."""
    selected, formations, kinds = [], set(), set()
    remaining = list(rows)
    while remaining and len(selected) < limit:
        row = min(remaining, key=lambda r: (
            -len(set(r["verdict"]["formation_types"]) - formations),
            -(r["verdict"]["entrypoint_kind"] not in kinds),
            len(plans[r["case_id"]]["payload"]["state"]), r["function"]))
        selected.append(row)
        formations.update(row["verdict"]["formation_types"])
        kinds.add(row["verdict"]["entrypoint_kind"])
        remaining.remove(row)
    return selected


def payload_for(context, blocks, candidates, batch, prompt, kind, args):
    return {"model": args.model, "max_len": args.max_len, "head_max_len": 256,
            "state": render_context(context, blocks, candidates, prompt["definition"], kind),
            "questions": {c["candidate_id"]: {"type": "choice", "instructions":
                "Is {} `{}` at {}:{} a NEW externally controlled input origin? Judge this {} itself, not its arguments or the whole function.".format(
                    c["candidate_id"], " ".join(c["expression"].split())[:100],
                    c["location"]["file"], c["location"]["start_line"], c["syntax_kind"]),
                "criteria": prompt["criteria"]} for c in batch}}


def prepare(args):
    if args.out.exists():
        raise ValueError("Choose a fresh --out directory for preparation")
    manifest = read(args.jev_run / "manifest.json")
    plans = {p["case_id"]: p for p in read(args.jev_run / "prepared.json")}
    rows = read(args.jev_run / "results.json")
    positives = [r for r in rows if r["status"] == "success" and r["verdict"]["is_entrypoint"] is True]
    for row in positives:
        if row["request_hash"] != plans[row["case_id"]]["request_hash"]:
            raise ValueError("Jev prediction does not match its prepared request")
    if args.function:
        selected = [r for r in positives if r["function"] in args.function]
        if set(args.function) != {r["function"] for r in selected}:
            raise ValueError("Requested function is not a successful Jev-positive entrypoint")
    else:
        selected = select_examples(positives, plans, args.limit)
    if not selected:
        raise ValueError("No Jev entrypoints selected")
    graph = ContextGraph(Path(manifest["index_directory"]), Path(manifest["repository"]))
    if graph.index_hashes != manifest["index_hashes"] or graph.summary.get("commit") != manifest["repository_commit"]:
        raise ValueError("Jev run and current UAST index do not match")
    builder = SourceContext(graph, args.max_helpers, args.max_helper_lines, args.max_candidates)
    prompt = read(HERE / "prompts/source_laya_v1.json")
    prepared, failures, cases = [], [], []
    for row in selected:
        plan, verdict = plans[row["case_id"]], row["verdict"]
        try:
            target = dict(graph.nodes[plan["function_id"]], definition_identity=plan["definition_identity"],
                          definition_alias_ids=plan["definition_alias_ids"])
            context = builder.build(target, verdict["formation_types"])
            blocks = list(context["blocks"])
            omitted_token_blocks = []
            while True:
                # A helper candidate is usable only while its full function is
                # present. Never judge a helper from a detached code fragment.
                covered = {(b["file"], n) for b in blocks for n in range(b["start_line"], b["end_line"] + 1)}
                owners = {target["id"]}
                for hid in context["helper_ids"]:
                    helper = graph.nodes[hid]
                    node = builder.compact.definition(helper)
                    if all((helper["file"], n) in covered for n in range(start_line(node), node.end_lineno + 1)):
                        owners.add(hid)
                candidates = [c for c in context["candidates"] if c["owner_id"] in owners]
                batches = [candidates[n:n + args.batch_size] for n in range(0, len(candidates), args.batch_size)]
                try:
                    requests = []
                    for batch in batches:
                        payload = payload_for(context, blocks, candidates, batch, prompt, verdict["entrypoint_kind"], args)
                        audit = token_audit(payload, args.tokenizer)
                        requests.append((payload, audit, batch))
                    break
                except ValueError as exc:
                    if not str(exc).startswith("Input would be truncated or options collapsed:"):
                        raise
                    optional = [i for i, b in enumerate(blocks) if b["role"] != "target"]
                    if not optional:
                        raise ValueError("Complete target and candidate catalog exceed model token budget") from exc
                    omitted_token_blocks.append(blocks.pop(optional[-1]))
            context.update(selected_blocks=blocks, omitted_token_blocks=omitted_token_blocks,
                           selected_candidates=candidates,
                           token_budget_omitted_candidates=[c for c in context["candidates"] if c["owner_id"] not in owners])
            write_json(args.out / "contexts" / (row["case_id"] + ".json"), context)
            max_tokens = 0
            for number, (payload, audit, batch) in enumerate(requests):
                rid = row["case_id"] + "_batch_" + str(number)
                item = {"request_id": rid, "case_id": row["case_id"], "function": row["function"],
                        "jev_verdict": verdict, "candidates": batch, "payload": payload,
                        "request_hash": fingerprint({"url": args.url, "payload": payload}), "token_audit": audit}
                prepared.append(item)
                max_tokens = max(max_tokens, max(a["sequence_tokens"] for a in audit.values()))
                write_json(args.out / "requests" / (rid + ".json"), payload)
            case = {"case_id": row["case_id"], "function": row["function"], "jev_verdict": verdict,
                    "candidates": len(candidates), "omitted_candidates": len(context["omitted_candidates"])
                        + len(context["token_budget_omitted_candidates"]),
                    "omitted_support": len(context["omitted_support"]),
                    "token_budget_omitted_blocks": len(omitted_token_blocks), "max_sequence_tokens": max_tokens,
                    "baseline_coverage": context["baseline_coverage"], "unresolved_links": len(context["unresolved"])}
            cases.append(case)
            print(json.dumps(case, ensure_ascii=False), flush=True)
        except (ValueError, KeyError, SyntaxError, OSError) as exc:
            failures.append({"case_id": row["case_id"], "function": row["function"], "error": str(exc)})
            print("[LAYA-SOURCE] Preparation error: {}: {}".format(row["function"], exc), flush=True)
    write_json(args.out / "prepared.json", prepared)
    write_json(args.out / "preparation-errors.json", failures)
    write_json(args.out / "prompt.json", prompt)
    write_json(args.out / "jev-predictions.snapshot.json", selected)
    write_json(args.out / "manifest.json", {
        "mode": "formation_guided_source_pilot_v1", "created_at": datetime.now(timezone.utc).isoformat(),
        "jev_run": str(args.jev_run.resolve()), "jev_results_sha256": digest(args.jev_run / "results.json"),
        "repository": str(graph.repo), "repository_commit": graph.summary.get("commit"),
        "index_directory": str(graph.index_dir), "index_hashes": graph.index_hashes,
        "url": args.url, "model": args.model, "tokenizer": str(args.tokenizer.resolve()),
        "implementation_hashes": {n: digest(HERE / n) for n in
            ("laya_sources.py", "source_context.py", "compact_context.py", "binding_context.py", "laya_smoke.py")},
        "selection": "explicit function names" if args.function else "predicted label/trigger coverage, then shortest saved input",
        "selected_entrypoints": len(selected), "prepared_entrypoints": len(cases), "cases": cases,
        "max_helpers": args.max_helpers, "max_helper_lines": args.max_helper_lines,
        "max_candidates": args.max_candidates, "helper_depth": 1, "batch_size": args.batch_size,
        "max_len": args.max_len,
        "source_policy": "external_controlled_boundary_origin", "ground_truth_used": False,
        "source_report_used": False, "target_body_complete": True,
        "limitations": ["Python only; static UAST references do not prove runtime dispatch.",
                        "Only parameters, call returns, attribute and subscript reads are candidate syntax.",
                        "Module execution, nested function bodies, dynamic links and omitted candidates are unassessed.",
                        "Configuration/database/network reads require external-control evidence; this differs from broad YASA source rules.",
                        "Model probabilities and entropy confidence have not been calibrated on this source task."]})
    summarize(args.out)
    return int(bool(failures))


def summarize(out):
    manifest, prepared = read(out / "manifest.json"), read(out / "prepared.json")
    provider = "Jev" if manifest.get("provider") == "jev" else "Laya"
    rows = read(out / "results.json") if (out / "results.json").exists() else []
    expected = {p["request_id"]: p for p in prepared}
    rows = [r for r in rows if r["request_id"] in expected
            and r["request_hash"] == expected[r["request_id"]]["request_hash"]]
    candidates = [dict(c, entrypoint=r["function"], case_id=r["case_id"])
                  for r in rows if r["status"] == "success" for c in r["candidates"]]
    counts = Counter(c["choice"] for c in candidates)
    successful = [r for r in rows if r["status"] == "success"]
    usage_missing = sum(not isinstance(r.get("usage"), dict)
                        or any(type(r["usage"].get(k)) is not int for k in ("input_tokens", "output_tokens"))
                        for r in successful)
    input_tokens = sum(r.get("usage", {}).get("input_tokens", 0) or 0 for r in successful if isinstance(r.get("usage"), dict))
    output_tokens = sum(r.get("usage", {}).get("output_tokens", 0) or 0 for r in successful if isinstance(r.get("usage"), dict))
    summary = {"entrypoints_selected": manifest["selected_entrypoints"],
               "entrypoints_prepared": manifest["prepared_entrypoints"],
               "preparation_errors": len(read(out / "preparation-errors.json")),
               "requests_prepared": len(prepared), "requests_successful": sum(r["status"] == "success" for r in rows),
               "requests_failed": sum(r["status"] != "success" for r in rows),
               "requests_not_attempted": len(prepared) - len(rows),
               "candidate_entrypoint_pairs": sum(len(p["candidates"]) for p in prepared),
               "candidates_completed": len(candidates), "possible_sources": counts["yes"],
               "non_sources": counts["no"], "unknown": counts["unknown"],
               "unique_source_positions": len({c["candidate_id"] for c in candidates if c["choice"] == "yes"}),
               "omitted_candidates": sum(c["omitted_candidates"] for c in manifest["cases"]),
               "saved_input_tokens": input_tokens, "saved_output_tokens": output_tokens,
               "saved_total_tokens": input_tokens + output_tokens,
               "responses_missing_usage": usage_missing}
    expected_by_case = Counter(p["case_id"] for p in prepared)
    success_by_case = Counter(r["case_id"] for r in successful)
    failures_by_case = Counter(r["case_id"] for r in rows if r["status"] != "success")
    case_status = []
    for case in manifest["cases"]:
        cid = case.get("case_id")
        if cid is None:
            continue
        completed = success_by_case[cid] == expected_by_case[cid]
        case_status.append({"case_id": cid, "function": case["function"], "requests_expected": expected_by_case[cid],
                            "requests_successful": success_by_case[cid], "requests_failed": failures_by_case[cid],
                            "completed": completed, "candidates": case.get("candidates", 0),
                            "no_candidates": expected_by_case[cid] == 0})
    summary.update(entrypoints_completed=sum(c["completed"] for c in case_status),
                   entrypoints_with_failed_requests=sum(c["requests_failed"] > 0 for c in case_status),
                   entrypoints_with_no_candidates=sum(c["no_candidates"] for c in case_status))
    unique = {}
    for c in candidates:
        group = unique.setdefault(c["candidate_id"], {k: c.get(k) for k in
            ("candidate_id", "owner", "syntax_kind", "expression", "location")})
        group.setdefault("entrypoint_decisions", []).append({k: c.get(k) for k in
            ("entrypoint", "case_id", "choice", "source_probability", "model_confidence")})
    for group in unique.values():
        group["choice_counts"] = dict(Counter(c["choice"] for c in group["entrypoint_decisions"]))
        group["conflicting_entrypoint_decisions"] = len(group["choice_counts"]) > 1
    write_json(out / "entrypoint-status.json", case_status)
    write_json(out / "unique-sources.json", [g for g in unique.values() if g["choice_counts"].get("yes", 0)])
    write_json(out / "summary.json", summary)
    write_json(out / "candidate-results.json", candidates)
    write_json(out / "possible-sources.json", [c for c in candidates if c["choice"] == "yes"])
    with (out / "candidate-results.csv").open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=("entrypoint", "owner", "file", "line", "column", "syntax_kind",
                                "expression", "choice", "source_probability", "model_confidence", "x_jev_confidence"))
        writer.writeheader()
        for c in candidates:
            loc = c["location"]
            writer.writerow({"entrypoint": c["entrypoint"], "owner": c.get("owner"), "file": loc["file"],
                "line": loc["start_line"], "column": loc["start_column_utf8"], "syntax_kind": c.get("syntax_kind"),
                **{k: c.get(k) for k in ("expression", "choice", "source_probability", "model_confidence", "x_jev_confidence")}})
    repository_scan = manifest.get("source_scan_mode") == "repository_entrypoints"
    lines = ["# {} source {}".format(provider, "全入口扫描" if repository_scan else "小规模试验"), "", "按 Jev 预测的形成方式取证；多标签合并、按源码位置去重。没有读取 ground truth 或漏洞报告。",
             "source 定义为外部可控输入进入应用的起点；普通传播、配置/数据库读取不自动算 source。", "",
             "`source_probability` 是 yes 的模型概率；`model_confidence` 保留服务返回的 confidence。两者不等同，均非已验证正确率。",
             "代码位置由 Python AST 枚举，yes/no/unknown 和概率由 {} 返回。没有替模型改标签。".format(provider), "", "```text"]
    lines += ["{:<34}: {}".format(k, v) for k, v in summary.items()]
    lines += ["```", "", "目标函数完整保留；只扩展一层本地函数。截断前移除可选证据，记录未判断候选；完整目标仍过长则明确报错。",
              ("沿用冻结的上下文和问题，仅切换服务；Laya 分词数不能当作 Jev 的分词数，实际用量见原始回复。"
               if provider == "Jev" else "每次实际输入均用本地 Laya tokenizer 检查。"),
              "外部依赖、动态调用、嵌套函数和遗漏位置不代表没有 source。", "",
              "| 入口 | 位置 | 表达式 | P(yes) | 模型 confidence |", "|---|---|---|---:|---:|"]
    if repository_scan:
        lines[1:1] = ["", "扫描范围来自此前入口扫描：{}，覆盖 {} 个预测入口。源代码文件统计为该范围的总量，"
                      "并非每个文件都存在入口。辅助扩展仍有预算；候选不设数量上限，按批次发送。".format(
                          manifest.get("selection", {}).get("area"), manifest["selected_entrypoints"]),
                      "本轮字符预算用于控制辅助证据，不能当作 Jev token 长度或服务端未截断证明。",
                      "possible_sources 是入口与候选的配对数；unique_source_positions 才是按源码位置去重后的数量。",
                      "unique-sources.json 保留同一位置在不同入口下的全部判断与分歧，不做投票改标签。"]
    for c in candidates:
        if c["choice"] != "yes":
            continue
        loc = c["location"]
        expr = c["expression"].replace("|", "\\|").replace("\n", " ")
        lines.append("| {} | {}:{}:{} | `{}` | {:.4f} | {} |".format(c["entrypoint"], loc["file"],
                     loc["start_line"], loc["start_column_utf8"], expr, c["source_probability"], c["model_confidence"]))
    (out / "RESULTS.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join("{:<34}: {}".format(k, v) for k, v in summary.items()), flush=True)
    return summary


def run(args):
    manifest, prepared = read(args.out / "manifest.json"), read(args.out / "prepared.json")
    if manifest["mode"] != "formation_guided_source_pilot_v1":
        raise ValueError("Not a source pilot")
    headers = {"Content-Type": "application/json"}
    provider = manifest.get("provider", "laya")
    api_key = ""
    if provider == "jev":
        settings = read_settings(getattr(args, "env_file", DEFAULT_ENV_FILE), require_key=True)
        if settings["base_url"] != manifest["url"] or settings["model"] != manifest["model"]:
            raise ValueError("Jev model/API root changed; prepare a fresh experiment")
        api_key = settings["api_key"]
    elif os.getenv("LAYA_API_KEY"):
        api_key = os.environ["LAYA_API_KEY"]
    if api_key:
        headers["Authorization"] = "Bearer " + api_key
    if provider == "jev":
        headers = api_headers(api_key)
    opener = request.build_opener() if provider == "jev" else request.build_opener(request.ProxyHandler({}))
    prefix = "[JEV-SOURCE]" if provider == "jev" else "[LAYA-SOURCE]"
    url = manifest["url"].rstrip("/")
    inference_url = api_url(url) if provider == "jev" else url + "/v1/systemone"
    if provider != "jev":
        with opener.open(request.Request(url + "/health", headers=headers), timeout=10) as response:
            write_json(args.out / "service-health.json", json.load(response))
    existing = read(args.out / "results.json") if (args.out / "results.json").exists() else []
    previous = {r["request_id"]: r for r in existing}
    results, attempts, reused = [], 0, 0
    started = time.monotonic()
    interrupted = False
    try:
        for item in prepared:
            if fingerprint({"url": manifest["url"], "payload": item["payload"]}) != item["request_hash"]:
                raise ValueError("Prepared payload changed: " + item["request_id"])
            raw_path = args.out / "responses" / (item["request_id"] + ".json")
            old = previous.get(item["request_id"], {})
            if old.get("status") == "success" and old.get("request_hash") == item["request_hash"] and raw_path.exists():
                if old.get("response_sha256") == digest(raw_path):
                    validate_answers(read(raw_path), item["payload"]["questions"])
                    results.append(old)
                    reused += 1
                    continue
            result = {k: item[k] for k in ("request_id", "case_id", "function", "request_hash")}
            tick = time.monotonic()
            attempts += 1
            try:
                # Audit again at execution: max_len alone does not prove no truncation.
                if provider != "jev":
                    token_audit(item["payload"], Path(manifest["tokenizer"]))
                wire = json.dumps(item["payload"], ensure_ascii=False).encode("utf-8")
                result["wire_sha256"] = hashlib.sha256(wire).hexdigest()
                req = request.Request(inference_url, data=wire, headers=headers, method="POST")
                with opener.open(req, timeout=args.timeout) as response:
                    raw = json.load(response)
                write_json(raw_path, raw)
                answers = validate_answers(raw, item["payload"]["questions"])
                result.update(status="success", response_sha256=digest(raw_path), usage=raw.get("usage"),
                    model=raw.get("model"), candidates=[dict(c, **{
                        "choice": answers[c["candidate_id"]]["choice"],
                        "probabilities": answers[c["candidate_id"]]["probabilities"],
                        "source_probability": answers[c["candidate_id"]]["probabilities"]["yes"],
                        "model_confidence": answers[c["candidate_id"]].get("confidence"),
                        "x_jev_confidence": answers[c["candidate_id"]].get("x_jev_confidence")}) for c in item["candidates"]])
            except error.HTTPError as exc:
                body = exc.read(4096).decode("utf-8", "replace")
                if api_key:
                    body = body.replace(api_key, "[REDACTED]")
                result.update(status="error", error="HTTP " + str(exc.code),
                              response_body=body)
            except (OSError, ValueError, KeyError, TypeError) as exc:
                result.update(status="error", error=str(exc))
            result["elapsed_seconds"] = round(time.monotonic() - tick, 3)
            results.append(result)
            # Keep existing later checkpoints even if a resume is interrupted.
            saved = dict(previous)
            saved.update({r["request_id"]: r for r in results})
            write_json(args.out / "results.json", list(saved.values()))
            print("{} {}/{} {} {} {}".format(prefix, len(results), len(prepared), result["status"],
                  item["function"], dict(Counter(c["choice"] for c in result.get("candidates", [])))), flush=True)
            if result.get("error") in {"HTTP 401", "HTTP 402", "HTTP 403", "HTTP 451"}:
                print(prefix + " Stopped on a service-wide access restriction.", flush=True)
                break
    except KeyboardInterrupt:
        interrupted = True
        print(prefix + " Interrupted; saved checkpoints can be resumed.", flush=True)
    finally:
        write_json(args.out / "last-invocation.json", {"finished_at": datetime.now(timezone.utc).isoformat(),
                   "status": "interrupted" if interrupted else "finished",
                   "elapsed_seconds": time.monotonic() - started, "requests_attempted": attempts, "requests_reused": reused})
        summarize(args.out)
    if interrupted:
        return 130
    return int(any(r["status"] != "success" for r in results))


def positive(text):
    number = int(text)
    if number < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "run", "summarize"))
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--jev-run", type=Path, default=HERE / "runs/jev-ctfd-application-bindings-v3")
    parser.add_argument("--function", action="append", default=[])
    parser.add_argument("--limit", type=positive, default=8)
    parser.add_argument("--model", default="multilingual")
    parser.add_argument("--url", default="http://127.0.0.1:8001")
    parser.add_argument("--tokenizer", type=Path, default=Path("/data/models/laya-multilingual/tokenizer"))
    parser.add_argument("--max-helpers", type=positive, default=6)
    parser.add_argument("--max-helper-lines", type=positive, default=100)
    parser.add_argument("--max-candidates", type=positive, default=64)
    parser.add_argument("--max-len", type=positive, default=4096)
    parser.add_argument("--batch-size", type=positive, default=4)
    parser.add_argument("--timeout", type=positive, default=180)
    args = parser.parse_args()
    if not 512 <= args.max_len <= 8192:
        parser.error("--max-len must be between 512 and 8192")
    if args.command == "prepare":
        return prepare(args)
    if args.command == "summarize":
        summarize(args.out)
        return 0
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
