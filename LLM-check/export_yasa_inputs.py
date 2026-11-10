#!/usr/bin/env python3
"""Export frozen Jev predictions for YASA; no API calls or reference labels."""

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from context_graph import ContextGraph


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def indexed(rows, key):
    result = {row[key]: row for row in rows}
    if len(result) != len(rows):
        raise ValueError("Duplicate " + key)
    return result


def export_inputs(jev_run, source_run, sink_run, repo=None, execute_decorators=False, sink_links=None):
    jev_run, source_run = Path(jev_run).resolve(), Path(source_run).resolve()
    sink_run = Path(sink_run).resolve()
    ep_manifest, src_manifest = read(jev_run / "manifest.json"), read(source_run / "manifest.json")
    sink_manifest = read(sink_run / "manifest.json")
    graph = ContextGraph(ep_manifest["index_directory"], repo or ep_manifest["repository"])
    for manifest in (ep_manifest, src_manifest, sink_manifest):
        if manifest["index_hashes"] != graph.index_hashes:
            raise ValueError("UAST index differs from experiment inputs")
    if src_manifest["jev_predictions_sha256"] != sha256(jev_run / "results.json"):
        raise ValueError("Source scan used different entrypoint predictions")
    plans = indexed(read(jev_run / "prepared.json"), "case_id")
    predictions = indexed(read(jev_run / "results.json"), "case_id")
    entries, by_case = [], {}
    for case_id, row in predictions.items():
        if row.get("status") != "success" or row["verdict"]["is_entrypoint"] is not True:
            continue
        plan = plans[case_id]
        if row["request_hash"] != plan["request_hash"]:
            raise ValueError("Entrypoint request mismatch: " + case_id)
        function = graph.nodes[plan["function_id"]]
        if (function["qualified_name"] != row["function"] or
                plan["location"]["file"] != function["file"] or
                plan["location"]["start_line"] != function["start_line"] or
                plan["location"]["end_line"] != function["end_line"]):
            raise ValueError("Entrypoint definition mismatch: " + case_id)
        entry = {"case_id": case_id, "function_id": function["id"], "function": function["qualified_name"],
                 "name": function["name"], "location": {k: function[k] for k in
                     ("file", "start_line", "start_column", "end_line", "end_column")},
                 "skip_decorators": not execute_decorators, "verdict": row["verdict"]}
        entries.append(entry)
        by_case[case_id] = entry
    if not entries:
        raise ValueError("No successful model-positive entrypoints")
    # A full source run is required: absent/error batches must not mean 'no source'.
    cases = indexed(src_manifest["cases"], "case_id")
    if set(cases) != set(by_case):
        raise ValueError("Source run must cover exactly the selected model entrypoints")
    batches = indexed(read(source_run / "prepared.json"), "request_id")
    answers = indexed(read(source_run / "results.json"), "request_id")
    if set(batches) != set(answers):
        raise ValueError("Source run has unattempted or unexpected batches")
    sources, seen = [], set()
    for request_id, batch in batches.items():
        answer = answers[request_id]
        if answer.get("status") != "success" or answer["request_hash"] != batch["request_hash"]:
            raise ValueError("Source batch incomplete/stale: " + request_id)
        expected = indexed(batch["candidates"], "candidate_id")
        actual = indexed(answer["candidates"], "candidate_id")
        if set(expected) != set(actual):
            raise ValueError("Source candidate inventory mismatch: " + request_id)
        for candidate_id, candidate in actual.items():
            original = expected[candidate_id]
            if any(candidate[k] != original[k] for k in
                   ("owner_id", "owner", "syntax_kind", "expression", "location")):
                raise ValueError("Source position changed: " + candidate_id)
            if candidate["choice"] != "yes":
                continue
            case_id = batch["case_id"]
            if case_id not in by_case:
                raise ValueError("Source belongs to an unselected entrypoint")
            owner = graph.nodes[candidate["owner_id"]]
            if candidate["location"]["file"] != owner["file"]:
                raise ValueError("Source owner file mismatch")
            key = (case_id, candidate_id)
            if key in seen:
                raise ValueError("Duplicate source decision: " + str(key))
            seen.add(key)
            sources.append(dict(candidate, case_id=case_id, owner_location={k: owner[k] for k in
                                ("file", "start_line", "start_column", "end_line", "end_column")}))
    sink_results = read(sink_run / "results.json")
    sinks = [dict(row["candidate"], verdict=row["verdict"]) for row in sink_results
             if row.get("status") == "success" and row.get("verdict", {}).get("is_sink") is True]
    if sink_links:
        links = read(Path(sink_links) / "sink-links.json")
        sink_ids = {row["sink_id"] for row in links}
        entry_ids = {entry["entrypoint_case_id"] for row in links for entry in row["entrypoint_links"]}
        entries = [entry for entry in entries if entry["case_id"] in entry_ids]
        sources = [source for source in sources if source["case_id"] in entry_ids]
        sinks = [sink for sink in sinks if sink["candidate_id"] in sink_ids]
    # Verify every parsed file, not just files holding positive locations. This
    # prevents silently mixing new helper implementations with an old experiment.
    files = [{"file": row["file"], "sha256": row["sha256"]} for row in graph.tables["files"]]
    return {"schema": "yasa-llm-input/v2", "language": "python", "mode": "replace",
            "created_at": datetime.now(timezone.utc).isoformat(), "repository": str(graph.repo),
            "files": files, "entrypoints": entries, "sources": sources, "sinks": sinks,
            "provenance": {"entrypoint_run": str(jev_run), "source_run": str(source_run),
                           "entrypoint_results_sha256": sha256(jev_run / "results.json"),
                           "source_results_sha256": sha256(source_run / "results.json"),
                           "sink_run": str(sink_run), "sink_results_sha256": sha256(sink_run / "results.json"),
                           "sink_links": str(Path(sink_links).resolve()) if sink_links else None,
                           "index_hashes": graph.index_hashes,
                           "selection": "original successful yes; optional existing sink reverse links restrict scope; no relabeling",
                           "sink_detection": "imported exact call positions and original dangerous arguments only; native sink rules disabled"}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jev-run", type=Path, required=True)
    parser.add_argument("--source-run", type=Path, required=True)
    parser.add_argument("--sink-run", type=Path, required=True)
    parser.add_argument("--sink-links", type=Path, help="Existing reverse-link directory; select its sinks and associated entrypoints")
    parser.add_argument("--repo", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--execute-decorators", action="store_true",
                        help="Execute entrypoint decorators instead of the default original body")
    args = parser.parse_args()
    if args.out.exists():
        parser.error("Choose a fresh --out file")
    try:
        result = export_inputs(args.jev_run, args.source_run, args.sink_run, args.repo, args.execute_decorators, args.sink_links)
    except (OSError, ValueError, KeyError) as exc:
        parser.exit(1, "ERROR: " + str(exc) + "\n")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"out": str(args.out.resolve()), "entrypoints": len(result["entrypoints"]),
                      "source_decisions": len(result["sources"]), "sink_decisions": len(result["sinks"]),
                      "sinks_without_selected_arguments": sum(not s["verdict"]["dangerous_arguments"] for s in result["sinks"]),
                      "files_verified": len(result["files"])},
                     ensure_ascii=False))


if __name__ == "__main__":
    main()
