#!/usr/bin/env python3
"""Link completed Jev sink predictions to YASA callers, entrypoints and sources.

Runs offline against a snapshot of results.json, including an unfinished sink
scan. Re-running updates derived tables; model predictions are never edited.
"""

import argparse
import csv
import json
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

from yasa_callgraph_context import YasaCallGraph


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_csv(path, columns, rows):
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def compact_json(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def definition_key(row):
    return tuple(row[k] for k in ("file", "start_line", "start_column", "end_line", "end_column"))


class CallerGraph:
    def __init__(self, graph, repo, functions):
        self.view = YasaCallGraph(graph, repo)
        self.graph, self.functions = graph, functions
        self.by_definition, aliases = defaultdict(list), {}
        for node_id, node in graph["nodes"].items():
            loc = (node.get("funcDef") or {}).get("loc", {})
            key = self.location_key(loc)
            if key[0] is not None:
                self.by_definition[key].append(node_id)
        # Different runtime symbols for one physical definition remain one
        # function for this function-level reachability query.
        for ids in self.by_definition.values():
            representative = min(ids)
            aliases.update((node_id, representative) for node_id in ids)
        self.canonical = {node_id: aliases.get(node_id, node_id) for node_id in graph["nodes"]}
        self.aliases_merged = len(graph["nodes"]) - len(set(self.canonical.values()))
        self.incoming, self.by_callsite = defaultdict(list), defaultdict(list)
        for edge in graph["edges"].values():
            source, target = self.canonical[edge["sourceNodeId"]], self.canonical[edge["targetNodeId"]]
            self.incoming[target].append((source, edge["id"]))
            self.by_callsite[self.location_key((edge.get("callSite") or {}).get("loc", {}))].append(edge["id"])
        self.cache, self.node_views = {}, {}

    def location_key(self, loc):
        start, end = loc.get("start", {}), loc.get("end", {})
        return (self.view.relative_file(loc.get("sourcefile")), start.get("line"), start.get("column"),
                end.get("line"), end.get("column"))

    def match(self, owner_id):
        row = self.functions.get(owner_id)
        return sorted({self.canonical[i] for i in self.by_definition.get(definition_key(row), [])}) if row else []

    def callsite(self, location):
        key = tuple(location[k] for k in ("file", "start_line", "start_column_utf8", "end_line", "end_column_utf8_exclusive"))
        return self.by_callsite.get(key, [])

    def backward(self, roots):
        key = tuple(roots)
        if key not in self.cache:
            toward_sink = {node_id: None for node_id in roots}
            queue = deque(roots)
            while queue:
                target = queue.popleft()
                for source, edge_id in self.incoming[target]:
                    if source not in toward_sink:
                        toward_sink[source] = (target, edge_id)
                        queue.append(source)
            self.cache[key] = toward_sink
        return self.cache[key]

    def node(self, node_id):
        if node_id in self.node_views:
            return self.node_views[node_id]
        node = self.graph["nodes"][node_id]
        loc = (node.get("funcDef") or {}).get("loc", {})
        self.node_views[node_id] = {"node_id": node_id, "name": node.get("fullName") or node_id,
                "definition": loc, "repository_file": self.view.relative_file(loc.get("sourcefile"))}
        return self.node_views[node_id]

    def witness(self, start, toward_sink):
        node_ids, edges, current = [start], [], start
        while toward_sink[current] is not None:
            target, edge_id = toward_sink[current]
            edges.append(edge_id)
            node_ids.append(target)
            current = target
        return {"node_ids": node_ids, "edge_ids": edges,
                "unresolved_node_ids": [i for i in node_ids if not self.node(i)["repository_file"]],
                "call_count": len(edges)}


def load_predictions(entrypoint_run, source_run, functions, graph):
    plans = {row["case_id"]: row for row in read(entrypoint_run / "prepared.json")}
    entries = {}
    for row in read(entrypoint_run / "results.json"):
        if row["status"] != "success" or row["verdict"]["is_entrypoint"] is not True:
            continue
        case_id = row["case_id"]
        plan, answers = plans[case_id], {}
        response_dir = entrypoint_run / row["variant"] / "responses"
        for path in sorted(response_dir.glob(case_id + "-*.json")):
            answers.update(read(path)["answers"])
        function = functions[plan["function_id"]]
        entries[case_id] = {"case_id": case_id, "function": row["function"], "function_id": function["id"],
            "location": {k: function[k] for k in ("file", "start_line", "start_column", "end_line", "end_column")},
            "verdict": row["verdict"], "model_answers": answers,
            "graph_node_ids": graph.match(function["id"]), "source_ids": [], "unknown_source_ids": []}
    source_manifest = read(source_run / "manifest.json")
    source_cases = {row["case_id"]: row for row in source_manifest["cases"]}
    source_batches, failed_batches = Counter(), Counter()
    sources, unknown = {}, {}
    for batch in read(source_run / "results.json"):
        case_id = batch["case_id"]
        if batch["status"] != "success":
            failed_batches[case_id] += 1
            continue
        source_batches[case_id] += 1
        for candidate in batch["candidates"]:
            if candidate["choice"] == "no":
                continue
            source_id = case_id + ":" + candidate["candidate_id"]
            item = dict(candidate, source_id=source_id, entrypoint_case_id=case_id,
                        graph_node_ids=graph.match(candidate["owner_id"]))
            (sources if candidate["choice"] == "yes" else unknown)[source_id] = item
            if case_id in entries:
                field = "source_ids" if candidate["choice"] == "yes" else "unknown_source_ids"
                entries[case_id][field].append(source_id)
    for case_id, entry in entries.items():
        case = source_cases.get(case_id)
        entry["source_scan"] = {"prepared": case is not None,
            "expected_batches": case["requests"] if case else None,
            "successful_batches": source_batches[case_id], "failed_batches": failed_batches[case_id],
            "complete": case is not None and source_batches[case_id] == case["requests"]}
    return entries, sources, unknown


def entry_gaps(entry, sources):
    gaps = []
    if not entry["source_scan"]["complete"]:
        gaps.append("source_scan_incomplete")
    if not entry["source_ids"]:
        gaps.append("no_model_positive_source_for_entrypoint")
    if entry["unknown_source_ids"]:
        gaps.append("source_decisions_unknown")
    if any(not sources[i]["graph_node_ids"] for i in entry["source_ids"]):
        gaps.append("source_owner_not_in_callgraph")
    return gaps


def link(args):
    sink_manifest = read(args.sink_run / "manifest.json")
    # Read once: new sink predictions arriving after this read belong to the
    # next invocation. All output counts refer to this same input snapshot.
    snapshot = read(args.sink_run / "results.json")
    repo = args.repo or Path(sink_manifest["repository"])
    index = args.index or Path(sink_manifest["index_directory"])
    functions = {row["id"]: row for row in (json.loads(line) for line in (index / "functions.jsonl").read_text().splitlines())}
    graph_data = read(args.callgraph)
    graph = CallerGraph(graph_data, repo, functions)
    entries, sources, unknown_sources = load_predictions(args.entrypoint_run, args.source_run, functions, graph)
    entries_by_node, sources_by_node = defaultdict(set), defaultdict(set)
    for case_id, entry in entries.items():
        for node_id in entry["graph_node_ids"]:
            entries_by_node[node_id].add(case_id)
    for source_id, source in sources.items():
        for node_id in source["graph_node_ids"]:
            sources_by_node[node_id].add(source_id)

    links, table, pending, involved_entries = [], [], [], set()
    statuses, missing = Counter(), Counter()
    for row in snapshot:
        verdict, candidate = row.get("verdict", {}), row["candidate"]
        if row["status"] != "success" or verdict["is_sink"] is None:
            pending.append({"candidate_id": row["case_id"], "file": candidate["location"]["file"],
                "line": candidate["location"]["start_line"], "expression": candidate["expression"],
                "status": row["status"], "sink_answer": compact_json(verdict.get("sink_answer")), "error": row.get("error", "")})
            continue
        if verdict["is_sink"] is not True:
            continue
        confidence = verdict["sink_answer"].get("confidence")
        if args.sink_confidence_gt is not None and (confidence is None or confidence <= args.sink_confidence_gt):
            continue
        roots = graph.match(candidate["owner_id"])
        toward_sink = graph.backward(roots)
        callsite_edges = graph.callsite(candidate["location"])
        gaps = []
        if not verdict["dangerous_arguments"]:
            gaps.append("no_selected_sink_argument")
        if verdict["sink_kind"] == "unknown":
            gaps.append("sink_kind_unknown")
        if candidate["owner_id"] not in functions:
            gaps.append("sink_owner_is_module_or_class")
        if not roots:
            gaps.append("sink_owner_not_in_callgraph")
        if not callsite_edges:
            gaps.append("sink_callsite_edge_not_in_callgraph")
        found = defaultdict(list)
        upstream_sources = set()
        for node_id in toward_sink:
            for case_id in entries_by_node[node_id]:
                found[case_id].append(node_id)
            upstream_sources.update(sources_by_node[node_id])
        if not found:
            gaps.append("no_entrypoint_in_reverse_graph")
        matched = []
        for case_id in sorted(found):
            entry = entries[case_id]
            paths = [graph.witness(node_id, toward_sink) for node_id in found[case_id]]
            path = min(paths, key=lambda p: p["call_count"])
            issues = entry_gaps(entry, sources)
            if path["unresolved_node_ids"]:
                issues.append("witness_contains_unresolved_or_external_nodes")
            matched.append({"entrypoint_case_id": case_id, "source_ids": entry["source_ids"],
                            "unknown_source_ids": entry["unknown_source_ids"], "call_path": path, "missing_information": issues})
            involved_entries.add(case_id)
        status = ("owner_not_in_callgraph" if not roots else "no_entrypoint" if not matched else
                  "entrypoints_with_sources" if any(m["source_ids"] for m in matched) else "entrypoints_without_sources")
        item = {"sink_id": row["case_id"], "candidate": candidate, "verdict": verdict,
                "status": status, "owner_graph_node_ids": roots, "sink_callsite_edge_ids": callsite_edges,
                "reverse_graph_nodes": len(toward_sink), "upstream_source_ids": sorted(upstream_sources),
                "entrypoint_links": matched, "missing_information": gaps}
        links.append(item)
        statuses[status] += 1
        missing.update(set(gaps + [issue for m in matched for issue in m["missing_information"]]))
        for match in matched or [None]:
            entry = entries[match["entrypoint_case_id"]] if match else None
            source_rows = [sources[i] for i in match["source_ids"]] if match else []
            path = match["call_path"] if match else None
            table.append({"sink_id": row["case_id"], "sink_file": candidate["location"]["file"],
                "sink_line": candidate["location"]["start_line"], "sink_column_utf8": candidate["location"]["start_column_utf8"],
                "sink_expression": candidate["expression"], "sink_owner": candidate["owner"], "sink_kind": verdict["sink_kind"],
                "sink_confidence": verdict["sink_answer"].get("confidence"),
                "sink_probabilities": compact_json(verdict["sink_answer"]["probabilities"]),
                "sink_kind_answer": compact_json(verdict["sink_kind_answer"]),
                "selected_arguments": compact_json(verdict["dangerous_arguments"]),
                "all_argument_answers": compact_json(verdict["argument_answers"]), "association_status": status,
                "entrypoint_case_id": entry["case_id"] if entry else "", "entrypoint": entry["function"] if entry else "",
                "entrypoint_location": compact_json(entry["location"]) if entry else "",
                "entrypoint_confidence": entry["model_answers"].get("is_entrypoint", {}).get("confidence") if entry else None,
                "entrypoint_probabilities": compact_json(entry["verdict"]["entrypoint_probabilities"]) if entry else "",
                "source_count": len(source_rows), "sources": compact_json(source_rows),
                "unknown_source_ids": compact_json(match["unknown_source_ids"] if match else []),
                "upstream_source_count": len(upstream_sources),
                "call_chain": " -> ".join(graph.node(i)["name"] for i in path["node_ids"]) if path else "",
                "call_sites": compact_json([graph.graph["edges"][i].get("callSite") for i in path["edge_ids"]]) if path else "[]",
                "sink_callsite_edges_matched": len(callsite_edges),
                "unresolved_path_nodes": compact_json(path["unresolved_node_ids"]) if path else "[]",
                "missing_information": ";".join(gaps + (match["missing_information"] if match else []))})
        if len(links) % 200 == 0:
            print("[SINK-LINK] Linked {} positive sinks; {} table rows.".format(len(links), len(table)), flush=True)

    successful = [r for r in snapshot if r["status"] == "success"]
    summary = {"created_at": datetime.now(timezone.utc).isoformat(), "repository": str(Path(repo).resolve()),
        "inputs": {k: str(getattr(args, k).resolve()) for k in ("sink_run", "entrypoint_run", "source_run", "callgraph")},
        "sink_calls_selected": sink_manifest["selected_candidates"], "sink_results_in_snapshot": len(snapshot),
        "sink_scan_complete": len(successful) == sink_manifest["selected_candidates"],
        "calls_not_attempted_in_snapshot": sink_manifest["selected_candidates"] - len(snapshot),
        "failed_or_blocked_calls": sum(r["status"] != "success" for r in snapshot),
        "unknown_calls": sum(r["verdict"]["is_sink"] is None for r in successful),
        "non_sinks": sum(r["verdict"]["is_sink"] is False for r in successful),
        "positive_sinks_in_scan": sum(r["verdict"]["is_sink"] is True for r in successful),
        "sink_selection": {"field": "verdict.sink_answer.confidence", "operator": ">",
                           "threshold": args.sink_confidence_gt, "original_predictions_changed": False},
        "positive_sinks": len(links), "sink_owners_matched": sum(bool(i["owner_graph_node_ids"]) for i in links),
        "sink_callsites_matched": sum(bool(i["sink_callsite_edge_ids"]) for i in links),
        "sinks_with_selected_arguments": sum(bool(i["verdict"]["dangerous_arguments"]) for i in links),
        "sinks_with_entrypoints": sum(bool(i["entrypoint_links"]) for i in links),
        "sinks_with_entrypoints_and_sources": statuses["entrypoints_with_sources"],
        "sinks_without_entrypoints_but_with_upstream_sources": sum(not i["entrypoint_links"] and bool(i["upstream_source_ids"]) for i in links),
        "sinks_needing_more_information": sum(bool(i["missing_information"]) or any(m["missing_information"] for m in i["entrypoint_links"]) for i in links),
        "association_rows": len(table), "entrypoint_sink_pairs": sum(len(i["entrypoint_links"]) for i in links),
        "entrypoints_selected": len(entries), "entrypoints_matched": sum(bool(e["graph_node_ids"]) for e in entries.values()),
        "entrypoints_involved": len(involved_entries), "positive_source_decisions": len(sources),
        "unknown_source_decisions": len(unknown_sources), "association_status_counts": dict(statuses),
        "missing_information_counts_by_sink": dict(missing), "graph_nodes": len(graph_data["nodes"]),
        "graph_edges": len(graph_data["edges"]), "graph_alias_nodes_merged": graph.aliases_merged,
        "method": {"reverse_traversal": "all upstream nodes; no depth cap; continue beyond matched entrypoints",
            "witness": "one shortest call path per entrypoint and sink owner; alternate paths not enumerated",
            "definition_matching": "exact repository-relative file and full definition span; no name fallback",
            "sources": "all original positive sources for each matched entrypoint, including helper functions off the witness path",
            "external_nodes": "traversed; unresolved/external witness nodes explicitly flagged",
            "source_sink_flow_proven": False, "confidence_threshold_applied": args.sink_confidence_gt is not None,
            "confidence_threshold_target": "reverse-traversal seed selection only; original labels unchanged", "api_requests": 0}}
    summary["positive_sinks_excluded_by_confidence"] = summary["positive_sinks_in_scan"] - len(links)
    args.out.mkdir(parents=True, exist_ok=True)
    write_json(args.out / "sink-links.json", links)
    node_ids = {i for row in links for i in row["owner_graph_node_ids"]}
    node_ids.update(i for row in links for match in row["entrypoint_links"] for i in match["call_path"]["node_ids"])
    write_json(args.out / "graph-nodes.json", {i: graph.node(i) for i in sorted(node_ids)})
    write_json(args.out / "entrypoints.json", list(entries.values()))
    write_json(args.out / "sources.json", list(sources.values()))
    write_json(args.out / "unknown-sources.json", list(unknown_sources.values()))
    columns = list(table[0]) if table else ["sink_id", "association_status", "missing_information"]
    write_csv(args.out / "associations.csv", columns, table)
    write_csv(args.out / "pending-calls.csv", ["candidate_id", "file", "line", "expression", "status", "sink_answer", "error"], pending)
    write_json(args.out / "summary.json", summary)
    labels = [("Sink calls selected", "sink_calls_selected"), ("Saved results in snapshot", "sink_results_in_snapshot"),
        ("Calls not attempted", "calls_not_attempted_in_snapshot"), ("Unknown calls", "unknown_calls"),
        ("Failed or blocked calls", "failed_or_blocked_calls"), ("Potential sinks in scan", "positive_sinks_in_scan"),
        ("Sinks selected for reverse traversal", "positive_sinks"),
        ("Sinks excluded by confidence", "positive_sinks_excluded_by_confidence"),
        ("Sink owners matched to graph", "sink_owners_matched"), ("Sink call sites matched to graph", "sink_callsites_matched"),
        ("Sinks with selected arguments", "sinks_with_selected_arguments"), ("Sinks with candidate entrypoints", "sinks_with_entrypoints"),
        ("Sinks with entrypoints and sources", "sinks_with_entrypoints_and_sources"),
        ("Sinks needing more information", "sinks_needing_more_information"), ("Entrypoint/sink pairs", "entrypoint_sink_pairs"),
        ("Entrypoints selected", "entrypoints_selected"), ("Entrypoints matched to graph", "entrypoints_matched"),
        ("Entrypoints involved", "entrypoints_involved")]
    terminal = "\n".join("{:<39}: {:,}".format(label, summary[key]) for label, key in labels)
    selection = ("本次反查所有模型判为 yes 的 sink。\n\n" if args.sink_confidence_gt is None else
                 "本次仅从原始 sink confidence > {} 的模型阳性调用点开始反查；等于阈值的不纳入。P(yes) 不参与筛选。\n\n".format(args.sink_confidence_gt))
    notes = (selection + "当前结果是已保存 sink 判断的离线快照；重新执行同一命令会更新本目录的派生结果。\n\n"
        "associations.csv 每行是一组 sink/候选入口；没有入口的 sink 也保留一行。sources 列包含源码位置、表达式和原始置信度/概率。\n"
        "sink-links.json 保存逐 sink 的完整参数判断、调用位置匹配、候选入口和调用链。graph-nodes.json 保存链路节点的名称和位置；边 ID 引用输入调用图。\n"
        "entrypoints.json 保存所有入口、图匹配及原始分类回答。\n"
        "sources.json 保留 source 的原始关联入口，不把其他入口的 source 转移到当前入口。unknown-sources.json 和 pending-calls.csv 保留未决判断。\n\n"
        "调用链只到 sink 所在函数；sink_callsite_edge_ids 单独给出敏感调用位置的图边。每对入口/sink 给一条最短查看路径，反查没有深度截断。\n"
        "同一源码定义的多个图节点合并用于函数级可达性；边仍引用原始调用图的边和节点。缺少定义的节点也参与反查，路径经过它们时明确标记。\n"
        "已有 source 可能位于另一个辅助函数，因此不要求它位于这条最短路径。upstream_source_ids 只说明 source 所属函数位于反查范围。\n\n"
        "这是候选关联，不证明 source 到 sink 参数的数据传播，也不证明运行时可达或漏洞成立。无匹配不等于安全。\n"
        "入口用途/形成方式、sink 类型/参数、source 的原始置信度和概率均保留；不合成链路置信度，不按阈值改写标签。\n")
    (args.out / "SUMMARY.md").write_text("# Sink、入口和 source 的调用图关联\n\n```text\n" + terminal + "\n```\n\n" + notes, encoding="utf-8")
    print(terminal, flush=True)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sink-run", type=Path, required=True)
    parser.add_argument("--entrypoint-run", type=Path, required=True)
    parser.add_argument("--source-run", type=Path, required=True)
    parser.add_argument("--callgraph", type=Path, required=True)
    parser.add_argument("--repo", type=Path)
    parser.add_argument("--index", type=Path)
    parser.add_argument("--sink-confidence-gt", type=float,
                        help="Reverse only model-positive sinks with original confidence strictly greater than this value")
    parser.add_argument("--out", type=Path, required=True)
    link(parser.parse_args())


if __name__ == "__main__":
    main()
