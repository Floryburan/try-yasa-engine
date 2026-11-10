#!/usr/bin/env python3
"""Extract explicitly marked YASA SARIF sources, without running the engine.

Never treats a path's first step as a source merely because it is first.
Report entrypoint descriptors are preserved, not treated as exact function IDs.
"""

import argparse
import ast
import csv
import hashlib
import json
import re
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urlsplit

HERE = Path(__file__).resolve().parent
SOURCE_LINE = re.compile(r"^\s*(?:\d+(?:-\d+)?\s*:\s*)?SOURCE:\s*", re.MULTILINE)


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def explicit_source(step):
    """Require a structured source role, or YASA's formatted SOURCE trace tag."""
    loc = step.get("location") or {}
    kinds = step.get("kinds") or []
    if "source" in kinds:
        return "structured_kind"
    for record in (step, loc):
        if str((record.get("properties") or {}).get("tag", "")).strip() == "SOURCE:":
            return "structured_tag"
    snippet = (((loc.get("physicalLocation") or {}).get("region") or {}).get("snippet") or {}).get("text", "")
    if SOURCE_LINE.search(snippet):
        return "yasa_source_trace_tag"
    return None


def report_location(location, run):
    physical = (location or {}).get("physicalLocation") or {}
    artifact = physical.get("artifactLocation") or {}
    if not artifact.get("uri") and isinstance(artifact.get("index"), int):
        artifacts = run.get("artifacts") or []
        index = artifact["index"]
        if 0 <= index < len(artifacts):
            artifact = dict(artifacts[index].get("location") or {}, **artifact)
    region = physical.get("region") or {}
    snippet = region.get("snippet") or {}
    return {"reported_uri": artifact.get("uri", ""),
            "start_line": region.get("startLine"), "start_column": region.get("startColumn"),
            "end_line": region.get("endLine"), "end_column": region.get("endColumn"),
            "expression": snippet.get("affectedNodeName") or "", "report_snippet": snippet.get("text", ""),
            "node_hash": physical.get("nodeHash")}


class SourceReader:
    def __init__(self, repo):
        self.repo = repo.resolve()
        self.cache = {}

    def resolve_file(self, uri):
        parsed = urlsplit(uri)
        if parsed.scheme and parsed.scheme != "file":
            return None
        if parsed.scheme == "file" and parsed.netloc not in {"", "localhost"}:
            return None
        path = Path(unquote(parsed.path))
        candidates = [path] if path.is_absolute() else [self.repo / path]
        # YASA sourceFileURI can encode repo-relative '/CTFd/...' as file:///CTFd/...
        if path.is_absolute():
            candidates.append(self.repo / str(path).lstrip("/"))
        for candidate in candidates:
            resolved = candidate.resolve()
            try:
                relative = resolved.relative_to(self.repo)
            except ValueError:
                continue
            if resolved.is_file():
                return relative.as_posix()
        return None

    def syntax(self, file):
        if file not in self.cache:
            path = self.repo / file
            raw = path.read_bytes()
            text = raw.decode("utf-8-sig")
            tree = ast.parse(text, filename=file)
            parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
            self.cache[file] = raw, text.splitlines(keepends=True), tree, parents
        return self.cache[file]

    def enrich(self, loc):
        file = self.resolve_file(loc["reported_uri"])
        result = {"file": file, "source_file_sha256": None, "source_text": None,
                  "source_expression_text": None, "enclosing_function": None, "enclosing_function_start_line": None,
                  "syntax_kind": "unresolved", "source_resolution": "unresolved_file"}
        if file is None:
            return result
        raw, lines, tree, parents = self.syntax(file)
        result["source_file_sha256"] = hashlib.sha256(raw).hexdigest()
        first, last = loc["start_line"], loc["end_line"] or loc["start_line"]
        if not isinstance(first, int) or not isinstance(last, int) or first < 1 or last < first or last > len(lines):
            result["source_resolution"] = "invalid_source_range"
            return result
        result["source_resolution"] = "located_in_current_source"
        result["source_text"] = "".join(lines[first - 1:last])
        a, b = loc["start_column"], loc["end_column"]
        if isinstance(a, int) and isinstance(b, int) and a > 0 and b > 0:
            fragment = [line.encode("utf-8") for line in lines[first - 1:last]]
            fragment[-1] = fragment[-1][:b - 1]
            fragment[0] = fragment[0][a - 1:]
            result["source_expression_text"] = b"".join(fragment).decode("utf-8")
        owners = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                  and n.lineno <= first and last <= n.end_lineno]
        if owners:
            owner = min(owners, key=lambda n: (n.end_lineno - n.lineno, -n.col_offset))
            names = [owner.name]
            parent = parents.get(owner)
            while parent:
                if isinstance(parent, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                    names.append(parent.name)
                parent = parents.get(parent)
            module = list(Path(file).with_suffix("").parts)
            if module[-1] == "__init__":
                module.pop()
            result["enclosing_function"] = ".".join(module + list(reversed(names)))
            result["enclosing_function_start_line"] = owner.lineno
        if isinstance(a, int) and isinstance(b, int):
            matches = [n for n in ast.walk(tree) if getattr(n, "lineno", None) == first
                       and getattr(n, "end_lineno", None) == last and getattr(n, "col_offset", -2) + 1 == a
                       and getattr(n, "end_col_offset", -2) + 1 == b]
            if any(isinstance(n, ast.arg) for n in matches):
                result["syntax_kind"] = "parameter"
            elif any(isinstance(n, ast.Call) for n in matches):
                result["syntax_kind"] = "call_return_value"
            elif any(isinstance(n, ast.Attribute) for n in matches):
                result["syntax_kind"] = "attribute_access"
            elif matches:
                result["syntax_kind"] = type(matches[0]).__name__
        return result


def extract(document, repo, report_hash):
    reader = SourceReader(repo)
    sources, occurrences, findings, unresolved, entrypoints = {}, [], [], [], {}
    threads = 0
    for run_index, run in enumerate(document.get("runs") or []):
        for result_index, finding in enumerate(run.get("results") or []):
            finding_id = "finding_" + digest([report_hash, run_index, result_index])[:20]
            ep = finding.get("entrypoint") or {}
            ep_id = "reported_ep_" + digest(ep)[:20] if ep else None
            if ep_id:
                entrypoints[ep_id] = ep
            sink = report_location((finding.get("locations") or [{}])[0], run)
            sink["file"] = reader.resolve_file(sink["reported_uri"])
            row = {"finding_id": finding_id, "run_index": run_index, "result_index": result_index,
                   "rule_id": finding.get("ruleId"), "message": (finding.get("message") or {}).get("text"),
                   "sink_info": finding.get("sinkInfo") or {}, "sink": sink,
                   "reported_entrypoint_id": ep_id, "entrypoint": ep, "source_ids": []}
            for flow_index, flow in enumerate(finding.get("codeFlows") or []):
                for thread_index, thread in enumerate(flow.get("threadFlows") or []):
                    threads += 1
                    hits = 0
                    for step_index, step in enumerate(thread.get("locations") or []):
                        marker = explicit_source(step)
                        if marker is None:
                            continue
                        hits += 1
                        loc = report_location(step.get("location") or {}, run)
                        enriched = reader.enrich(loc)
                        key = [enriched["file"] or loc["reported_uri"], loc["start_line"], loc["start_column"],
                               loc["end_line"], loc["end_column"], loc["expression"]]
                        source_id = "source_" + digest(key)[:20]
                        if source_id not in sources:
                            sources[source_id] = dict(source_id=source_id, **loc, **enriched,
                                taint_kind=None, matched_source_rule=None, interpretation="YASA_reported_SOURCE",
                                occurrences=0, finding_ids=[], reported_entrypoint_ids=[], reported_uris=[], node_hashes=[])
                        source = sources[source_id]
                        source["occurrences"] += 1
                        for column, value in (("finding_ids", finding_id), ("reported_entrypoint_ids", ep_id),
                                              ("reported_uris", loc["reported_uri"]), ("node_hashes", loc["node_hash"])):
                            if value is not None and value not in source[column]:
                                source[column].append(value)
                        if source_id not in row["source_ids"]:
                            row["source_ids"].append(source_id)
                        occurrences.append({"source_id": source_id, "finding_id": finding_id, "run_index": run_index,
                            "result_index": result_index, "code_flow_index": flow_index, "thread_flow_index": thread_index,
                            "step_index": step_index, "marker": marker, "reported_entrypoint_id": ep_id,
                            "entrypoint": ep, "location": loc, "sink": sink, "sink_info": row["sink_info"]})
                    if not hits:
                        unresolved.append({"finding_id": finding_id, "run_index": run_index, "result_index": result_index,
                            "code_flow_index": flow_index, "thread_flow_index": thread_index, "reason": "no_explicit_source_marker"})
            findings.append(row)
    rows = sorted(sources.values(), key=lambda s: (s["file"] or s["reported_uri"], s["start_line"] or 0, s["start_column"] or 0, s["expression"]))
    for row in rows:
        row["finding_count"] = len(row["finding_ids"])
        row["reported_entrypoint_count"] = len(row["reported_entrypoint_ids"])
    return rows, occurrences, findings, unresolved, entrypoints, threads


def write_outputs(out, data, report, repo):
    sources, occurrences, findings, unresolved, entrypoints, threads = data
    out.mkdir(parents=True, exist_ok=True)
    def write(name, value):
        (out / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write("sources.json", sources)
    (out / "sources.jsonl").write_text("".join(json.dumps(s, ensure_ascii=False) + "\n" for s in sources), encoding="utf-8")
    write("source-occurrences.json", occurrences)
    write("findings.json", findings)
    write("unresolved.json", unresolved)
    write("reported-entrypoints.json", entrypoints)
    columns = ("source_id", "file", "start_line", "start_column", "end_line", "end_column", "expression", "syntax_kind",
               "enclosing_function", "enclosing_function_start_line", "finding_count", "occurrences", "reported_entrypoint_count",
               "source_resolution", "source_expression_text", "source_text", "reported_uri")
    with (out / "sources.csv").open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(sources)
    # Explicitly retain every source-to-finding/entrypoint link; no function-name merging.
    columns = ("source_id", "finding_id", "result_index", "entrypoint_file", "entrypoint_function", "entrypoint_type",
               "entrypoint_start_line", "source_file", "source_line", "source_expression", "sink_file", "sink_line", "sink_rule", "sink_attributes")
    with (out / "source-finding-links.csv").open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        for row in occurrences:
            ep, loc, sink = row["entrypoint"], row["location"], row["sink"]
            src = next(s for s in sources if s["source_id"] == row["source_id"])
            writer.writerow({"source_id": row["source_id"], "finding_id": row["finding_id"], "result_index": row["result_index"],
                "entrypoint_file": ep.get("filePath"), "entrypoint_function": ep.get("functionName"), "entrypoint_type": ep.get("type"),
                "entrypoint_start_line": ep.get("funcLocStart"), "source_file": src["file"], "source_line": loc["start_line"],
                "source_expression": loc["expression"], "sink_file": sink["file"] or sink["reported_uri"], "sink_line": sink["start_line"],
                "sink_rule": row["sink_info"].get("sinkRule"), "sink_attributes": ";".join(row["sink_info"].get("sinkAttribute") or [])})
    summary = {"findings": len(findings), "findings_with_source": sum(bool(r["source_ids"]) for r in findings),
        "threads": threads, "threads_without_explicit_source": len(unresolved), "source_occurrences": len(occurrences),
        "unique_sources": len(sources), "source_files": len({s["file"] for s in sources if s["file"]}),
        "source_resolution_counts": dict(Counter(s["source_resolution"] for s in sources)),
        "source_syntax_counts": dict(Counter(s["syntax_kind"] for s in sources)),
        "reported_entrypoint_descriptors": len(entrypoints), "reported_entrypoints_are_exact_function_ids": False,
        "scope": "sources explicitly marked in this SARIF report only; not all sources in the repository",
        "independently_validated_untrusted_inputs": False, "engine_executed": False, "api_called": False}
    write("summary.json", summary)
    commit = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True)
    scan_summary = report.with_name("scan_summary.json")
    provenance = {"created_at": datetime.now(timezone.utc).isoformat(), "report": str(report.resolve()),
        "report_sha256": hashlib.sha256(report.read_bytes()).hexdigest(), "report_bytes": report.stat().st_size,
        "repository": str(repo.resolve()), "current_repository_commit": commit.stdout.strip() if commit.returncode == 0 else None,
        "current_repository_commit_is_report_commit_proof": False,
        "extractor_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "source_files_sha256": {s["file"]: s["source_file_sha256"] for s in sources if s["file"]},
        "source_detection": "explicit SOURCE tag or structured source role; no first-step fallback",
        "deduplication": "normalized file/URI + start/end line/column + affected expression; not nodehash or function name",
        "limitations": ["No sources absent from emitted findings can be recovered.",
                        "YASA marks are not independently confirmed attacker-controlled input.",
                        "SARIF does not identify the original source rule/tag kind here; these fields remain null.",
                        "Current-source owner/syntax enrichment does not prove the report was produced from that commit.",
                        "Entrypoint descriptors may omit class and definition location; do not treat them as exact IDs."],
        "engine_executed": False, "api_called": False}
    write("manifest.json", provenance)
    if scan_summary.exists():
        (out / "scan-summary.snapshot.json").write_bytes(scan_summary.read_bytes())
    lines = ["# CTFd 漏洞报告 source 提取", "", "仅提取报告中明确标记 SOURCE 的步骤，未运行 YASA 或调用模型。", "",
        f"输入：`{report}`。告警 {len(findings)} 条，source 出现 {len(occurrences)} 次，按源码位置和表达式去重后 {len(sources)} 个。", "",
        "- [sources.csv](sources.csv)：去重 source 表，可用 Excel 打开。",
        "- [sources.json](sources.json)：完整位置、源码、所属函数及关联记录。",
        "- [source-finding-links.csv](source-finding-links.csv)：source、报告入口和告警/sink 的关联。",
        "- [source-occurrences.json](source-occurrences.json)：每次出现的 SARIF 精确索引和原始位置。",
        "- [findings.json](findings.json)：每条告警的入口、sink 与 source ID。", "",
        "## 去重来源", "", "| 文件位置 | 所属函数 | 报告中的来源表达式 | 关联告警数 |", "|---|---|---|---:|"]
    for s in sources:
        expression = s["expression"].replace("|", "\\|").replace("\n", " ")
        label = f"{s['file'] or s['reported_uri']}:{s['start_line']}"
        location = f"[{label}]({repo.resolve() / s['file']}:{s['start_line']})" if s["file"] else label
        lines.append(f"| {location} | {s['enclosing_function'] or '—'} | `{expression}` | {s['finding_count']} |")
    lines += ["", "## 使用边界", "", "这些是 YASA 在已输出告警路径中标记的来源，不是全仓 source 清单，也不是人工确认的外部输入真值。配置/数据库读取等记录原样保留，不按人工语义过滤。",
        "同一来源可以关联多个入口和告警。报告入口可能缺少类名和定义行号，因此 descriptor 数不能当成精确去重的函数数；尤其不要合并同名 get 方法为同一个真实函数。",
        "源码片段和所属函数从当前本地源码补充；不擅自宣称已经证明历史扫描与当前 commit 一致。原始报告片段、位置和 nodehash 均保留。",
        "source 的污点标签及原始匹配规则未保存在这份 SARIF 中，相关字段保留 null。告警索引采用 SARIF 原始的零起始索引。", "",
        "重现命令（在 YASA-Engine 下执行）：", "", "```bash",
        "PYTHONDONTWRITEBYTECODE=1 /data/fyn/conda_envs/laya/bin/python -B LLM-check/extract_report_sources.py \\",
        f"  --report {report} --repo {repo} --out LLM-check/source-extractions/ctfd-yasa-manual-v1", "```", ""]
    (out / "README.md").write_text("\n".join(lines), encoding="utf-8")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=HERE.parent / "artifacts/ctfd-yasa-manual/report/report.sarif")
    parser.add_argument("--repo", type=Path, default=HERE.parent / "CTFd")
    parser.add_argument("--out", type=Path, default=HERE / "source-extractions/ctfd-yasa-manual-v1")
    args = parser.parse_args()
    if (args.out / "manifest.json").exists():
        parser.error("Choose a fresh --out to preserve an existing extraction")
    raw = args.report.read_bytes()
    data = extract(json.loads(raw), args.repo, hashlib.sha256(raw).hexdigest())
    print(json.dumps(write_outputs(args.out, data, args.report, args.repo), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
