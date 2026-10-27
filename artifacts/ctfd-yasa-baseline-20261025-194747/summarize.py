"""Summarize finished YASA output without treating alerts as confirmed vulnerabilities."""
import json
from collections import Counter
from pathlib import Path
from urllib.parse import unquote, urlparse

root = Path(__file__).resolve().parent
report = root / "report"
command = json.loads((root / "command.json").read_text())
exit_info = json.loads((root / "exit.json").read_text())
repo = Path(command["repository"])
sarif = json.loads((report / "report.sarif").read_text())
scan = json.loads((report / "scan_summary.json").read_text())
metrics_path = report / "entrypoint-metrics.json"
metrics = json.loads(metrics_path.read_text()) if metrics_path.exists() else []
alerts = []
for run in sarif.get("runs", []):
    for result in run.get("results", []):
        locations = result.get("locations") or [{}]
        physical = locations[0].get("physicalLocation", {})
        uri = physical.get("artifactLocation", {}).get("uri", "")
        file = unquote(urlparse(uri).path) if uri.startswith("file:") else unquote(uri)
        if file.startswith(str(repo) + "/"):
            file = file[len(str(repo)) + 1:]
        file = file.lstrip("/")
        group = {"CTFd": "application", "tests": "tests", "migrations": "migrations"}.get(file.split("/")[0], "scripts_or_other")
        line = physical.get("region", {}).get("startLine")
        alerts.append({"index": len(alerts) + 1, "file": file, "line": line, "area": group,
                       "message": result.get("message", {}).get("text"), "level": result.get("level"),
                       "sink_info": result.get("sinkInfo"), "entrypoint": result.get("entrypoint"),
                       "source_file_exists": (repo / file).is_file(),
                       "matched_sanitizer_tags": result.get("matchedSanitizerTags"),
                       "trace_locations": sum(len(flow.get("locations", [])) for code in result.get("codeFlows", []) for flow in code.get("threadFlows", []))})
runtime = (root / "runtime.log").read_text(errors="replace")
result = {"repository_commit": command["repository_commit"], "runtime": command["runtime"], **exit_info,
          "sarif_alerts": len(alerts), "alerts_by_area": dict(Counter(a["area"] for a in alerts)),
          "alerts_by_message": dict(Counter(a["message"] for a in alerts)),
          "alerts_by_sink_location": len({(a["file"], a["line"], json.dumps(a["sink_info"], sort_keys=True)) for a in alerts}),
          "entrypoint_metric_records": len(metrics),
          "entrypoint_attributes": dict(Counter(m.get("attribute", "unknown") for m in metrics)),
          "skipped_entrypoints": sum(bool(m.get("skipped")) for m in metrics),
          "skip_reasons": dict(Counter(m.get("skipReason", "unknown") for m in metrics if m.get("skipped"))),
          "circular_import_diagnostics": runtime.count("Circular import detected for:"),
          "scan_summary": {key: value for key, value in scan.items() if key != "ruleConfig"},
          "alerts": alerts,
          "interpretation": "Static analyzer alerts require manual review; not confirmed vulnerabilities or verified historical CVEs."}
(root / "analysis-summary.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
lines = ["# CTFd / YASA 默认检测基线", "", "- 输入提交：`" + command["repository_commit"] + "`",
         "- 引擎：当前 TypeScript 源码；Python 默认检测包及随仓库提供的 Python 规则。",
         "- 范围：整个仓库，包括测试与迁移。", "- 退出码：`" + str(exit_info["exit_code"]) + "`",
         "- 耗时：" + str(exit_info["elapsed_seconds"]) + " 秒。",
         "- SARIF 告警：" + str(len(alerts)) + " 条，按 sink 位置和 sink 信息归并后 " + str(result["alerts_by_sink_location"]) + " 处。",
         "- 入口执行记录：" + str(len(metrics)) + "，跳过 " + str(result["skipped_entrypoints"]) + " 条。",
         "", "告警尚未人工确认，不能直接称为真实漏洞或历史漏洞复现。", "",
         "## 告警", "", "| 编号 | 区域 | 文件及行号 | 告警 |", "| --- | --- | --- | --- |"]
for alert in alerts:
    location = alert["file"] + ":" + str(alert["line"])
    label = (alert.get("message") or "").replace("|", "\\|").replace("\n", " ")
    lines.append("| {} | {} | {} | {} |".format(alert["index"], alert["area"], location, label))
lines += ["", "## 产物", "", "- `report/report.sarif`：完整告警和数据流路径。",
          "- `report/scan_summary.json`：引擎扫描统计及规则。",
          "- `report/entrypoint-metrics.json`：入口运行情况。",
          "- `runtime.log`：完整标准输出及错误输出。",
          "- `command.json`、`exit.json`：运行参数、版本和完成状态。",
          "- `analysis-summary.json`：结构化归并结果。", ""]
(root / "RESULTS.md").write_text("\n".join(lines))
print(json.dumps({key: result[key] for key in ("exit_code", "elapsed_seconds", "sarif_alerts", "alerts_by_area", "alerts_by_sink_location", "entrypoint_metric_records", "skipped_entrypoints", "skip_reasons")}, ensure_ascii=False, indent=2))
