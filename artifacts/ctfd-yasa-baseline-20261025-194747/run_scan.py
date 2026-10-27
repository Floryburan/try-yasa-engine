"""Run the current YASA source against the entire local CTFd repository."""
import hashlib
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

out = Path(__file__).resolve().parent
engine = out.parents[1]
repo = engine / "CTFd"
command = [
    "node", "--max-old-space-size=16384", "--require",
    str(engine / "node_modules/tsx/dist/cjs/index.cjs"),
    str(engine / "src/main.ts"),
    "--sourcePath", str(repo),
    "--language", "python", "--analyzer", "PythonAnalyzer",
    "--checkerPackIds", "taint-flow-python-default",
    "--ruleConfigFile", str(engine / "resource/example-rule-config/rule_config_python.json"),
    "--uastSDKPath", str(engine / "my-release-bundle/uast4py-linux-amd64"),
    "--incremental", "false", "--taintTraceOutputStrategy", "full",
    "--enablePerformanceLogging", "--report", str(out / "report"),
]
metadata = {
    "command": command, "cwd": str(out), "runtime": "current TypeScript source through tsx",
    "repository": str(repo),
    "repository_commit": subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip(),
    "started_at": datetime.now(timezone.utc).isoformat(),
    "scope": "All Python source under CTFd, including tests and migrations",
    "node_heap_limit_mb": 16384,
    "default_entrypoint_and_scan_budgets_preserved": True,
    "sha256": {str(p.relative_to(engine)): hashlib.sha256(p.read_bytes()).hexdigest() for p in (
        engine / "src/main.ts", engine / "src/config.ts",
        engine / "resource/checker/checker-pack-config.json",
        engine / "resource/example-rule-config/rule_config_python.json",
        engine / "my-release-bundle/uast4py-linux-amd64")},
}
(out / "command.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n")
started = time.monotonic()
with (out / "runtime.log").open("w", encoding="utf-8") as log:
    process = subprocess.Popen(command, cwd=out, stdout=log, stderr=subprocess.STDOUT)
    (out / "process.json").write_text(json.dumps({"pid": process.pid, "started_at": metadata["started_at"]}, indent=2) + "\n")
    code = process.wait()
result = {"exit_code": code, "elapsed_seconds": round(time.monotonic() - started, 3),
          "finished_at": datetime.now(timezone.utc).isoformat(), "runtime_log": str(out / "runtime.log")}
(out / "exit.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result, indent=2), flush=True)
raise SystemExit(code)
