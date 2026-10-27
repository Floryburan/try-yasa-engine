#!/usr/bin/env python3
"""Export YASA's whole-repository call graph without running taint entrypoints."""

import argparse
import hashlib
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=ENGINE / "CTFd")
    parser.add_argument("--out", type=Path, default=ENGINE / "artifacts/ctfd-full-callgraph-20261026")
    args = parser.parse_args()
    out, repo = args.out.resolve(), args.repo.resolve()
    if (out / "command.json").exists():
        raise SystemExit("Output already exists; choose a fresh --out to preserve the export")
    out.mkdir(parents=True, exist_ok=True)
    command = ["node", "--max-old-space-size=16384", "--require",
               str(ENGINE / "node_modules/tsx/dist/cjs/index.cjs"), str(ENGINE / "src/main.ts"),
               "--sourcePath", str(repo), "--language", "python", "--analyzer", "PythonAnalyzer",
               "--checkerIds", "callgraph", "--dumpAllCG", "--dumpEntrypoint",
               "--uastSDKPath", str(ENGINE / "my-release-bundle/uast4py-linux-amd64"),
               "--incremental", "false", "--enablePerformanceLogging", "--report", str(out / "report")]
    sources = ["src/checker/common/full-callgraph-file-entrypoint.ts", "src/checker/callgraph/callgraph-checker.ts",
               "src/util/graph.ts", "src/main.ts", "my-release-bundle/uast4py-linux-amd64"]
    metadata = {"command": command, "cwd": str(out), "repository": str(repo),
                "repository_commit": subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip(),
                "started_at": datetime.now(timezone.utc).isoformat(), "entrypoint_checkers": [],
                "note": "Only callgraph checker. dumpEntrypoint skips downstream symbolInterpret but retains callgraph generation/endAnalyze. entrypoints.json is not model input.",
                "engine_sources_sha256": {p: hashlib.sha256((ENGINE / p).read_bytes()).hexdigest() for p in sources}}
    (out / "command.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n")
    started = time.monotonic()
    with (out / "runtime.log").open("w", encoding="utf-8") as log:
        proc = subprocess.Popen(command, cwd=out, stdout=log, stderr=subprocess.STDOUT)
        code = proc.wait()
    result = {"exit_code": code, "elapsed_seconds": round(time.monotonic() - started, 3),
              "finished_at": datetime.now(timezone.utc).isoformat()}
    if code == 0:
        graph_path = out / "report/callgraph.json"
        graph = json.loads(graph_path.read_text())
        result.update(nodes=len(graph["nodes"]), edges=len(graph["edges"]),
                      graph_sha256=hashlib.sha256(graph_path.read_bytes()).hexdigest())
    (out / "exit.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, ensure_ascii=False, indent=2), flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
