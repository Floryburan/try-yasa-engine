"""Terminal scan statistics and an append-only journal of real API attempts."""

import hashlib
import json
import math
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path


def save(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def token_number(value):
    return value if type(value) is int and value >= 0 else None


def usage_totals(events):
    result = {"attempts": len(events), "http_successes": 0, "http_errors": 0, "transport_errors": 0,
              "input_tokens": 0, "output_tokens": 0, "total_tokens": 0,
              "responses_missing_input_tokens": 0, "responses_missing_output_tokens": 0,
              "responses_missing_total_tokens": 0}
    durations = []
    for event in events:
        status = event.get("http_status")
        success = type(status) is int and 200 <= status < 300
        result["http_successes" if success else "http_errors" if status is not None else "transport_errors"] += 1
        usage = event.get("usage") or {}
        counts = {key: token_number(usage.get(key)) for key in ("input_tokens", "output_tokens", "total_tokens")}
        if counts["total_tokens"] is None and counts["input_tokens"] is not None and counts["output_tokens"] is not None:
            counts["total_tokens"] = counts["input_tokens"] + counts["output_tokens"]
        for key, value in counts.items():
            if value is not None:
                result[key] += value
            elif success:
                result["responses_missing_" + key] += 1
        if type(event.get("elapsed_seconds")) in (int, float):
            durations.append(event["elapsed_seconds"])
    durations.sort()
    result["latency_avg_ms"] = 1000 * sum(durations) / len(durations) if durations else None
    result["latency_p70_p99_max_ms"] = [1000 * durations[max(0, math.ceil(len(durations) * p) - 1)]
                                          for p in (.70, .99, 1)] if durations else None
    return result


def source_statistics(manifest, prepared):
    stats = {"language": "python", "files_in_scope": None, "source_lines_in_scope": None,
             "files_with_targets": len({r["location"]["file"] for r in prepared})}
    if manifest.get("source_statistics"):
        return dict(stats, **manifest["source_statistics"])
    # Older prepared CTFd runs did not store index_directory. Only use their
    # default index when its bytes match the frozen index hash.
    index = Path(manifest.get("index_directory") or Path(__file__).resolve().parent.parent / "artifacts/ctfd-uast/index")
    path = index / "files.jsonl"
    try:
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != manifest.get("index_hashes", {}).get("files"):
            return stats
        files = [json.loads(line) for line in data.decode().splitlines() if line.strip()]
        area = manifest["selection"]["area"]
        selected = [f for f in files if area == "all" or f.get("area") == area]
        stats.update(files_in_scope=len(selected), source_lines_in_scope=sum(f["lines"] for f in selected))
    except (OSError, ValueError, KeyError):
        pass
    return stats


class ScanStatistics:
    def __init__(self, out, total):
        self.out, self.total = out, total
        self.started = time.monotonic()
        self.events = []
        self.record = {"invocation_id": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:8],
                       "started_at": datetime.now(timezone.utc).isoformat(), "status": "running",
                       "resumed_functions": 0, "functions_processed_this_invocation": 0, "elapsed_seconds": 0}
        self.save()

    def save(self):
        self.record["elapsed_seconds"] = round(time.monotonic() - self.started, 6)
        save(self.out / "invocations" / (self.record["invocation_id"] + ".json"), self.record)
        save(self.out / "last-invocation.json", self.record)

    def request(self, case_id, stage_id, digest, elapsed, status, usage):
        event = {"case_id": case_id, "stage_id": stage_id, "request_hash": digest,
                 "elapsed_seconds": elapsed, "http_status": status, "usage": usage}
        self.events.append(event)
        path = self.out / "usage-events" / (self.record["invocation_id"] + ".jsonl")
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event, ensure_ascii=False) + "\n")

    def progress(self, rows):
        self.record["functions_processed_this_invocation"] += 1
        if self.record["functions_processed_this_invocation"] % 10 == 0 or len(rows) == self.total:
            self.save()
            usage = usage_totals(self.events)
            positives = sum(r.get("verdict", {}).get("is_entrypoint") is True for r in rows)
            print("[JEV] Functions {}/{} | Entrypoints {} | Requests {} | Input tokens {:,} | Time {}".format(
                len(rows), self.total, positives, usage["attempts"], usage["input_tokens"],
                duration(time.monotonic() - self.started)), flush=True)

    def finish(self, status):
        self.record["status"] = status
        self.save()


def last_invocation(out):
    path = out / "last-invocation.json"
    if not path.exists():
        return None
    record = json.loads(path.read_text())
    journal = out / "usage-events" / (record["invocation_id"] + ".jsonl")
    events = []
    if journal.exists():
        lines = journal.read_bytes().splitlines(keepends=True)
        for i, line in enumerate(lines):
            try:
                events.append(json.loads(line))
            except (ValueError, UnicodeError):
                if i != len(lines) - 1 or line.endswith(b"\n"):
                    raise
                # A reader may observe the final event while it is being written.
    record["usage"] = usage_totals(events)
    if record["status"] == "running":
        record["elapsed_seconds"] = max(0, (datetime.now(timezone.utc) - datetime.fromisoformat(record["started_at"])).total_seconds())
    return record


def duration(seconds):
    if seconds is None:
        return "not recorded"
    milliseconds = round(seconds * 1000)
    minutes, remainder = divmod(milliseconds, 60000)
    seconds, milliseconds = divmod(remainder, 1000)
    return "{}m{}s{:03d}ms".format(minutes, seconds, milliseconds)


def terminal_statistics(out, manifest, prepared, rows, summary):
    # Saved-result usage is a snapshot of retained responses, not an account bill
    # or all historical consumption. Failed/overwritten attempts may be absent.
    stages = [s for r in rows for s in r.get("stages", [])]
    saved_usage = usage_totals([{"http_status": 200, "usage": s.get("usage")} for s in stages])
    invocation = last_invocation(out)
    source = source_statistics(manifest, prepared)
    identity = {r["case_id"]: r for r in prepared}
    completed_files = {identity[r["case_id"]]["location"]["file"] for r in rows if r["status"] == "success"}
    stats = {"source": source, "saved_result_usage": saved_usage, "last_invocation": invocation}
    summary["terminal_statistics"] = stats
    save(out / "terminal-statistics.json", stats)

    def number(value):
        return "not recorded" if value is None else format(value, ",")

    def tokens(usage, key):
        value = number(usage[key])
        missing = usage["responses_missing_" + key]
        return value + (" (partial; {} responses missing)".format(missing) if missing else "")

    pairs = [("Language", source["language"]), ("Scan scope", manifest["selection"]["area"]),
             ("Model", manifest.get("model", "not recorded")),
             ("Files in scope", number(source["files_in_scope"])),
             ("Source lines in scope", number(source["source_lines_in_scope"])),
             ("Files with target functions", number(source["files_with_targets"])),
             ("Files with completed functions", number(len(completed_files)))]
    pairs += [(label, number(summary[key])) for label, key in (
        ("Functions selected", "selected_functions"), ("Functions completed", "successful_functions"),
        ("Entrypoints (model)", "entrypoints"), ("Non-entrypoints", "non_entrypoints"),
        ("Unknown functions", "unknown"), ("Failed functions", "request_failed_functions"),
        ("Preparation errors", "preparation_errors"), ("Functions not attempted", "not_attempted_functions"))]
    pairs += [(label, number(summary[key])) for label, key in (
        ("Definition aliases merged", "definition_aliases_merged"),
        ("Functions with binding sites", "functions_with_binding_sites"),
        ("Functions with inherited receivers", "functions_with_inherited_receivers")) if key in summary]
    if invocation:
        usage = invocation["usage"]
        pairs += [("Last invocation status", invocation["status"]),
                  ("Total time (last invocation)", duration(invocation["elapsed_seconds"])),
                  ("Resumed functions (last invocation)", number(invocation["resumed_functions"])),
                  ("Jev requests (last invocation)", number(usage["attempts"])),
                  ("Jev HTTP errors (last invocation)", number(usage["http_errors"])),
                  ("Jev network errors (last invocation)", number(usage["transport_errors"]))]
        pairs += [("Jev {} (last invocation)".format(key.replace("_", " ")), tokens(usage, key))
                  for key in ("input_tokens", "output_tokens", "total_tokens")]
        latency = usage["latency_p70_p99_max_ms"]
        pairs += [("Avg API request time", "{:.2f}ms".format(usage["latency_avg_ms"]) if latency else "n/a"),
                  ("API time 70%/99%/100%", "/".join("{:.2f}ms".format(v) for v in latency) if latency else "n/a")]
    else:
        pairs.append(("Total time (last invocation)", "not recorded (older run)" if rows else "not started"))
    pairs += [("Saved API responses", number(saved_usage["attempts"]))]
    pairs += [("Saved {}".format(key.replace("_", " ")), tokens(saved_usage, key))
              for key in ("input_tokens", "output_tokens", "total_tokens")]
    text = "\n".join("{:<38} : {}".format(label, value) for label, value in pairs)
    print("\n" + text, flush=True)
    return text
