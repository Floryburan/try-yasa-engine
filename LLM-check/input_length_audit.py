"""Distinguish provider token usage from explicit truncation telemetry."""

import hashlib
import json


def response_audit(raw, payload, wire_bytes):
    usage = raw.get("usage") or {}
    tokens = usage.get("input_tokens")
    if type(tokens) is not int or tokens < 0:
        tokens = None
    flag = usage.get("truncated")
    dropped = usage.get("state_tokens_dropped")
    if flag is True or (type(dropped) is int and dropped > 0):
        status = "reported_truncation"
    elif flag is False and dropped == 0:
        status = "reported_no_truncation"
    else:
        status = "not_reported"
    return {"provider_reported_input_tokens": tokens, "resolved_model": raw.get("model"),
            "server_truncation_status": status, "server_state_tokens_dropped": dropped,
            "client_state_truncated": False,
            "state_characters": len(payload["state"]) if isinstance(payload["state"], str) else None,
            "request_utf8_bytes": len(wire_bytes), "request_sha256": hashlib.sha256(wire_bytes).hexdigest()}


def summarize_input_audits(rows):
    audits = [dict(case_id=row["case_id"], variant=row["variant"], stage_id=stage["stage_id"], **stage["input_audit"])
              for row in rows for stage in row.get("stages", []) if "input_audit" in stage]
    tokens = [a["provider_reported_input_tokens"] for a in audits if a["provider_reported_input_tokens"] is not None]
    return {"responses_audited": len(audits), "actual_input_token_min": min(tokens) if tokens else None,
            "actual_input_token_max": max(tokens) if tokens else None,
            "total_reported_input_tokens": sum(tokens), "responses_without_token_usage": len(audits) - len(tokens),
            "truncation_status_counts": {status: sum(a["server_truncation_status"] == status for a in audits)
                                         for status in ("reported_truncation", "reported_no_truncation", "not_reported")},
            "request_errors": [{"case_id": row["case_id"], "variant": row["variant"], "error": row.get("error")}
                               for row in rows if row["status"] != "success"],
            "requests": audits}
