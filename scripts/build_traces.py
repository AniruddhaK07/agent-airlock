"""
Trace Extraction and Scrubbing Script for Agent Airlock v2 (Phase 0.2).
Extracts ordered per-session command sequences with outcomes from private/audit.jsonl,
scrubs all secrets, tokens, and user paths, and saves them to data/traces/<session_id>.json.
"""

import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from agent_airlock.scrubber import scrub_data

AUDIT_PATH = Path("private/audit.jsonl")
TRACES_DIR = Path("data/traces")


def is_test_record(rec: Dict[str, Any]) -> bool:
    cid = str(rec.get("conversation_id", "") or "").lower()
    ws = str(rec.get("workspace_root", "") or "").lower()
    cmd = ""
    tool_args = rec.get("tool_args", {})
    if isinstance(tool_args, dict):
        cmd = str(tool_args.get("CommandLine", "") or tool_args.get("command", "") or "").lower()

    if any(k in ws for k in ["appdata\\local\\temp", "appdata/local/temp", "\\tmp\\", "/tmp/", "pytest", "test-daemon"]):
        return True
    if any(k in cid for k in ["test", "mock", "scenario", "dummy", "sample", "fixture"]):
        return True
    if any(k in cmd for k in ["test-daemon", "scenario-attack", "project_z", "echo test"]):
        return True
    return False


def build_traces(min_steps: int = 5) -> None:
    if not AUDIT_PATH.exists():
        raise FileNotFoundError(f"Source audit file not found: {AUDIT_PATH}")

    TRACES_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Collect clean records grouped by conversation
    conv_records = defaultdict(list)
    raw_count = 0
    clean_count = 0

    with open(AUDIT_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            raw_count += 1
            rec = json.loads(line)
            if is_test_record(rec):
                continue
            clean_count += 1
            cid = rec.get("conversation_id")
            if cid:
                conv_records[cid].append(rec)

    print(f"Loaded {raw_count} raw records -> {clean_count} clean records across {len(conv_records)} conversations.")

    # 2. Process each conversation into an ordered trace
    total_traces_built = 0
    total_steps_extracted = 0

    for cid, records in conv_records.items():
        # Separate PreToolUse and PostToolUse
        pre_events = []
        post_map = {}  # (step_idx, tool_name) -> post_record

        for r in records:
            et = r.get("event_type")
            sidx = r.get("step_idx")
            tname = r.get("tool_name")
            key = (sidx, tname)
            if et == "PreToolUse":
                pre_events.append(r)
            elif et == "PostToolUse":
                post_map[key] = r

        if len(pre_events) < min_steps:
            continue

        # Sort PreToolUse by step_idx, then timestamp
        pre_events.sort(key=lambda r: (r.get("step_idx", 0), r.get("timestamp", "")))

        trace_steps = []
        for pre in pre_events:
            sidx = pre.get("step_idx")
            tname = pre.get("tool_name")
            key = (sidx, tname)
            post = post_map.get(key)

            dec = pre.get("final_decision")
            tool_args = pre.get("tool_args", {})
            if isinstance(tool_args, dict):
                cmd = tool_args.get("CommandLine", "") or tool_args.get("command", "") or ""
            else:
                cmd = str(tool_args)

            # Infer human approval
            # If decision was ask/force_ask: approved if matching PostToolUse found
            if dec in ("ask", "force_ask"):
                human_approved = (post is not None)
            elif dec == "allow":
                human_approved = True
            else:
                human_approved = False

            # Infer execution outcome from post event
            outcome = "unknown"
            if post:
                # check error or exit code in tool_result
                res = post.get("tool_result") or {}
                if isinstance(res, dict):
                    if res.get("error") or res.get("exit_code", 0) != 0:
                        outcome = "failure"
                    else:
                        outcome = "success"
                elif isinstance(res, str) and ("error" in res.lower() or "exception" in res.lower()):
                    outcome = "failure"
                else:
                    outcome = "success"
            elif dec == "deny":
                outcome = "denied"
            elif dec in ("ask", "force_ask") and not post:
                outcome = "rejected_or_aborted"

            step_data = {
                "step_idx": sidx,
                "tool_name": tname,
                "command": cmd,
                "tool_args": tool_args,
                "workspace_root": pre.get("workspace_root"),
                "timestamp": pre.get("timestamp"),
                "v1_decision": dec,
                "policy_verdict": pre.get("policy_verdict"),
                "matched_rule_id": pre.get("matched_rule_id"),
                "human_approved_inferred": human_approved,
                "outcome": outcome,
            }

            # Scrub all fields
            scrubbed_step = scrub_data(step_data)
            trace_steps.append(scrubbed_step)

        # Build trace document
        trace_doc = {
            "conversation_id": cid,
            "step_count": len(trace_steps),
            "start_time": trace_steps[0].get("timestamp"),
            "end_time": trace_steps[-1].get("timestamp"),
            "steps": trace_steps,
        }

        # Write to file
        safe_cid = re.sub(r"[^a-zA-Z0-9_-]", "_", cid)
        out_file = TRACES_DIR / f"trace_{safe_cid}.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(trace_doc, f, indent=2)

        total_traces_built += 1
        total_steps_extracted += len(trace_steps)

    print(f"\n[PASS] Successfully extracted {total_traces_built} scrubbed traces ({total_steps_extracted} steps) into {TRACES_DIR}")


if __name__ == "__main__":
    build_traces()
