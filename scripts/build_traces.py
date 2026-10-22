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
HOST_RULES_PATH = Path("private/host-allow-rules.txt")


def load_host_allow_rules() -> List[tuple]:
    if not HOST_RULES_PATH.exists():
        return []
    with open(HOST_RULES_PATH, "r", encoding="utf-8") as f:
        content = f.read().strip()
    if not content.startswith("{"):
        content = "{" + content
    if not content.endswith("}"):
        content = content + "}"
    try:
        data = json.loads(content)
        raw_rules = data.get("allow", [])
    except Exception:
        raw_rules = []

    matchers = []
    for r in raw_rules:
        m = re.match(r"^command\((.*)\)$", r.strip())
        if not m:
            continue
        pat = m.group(1).strip()
        creg = None
        try:
            creg = re.compile(f"^(?:{pat})(?:\\s+.*)?$", re.IGNORECASE)
        except Exception:
            pass
        matchers.append((pat, creg))
    return matchers


def find_matching_host_rule(cmd: str, matchers: List[tuple]) -> Optional[str]:
    cmd_clean = cmd.strip()
    if not cmd_clean:
        return None
    for pat, creg in matchers:
        if cmd_clean == pat or cmd_clean.startswith(pat + " "):
            return pat
        if creg is not None:
            try:
                if creg.match(cmd_clean):
                    return pat
            except Exception:
                pass
    return None


def matches_host_rule(cmd: str, matchers: List[tuple]) -> bool:
    return find_matching_host_rule(cmd, matchers) is not None


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


def parse_timestamp(ts_str: Optional[str]) -> Optional[datetime]:
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except Exception:
        return None


def build_traces(min_steps: int = 5) -> None:
    if not AUDIT_PATH.exists():
        raise FileNotFoundError(f"Source audit file not found: {AUDIT_PATH}")

    TRACES_DIR.mkdir(parents=True, exist_ok=True)
    host_matchers = load_host_allow_rules()
    print(f"Loaded {len(host_matchers)} host allow rules from {HOST_RULES_PATH}")

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

    # 2. Pair PreToolUse and PostToolUse per conversation
    parsed_convs = {}
    all_pre_events = []

    for cid, records in conv_records.items():
        pre_events = []
        post_map = defaultdict(list)

        for r in records:
            et = r.get("event_type")
            sidx = r.get("step_idx")
            tname = r.get("tool_name")
            key = (sidx, tname)
            if et == "PreToolUse":
                pre_events.append(r)
            elif et == "PostToolUse":
                post_map[key].append(r)

        if len(pre_events) < min_steps:
            continue

        pre_events.sort(key=lambda r: (r.get("step_idx", 0), r.get("timestamp", "")))
        conv_items = []

        for pre in pre_events:
            sidx = pre.get("step_idx")
            tname = pre.get("tool_name")
            key = (sidx, tname)
            posts = post_map.get(key, [])

            pre_ts = parse_timestamp(pre.get("timestamp"))
            matched_post = None
            min_delta = None
            for p in posts:
                post_ts = parse_timestamp(p.get("timestamp"))
                if post_ts and pre_ts and post_ts >= pre_ts:
                    delta = (post_ts - pre_ts).total_seconds()
                    if min_delta is None or delta < min_delta:
                        min_delta = delta
                        matched_post = p

            item = {
                "cid": cid,
                "pre": pre,
                "matched_post": matched_post,
                "min_delta": min_delta,
                "pre_ts": pre_ts,
            }
            conv_items.append(item)
            all_pre_events.append(item)

        parsed_convs[cid] = conv_items

    # 3. Global chronological pass for first-match host rule resolution
    all_pre_events.sort(key=lambda item: (item["pre_ts"] or datetime.min, item["pre"].get("step_idx", 0)))

    seen_host_rules_global = set()
    classified_steps_by_conv = defaultdict(list)

    for item in all_pre_events:
        cid = item["cid"]
        pre = item["pre"]
        sidx = pre.get("step_idx")
        tname = pre.get("tool_name")
        matched_post = item["matched_post"]
        min_delta = item["min_delta"]
        dec = pre.get("final_decision")

        tool_args = pre.get("tool_args", {})
        if isinstance(tool_args, dict):
            cmd = tool_args.get("CommandLine", "") or tool_args.get("command", "") or ""
        else:
            cmd = str(tool_args)

        # 3-way classification
        if dec in ("ask", "force_ask"):
            if matched_post and min_delta is not None and min_delta <= 600.0:
                human_approved = True
                # Delay-only (upper)
                lc_delay_only = "host_auto" if min_delta < 1.5 else "human_prompt"

                # Matching host rule
                matched_pat = find_matching_host_rule(cmd, host_matchers) if tname == "run_command" else None

                # Retroactive (lower)
                if matched_pat is not None or min_delta < 1.5:
                    lc_retroactive = "host_auto"
                else:
                    lc_retroactive = "human_prompt"

                # First-match (middle)
                if matched_pat is not None:
                    if matched_pat not in seen_host_rules_global:
                        seen_host_rules_global.add(matched_pat)
                        lc_first_match = "human_prompt"
                    else:
                        lc_first_match = "host_auto"
                elif min_delta < 1.5:
                    lc_first_match = "host_auto"
                else:
                    lc_first_match = "human_prompt"
            else:
                human_approved = False
                lc_delay_only = "unapproved"
                lc_retroactive = "unapproved"
                lc_first_match = "unapproved"
        elif dec == "allow":
            human_approved = True
            lc_delay_only = "v1_allow"
            lc_retroactive = "v1_allow"
            lc_first_match = "v1_allow"
        elif dec == "deny":
            human_approved = False
            lc_delay_only = "v1_deny"
            lc_retroactive = "v1_deny"
            lc_first_match = "v1_deny"
        else:
            human_approved = False
            lc_delay_only = "unknown"
            lc_retroactive = "unknown"
            lc_first_match = "unknown"

        # Infer outcome
        outcome = "unknown"
        if matched_post:
            res = matched_post.get("tool_result") or {}
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
        elif dec in ("ask", "force_ask") and not matched_post:
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
            "latency_class": lc_first_match,
            "latency_class_delay_only": lc_delay_only,
            "latency_class_retroactive": lc_retroactive,
            "latency_class_first_match": lc_first_match,
            "outcome": outcome,
        }
        scrubbed_step = scrub_data(step_data)
        classified_steps_by_conv[cid].append(scrubbed_step)

    # 4. Write trace documents per conversation
    total_traces_built = 0
    total_steps_extracted = 0

    for cid, trace_steps in classified_steps_by_conv.items():
        if not trace_steps:
            continue
        # Sort back into execution order by step_idx
        trace_steps.sort(key=lambda s: s.get("step_idx", 0))

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
