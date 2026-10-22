"""
Extract a 50-row sample of the (conversation_id, step_idx, tool_name) join
from private/audit.jsonl (clean corpus) to validate human approval inference.
"""

import json
from pathlib import Path
from collections import defaultdict
from datetime import datetime

AUDIT_PATH = Path("private/audit.jsonl")

# Read clean records
pre_events = []
post_events = defaultdict(dict)  # (conv_id, step_idx, tool_name) -> post_record

with open(AUDIT_PATH, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        cid = str(r.get("conversation_id", "") or "").lower()
        ws = str(r.get("workspace_root", "") or "").lower()
        if any(k in ws for k in ["appdata\\local\\temp", "appdata/local/temp", "\\tmp\\", "/tmp/", "pytest", "test-daemon"]):
            continue
        if any(k in cid for k in ["test", "mock", "scenario", "dummy", "sample", "fixture"]):
            continue

        evt = r.get("event_type")
        conv_id = r.get("conversation_id")
        step_idx = r.get("step_idx")
        tool = r.get("tool_name")
        key = (conv_id, step_idx, tool)

        if evt == "PreToolUse":
            dec = r.get("final_decision")
            if dec in ("ask", "force_ask"):
                pre_events.append(r)
        elif evt == "PostToolUse":
            post_events[key] = r

# Take a diverse 50-row sample across conversations
# Pick evenly across pre_events
total_asked = len(pre_events)
step = max(1, total_asked // 50)
sample_rows = [pre_events[i] for i in range(0, total_asked, step)][:50]

print(f"Total clean prompted PreToolUse events: {total_asked}")
print(f"Sampled 50 rows for join validation (step={step}):\n")

print(f"{'#':<3} | {'Conversation ID':<16} | {'Step':<4} | {'Tool':<18} | {'Decision':<9} | {'Post-Event':<17} | {'Delta(s)':<8} | Command / Args")
print("-" * 110)

for idx, pre in enumerate(sample_rows, 1):
    conv_id = pre.get("conversation_id")
    short_cid = conv_id[:14] + ".." if len(conv_id) > 16 else conv_id
    step_idx = pre.get("step_idx")
    tool = pre.get("tool_name", "")
    dec = pre.get("final_decision", "")
    key = (conv_id, step_idx, tool)
    
    post = post_events.get(key)
    if post:
        outcome = "approved_inferred"
        # calculate delta if timestamps exist
        t_pre = pre.get("timestamp")
        t_post = post.get("timestamp")
        delta_str = "n/a"
        if t_pre and t_post:
            try:
                # ISO parsing
                dt0 = datetime.fromisoformat(t_pre.replace("Z", "+00:00"))
                dt1 = datetime.fromisoformat(t_post.replace("Z", "+00:00"))
                delta_s = (dt1 - dt0).total_seconds()
                delta_str = f"{delta_s:.1f}s"
            except Exception:
                pass
    else:
        outcome = "no_post_event"
        delta_str = "-"

    tool_args = pre.get("tool_args", {})
    cmd = ""
    if isinstance(tool_args, dict):
        cmd = tool_args.get("CommandLine", "") or tool_args.get("command", "") or tool_args.get("TargetFile", "") or str(tool_args)
    cmd = cmd.replace("\n", " ").strip()
    if len(cmd) > 40:
        cmd = cmd[:37] + "..."

    print(f"{idx:<3} | {short_cid:<16} | {step_idx:<4} | {tool:<18} | {dec:<9} | {outcome:<17} | {delta_str:<8} | {cmd}")
