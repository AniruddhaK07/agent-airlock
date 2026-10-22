import json
import re
from datetime import datetime
from collections import defaultdict, Counter

def is_test_record(rec):
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

def parse_timestamp(ts_str):
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except Exception:
        return None

clean_pre_records = []
clean_post_events = defaultdict(list)
total_clean_pre = 0

with open("private/audit.jsonl", "r", encoding="utf-8") as f:
    for line_no, line in enumerate(f, 1):
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        if is_test_record(rec):
            continue

        cid = str(rec.get("conversation_id", "") or "").strip()
        if not cid:
            continue

        et = rec.get("event_type")
        sidx = rec.get("step_idx")
        tool = rec.get("tool_name")
        key = (cid, sidx, tool)

        if et == "PreToolUse":
            total_clean_pre += 1
            if rec.get("final_decision") in ("ask", "force_ask"):
                clean_pre_records.append((line_no, rec))
        elif et == "PostToolUse":
            clean_post_events[key].append(rec)

# Correlate Pre -> Post
MAX_WINDOW_SECONDS = 600.0
human_prompt_events = []

for lno, pre in clean_pre_records:
    cid = pre.get("conversation_id")
    sidx = pre.get("step_idx")
    tool = pre.get("tool_name")
    key = (cid, sidx, tool)

    pre_ts = parse_timestamp(pre.get("timestamp"))
    posts = clean_post_events.get(key, [])

    min_delta = None
    for post in posts:
        post_ts = parse_timestamp(post.get("timestamp"))
        if post_ts and post_ts >= pre_ts:
            delta = (post_ts - pre_ts).total_seconds()
            if min_delta is None or delta < min_delta:
                min_delta = delta

    if min_delta is not None and 1.5 <= min_delta <= MAX_WINDOW_SECONDS:
        cmd = ""
        args = pre.get("tool_args", {})
        if isinstance(args, dict):
            cmd = args.get("CommandLine", "") or args.get("command", "")
        human_prompt_events.append({
            "line_no": lno,
            "tool": tool,
            "cmd": cmd,
            "delay": min_delta,
            "rec": pre,
        })

print("=" * 80)
print(f"HUMAN_PROMPT CLASS ANALYSIS (Delay 1.5s - 600s)")
print(f"Total Clean PreToolUse (Denominator): {total_clean_pre}")
print(f"Total human_prompt Events: {len(human_prompt_events)} ({len(human_prompt_events)/total_clean_pre*100:.2f} per 100 commands)")
print("=" * 80)

# 1. By Tool
tool_counter = Counter(e["tool"] for e in human_prompt_events)
print("\n--- By Tool (human_prompt only) ---")
print(f"{'Tool Name':<25} {'Count':<8} {'% of Human Prompts':<20} {'Prompts per 100 Cmds'}")
print("-" * 75)
for t, c in tool_counter.most_common():
    pct = c / len(human_prompt_events) * 100
    per_100 = c / total_clean_pre * 100
    print(f"{t:<25} {c:<8} {pct:>6.2f}%              {per_100:>6.2f}")

# 2. Command Prefixes in run_command (human_prompt only)
human_cmds = [e for e in human_prompt_events if e["tool"] == "run_command"]
print(f"\n--- Top 35 Command Prefixes in run_command (Total: {len(human_cmds)}) ---")

def extract_cmd_prefix(cmd):
    cmd = cmd.strip()
    # Normalize common wrappers
    toks = cmd.split()
    if not toks:
        return "<empty>"
    t0 = toks[0]
    # Check powershell cmdlet or command
    if t0.lower() in ("python", "python.exe"):
        if len(toks) > 1 and toks[1].startswith("-m"):
            return f"python -m {toks[2]}" if len(toks) > 2 else "python -m"
        elif len(toks) > 1 and toks[1] == "-c":
            return "python -c"
        return "python"
    if t0.lower() in ("git", "git.exe"):
        # Check flags like -C or --no-pager
        idx = 1
        prefix_parts = ["git"]
        while idx < len(toks) and toks[idx].startswith("-"):
            if toks[idx] == "-C" and idx + 1 < len(toks):
                prefix_parts.append(f"-C {toks[idx+1]}")
                idx += 2
            else:
                prefix_parts.append(toks[idx])
                idx += 1
        if idx < len(toks):
            prefix_parts.append(toks[idx])
        return " ".join(prefix_parts[:3])
    if t0.lower() in ("npm", "npx"):
        return f"{t0} {toks[1]}" if len(toks) > 1 else t0
    return t0

prefix_counter = Counter(extract_cmd_prefix(e["cmd"]) for e in human_cmds)
print(f"{'Command Prefix':<35} {'Count':<8} {'% of Cmd Prompts':<18} {'Prompts per 100 Cmds'}")
print("-" * 80)
for pfx, c in prefix_counter.most_common(35):
    pct = c / len(human_cmds) * 100
    per_100 = c / total_clean_pre * 100
    print(f"{pfx:<35} {c:<8} {pct:>6.2f}%            {per_100:>6.2f}")

# 3. Candidate L1 Families Evaluation
print("\n" + "=" * 80)
print("CANDIDATE L1 FAMILIES RANKED BY HUMAN PROMPTS SAVED PER 100 COMMANDS")
print("=" * 80)

# Family A: PowerShell read-only cmdlets
# Get-ChildItem, Select-String, Get-Content, Test-Path, Get-Process, Get-Command
ps_ro_regex = re.compile(r"^\s*(Get-ChildItem|Select-String|Get-Content|Test-Path|Get-Process|Get-Command|dir|ls|cat)\b", re.IGNORECASE)

# Family B: Git read-only variants
# git status with flags, git -C <dir> status/diff/log, git --no-pager
git_ro_regex = re.compile(r"^\s*git\s+(?:(?:-C\s+\S+|--no-pager)\s+)?(?:status(?:\s+.*)?|diff(?:\s+.*)?|log(?:\s+.*)?)$", re.IGNORECASE)

# Family C: Workspace-scoped writes (replace_file_content & write_to_file)
# (tools replace_file_content and write_to_file)

# Family D: manage_task (status)
# tool == manage_task, action == status

families = {
    "PowerShell Read-Only Cmdlets": {
        "matches": [e for e in human_prompt_events if e["tool"] == "run_command" and ps_ro_regex.search(e["cmd"])]
    },
    "Git Read-Only Variants (flags/-C/--no-pager)": {
        "matches": [e for e in human_prompt_events if e["tool"] == "run_command" and git_ro_regex.search(e["cmd"])]
    },
    "Workspace File Edits (replace_file_content)": {
        "matches": [e for e in human_prompt_events if e["tool"] == "replace_file_content"]
    },
    "Workspace File Writes (write_to_file)": {
        "matches": [e for e in human_prompt_events if e["tool"] == "write_to_file"]
    },
    "Manage Task Status (manage_task)": {
        "matches": [e for e in human_prompt_events if e["tool"] == "manage_task" and e["rec"].get("tool_args", {}).get("Action") == "status"]
    },
}

print(f"{'Candidate L1 Family':<45} {'Human Prompts':<14} {'Saved / 100 Cmds'}")
print("-" * 80)
ranked_families = sorted(families.items(), key=lambda x: -len(x[1]["matches"]))
for name, data in ranked_families:
    cnt = len(data["matches"])
    saved_per_100 = cnt / total_clean_pre * 100
    print(f"{name:<45} {cnt:<14} {saved_per_100:>6.2f}")
