import json
import re
from datetime import datetime
from pathlib import Path
from collections import defaultdict, Counter

# 1. Load host allow rules
with open("private/host-allow-rules.txt", "r", encoding="utf-8") as f:
    text = "{" + f.read().strip() + "}"
data = json.loads(text)
raw_rules = data.get("allow", [])

command_rules = []
for r in raw_rules:
    m = re.match(r"^command\((.*)\)$", r)
    if m:
        command_rules.append(m.group(1))

print(f"Loaded {len(command_rules)} host command rules.")

# Matching logic
exact_rules = set()
bare_rules = set()
regex_rules = []

for r in command_rules:
    # If regex escaped characters
    if re.search(r"\\\(|\\\)|\\\[|\\\]|\\\.|\\\*", r):
        try:
            # Match start of command
            regex_rules.append(re.compile(f"^{r}", re.IGNORECASE))
        except Exception:
            pass
    elif " " not in r:
        bare_rules.add(r.lower())
    else:
        exact_rules.add(r.strip().lower())

def matches_host_rule(cmd: str) -> bool:
    if not cmd:
        return False
    cmd_clean = cmd.strip()
    cmd_lower = cmd_clean.lower()
    
    # Check exact match
    if cmd_lower in exact_rules:
        return True
        
    # Check bare command
    first_tok = cmd_clean.split()[0].lower() if cmd_clean.split() else ""
    first_tok_bare = re.sub(r"^[.\\/]+", "", first_tok)
    if first_tok in bare_rules or first_tok_bare in bare_rules:
        return True
        
    # Check exact rule prefix
    for er in exact_rules:
        if cmd_lower == er or cmd_lower.startswith(er + " "):
            return True
            
    # Check regex
    for pat in regex_rules:
        if pat.search(cmd_clean):
            return True
            
    return False

# 2. Load clean audit log
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

clean_pre_asks = []
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
                clean_pre_asks.append((line_no, rec))
        elif et == "PostToolUse":
            clean_post_events[key].append(rec)

print(f"Total clean PreToolUse: {total_clean_pre}")
print(f"Total clean prompted events: {len(clean_pre_asks)}")

# Correlate
MAX_WINDOW_SECONDS = 600.0
events_with_delay = []

for lno, pre in clean_pre_asks:
    cid = pre.get("conversation_id")
    sidx = pre.get("step_idx")
    tool = pre.get("tool_name")
    key = (cid, sidx, tool)

    pre_ts = parse_timestamp(pre.get("timestamp"))
    posts = clean_post_events.get(key, [])

    matched_post = None
    min_delta = None

    for post in posts:
        post_ts = parse_timestamp(post.get("timestamp"))
        if post_ts and post_ts >= pre_ts:
            delta = (post_ts - pre_ts).total_seconds()
            if min_delta is None or delta < min_delta:
                min_delta = delta
                matched_post = post

    cmd = ""
    args = pre.get("tool_args", {})
    if isinstance(args, dict):
        cmd = args.get("CommandLine", "") or args.get("command", "")

    events_with_delay.append({
        "line_no": lno,
        "pre": pre,
        "tool": tool,
        "cmd": cmd,
        "delay": min_delta,
        "in_window": (min_delta is not None and min_delta <= MAX_WINDOW_SECONDS)
    })

# Split into classes
host_auto = [e for e in events_with_delay if e["in_window"] and e["delay"] < 1.5]
fast_human = [e for e in events_with_delay if e["in_window"] and 1.5 <= e["delay"] < 2.0]
human_prompt = [e for e in events_with_delay if e["in_window"] and 1.5 <= e["delay"] <= 600.0]
timeout_unapproved = [e for e in events_with_delay if not e["in_window"]]

print("\n" + "="*80)
print("1.5s CUTOFF VALIDATION AGAINST HOST ALLOW RULES")
print("="*80)
print(f"host_auto (<1.5s): {len(host_auto)} ({len(host_auto)/len(clean_pre_asks)*100:.2f}%)")
print(f"fast_human (1.5-2.0s): {len(fast_human)} ({len(fast_human)/len(clean_pre_asks)*100:.2f}%)")
print(f"human_prompt (1.5-600s): {len(human_prompt)} ({len(human_prompt)/len(clean_pre_asks)*100:.2f}%)")
print(f"unapproved / timeout: {len(timeout_unapproved)} ({len(timeout_unapproved)/len(clean_pre_asks)*100:.2f}%)")

# Tools in host_auto
tool_counts_host_auto = Counter(e["tool"] for e in host_auto)
print("\nTools in host_auto (<1.5s):")
for t, c in tool_counts_host_auto.most_common():
    print(f"  {t}: {c} ({c/len(host_auto)*100:.1f}%)")

# Cross check run_command in host_auto
host_auto_cmds = [e for e in host_auto if e["tool"] == "run_command"]
matched_host_auto = [e for e in host_auto_cmds if matches_host_rule(e["cmd"])]
match_rate = len(matched_host_auto) / len(host_auto_cmds) * 100 if host_auto_cmds else 0
print(f"\nrun_command in host_auto: {len(host_auto_cmds)}")
print(f"Matched host-allow-rules.txt: {len(matched_host_auto)} ({match_rate:.2f}%)")

# Sample unmatched host_auto
unmatched_host_auto = [e for e in host_auto_cmds if not matches_host_rule(e["cmd"])]
print(f"Unmatched host_auto run_command: {len(unmatched_host_auto)}")
if unmatched_host_auto:
    print("Sample unmatched commands (first 5):")
    for e in unmatched_host_auto[:5]:
        print(f"  [{e['delay']:.2f}s] {e['cmd'][:80]}")

# Cross check fast_human (1.5-2.0s)
fast_human_cmds = [e for e in fast_human if e["tool"] == "run_command"]
matched_fast_human = [e for e in fast_human_cmds if matches_host_rule(e["cmd"])]
fh_match_rate = len(matched_fast_human) / len(fast_human_cmds) * 100 if fast_human_cmds else 0
print(f"\nfast_human (1.5-2.0s) total: {len(fast_human)}")
print(f"run_command in fast_human: {len(fast_human_cmds)}")
print(f"Matches host-allow-rules.txt (could be host_auto misclassified as human): {len(matched_fast_human)} ({fh_match_rate:.2f}%)")

# Human prompt total analysis
human_cmds = [e for e in human_prompt if e["tool"] == "run_command"]
matched_human = [e for e in human_cmds if matches_host_rule(e["cmd"])]
print(f"\nEntire human_prompt (1.5-600s) run_command: {len(human_cmds)}")
print(f"Matched host-allow-rules.txt: {len(matched_human)} ({len(matched_human)/len(human_cmds)*100:.2f}%)")
