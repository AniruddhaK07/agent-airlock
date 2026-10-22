"""
Deep Dive: ASK Composition, Cold-Start Analysis, and PreToolUse Accounting on Clean Corpus.
Answers:
1. Complete accounting of all clean PreToolUse events
2. Detailed breakdown of prompted events (ask / force_ask) by reason category
3. Tool distribution and Top 30 command prefixes for prompted events
4. Root cause analysis for why ML auto-allow has only 31 events (timeline, model availability, thresholds)
5. Time-to-ready and cold-start request counts
"""

import json
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

AUDIT_PATH = Path("private/audit.jsonl")


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


def main():
    print("=" * 80)
    print("CLEAN CORPUS ASK COMPOSITION & PRETOOLUSE ACCOUNTING")
    print("=" * 80)

    total_clean = 0
    clean_pre = []
    clean_post = []

    with open(AUDIT_PATH, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if is_test_record(rec):
                continue
            total_clean += 1
            if rec.get("event_type") == "PreToolUse":
                clean_pre.append((line_no, rec))
            elif rec.get("event_type") == "PostToolUse":
                clean_post.append((line_no, rec))

    print(f"Total Clean Records: {total_clean}")
    print(f"  Clean PreToolUse : {len(clean_pre)}")
    print(f"  Clean PostToolUse: {len(clean_post)}")

    # 1. Full Accounting of PreToolUse decisions
    pre_decisions = Counter(r.get("final_decision") for _, r in clean_pre)
    pre_verdicts = Counter(r.get("policy_verdict") for _, r in clean_pre)
    has_jev = Counter(r.get("jev_evaluation") is not None for _, r in clean_pre)

    print("\n--- 1. PreToolUse Decision Accounting ---")
    for dec, cnt in pre_decisions.most_common():
        print(f"  final_decision = '{dec}': {cnt} ({cnt/len(clean_pre)*100:.2f}%)")

    print("\nPolicy Verdict Breakdown for PreToolUse:")
    for verd, cnt in pre_verdicts.most_common():
        print(f"  policy_verdict = '{verd}': {cnt} ({cnt/len(clean_pre)*100:.2f}%)")

    # Accounting for the ~1,000 PreToolUse events not in allow/ML/ask:
    # Let's inspect all non-(allow/ask/force_ask) decisions
    non_standard = [r for _, r in clean_pre if r.get("final_decision") not in ("allow", "ask", "force_ask")]
    print(f"\nNon-standard final_decisions (outside allow/ask/force_ask): {len(non_standard)}")
    for r in non_standard[:5]:
        print(f"  decision={r.get('final_decision')}, rule={r.get('matched_rule_id')}, reason={r.get('reason')}")

    # 2. ASK / FORCE_ASK Breakdown by Reason
    prompted = [r for _, r in clean_pre if r.get("final_decision") in ("ask", "force_ask")]
    print(f"\n--- 2. Prompted Events (N={len(prompted)}) Reason Breakdown ---")
    
    reason_categories = Counter()
    cold_start_count = 0
    circuit_breaker_count = 0
    ml_evaluated_asks = 0
    ambiguous_without_ml = 0
    other_reasons = Counter()

    for r in prompted:
        reason = str(r.get("reason", "") or "")
        cb = r.get("circuit_breaker_tripped", False) or r.get("final_decision") == "force_ask"
        jev = r.get("jev_evaluation")

        if cb or "circuit breaker" in reason.lower() or "force_ask" in r.get("final_decision", ""):
            circuit_breaker_count += 1
            reason_categories["circuit_breaker_force_ask"] += 1
        elif "model initializing" in reason.lower() or "background" in reason.lower():
            cold_start_count += 1
            reason_categories["cold_start_model_initializing"] += 1
        elif jev is not None:
            ml_evaluated_asks += 1
            # Check route / rubric
            route = jev.get("choice_route") if isinstance(jev, dict) else getattr(jev, "choice_route", "unknown")
            blast = jev.get("score_blast_radius") if isinstance(jev, dict) else getattr(jev, "score_blast_radius", 0)
            reason_categories[f"ml_evaluated_ask (route={route})"] += 1
        elif "ambiguous" in reason.lower() or r.get("policy_verdict") == "ambiguous":
            ambiguous_without_ml += 1
            reason_categories["ambiguous_no_ml_evaluation"] += 1
        else:
            other_reasons[reason[:60]] += 1
            reason_categories["other"] += 1

    for cat, cnt in reason_categories.most_common():
        print(f"  {cat:35s}: {cnt:5d} ({cnt/len(prompted)*100:5.2f}%)")

    # 3. Prompted Events by Tool
    tool_counts = Counter(r.get("tool_name", "") for r in prompted)
    print("\n--- 3. Prompted Events by Tool ---")
    for tname, cnt in tool_counts.most_common():
        print(f"  {tname:25s}: {cnt:5d} ({cnt/len(prompted)*100:5.2f}%)")

    # 4. Top 30 Command Prefixes for Prompted Events
    cmd_prefixes = Counter()
    for r in prompted:
        tool_args = r.get("tool_args", {})
        if isinstance(tool_args, dict):
            cmd = tool_args.get("CommandLine", "") or tool_args.get("command", "") or ""
            if cmd:
                tokens = cmd.strip().split()
                if tokens:
                    # 1-word prefix
                    cmd_prefixes[tokens[0]] += 1
                    # 2-word prefix if e.g. git commit, docker run, npm run, etc.
                    if len(tokens) > 1 and tokens[0] in ("git", "npm", "docker", "cargo", "pip", "python", "pnpm", "yarn", "go"):
                        cmd_prefixes[f"{tokens[0]} {tokens[1]}"] += 1

    print("\n--- 4. Top 30 Command Prefixes in Prompted Events ---")
    for prefix, cnt in cmd_prefixes.most_common(30):
        print(f"  {prefix:25s}: {cnt:5d}")

    # 5. Root Cause of ML Auto-Allow (Only 31 events)
    print("\n--- 5. ML Model Availability & Auto-Allow Investigation ---")
    total_with_jev = sum(1 for _, r in clean_pre if r.get("jev_evaluation") is not None)
    print(f"Clean PreToolUse records with jev_evaluation populated: {total_with_jev} of {len(clean_pre)} ({total_with_jev/len(clean_pre)*100:.2f}%)")
    
    # Check timestamp distribution of records with JEV vs without JEV
    jev_timestamps = []
    no_jev_timestamps = []
    for _, r in clean_pre:
        ts_str = r.get("timestamp")
        if ts_str:
            try:
                dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                if r.get("jev_evaluation") is not None:
                    jev_timestamps.append(dt)
                else:
                    no_jev_timestamps.append(dt)
            except Exception:
                pass

    if jev_timestamps:
        print(f"JEV evaluations date range: {min(jev_timestamps)} to {max(jev_timestamps)}")
    if no_jev_timestamps:
        print(f"Non-JEV records date range: {min(no_jev_timestamps)} to {max(no_jev_timestamps)}")

    # For the records WITH jev_evaluation: what were the outcomes?
    jev_outcomes = Counter()
    for _, r in clean_pre:
        if r.get("jev_evaluation") is not None:
            dec = r.get("final_decision")
            jev = r.get("jev_evaluation", {})
            rt = jev.get("choice_route")
            conf = jev.get("choice_confidence")
            blast = jev.get("score_blast_radius")
            jev_outcomes[f"final={dec}, route={rt}"] += 1

    print("\nOutcomes of all events that ran through ML model:")
    for out, cnt in jev_outcomes.most_common():
        print(f"  {out}: {cnt}")


if __name__ == "__main__":
    main()
