"""
Audit Corpus Hygiene and Schema Analyzer for Agent Airlock v2.
Analyzes private/audit.jsonl to:
1. Parse record schema and verify field completeness
2. Distinguish human approvals vs ML auto-allows vs policy decisions
3. Identify test-generated records using explicit heuristics
4. Produce before-and-after counts
"""

import json
import re
from collections import Counter
from pathlib import Path

AUDIT_PATH = Path("private/audit.jsonl")


def analyze():
    if not AUDIT_PATH.exists():
        print(f"Error: {AUDIT_PATH} does not exist.")
        return

    total = 0
    event_types = Counter()
    final_decisions = Counter()
    policy_verdicts = Counter()
    jev_counts = Counter()
    matched_rules = Counter()

    # Heuristic counters
    test_reasons = Counter()
    clean_records = []
    excluded_records = []

    # Check discriminability: how to tell human approval vs ML auto-allow
    # When final_decision == "allow":
    # Case 1: policy_verdict == "allow" (deterministic rule allow)
    # Case 2: policy_verdict == "ask" / "ambiguous" and jev_evaluation is populated and jev_evaluation.choice_route == "deterministic-safe" -> ML auto-allow
    # Case 3: Is there a PostToolUse event? Or an event where human explicitly approved?
    allow_breakdown = Counter()

    with open(AUDIT_PATH, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            total += 1
            try:
                record = json.loads(line)
            except Exception as e:
                test_reasons["corrupt_json"] += 1
                excluded_records.append((line_no, "corrupt_json", line[:100]))
                continue

            event_type = record.get("event_type")
            final_dec = record.get("final_decision")
            pol_verd = record.get("policy_verdict")
            matched_rule = record.get("matched_rule_id")
            jev_eval = record.get("jev_evaluation")
            conv_id = str(record.get("conversation_id", "") or "")
            ws_root = str(record.get("workspace_root", "") or "")
            tool_args = record.get("tool_args", {})
            cmd = ""
            if isinstance(tool_args, dict):
                cmd = str(tool_args.get("CommandLine", "") or tool_args.get("command", "") or "")

            event_types[event_type] += 1
            final_decisions[final_dec] += 1
            policy_verdicts[pol_verd] += 1
            matched_rules[matched_rule] += 1

            # Analysis of ALLOW decisions:
            if final_dec == "allow":
                if pol_verd == "allow":
                    allow_breakdown["policy_hard_allow"] += 1
                elif jev_eval is not None:
                    allow_breakdown["ml_auto_allow"] += 1
                else:
                    allow_breakdown["other_allow_no_ml_no_policy"] += 1

            # Heuristics for test-generated records:
            # H1: Conversation ID contains test, mock, scenario, sample, or dummy
            # H2: Workspace root is in Temp / tmp directory or contains test / mock
            # H3: Tool command explicitly executes test harness commands with dummy fixtures
            # H4: Missing / empty conversation ID AND workspace in Temp
            is_test = False
            reasons = []

            # Check conversation_id
            lower_cid = conv_id.lower()
            if any(k in lower_cid for k in ["test", "mock", "scenario", "dummy", "sample", "fixture"]):
                is_test = True
                reasons.append("conv_id_test_pattern")

            # Check workspace_root
            lower_ws = ws_root.lower()
            if any(k in lower_ws for k in ["appdata\\local\\temp", "appdata/local/temp", "\\tmp\\", "/tmp/", "pytest", "test-daemon"]):
                is_test = True
                reasons.append("temp_or_test_workspace")

            # Check if command has test artifacts
            lower_cmd = cmd.lower()
            if any(k in lower_cmd for k in ["test-daemon", "scenario-attack", "project_z", "echo test"]):
                is_test = True
                reasons.append("test_command_artifact")

            if is_test:
                for r in reasons:
                    test_reasons[r] += 1
                excluded_records.append((line_no, reasons, record))
            else:
                clean_records.append((line_no, record))

    print("=" * 80)
    print(f"AUDIT CORPUS ANALYSIS: {AUDIT_PATH}")
    print("=" * 80)
    print(f"Total Raw Records: {total}")
    print(f"Event Types: {dict(event_types)}")
    print(f"Final Decisions: {dict(final_decisions)}")
    print(f"Policy Verdicts: {dict(policy_verdicts)}")
    print(f"Allow Breakdown: {dict(allow_breakdown)}")
    print()
    print("Top 10 Matched Rules:")
    for rule, cnt in matched_rules.most_common(10):
        print(f"  {rule}: {cnt}")
    print()
    print("=" * 80)
    print("TEST-GENERATED RECORD EXCLUSION SUMMARY")
    print("=" * 80)
    print(f"Excluded Test Records: {len(excluded_records)} ({len(excluded_records)/total*100:.2f}%)")
    print(f"Clean Production Records: {len(clean_records)} ({len(clean_records)/total*100:.2f}%)")
    print("Exclusion Heuristics Breakdown:")
    for r, cnt in test_reasons.most_common():
        print(f"  {r}: {cnt}")

    # Inspect clean records sample
    if clean_records:
        print("\nClean Records Sample (first 3):")
        for lno, rec in clean_records[:3]:
            print(f"  Line {lno}: event_type={rec.get('event_type')}, conv={rec.get('conversation_id')}, tool={rec.get('tool_name')}, final={rec.get('final_decision')}, ws={rec.get('workspace_root')}")
            if "CommandLine" in rec.get("tool_args", {}):
                print(f"    Command: {rec['tool_args']['CommandLine'][:80]}")

    # Let's inspect conversation IDs in clean records
    clean_convs = Counter(r.get("conversation_id", "") for _, r in clean_records)
    print(f"\nUnique Clean Conversations: {len(clean_convs)}")
    print("Top 5 Clean Conversations by event count:")
    for cid, cnt in clean_convs.most_common(5):
        print(f"  '{cid}': {cnt} events")

    # =========================================================================
    # CORRELATION ANALYSIS: Human Approvals vs ML Auto-Allows
    # =========================================================================
    print()
    print("=" * 80)
    print("CORRELATION ANALYSIS: HUMAN APPROVALS VS ML AUTO-ALLOWS")
    print("=" * 80)
    # Map PreToolUse ask events by (conversation_id, step_idx, tool_name)
    # Also collect PostToolUse events
    pre_ask_events = {}
    post_event_keys = set()
    post_event_details = {}

    for lno, rec in clean_records:
        et = rec.get("event_type")
        cid = rec.get("conversation_id", "")
        sidx = rec.get("step_idx")
        tname = rec.get("tool_name")
        key = (cid, sidx, tname)
        if et == "PreToolUse" and rec.get("final_decision") in ("ask", "force_ask"):
            pre_ask_events[key] = (lno, rec)
        elif et == "PostToolUse":
            post_event_keys.add(key)
            post_event_details[key] = (lno, rec)

    human_approved = 0
    human_rejected_or_aborted = 0

    for key, (lno, pre_rec) in pre_ask_events.items():
        if key in post_event_keys:
            human_approved += 1
        else:
            human_rejected_or_aborted += 1

    print(f"Clean PreToolUse Prompted to Human (ASK / FORCE_ASK): {len(pre_ask_events)}")
    print(f"  - Correlated with PostToolUse (Human Approved): {human_approved} ({human_approved/len(pre_ask_events)*100:.1f}%)")
    print(f"  - No PostToolUse found (Human Denied / Aborted): {human_rejected_or_aborted} ({human_rejected_or_aborted/len(pre_ask_events)*100:.1f}%)")
    print(f"ML Auto-Allows in clean corpus: {allow_breakdown.get('ml_auto_allow', 0)}")
    print(f"Policy Hard-Allows in clean corpus: {allow_breakdown.get('policy_hard_allow', 0)}")


if __name__ == "__main__":
    analyze()
