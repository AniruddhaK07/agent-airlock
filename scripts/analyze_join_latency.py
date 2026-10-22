"""
Join Latency Analysis & Histogram for Agent Airlock v2 (Fix 1).
Analyzes the delay between PreToolUse (ask/force_ask) and PostToolUse:
- Requires non-empty conversation_id
- Applies max 10-minute (600s) window for correlation
- Classifies into latency_class: host_auto (<1.5s) vs human_prompt (>=1.5s <=600s) vs timeout/no_post
- Computes latency histogram and splits ASK counts / approval fatigue
"""

import json
from datetime import datetime
from pathlib import Path
from collections import defaultdict, Counter
import numpy as np

AUDIT_PATH = Path("private/audit.jsonl")
MAX_WINDOW_SECONDS = 600.0  # 10 minutes
HOST_AUTO_CUTOFF_SECONDS = 1.5  # < 1.5s indicates host auto-approval rule


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


def main():
    print("=" * 80)
    print("PRE->POST JOIN LATENCY HISTOGRAM & APPROVAL CLASSIFICATION")
    print("=" * 80)

    clean_pre_asks = []
    clean_post_events = defaultdict(list)  # (cid, step_idx, tool_name) -> list of post records
    total_clean_pre = 0

    with open(AUDIT_PATH, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if is_test_record(rec):
                continue

            cid = str(rec.get("conversation_id", "") or "").strip()
            # Requirement: non-empty conversation_id
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

    print(f"Total Clean PreToolUse (non-empty cid): {total_clean_pre}")
    print(f"Total Clean Prompted Events (ASK / FORCE_ASK): {len(clean_pre_asks)}")

    # Correlate Pre -> Post
    delays = []
    host_auto_records = []
    human_prompt_records = []
    window_timeout_records = []
    no_post_records = []

    for lno, pre in clean_pre_asks:
        cid = pre.get("conversation_id")
        sidx = pre.get("step_idx")
        tool = pre.get("tool_name")
        key = (cid, sidx, tool)

        pre_ts = parse_timestamp(pre.get("timestamp"))
        posts = clean_post_events.get(key, [])

        if not posts or pre_ts is None:
            no_post_records.append((pre, None))
            continue

        # Find matching post within window
        matched_post = None
        min_delta = None

        for post in posts:
            post_ts = parse_timestamp(post.get("timestamp"))
            if post_ts and post_ts >= pre_ts:
                delta = (post_ts - pre_ts).total_seconds()
                if min_delta is None or delta < min_delta:
                    min_delta = delta
                    matched_post = post

        if min_delta is not None:
            if min_delta <= MAX_WINDOW_SECONDS:
                delays.append(min_delta)
                if min_delta < HOST_AUTO_CUTOFF_SECONDS:
                    host_auto_records.append((pre, matched_post, min_delta))
                else:
                    human_prompt_records.append((pre, matched_post, min_delta))
            else:
                window_timeout_records.append((pre, matched_post, min_delta))
        else:
            no_post_records.append((pre, None))

    total_prompted = len(clean_pre_asks)
    total_approved = len(delays)
    total_unapproved = len(no_post_records) + len(window_timeout_records)

    print("\n--- 1. Join Outcomes (Max Window = 10 min) ---")
    print(f"  Approved within 10-min window : {total_approved:5d} ({total_approved/total_prompted*100:5.2f}%)")
    print(f"  No PostToolUse (denied/aborted): {len(no_post_records):5d} ({len(no_post_records)/total_prompted*100:5.2f}%)")
    print(f"  Window Exceeded (> 10 min)     : {len(window_timeout_records):5d} ({len(window_timeout_records)/total_prompted*100:5.2f}%)")
    print(f"  Total Unapproved / Dropped     : {total_unapproved:5d} ({total_unapproved/total_prompted*100:5.2f}%)")

    print("\n--- 2. Latency Class Split (< 1.5s Cutoff) ---")
    print(f"  host_auto (< 1.5s)             : {len(host_auto_records):5d} ({len(host_auto_records)/total_prompted*100:5.2f}% of ASKs)")
    print(f"  human_prompt (1.5s - 600s)     : {len(human_prompt_records):5d} ({len(human_prompt_records)/total_prompted*100:5.2f}% of ASKs)")
    print(f"  unapproved / timeout           : {total_unapproved:5d} ({total_unapproved/total_prompted*100:5.2f}% of ASKs)")

    # Histogram of approved delays
    delays_arr = np.array(delays)
    p25 = np.percentile(delays_arr, 25)
    p50 = np.percentile(delays_arr, 50)
    p75 = np.percentile(delays_arr, 75)
    p90 = np.percentile(delays_arr, 90)
    p95 = np.percentile(delays_arr, 95)
    p99 = np.percentile(delays_arr, 99)

    print("\n--- 3. Pre->Post Delay Percentiles (Seconds) ---")
    print(f"  p25={p25:.2f}s | p50={p50:.2f}s | p75={p75:.2f}s | p90={p90:.2f}s | p95={p95:.2f}s | p99={p99:.2f}s")
    print(f"  Min={delays_arr.min():.3f}s | Max={delays_arr.max():.2f}s | Mean={delays_arr.mean():.2f}s")

    # Histogram bins
    bins = [
        (0.0, 0.5, "< 0.5s"),
        (0.5, 1.0, "0.5s - 1.0s"),
        (1.0, 1.5, "1.0s - 1.5s"),
        (1.5, 2.0, "1.5s - 2.0s"),
        (2.0, 5.0, "2.0s - 5.0s"),
        (5.0, 10.0, "5.0s - 10.0s"),
        (10.0, 30.0, "10.0s - 30.0s"),
        (30.0, 60.0, "30.0s - 60.0s"),
        (60.0, 180.0, "1.0m - 3.0m"),
        (180.0, 600.0, "3.0m - 10.0m"),
    ]

    print("\n--- 4. Pre->Post Delay Histogram ---")
    print(f"{'Delay Range':<16} | {'Count':<7} | {'Percent':<8} | Cumulative")
    print("-" * 50)
    cum = 0
    for low, high, label in bins:
        cnt = int(np.sum((delays_arr >= low) & (delays_arr < high)))
        cum += cnt
        pct = cnt / len(delays) * 100
        cum_pct = cum / len(delays) * 100
        bar = "#" * int(pct / 2)
        print(f"{label:<16} | {cnt:5d}   | {pct:5.2f}%  | {cum_pct:5.2f}%  {bar}")

    # 5. Approval Fatigue Rate Split
    # Total clean PreToolUse: total_clean_pre
    fatigue_raw = total_prompted / total_clean_pre * 100
    fatigue_human = len(human_prompt_records) / total_clean_pre * 100
    fatigue_auto = len(host_auto_records) / total_clean_pre * 100

    print("\n--- 5. Approval Fatigue Rates (Per 100 Commands) ---")
    print(f"  Total Prompted (Upper Bound) : {fatigue_raw:.2f} ASKs per 100 commands ({total_prompted}/{total_clean_pre})")
    print(f"  True Human Prompts (>= 1.5s) : {fatigue_human:.2f} prompts per 100 commands ({len(human_prompt_records)}/{total_clean_pre})")
    print(f"  Host Auto-Approved (< 1.5s)  : {fatigue_auto:.2f} auto-prompts per 100 commands ({len(host_auto_records)}/{total_clean_pre})")
    print(f"  Human Denials / Timeouts     : {total_unapproved / total_clean_pre * 100:.2f} per 100 commands ({total_unapproved}/{total_clean_pre})")


if __name__ == "__main__":
    main()
