"""
Analyzes PreToolUse -> PostToolUse delay comparing v1 ALLOWed vs v1 ASKed across tools in private/audit.jsonl.
"""

import json
from datetime import datetime
from pathlib import Path
from collections import defaultdict
import numpy as np


def parse_timestamp(ts_str):
    if not ts_str:
        return None
    try:
        if ts_str.endswith("Z"):
            ts_str = ts_str[:-1] + "+00:00"
        return datetime.fromisoformat(ts_str)
    except Exception:
        return None


def main():
    audit_path = Path("private/audit.jsonl")
    if not audit_path.exists():
        print("private/audit.jsonl not found.")
        return

    pre_events = []
    post_map = defaultdict(list)

    with open(audit_path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except Exception:
                continue

            ev_type = event.get("event_type") or event.get("event")
            tname = event.get("tool_name")
            cid = event.get("conversation_id")
            sidx = event.get("step_idx")

            if ev_type == "PreToolUse":
                pre_events.append(event)
            elif ev_type == "PostToolUse":
                post_map[(cid, sidx, tname)].append(event)

    delays_by_category = defaultdict(list)

    for pre in pre_events:
        cid = pre.get("conversation_id")
        sidx = pre.get("step_idx")
        tname = pre.get("tool_name")
        dec = pre.get("final_decision", "unknown").lower()
        pre_ts = parse_timestamp(pre.get("timestamp"))

        posts = post_map.get((cid, sidx, tname), [])
        min_delta = None
        for p in posts:
            p_ts = parse_timestamp(p.get("timestamp"))
            if p_ts and pre_ts and p_ts >= pre_ts:
                delta = (p_ts - pre_ts).total_seconds()
                if min_delta is None or delta < min_delta:
                    min_delta = delta

        if min_delta is not None and min_delta <= 600.0:
            if tname in ("write_to_file", "replace_file_content"):
                cat = f"writes_{dec}"
            elif tname == "run_command":
                cat = f"run_cmd_{dec}"
            elif tname == "view_file":
                cat = f"view_file_{dec}"
            else:
                cat = f"{tname}_{dec}"
            delays_by_category[cat].append(min_delta)

    print("=" * 80)
    print("HOST-SUPPRESSION OBSERVATIONAL EVIDENCE: DELAY ANALYSIS BY TOOL & VERDICT")
    print("=" * 80)

    for cat in sorted(delays_by_category.keys()):
        delays = sorted(delays_by_category[cat])
        n = len(delays)
        arr = np.array(delays)
        p10 = np.percentile(arr, 10)
        p25 = np.percentile(arr, 25)
        p50 = np.percentile(arr, 50)
        p75 = np.percentile(arr, 75)
        p90 = np.percentile(arr, 90)
        p95 = np.percentile(arr, 95)
        p99 = np.percentile(arr, 99)

        lt_1_5s = np.mean(arr < 1.5) * 100
        ge_1_5s = np.mean(arr >= 1.5) * 100
        ge_5s = np.mean(arr >= 5.0) * 100
        ge_10s = np.mean(arr >= 10.0) * 100

        print(f"\nCategory: {cat} (N = {n})")
        print(f"  Min: {arr[0]:.3f}s | p25: {p25:.3f}s | Median (p50): {p50:.3f}s | p75: {p75:.3f}s | p90: {p90:.3f}s | p95: {p95:.3f}s | Max: {arr[-1]:.3f}s")
        print(f"  Distribution: <1.5s: {lt_1_5s:.1f}% | >=1.5s: {ge_1_5s:.1f}% | >=5.0s: {ge_5s:.1f}% | >=10.0s: {ge_10s:.1f}%")

    print("\n" + "=" * 80)


if __name__ == "__main__":
    main()
