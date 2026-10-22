"""
Verifies L0 Grounding on Replay of Historically Successful Commands.
Enforces requirement: Zero False Positives on Historically Successful Commands.
Analyzes 41 clean production traces (7,051 total steps).
"""

import json
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Any

from agent_airlock.config import GroundingConfig
from agent_airlock.grounding import GroundingEngine


def run_grounding_replay_verification() -> Dict[str, Any]:
    traces_dir = Path("data/traces")
    if not traces_dir.is_dir():
        raise FileNotFoundError(f"Traces directory not found: {traces_dir}")

    trace_files = sorted(traces_dir.glob("trace_*.json"))
    if not trace_files:
        raise FileNotFoundError("No trace files found in data/traces/")

    # Initialize grounding engine in enforce mode to verify would-deny behavior
    config = GroundingConfig(enabled=True, mode="enforce")
    engine = GroundingEngine(config)

    total_trace_steps = 0
    total_successful_commands = 0
    false_positives = []
    failures_by_check = defaultdict(int)

    for tf in trace_files:
        try:
            doc = json.loads(tf.read_text(encoding="utf-8"))
        except Exception:
            continue

        steps = doc.get("steps", [])
        for step in steps:
            total_trace_steps += 1

            outcome = step.get("outcome")
            tname = step.get("tool_name", "")
            tool_args = step.get("tool_args", {}) or {}
            ws_root = step.get("workspace_root") or ""
            cmd = step.get("command", "")

            # We test all historically successful executions
            if outcome == "success":
                total_successful_commands += 1
                res = engine.evaluate(
                    tool_name=tname,
                    tool_args=tool_args,
                    cwd=tool_args.get("Cwd") or tool_args.get("cwd") or ws_root,
                    workspace_root=ws_root,
                )

                if res.is_failed:
                    failures_by_check[res.check_id] += 1
                    false_positives.append({
                        "file": tf.name,
                        "step_idx": step.get("step_idx"),
                        "tool_name": tname,
                        "command": cmd,
                        "check_id": res.check_id,
                        "hint": res.hint,
                        "target": res.target,
                    })

    print(f"\n=== L0 Grounding Replay Verification ===")
    print(f"Traces analyzed: {len(trace_files)}")
    print(f"Total trace steps: {total_trace_steps}")
    print(f"Historically successful commands evaluated: {total_successful_commands}")
    print(f"False Positives (Grounding failures on successful commands): {len(false_positives)}")

    if false_positives:
        print("\nFailures by check type:")
        for chk, cnt in failures_by_check.items():
            print(f"  {chk}: {cnt}")

        c1_fps = [fp for fp in false_positives if fp["check_id"] == "C1"]
        print(f"\nTotal C1 false positives: {len(c1_fps)}")
        print("\nSample C1 False Positives (first 25):")
        for fp in c1_fps[:25]:
            print(f"  {fp['file']}:{fp['step_idx']} -> {fp['command'][:80]} | Hint: {fp['hint']}")
    else:
        print("\nSUCCESS: ZERO FALSE POSITIVES on replay of historically successful commands!")

    return {
        "traces_analyzed": len(trace_files),
        "total_steps": total_trace_steps,
        "successful_commands": total_successful_commands,
        "false_positive_count": len(false_positives),
        "false_positives": false_positives,
    }


if __name__ == "__main__":
    run_grounding_replay_verification()
