"""
L1 Policy Latency Profiler by Rule Family.
Measures execution time of HardPolicyEngine.evaluate() across all real trace steps.
Identifies the slowest 20 real commands per rule family (Family A Git, Family B PowerShell, Family C Writes, Ambiguous).
"""

import json
from pathlib import Path
import time
from typing import Any, Dict, List, Tuple
import numpy as np

from agent_airlock.policy.engine import HardPolicyEngine
from agent_airlock.policy.default_rules import get_default_rules


def classify_family(tool_name: str, tool_args: Dict[str, Any], rule_id: str | None) -> str:
    if tool_name in ("write_to_file", "replace_file_content"):
        return "Family C (File Mutations/Writes)"

    if tool_name == "run_command":
        cmd = tool_args.get("CommandLine", "") or tool_args.get("command", "") or ""
        cmd_stripped = cmd.strip()
        cmd_lower = cmd_stripped.lower()

        # Git commands
        if (rule_id and "git" in rule_id) or cmd_lower.startswith("git ") or cmd_lower == "git":
            return "Family A (Git Inspection/Ops)"

        # PowerShell inspection
        ps_cmdlets = ("test-path", "get-childitem", "get-content", "select-string", "dir", "ls", "type", "cat")
        if (rule_id and "powershell" in rule_id) or any(cmd_lower.startswith(c) for c in ps_cmdlets):
            return "Family B (PowerShell Inspection)"

        if any(w in cmd_lower for w in ("remove-item", "rm ", "rmdir", "del ", "mkdir", "copy-item", "cp ", "mv ")):
            return "Family C (File Mutations/Writes)"

        return "Unmatched / Other run_command"

    return f"Other Tool ({tool_name})"


def main():
    traces_dir = Path("data/traces")
    trace_files = sorted(traces_dir.glob("trace_*.json"))
    if not trace_files:
        print("No trace files found in data/traces.")
        return

    engine = HardPolicyEngine(get_default_rules())

    records_by_family: Dict[str, List[Dict[str, Any]]] = {}

    # Warm-up engine regex cache
    for _ in range(5):
        engine.evaluate("run_command", {"CommandLine": "git status"}, workspace_root="C:\\test")
        engine.evaluate("run_command", {"CommandLine": "Test-Path foo.txt"}, workspace_root="C:\\test")
        engine.evaluate("write_to_file", {"TargetFile": "C:\\test\\foo.txt", "CodeContent": "hello"}, workspace_root="C:\\test")

    total_steps = 0

    for tf in trace_files:
        try:
            with open(tf, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            continue

        conv_id = data.get("conversation_id", tf.stem)
        steps = data.get("steps", [])

        for s in steps:
            tool_name = s.get("tool_name", "")
            tool_args = s.get("tool_args", {})
            ws_root = s.get("workspace_root") or "C:\\mock\\workspace"

            t0 = time.perf_counter_ns()
            res = engine.evaluate(tool_name, tool_args, workspace_root=ws_root)
            elapsed_ns = time.perf_counter_ns() - t0

            elapsed_ms = elapsed_ns / 1_000_000.0
            total_steps += 1

            matched_rule = res.rule_id
            family = classify_family(tool_name, tool_args, matched_rule)

            cmd_summary = ""
            if tool_name == "run_command":
                cmd_summary = str(tool_args.get("CommandLine", "") or tool_args.get("command", ""))
            elif tool_name == "write_to_file":
                cmd_summary = f"write_to_file: {tool_args.get('TargetFile', '')} (len={len(str(tool_args.get('CodeContent', '')))})"
            elif tool_name == "replace_file_content":
                cmd_summary = f"replace_file_content: {tool_args.get('TargetFile', '')} (len={len(str(tool_args.get('ReplacementContent', '')))})"
            else:
                cmd_summary = f"{tool_name}: {list(tool_args.keys())}"

            item = {
                "elapsed_ms": elapsed_ms,
                "elapsed_ns": elapsed_ns,
                "tool_name": tool_name,
                "command": cmd_summary,
                "cmd_length": len(cmd_summary),
                "verdict": res.verdict.value,
                "rule_id": matched_rule,
                "reason": res.reason,
                "conv_id": conv_id,
                "step_idx": s.get("step_idx", 0),
            }

            if family not in records_by_family:
                records_by_family[family] = []
            records_by_family[family].append(item)

    print(f"\n================================================================================")
    print(f"L1 POLICY LATENCY PROFILING REPORT ({total_steps} total trace steps across {len(trace_files)} traces)")
    print(f"================================================================================\n")

    summary_rows = []
    for fam, items in sorted(records_by_family.items()):
        lats = [it["elapsed_ms"] for it in items]
        cnt = len(lats)
        p50 = np.percentile(lats, 50)
        p95 = np.percentile(lats, 95)
        p99 = np.percentile(lats, 99)
        max_lat = np.max(lats)
        mean_lat = np.mean(lats)

        summary_rows.append({
            "Family": fam,
            "Count": cnt,
            "p50_ms": p50,
            "p95_ms": p95,
            "p99_ms": p99,
            "max_ms": max_lat,
            "mean_ms": mean_lat,
        })
        print(f"Family: {fam} (Count: {cnt})")
        print(f"  Latency: p50={p50:.3f} ms | p95={p95:.3f} ms | p99={p99:.3f} ms | max={max_lat:.3f} ms | mean={mean_lat:.3f} ms\n")

    # Now print the slowest 20 real commands per rule family
    target_families = [
        "Family A (Git Inspection/Ops)",
        "Family B (PowerShell Inspection)",
        "Family C (File Mutations/Writes)",
        "Unmatched / Other run_command",
    ]

    for fam in target_families:
        items = records_by_family.get(fam, [])
        if not items:
            continue
        sorted_items = sorted(items, key=lambda x: x["elapsed_ms"], reverse=True)[:20]

        print(f"\n--------------------------------------------------------------------------------")
        print(f"SLOWEST 20 REAL COMMANDS: {fam}")
        print(f"--------------------------------------------------------------------------------")
        print(f"{'Rank':<4} | {'Latency (ms)':<12} | {'Length':<6} | {'Verdict':<8} | {'Rule ID':<30} | Command")
        print("-" * 115)
        for i, it in enumerate(sorted_items, 1):
            cmd_preview = it["command"].replace("\n", "\\n")
            if len(cmd_preview) > 60:
                cmd_preview = cmd_preview[:57] + "..."
            rule_str = it["rule_id"] or it["verdict"]
            print(f"{i:<4} | {it['elapsed_ms']:<12.3f} | {it['cmd_length']:<6} | {it['verdict']:<8} | {rule_str:<30} | {cmd_preview}")

    # Output JSON summary for docs
    out_json = {
        "total_steps": total_steps,
        "traces_count": len(trace_files),
        "summary": summary_rows,
        "slowest_by_family": {
            fam: sorted(records_by_family.get(fam, []), key=lambda x: x["elapsed_ms"], reverse=True)[:20]
            for fam in target_families if fam in records_by_family
        }
    }
    Path("private").mkdir(exist_ok=True)
    with open("private/l1-latency-profile.json", "w", encoding="utf-8") as f:
        json.dump(out_json, f, indent=2)
    print(f"\nSaved detailed profile data to private/l1-latency-profile.json.")


if __name__ == "__main__":
    main()
