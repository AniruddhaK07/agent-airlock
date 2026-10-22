"""
Regression test verifying zero false positives on replay of historically successful commands.
Enforces the mandatory gate: zero false positives on replay before enforcement mode.
"""

import json
from pathlib import Path
import pytest

from agent_airlock.config import GroundingConfig
from agent_airlock.grounding import GroundingEngine


def test_zero_false_positives_on_historical_replay():
    traces_dir = Path("data/traces")
    if not traces_dir.is_dir():
        pytest.skip("data/traces directory not available")

    trace_files = sorted(traces_dir.glob("trace_*.json"))
    if not trace_files:
        pytest.skip("No trace files found in data/traces/")

    config = GroundingConfig(enabled=True, mode="enforce")
    engine = GroundingEngine(config)

    total_successful = 0
    false_positives = []

    for tf in trace_files:
        try:
            doc = json.loads(tf.read_text(encoding="utf-8"))
        except Exception:
            continue

        for step in doc.get("steps", []):
            if step.get("outcome") == "success":
                total_successful += 1
                tname = step.get("tool_name", "")
                tool_args = step.get("tool_args", {}) or {}
                ws_root = step.get("workspace_root") or ""
                cwd = tool_args.get("Cwd") or tool_args.get("cwd") or ws_root

                res = engine.evaluate(
                    tool_name=tname,
                    tool_args=tool_args,
                    cwd=cwd,
                    workspace_root=ws_root,
                )

                if res.is_failed:
                    false_positives.append({
                        "file": tf.name,
                        "step_idx": step.get("step_idx"),
                        "tool_name": tname,
                        "command": step.get("command", ""),
                        "check_id": res.check_id,
                        "hint": res.hint,
                    })

    assert total_successful > 0, "No successful commands found in trace files"
    assert len(false_positives) == 0, (
        f"Expected 0 false positives on historical replay, but found {len(false_positives)}: "
        f"{false_positives[:5]}"
    )
