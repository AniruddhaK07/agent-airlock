"""
Extract 10 sample records for each audit hygiene exclusion heuristic.
"""

import json
from pathlib import Path

AUDIT_PATH = Path("private/audit.jsonl")

temp_samples = []
conv_samples = []

with open(AUDIT_PATH, "r", encoding="utf-8") as f:
    for line_no, line in enumerate(f, 1):
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        cid = str(rec.get("conversation_id", "") or "").lower()
        ws = str(rec.get("workspace_root", "") or "").lower()
        cmd = ""
        tool_args = rec.get("tool_args", {})
        if isinstance(tool_args, dict):
            cmd = str(tool_args.get("CommandLine", "") or tool_args.get("command", "") or "")

        is_temp = any(k in ws for k in ["appdata\\local\\temp", "appdata/local/temp", "\\tmp\\", "/tmp/", "pytest", "test-daemon"])
        is_conv = any(k in cid for k in ["test", "mock", "scenario", "dummy", "sample", "fixture"])

        if is_temp and len(temp_samples) < 10:
            temp_samples.append((line_no, rec))
        if is_conv and len(conv_samples) < 10:
            conv_samples.append((line_no, rec))

        if len(temp_samples) >= 10 and len(conv_samples) >= 10:
            break

print("=" * 80)
print("10 SAMPLE RECORDS EXCLUDED BY 'temp_or_test_workspace' HEURISTIC")
print("=" * 80)
for idx, (lno, r) in enumerate(temp_samples, 1):
    print(f"[{idx:02d}] Line {lno}: tool={r.get('tool_name')}, decision={r.get('final_decision')}, ws={r.get('workspace_root')}")
    cmd = r.get('tool_args', {}).get('CommandLine', '')
    if cmd:
        print(f"     Command: {cmd}")
    print()

print("=" * 80)
print("10 SAMPLE RECORDS EXCLUDED BY 'conv_id_test_pattern' HEURISTIC")
print("=" * 80)
for idx, (lno, r) in enumerate(conv_samples, 1):
    print(f"[{idx:02d}] Line {lno}: conv_id={r.get('conversation_id')}, tool={r.get('tool_name')}, decision={r.get('final_decision')}")
    cmd = r.get('tool_args', {}).get('CommandLine', '')
    if cmd:
        print(f"     Command: {cmd}")
    print()
