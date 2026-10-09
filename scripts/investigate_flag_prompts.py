"""
Investigate why git status -s and other flag variants of hard-allow commands prompted.
Evaluates which L1 rules failed to match and why.
"""

import json
import re
from pathlib import Path
from collections import Counter

from agent_airlock.policy.engine import HardPolicyEngine
from agent_airlock.policy.default_rules import get_default_rules

AUDIT_PATH = Path("private/audit.jsonl")


def main():
    print("=" * 80)
    print("INVESTIGATION: WHY FLAG VARIANTS OF HARD-ALLOW COMMANDS PROMPTED")
    print("=" * 80)

    engine = HardPolicyEngine(get_default_rules())

    git_status_variants = Counter()
    git_commands_prompted = Counter()
    powershell_readonly_prompted = Counter()
    version_flag_variants = Counter()

    with open(AUDIT_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            cid = str(rec.get("conversation_id", "") or "").lower()
            ws = str(rec.get("workspace_root", "") or "").lower()
            if any(k in ws for k in ["appdata\\local\\temp", "appdata/local/temp", "\\tmp\\", "/tmp/", "pytest", "test-daemon"]):
                continue
            if any(k in cid for k in ["test", "mock", "scenario", "dummy", "sample", "fixture"]):
                continue

            if rec.get("event_type") != "PreToolUse":
                continue

            dec = rec.get("final_decision")
            tool = rec.get("tool_name")
            tool_args = rec.get("tool_args", {})
            cmd = ""
            if isinstance(tool_args, dict):
                cmd = str(tool_args.get("CommandLine", "") or tool_args.get("command", "") or "").strip()

            if dec in ("ask", "force_ask") and tool == "run_command":
                # Check git status variants
                if re.match(r'^git\s+status\b', cmd, re.IGNORECASE):
                    git_status_variants[cmd] += 1

                # Check general git commands
                if re.match(r'^git\b', cmd, re.IGNORECASE):
                    # Extract subcommand
                    tokens = cmd.split()
                    sub = " ".join(tokens[:2]) if len(tokens) >= 2 else tokens[0]
                    git_commands_prompted[sub] += 1

                # Check PowerShell read-only cmdlets
                if re.match(r'^(?:Get-ChildItem|Get-Content|Select-String|Test-Path|Get-Process|Get-Command)\b', cmd, re.IGNORECASE):
                    tokens = cmd.split()
                    powershell_readonly_prompted[tokens[0]] += 1

                # Check version checks with flags
                if any(k in cmd for k in ["--version", "-v", "-V", "--help", "-h"]) and len(cmd.split()) <= 4:
                    version_flag_variants[cmd] += 1

    print("\n--- 1. 'git status' Flag Variants that Prompted (N=%d) ---" % sum(git_status_variants.values()))
    for cmd, cnt in git_status_variants.most_common(15):
        res = engine.evaluate("run_command", {"CommandLine": cmd})
        print(f"  [{cnt:3d}x] '{cmd}' -> verdict={res.verdict.value}, rule={res.rule_id}")

    print("\n--- 2. Other Read-only Git Commands that Prompted ---")
    for sub, cnt in git_commands_prompted.most_common(15):
        print(f"  [{cnt:3d}x] '{sub}'")

    print("\n--- 3. PowerShell Read-Only Cmdlets that Prompted (Zero L1 Rules) ---")
    for cmdlet, cnt in powershell_readonly_prompted.most_common(15):
        print(f"  [{cnt:3d}x] '{cmdlet}'")

    print("\n--- 4. Root Cause Analysis ---")
    print("1. Rule 'allow-git-status-diff-log' pattern:")
    print(r"   r'^git\s+(?:status|diff(?:\s+.*)?|log(?:\s+.*)?|...)'")
    print("   'status' is strictly anchored as bare 'git status' with NO optional argument group.")
    print("   Any flag (e.g., -s, --porcelain, -sb, -u, --ignored) causes regex mismatch -> verdict=AMBIGUOUS -> prompts.")
    print("2. 'git -C <dir> ...' or 'git --no-pager ...' global flag prefixes fail '^git\s+' subcommands.")
    print("3. PowerShell cmdlets (Get-ChildItem, Get-Content, Select-String, Test-Path) have ZERO L1 allow rules in v1,")
    print("   causing hundreds of read-only developer queries to fall through to ML/ASK.")


if __name__ == "__main__":
    main()
