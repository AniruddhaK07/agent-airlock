"""
CLI entrypoint for Agent Airlock Rule Suggester (Phase 1.3).
Usage:
    python -m agent_airlock.suggest_rules [--audit-log path] [--min-approvals N] [--output path] [--json]
"""

import argparse
import json
from pathlib import Path
import sys

from agent_airlock.policy.suggester import RuleSuggester


def main():
    parser = argparse.ArgumentParser(description="Agent Airlock Audit-Log Rule Suggester")
    parser.add_argument(
        "--audit-log",
        type=str,
        default="private/audit.jsonl",
        help="Path to audit log (defaults to private/audit.jsonl or ~/.gemini/antigravity-cli/audit.jsonl)",
    )
    parser.add_argument(
        "--min-approvals",
        type=int,
        default=3,
        help="Minimum number of human approvals required to suggest a rule (default: 3)",
    )
    parser.add_argument(
        "--eval-set",
        type=str,
        default="data/eval_set.jsonl",
        help="Path to evaluation set for safety gate (default: data/eval_set.jsonl)",
    )
    parser.add_argument(
        "--host-rules",
        type=str,
        default="private/host-allow-rules.txt",
        help="Path to host allow rules file (default: private/host-allow-rules.txt)",
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Optional path to write generated YAML snippet to (never writes to .airlock-policy.yaml directly)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output structured JSON instead of YAML snippet",
    )
    args = parser.parse_args()

    audit_path = Path(args.audit_log)
    if not audit_path.exists():
        fallback = Path("~/.gemini/antigravity-cli/audit.jsonl").expanduser()
        if fallback.exists():
            audit_path = fallback
        else:
            print(f"Error: Audit log not found at '{args.audit_log}' and fallback '{fallback}' missing.", file=sys.stderr)
            sys.exit(1)

    eval_path = Path(args.eval_set) if args.eval_set else None
    host_path = Path(args.host_rules) if args.host_rules else None

    print(f"Mining audit log '{audit_path}' for human-approved commands (min approvals: {args.min_approvals})...")
    suggester = RuleSuggester(eval_set_path=eval_path, host_rules_path=host_path)
    suggestions = suggester.mine_audit_log(audit_path=audit_path, min_approvals=args.min_approvals)

    print(f"\nDiscovered {len(suggestions)} safe candidate rule(s):")
    if suggestions:
        print(f"{'Rule ID':<35} | {'Saved':<6} | {'Warning':<25} | Pattern")
        print("-" * 105)
        for s in suggestions:
            warning_tag = "[WARN] repo code" if s.executes_repo_controlled_code else "safe"
            saved_cnt = s.prompts_saved or s.approvals_count
            print(f"{s.id:<35} | {saved_cnt:<6} | {warning_tag:<25} | {s.pattern}")

    if args.json:
        data = [s.to_yaml_dict() for s in suggestions]
        out_text = json.dumps(data, indent=2)
    else:
        out_text = suggester.export_yaml(suggestions)

    if args.output:
        out_file = Path(args.output)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(out_text)
        print(f"[PASS] Successfully exported suggested rules to '{out_file}'.")
    else:
        print("\n" + out_text)


if __name__ == "__main__":
    main()
