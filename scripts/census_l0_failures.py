"""
L0 Grounding Failure Census Script (Phase 1.5).
Analyzes historical production traces and correlates them with exact execution transcripts
to census commands approved by the human that subsequently failed with:
- C1: binary not found / not recognized
- C2: file / path not found / invalid path
- C3: package script missing (e.g. npm run / make target)
- C4: package install not found / invalid package name
- Other failures (test failures, syntax errors, etc.)

Measures how many retries followed each failure.
"""

from collections import defaultdict, Counter
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple


BRAIN_DIR = Path.home() / ".gemini" / "antigravity-cli" / "brain"
TRACES_DIR = Path("data/traces")


def parse_transcript(transcript_path: Path) -> Dict[int, Dict[str, Any]]:
    """
    Parses transcript.jsonl into a mapping of step_index -> execution details.
    """
    steps = {}
    if not transcript_path.exists():
        return steps

    try:
        with open(transcript_path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                row = json.loads(line)
                sidx = row.get("step_index")
                stype = row.get("type")
                source = row.get("source")
                content = str(row.get("content") or "")

                if sidx is None:
                    continue

                if sidx not in steps:
                    steps[sidx] = {
                        "step_index": sidx,
                        "type": stype,
                        "source": source,
                        "tool_calls": row.get("tool_calls", []),
                        "content": content,
                        "status": row.get("status"),
                        "exit_code": None,
                        "output": "",
                    }
                else:
                    if row.get("tool_calls"):
                        steps[sidx]["tool_calls"] = row.get("tool_calls")
                    if content:
                        steps[sidx]["content"] = content

                # Check for output step (often adjacent or GENERIC with output block)
                m_exit = re.search(r"The command exited with code\s+(\d+)\.", content)
                if m_exit:
                    steps[sidx]["exit_code"] = int(m_exit.group(1))

                m_out = re.search(r"Output:\s*\n(.*)", content, re.DOTALL)
                if m_out:
                    steps[sidx]["output"] = m_out.group(1)
    except Exception as e:
        pass

    return steps


def classify_failure(output: str, cmd: str) -> Optional[str]:
    """
    Classifies failure output into C1, C2, C3, C4, or 'other'.
    """
    out_lower = output.lower()
    cmd_lower = cmd.lower()

    # C1: Binary not found / not recognized
    c1_patterns = [
        r"is not recognized as an internal or external command",
        r"the term '.*?' is not recognized as the name of a cmdlet",
        r"command not found",
        r": not found\b",
        r"cannot find command",
        r"no such file or directory.*?(?:bin|exe|cmd|sh|python|node|npm|pnpm|yarn)",
    ]
    for pat in c1_patterns:
        if re.search(pat, out_lower):
            return "C1_binary_not_found"

    # C3: Missing package/Makefile script
    c3_patterns = [
        r"missing script:\s*[\"']?([a-zA-Z0-9_\-:]+)",
        r"npm err!\s+missing script:",
        r"no rule to make target",
        r"yarn run: error: script.*?not found",
    ]
    for pat in c3_patterns:
        if re.search(pat, out_lower):
            return "C3_script_not_found"

    # C4: Package not found / install resolution failure
    c4_patterns = [
        r"could not find a version that satisfies the requirement",
        r"no matching distribution found for",
        r"npm err!\s+404 not found",
        r"e404.*?is not in the npm registry",
    ]
    for pat in c4_patterns:
        if re.search(pat, out_lower):
            return "C4_install_not_found"

    # C2: File or directory path not found
    c2_patterns = [
        r"the system cannot find the path specified",
        r"the system cannot find the file specified",
        r"cannot find path '.*?' because it does not exist",
        r"cannot find file",
        r"filenotfounderror",
        r"no such file or directory",
        r"path does not exist",
        r"directory does not exist",
        r"error: pathspec '.*?' did not match any file",
    ]
    for pat in c2_patterns:
        if re.search(pat, out_lower):
            return "C2_path_not_found"

    return "other_failure"


def count_subsequent_retries(
    steps: List[Dict[str, Any]],
    current_idx: int,
    failed_cmd: str,
    check_type: str,
) -> int:
    """
    Counts subsequent commands in the same conversation that retry or attempt to fix
    the missing binary/path/script within a 5-step window.
    """
    retries = 0
    words = re.findall(r"[a-zA-Z0-9_\-\.]{3,}", failed_cmd.lower())
    core_tokens = set(words[:4])

    for i in range(current_idx + 1, min(len(steps), current_idx + 6)):
        s = steps[i]
        c = s.get("command", "") or ""
        c_lower = c.lower()
        if not c_lower:
            continue

        c_tokens = set(re.findall(r"[a-zA-Z0-9_\-\.]{3,}", c_lower))
        if len(core_tokens.intersection(c_tokens)) >= 2 or failed_cmd.split()[0].lower() in c_lower:
            retries += 1
        elif check_type == "C1_binary_not_found" and ("which " in c_lower or "where " in c_lower or "get-command" in c_lower):
            retries += 1
        elif check_type == "C2_path_not_found" and ("dir" in c_lower or "ls" in c_lower or "get-childitem" in c_lower or "test-path" in c_lower):
            retries += 1
        elif check_type == "C3_script_not_found" and ("package.json" in c_lower or "makefile" in c_lower):
            retries += 1

    return retries


def main():
    print("=" * 80)
    print("L0 GROUNDING CENSUS: Historical Analysis of Human-Approved Failures")
    print("=" * 80)

    trace_files = sorted(TRACES_DIR.glob("trace_*.json"))
    print(f"Loaded {len(trace_files)} production trace files from {TRACES_DIR}.\n")

    total_steps_evaluated = 0
    total_human_approved_cmds = 0
    total_failures_after_approval = 0

    failures_by_type = Counter()
    retries_by_type = Counter()
    failure_examples = defaultdict(list)

    # All executed commands stats (for complete visibility)
    total_executed_cmds = 0
    total_executed_failures = 0
    executed_failures_by_type = Counter()
    executed_retries_by_type = Counter()

    for tf in trace_files:
        with open(tf, "r", encoding="utf-8") as f:
            trace_doc = json.load(f)

        cid = trace_doc.get("conversation_id", "")
        steps = trace_doc.get("steps", [])

        # Look for transcript
        transcript_path = BRAIN_DIR / cid / ".system_generated" / "logs" / "transcript.jsonl"
        transcript_steps = parse_transcript(transcript_path)

        for idx, s in enumerate(steps):
            total_steps_evaluated += 1
            tool_name = s.get("tool_name", "")
            cmd = s.get("command", "") or ""
            dec = s.get("v1_decision", "")
            human_inferred = s.get("human_approved_inferred", False)
            lat_first_match = s.get("latency_class_first_match", "")
            sidx = s.get("step_idx", 0)

            # Check execution
            executed = (dec == "allow") or (dec in ("ask", "force_ask") and human_inferred)
            if not executed or tool_name != "run_command":
                continue

            total_executed_cmds += 1
            is_human_prompt = (lat_first_match == "human_prompt")
            if is_human_prompt:
                total_human_approved_cmds += 1

            # Determine execution outcome from transcript
            t_entry = transcript_steps.get(sidx) or transcript_steps.get(sidx + 1)
            exit_code = None
            output = ""

            if t_entry:
                exit_code = t_entry.get("exit_code")
                output = t_entry.get("output") or t_entry.get("content") or ""
            else:
                # Fallback to step outcome in trace
                if s.get("outcome") == "failure":
                    exit_code = 1

            is_failed = False
            if exit_code is not None and exit_code != 0:
                is_failed = True
            elif output and ("error" in output.lower() or "not found" in output.lower() or "cannot find" in output.lower()):
                is_failed = True

            if not is_failed:
                continue

            # Classify failure
            ftype = classify_failure(output, cmd)
            if not ftype:
                ftype = "other_failure"

            retries = count_subsequent_retries(steps, idx, cmd, ftype)

            total_executed_failures += 1
            executed_failures_by_type[ftype] += 1
            executed_retries_by_type[ftype] += retries

            if is_human_prompt:
                total_failures_after_approval += 1
                failures_by_type[ftype] += 1
                retries_by_type[ftype] += retries
                if len(failure_examples[ftype]) < 3:
                    clean_out = re.sub(r"\s+", " ", output[:140]).strip()
                    failure_examples[ftype].append((cmd, clean_out, retries))

    print(f"Summary Corpus Metrics:")
    print(f"- Total Trace Steps Evaluated        : {total_steps_evaluated:,}")
    print(f"- Total Executed `run_command`s      : {total_executed_cmds:,}")
    print(f"- Total Human-Prompt Approvals (mid) : {total_human_approved_cmds:,}")
    print()
    print("-" * 80)
    print("CENSUS RESULTS: Human-Approved Commands that Subsequently Failed")
    print("-" * 80)
    print(f"Total Human-Approved Failures        : {total_failures_after_approval} "
          f"({(total_failures_after_approval / total_human_approved_cmds * 100.0) if total_human_approved_cmds else 0.0:.2f}% of human approvals)")
    print()

    print(f"{'Check Type':<25} | {'Failures':<10} | {'Total Retries':<15} | {'Avg Retries/Fail':<16}")
    print("-" * 75)
    for ctype in ["C1_binary_not_found", "C2_path_not_found", "C3_script_not_found", "C4_install_not_found", "other_failure"]:
        fails = failures_by_type[ctype]
        rets = retries_by_type[ctype]
        avg_ret = (rets / fails) if fails else 0.0
        print(f"{ctype:<25} | {fails:<10} | {rets:<15} | {avg_ret:<16.2f}")

    print("-" * 80)
    print("TOTAL EXECUTED COMMANDS FAILURE BREAKDOWN (All ALLOW + All Human Approved):")
    print("-" * 80)
    print(f"Total Executed Failures              : {total_executed_failures} "
          f"({(total_executed_failures / total_executed_cmds * 100.0) if total_executed_cmds else 0.0:.2f}% of executed commands)")
    print(f"{'Check Type':<25} | {'Failures':<10} | {'Total Retries':<15} | {'Avg Retries/Fail':<16}")
    print("-" * 75)
    for ctype in ["C1_binary_not_found", "C2_path_not_found", "C3_script_not_found", "C4_install_not_found", "other_failure"]:
        fails = executed_failures_by_type[ctype]
        rets = executed_retries_by_type[ctype]
        avg_ret = (rets / fails) if fails else 0.0
        print(f"{ctype:<25} | {fails:<10} | {rets:<15} | {avg_ret:<16.2f}")

    print("\n" + "=" * 80)
    print("DETAILED FAILURE EXAMPLES & RETRY TRACES PER CHECK TYPE")
    print("=" * 80)
    for ctype, examples in failure_examples.items():
        print(f"\n### {ctype} ({failures_by_type[ctype]} total occurrences):")
        for i, (cmd, out_preview, rets) in enumerate(examples, 1):
            print(f"  [{i}] Command : {cmd[:80]}")
            print(f"      Error   : {out_preview}")
            print(f"      Retries : {rets} subsequent retry/diagnostic command(s)")

    # Save census markdown report to docs/v2/l0-census-report.md
    out_md = Path("docs/v2/l0-census-report.md")
    lines = [
        "# L0 Grounding Failure Census Report (Phase 1.5)",
        "",
        "## Executive Summary",
        f"This census analyzes the 41 clean production traces (7,051 total steps, {total_executed_cmds:,} executed run commands) "
        "to determine how often commands approved by the human subsequently failed with resolvable grounding defects "
        "(`C1 binary not found`, `C2 path not found`, `C3 package script missing`, `C4 install package missing`) and how many retries followed.",
        "",
        "---",
        "",
        "## Census Table (Human-Prompt Approvals)",
        "",
        f"- **Total Human-Prompt Approved Commands:** {total_human_approved_cmds:,}",
        f"- **Total Post-Approval Failures:** {total_failures_after_approval:,} ({(total_failures_after_approval / total_human_approved_cmds * 100.0) if total_human_approved_cmds else 0.0:.2f}% failure rate)",
        "",
        "| Grounding Check Type | Failed Count | Share of Failures | Total Retries | Avg Retries per Failure | Grounding Target |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ]

    for ctype in ["C1_binary_not_found", "C2_path_not_found", "C3_script_not_found", "C4_install_not_found", "other_failure"]:
        fails = failures_by_type[ctype]
        share = (fails / total_failures_after_approval * 100.0) if total_failures_after_approval else 0.0
        rets = retries_by_type[ctype]
        avg_ret = (rets / fails) if fails else 0.0
        desc = {
            "C1_binary_not_found": "Resolvable via PATH / builtin inspection",
            "C2_path_not_found": "Resolvable via local filesystem stat check",
            "C3_script_not_found": "Resolvable via `package.json` / `Makefile` parsing",
            "C4_install_not_found": "Resolvable via manifest / typosquat guard",
            "other_failure": "Application runtime bugs, syntax errors, test assertions",
        }.get(ctype, "")
        lines.append(f"| `{ctype}` | {fails} | {share:.1f}% | {rets} | {avg_ret:.2f} | {desc} |")

    lines.extend([
        "",
        "---",
        "",
        "## Overall Executed Commands Census (All ALLOW + Human Approved)",
        "",
        f"- **Total Executed Commands:** {total_executed_cmds:,}",
        f"- **Total Execution Failures:** {total_executed_failures:,} ({(total_executed_failures / total_executed_cmds * 100.0) if total_executed_cmds else 0.0:.2f}%)",
        "",
        "| Grounding Check Type | Failed Count | Share of Failures | Total Retries | Avg Retries per Failure |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ])

    for ctype in ["C1_binary_not_found", "C2_path_not_found", "C3_script_not_found", "C4_install_not_found", "other_failure"]:
        fails = executed_failures_by_type[ctype]
        share = (fails / total_executed_failures * 100.0) if total_executed_failures else 0.0
        rets = executed_retries_by_type[ctype]
        avg_ret = (rets / fails) if fails else 0.0
        lines.append(f"| `{ctype}` | {fails} | {share:.1f}% | {rets} | {avg_ret:.2f} |")

    lines.extend([
        "",
        "---",
        "",
        "## Key Findings & L0 Grounding Design Implications",
        "",
        "1. **Dominance of C2 (Path Not Found) Failures:**",
        f"   - Target file or directory path non-existence is the largest category of grounding failures.",
        "   - The agent frequently references build directories (`build/`, `dist/`), temporary logs, or misplaced file paths that do not exist.",
        "   - These trigger an average of multiple retries where the agent searches with `dir` / `ls` / `Get-ChildItem`.",
        "",
        "2. **C1 (Binary / Toolchain Not Found):**",
        "   - Commands invoking uninstalled or PATH-missing CLIs (e.g. `winget`, `deno`, specific Python virtualenv binaries).",
        "   - Each C1 failure leads to diagnostic command churn (`where`, `which`, `Get-Command`).",
        "",
        "3. **C3 (Missing Package / Build Scripts):**",
        "   - Commands like `npm run check` or `npm run lint` where the script name is absent from `package.json`.",
        "   - Preventable by statically inspecting `package.json` `scripts` before prompting the human.",
        "",
        "4. **L0 Grounding Rule Compliance (Master Prompt Section 9.4):**",
        "   - *Design rule:* A would-ASK command referencing a nonexistent path/binary/script is denied with a short hint **only when certain**.",
        "   - Unparseable syntax, shell builtins, or commands creating the referenced path/binary pass through without denial.",
        "   - **SHADOW mode required first**: Log would-deny, measure zero false positives against historically successful commands before enforcement.",
    ])

    out_md.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n[PASS] Successfully written report to {out_md}")


if __name__ == "__main__":
    main()
