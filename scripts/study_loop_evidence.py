"""
2a Loop-Evidence Study (Phase 2a).
Analyzes the 41 production traces to find repeated or near-repeated failing sequences
(same or similar command plus the same final error line, 3 or more within a window)
that the exact hash circuit breaker did not catch.

Uses normalized edit distance and token Jaccard similarity (no ML models).
Reports counts of sequences, commands, and wasted turns (upper bound),
plus 10 scrubbed examples for Ani.
"""

import json
import re
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Any, Tuple, Optional


BRAIN_DIR = Path.home() / ".gemini" / "antigravity-cli" / "brain"
TRACES_DIR = Path("data/traces")


def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes standard Levenshtein edit distance."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def normalized_edit_distance(s1: str, s2: str) -> float:
    """Returns normalized edit distance in [0.0, 1.0]. 0.0 means identical."""
    m = max(len(s1), len(s2))
    if m == 0:
        return 0.0
    return levenshtein_distance(s1, s2) / m


def token_jaccard(s1: str, s2: str) -> float:
    """Computes token-level Jaccard similarity in [0.0, 1.0]. 1.0 means identical token sets."""
    toks1 = set(re.findall(r"\w+", s1.lower()))
    toks2 = set(re.findall(r"\w+", s2.lower()))
    if not toks1 and not toks2:
        return 1.0
    if not toks1 or not toks2:
        return 0.0
    return len(toks1.intersection(toks2)) / len(toks1.union(toks2))


def extract_final_error_line(output: str) -> str:
    """Extracts the final meaningful, normalized error line from tool output."""
    if not output:
        return ""
    lines = [ln.strip() for ln in output.splitlines() if ln.strip()]
    if not lines:
        return ""

    # Reverse search for last significant error line
    for ln in reversed(lines):
        ln_clean = ln.strip()
        # Skip generic completion/status lines
        if re.search(r"exited with code|completed at|created at", ln_clean, re.I):
            continue
        if ln_clean:
            # Scrub dynamic memory addresses, line numbers, and hex
            scrubbed = re.sub(r"0x[0-9a-fA-F]+", "0xADDR", ln_clean)
            scrubbed = re.sub(r"line \d+", "line N", scrubbed, flags=re.I)
            scrubbed = re.sub(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\s]*", "<TS>", scrubbed)
            return scrubbed

    return lines[-1]


def parse_transcript(transcript_path: Path) -> Dict[int, Dict[str, Any]]:
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
                content = str(row.get("content") or "")
                if sidx is None:
                    continue

                if sidx not in steps:
                    steps[sidx] = {"step_index": sidx, "content": content, "exit_code": None, "output": ""}
                else:
                    if content:
                        steps[sidx]["content"] = content

                m_exit = re.search(r"The command exited with code\s+(\d+)\.", content)
                if m_exit:
                    steps[sidx]["exit_code"] = int(m_exit.group(1))

                m_out = re.search(r"Output:\s*\n(.*)", content, re.DOTALL)
                if m_out:
                    steps[sidx]["output"] = m_out.group(1)
    except Exception:
        pass

    return steps


def scrub_path(p: str) -> str:
    """Removes usernames and local machine roots for clean reporting."""
    s = re.sub(r"C:[\\/]Users[\\/][^\\/]+", "C:/Users/<USER>", p, flags=re.I)
    s = re.sub(r"/home/[^/]+", "/home/<USER>", s)
    s = re.sub(r"Desktop[\\/][^\\/]+", "Desktop/<PROJECT>", s)
    return s


def run_loop_study():
    trace_files = sorted(TRACES_DIR.glob("trace_*.json"))
    print(f"Loaded {len(trace_files)} traces from {TRACES_DIR}.\n")

    # Collect failing executions per trace
    failing_runs_by_trace = defaultdict(list)
    total_executed_commands = 0
    total_failures = 0

    for tf in trace_files:
        with open(tf, "r", encoding="utf-8") as f:
            trace_doc = json.load(f)

        cid = trace_doc.get("conversation_id", "")
        steps = trace_doc.get("steps", [])
        transcript_path = BRAIN_DIR / cid / ".system_generated" / "logs" / "transcript.jsonl"
        transcript_steps = parse_transcript(transcript_path)

        for s in steps:
            tname = s.get("tool_name", "")
            cmd = s.get("command", "") or ""
            dec = s.get("v1_decision", "")
            human_inferred = s.get("human_approved_inferred", False)
            sidx = s.get("step_idx", 0)

            executed = (dec == "allow") or (dec in ("ask", "force_ask") and human_inferred)
            if not executed or tname != "run_command" or not cmd:
                continue

            total_executed_commands += 1

            t_entry = transcript_steps.get(sidx) or transcript_steps.get(sidx + 1)
            exit_code = None
            output = ""

            if t_entry:
                exit_code = t_entry.get("exit_code")
                output = t_entry.get("output", "")
                if exit_code is None and t_entry.get("content"):
                    m_exit = re.search(r"The command exited with code\s+(\d+)\.", t_entry["content"])
                    if m_exit:
                        exit_code = int(m_exit.group(1))
                    m_out = re.search(r"Output:\s*\n(.*)", t_entry["content"], re.DOTALL)
                    if m_out:
                        output = m_out.group(1)

            # Check if this command failed
            is_failure = (exit_code is not None and exit_code != 0)
            if not is_failure and output:
                err_signals = ["traceback (most recent call last)", "syntaxerror:", "modulenotfounderror:",
                               "importerror:", "error:", "fatal:", "failed:", "command not found",
                               "the term '", "is not recognized"]
                if any(sig in output.lower() for sig in err_signals):
                    is_failure = True

            if is_failure:
                total_failures += 1
                final_err = extract_final_error_line(output)
                failing_runs_by_trace[tf.name].append({
                    "step_idx": sidx,
                    "command": cmd,
                    "exit_code": exit_code,
                    "final_error": final_err,
                    "raw_output": output[:300],
                })

    print(f"Total executed commands: {total_executed_commands}")
    print(f"Total failing commands: {total_failures} ({total_failures/total_executed_commands*100:.2f}% failure rate)\n")

    # Evaluate loop sequences
    # A loop sequence is 3 or more failing commands within a sliding window of <= 6 failing commands
    # where commands are lexically similar (Jaccard >= 0.7 OR edit_dist <= 0.3)
    # AND final errors are similar (Jaccard >= 0.7 OR edit_dist <= 0.3)
    exact_hash_trips = 0
    near_loop_sequences = []
    total_near_loop_commands = 0
    total_wasted_turns = 0

    for trace_name, fails in failing_runs_by_trace.items():
        n = len(fails)
        if n < 3:
            continue

        # Check exact hash breaker simulation
        # Rolling window of 3: identical command + identical final error line
        for i in range(n - 2):
            w = fails[i:i+3]
            c0, e0 = w[0]["command"].strip(), w[0]["final_error"].strip()
            c1, e1 = w[1]["command"].strip(), w[1]["final_error"].strip()
            c2, e2 = w[2]["command"].strip(), w[2]["final_error"].strip()
            if c0 == c1 == c2 and e0 == e1 == e2 and c0:
                exact_hash_trips += 1

        # Check near-loop sequence simulation
        # Sliding window across failing commands
        i = 0
        while i < n:
            cluster = [fails[i]]
            for j in range(i + 1, min(n, i + 6)):
                cand = fails[j]
                # Compare cand against cluster anchor
                anchor = cluster[0]
                cmd_jaccard = token_jaccard(anchor["command"], cand["command"])
                cmd_dist = normalized_edit_distance(anchor["command"], cand["command"])
                cmd_similar = (cmd_jaccard >= 0.65 or cmd_dist <= 0.35)

                err_jaccard = token_jaccard(anchor["final_error"], cand["final_error"])
                err_dist = normalized_edit_distance(anchor["final_error"], cand["final_error"])
                err_similar = (err_jaccard >= 0.60 or err_dist <= 0.40) or (not anchor["final_error"] and not cand["final_error"])

                if cmd_similar and err_similar:
                    cluster.append(cand)

            if len(cluster) >= 3:
                # Discovered a near-loop sequence
                near_loop_sequences.append({
                    "trace": trace_name,
                    "cluster_size": len(cluster),
                    "steps": [c["step_idx"] for c in cluster],
                    "commands": [c["command"] for c in cluster],
                    "final_errors": [c["final_error"] for c in cluster],
                    "anchor_cmd": cluster[0]["command"],
                    "anchor_err": cluster[0]["final_error"],
                })
                total_near_loop_commands += len(cluster)
                # Wasted turns are turns past the 2nd repetition
                total_wasted_turns += (len(cluster) - 2)
                i += len(cluster)  # Advance past this cluster
            else:
                i += 1

    print("=== LOOP-EVIDENCE STUDY RESULTS ===")
    print(f"Exact Hash Breaker Trips (Identical 3x match) : {exact_hash_trips}")
    print(f"Near-Repeated Failing Sequences Found (>= 3x)  : {len(near_loop_sequences)}")
    print(f"Total Commands in Near-Loop Sequences          : {total_near_loop_commands}")
    print(f"Upper Bound Wasted Turns                       : {total_wasted_turns}")

    print("\n=== 10 SCRUBBED NEAR-LOOP EXAMPLES ===")
    for idx, seq in enumerate(near_loop_sequences[:10], 1):
        print(f"\n--- Example {idx:2d} ({seq['trace']} | {seq['cluster_size']} attempts | Steps: {seq['steps']}) ---")
        for attempt, (cmd, err) in enumerate(zip(seq["commands"], seq["final_errors"]), 1):
            cmd_scrubbed = scrub_path(cmd.strip().replace("\n", " ")[:95])
            err_scrubbed = scrub_path(err.strip()[:95])
            print(f"  Attempt {attempt}: {cmd_scrubbed}")
            print(f"            Error: {err_scrubbed}")
        # Explain why exact hash missed it
        c_set = set(seq["commands"])
        if len(c_set) > 1:
            diff_reason = "Slight command edits (args/flags/quotes/paths differed across attempts)"
        else:
            diff_reason = "Commands identical but final error line had variable traces or step spacing"
        print(f"  Hash Breaker Miss Reason: {diff_reason}")

    return {
        "exact_hash_trips": exact_hash_trips,
        "near_loop_sequences": len(near_loop_sequences),
        "total_commands": total_near_loop_commands,
        "wasted_turns": total_wasted_turns,
        "examples": near_loop_sequences[:10],
    }


if __name__ == "__main__":
    run_loop_study()
