"""
L0 Coverage, Recall, and Reason Breakdown Analysis.
Evaluates C1-C4 on all 41 production traces (7,051 steps).
Audits the 12 known census failures and tests a 50+ synthetic typo benchmark.
"""

import json
import re
import tempfile
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Any, Tuple

from agent_airlock.config import GroundingConfig
from agent_airlock.grounding.engine import GroundingEngine
from agent_airlock.policy.normalizer import parse_command_segments, CommandSegment
from agent_airlock.grounding.c1_binary import (
    ALL_SHELL_BUILTINS,
    POWERSHELL_PREFIXES,
    POWERSHELL_BUILTINS,
    COMMON_DEVELOPMENT_BINARIES,
    check_binary,
)
from agent_airlock.grounding.c2_files import extract_target_path, check_files
from agent_airlock.grounding.c3_scripts import check_scripts
from agent_airlock.grounding.c4_installs import check_installs


def analyze_trace_coverage():
    traces_dir = Path("data/traces")
    trace_files = sorted(traces_dir.glob("trace_*.json"))

    config = GroundingConfig(enabled=True, mode="enforce")
    engine = GroundingEngine(config)

    c1_stats = defaultdict(int)
    c2_stats = defaultdict(int)
    c3_stats = defaultdict(int)
    c4_stats = defaultdict(int)

    # Detailed pass-through reasons for C1
    # Reasons: builtin, cmdlet, common_binary, path_exists, dynamic_expansion, preceded_by_create, unparseable, placeholder_or_offline
    c1_reasons = defaultdict(int)
    c2_reasons = defaultdict(int)
    c3_reasons = defaultdict(int)
    c4_reasons = defaultdict(int)

    total_trace_steps = 0
    total_run_commands = 0
    total_file_tools = 0

    for tf in trace_files:
        try:
            doc = json.loads(tf.read_text(encoding="utf-8"))
        except Exception:
            continue

        for s in doc.get("steps", []):
            total_trace_steps += 1
            tname = s.get("tool_name", "")
            tool_args = s.get("tool_args", {}) or {}
            cmd = s.get("command", "") or tool_args.get("CommandLine", "") or ""
            ws_root = s.get("workspace_root") or ""
            cwd = tool_args.get("Cwd") or tool_args.get("cwd") or ws_root

            if tname == "run_command" and cmd:
                total_run_commands += 1
                segments = parse_command_segments(cmd)
                for seg in segments:
                    c1_stats["evaluated"] += 1
                    b_raw = seg.binary
                    b_clean = b_raw.strip("'\"")
                    b_lower = b_clean.lower()
                    if b_lower.endswith(".exe"):
                        b_lower = b_lower[:-4]

                    # Classify reason
                    if seg.is_dynamic_or_unparseable:
                        c1_reasons["dynamic_or_unparseable"] += 1
                    elif seg.preceded_by_build_step:
                        c1_reasons["preceded_by_create"] += 1
                    elif any(marker in b_raw for marker in ("<USER>", "<WS>", "<HOME>", "<REPO>", "<TMP>")):
                        c1_reasons["placeholder_or_offline"] += 1
                    elif b_lower in ALL_SHELL_BUILTINS:
                        c1_reasons["builtin"] += 1
                    elif any(b_lower.startswith(p.lower()) for p in POWERSHELL_PREFIXES) or b_lower in POWERSHELL_BUILTINS:
                        c1_reasons["cmdlet"] += 1
                    elif b_lower in COMMON_DEVELOPMENT_BINARIES:
                        c1_reasons["common_binary"] += 1
                    else:
                        ok, hint, b_tgt = check_binary(seg, cwd, None, engine.path_cache)
                        if ok:
                            c1_reasons["path_exists"] += 1
                        else:
                            c1_stats["would_deny"] += 1
                            c1_reasons["would_deny"] += 1

                    # C3: Scripts check
                    if b_lower in ("npm", "pnpm", "yarn", "make"):
                        c3_stats["evaluated"] += 1
                        is_g, hint, tgt = check_scripts(seg, cwd, ws_root)
                        if not is_g:
                            c3_stats["would_deny"] += 1
                            c3_reasons["would_deny"] += 1
                        else:
                            if not tgt:
                                c3_reasons["no_script_arg"] += 1
                            else:
                                c3_reasons["passed_or_offline"] += 1

                    # C4: Installs check
                    if (b_lower in ("pip", "pip3") and "install" in seg.args) or \
                       (b_lower in ("npm", "pnpm", "yarn") and any(a in ("install", "i", "add") for a in seg.args)) or \
                       (b_lower == "cargo" and any(a in ("install", "add") for a in seg.args)):
                        c4_stats["evaluated"] += 1
                        is_g, hint, tgt = check_installs(seg, cwd, ws_root)
                        if not is_g:
                            c4_stats["would_deny"] += 1
                            c4_reasons["would_deny"] += 1
                        else:
                            c4_reasons["passed_or_offline"] += 1

            elif tname in ("view_file", "write_to_file", "replace_file_content"):
                total_file_tools += 1
                c2_stats["evaluated"] += 1
                target = extract_target_path(tool_args)
                is_g, hint, tgt = check_files(tname, tool_args, cwd, ws_root)
                if not is_g:
                    c2_stats["would_deny"] += 1
                    c2_reasons["would_deny"] += 1
                else:
                    if not target:
                        c2_reasons["no_target_arg"] += 1
                    elif any(m in target for m in ("<USER>", "<WS>", "<HOME>", "<REPO>", "<TMP>")):
                        c2_reasons["placeholder"] += 1
                    elif ws_root and not Path(ws_root).exists():
                        c2_reasons["offline_workspace"] += 1
                    elif Path(target).exists():
                        c2_reasons["path_exists"] += 1
                    else:
                        c2_reasons["passed_conservative"] += 1

    print("=== L0 COVERAGE & PASS-THROUGH REASON BREAKDOWN ===")
    print(f"Total Steps: {total_trace_steps}, run_command: {total_run_commands}, file tools: {total_file_tools}\n")

    print(f"C1 Binary Grounding (Evaluated: {c1_stats['evaluated']}, Would-Deny: {c1_stats['would_deny']}):")
    for r, count in sorted(c1_reasons.items(), key=lambda x: -x[1]):
        pct = (count / c1_stats['evaluated']) * 100
        print(f"  - {r:25s}: {count:5d} ({pct:5.2f}%)")

    print(f"\nC2 Files Grounding (Evaluated: {c2_stats['evaluated']}, Would-Deny: {c2_stats['would_deny']}):")
    for r, count in sorted(c2_reasons.items(), key=lambda x: -x[1]):
        pct = (count / c2_stats['evaluated']) * 100 if c2_stats['evaluated'] else 0
        print(f"  - {r:25s}: {count:5d} ({pct:5.2f}%)")

    print(f"\nC3 Scripts Grounding (Evaluated: {c3_stats['evaluated']}, Would-Deny: {c3_stats['would_deny']}):")
    for r, count in sorted(c3_reasons.items(), key=lambda x: -x[1]):
        pct = (count / c3_stats['evaluated']) * 100 if c3_stats['evaluated'] else 0
        print(f"  - {r:25s}: {count:5d} ({pct:5.2f}%)")

    print(f"\nC4 Installs Grounding (Evaluated: {c4_stats['evaluated']}, Would-Deny: {c4_stats['would_deny']}):")
    for r, count in sorted(c4_reasons.items(), key=lambda x: -x[1]):
        pct = (count / c4_stats['evaluated']) * 100 if c4_stats['evaluated'] else 0
        print(f"  - {r:25s}: {count:5d} ({pct:5.2f}%)")

    return {
        "c1": (dict(c1_stats), dict(c1_reasons)),
        "c2": (dict(c2_stats), dict(c2_reasons)),
        "c3": (dict(c3_stats), dict(c3_reasons)),
        "c4": (dict(c4_stats), dict(c4_reasons)),
    }


def audit_12_known_failures():
    """Audits the 12 known grounding failures from the census."""
    # From census_l0_failures.py
    known_12 = [
        # C1 failures (10 from human approvals + 2 other = 12 total C1/C2)
        {"type": "C1", "cmd": "npx tsx -e \"fetch('https://overpass-api.de/api/interpreter', { method: 'POST', body: 'suburb' })\"", "reason": "suburb term split"},
        {"type": "C1", "cmd": "powershell -Command \"$env:VITE_ENGINE_MODE='live'; npx vitest run tests/compareA\"", "reason": "=live unrecognized cmdlet"},
        {"type": "C1", "cmd": "powershell -Command \"$env:VITE_ENGINE_MODE='live'; npx vitest run\"", "reason": "=live unrecognized cmdlet"},
        {"type": "C1", "cmd": "winget install -e --id Python.Python.3.11", "reason": "winget not installed on host"},
        {"type": "C1", "cmd": "deno test tests/engine.ts", "reason": "deno not installed on host"},
        {"type": "C1", "cmd": "uv venv", "reason": "uv not in PATH"},
        {"type": "C1", "cmd": "uv pip install -r requirements.txt", "reason": "uv not in PATH"},
        {"type": "C1", "cmd": ".venv\\Scripts\\python.exe -m pytest", "reason": "ephemeral .venv missing at that point"},
        {"type": "C1", "cmd": "test_vectors\\astropy\\.venv\\Scripts\\python -m pytest", "reason": "ephemeral venv missing"},
        {"type": "C1", "cmd": "conda activate non_existent_env_xyz", "reason": "conda env missing"},
        # C2 failures (2 in overall corpus)
        {"type": "C2", "tool": "view_file", "path": "test_vectors/django/missing_file.py", "reason": "file does not exist"},
        {"type": "C2", "tool": "replace_file_content", "path": "test_vectors/django/non_existent.py", "reason": "file does not exist"},
    ]

    config = GroundingConfig(enabled=True, mode="enforce")
    engine = GroundingEngine(config)

    print("\n=== AUDIT OF THE 12 KNOWN CENSUS FAILURES ===")
    flagged = 0
    common_binary_hidden = 0

    for idx, item in enumerate(known_12, 1):
        ctype = item["type"]
        if ctype == "C1":
            cmd = item["cmd"]
            segments = parse_command_segments(cmd)
            is_flagged = False
            hidden_by_common = False
            for seg in segments:
                res = engine.evaluate("run_command", {"CommandLine": cmd}, cwd=".", workspace_root=".")
                if res.is_failed:
                    is_flagged = True
                else:
                    b_lower = seg.binary.lower().replace(".exe", "")
                    if b_lower in COMMON_DEVELOPMENT_BINARIES:
                        hidden_by_common = True
            print(f"[{idx:2d}] C1: {cmd[:65]:65s} -> Flagged: {is_flagged} | Reason: {item['reason']}")
            if is_flagged:
                flagged += 1
            if hidden_by_common:
                common_binary_hidden += 1
        elif ctype == "C2":
            res = engine.evaluate(item["tool"], {"TargetFile": item["path"]}, cwd=".", workspace_root=".")
            is_flagged = res.is_failed
            print(f"[{idx:2d}] C2: {item['path']:65s} -> Flagged: {is_flagged} | Reason: {item['reason']}")
            if is_flagged:
                flagged += 1

    print(f"\nResult: L0 would have flagged {flagged}/{len(known_12)} known failures.")
    print(f"Failures masked by COMMON_DEVELOPMENT_BINARIES: {common_binary_hidden}")


def evaluate_synthetic_typos():
    """Builds a synthetic benchmark of 50+ hallucination-style typos and measures recall."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        # Create a mock repo
        (tmp_path / "package.json").write_text(json.dumps({
            "name": "mock-repo",
            "scripts": {
                "build": "tsc",
                "test": "vitest",
                "lint": "eslint",
                "dev": "vite",
                "start": "node index.js"
            }
        }), encoding="utf-8")
        (tmp_path / "Makefile").write_text("all:\n\techo all\ncompile:\n\techo compile\ntest:\n\techo test\n", encoding="utf-8")
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\npytest==8.0.0\nflask==3.0.0\nnumpy==1.26.0\n", encoding="utf-8")
        (tmp_path / "real_file.py").write_text("print('hello')", encoding="utf-8")
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "index.ts").write_text("export const x = 1;", encoding="utf-8")

        config = GroundingConfig(enabled=True, mode="enforce")
        engine = GroundingEngine(config)

        # 55 synthetic typos across C1, C2, C3, C4
        typos = [
            # C1: 15 Binary typos (hallucinated / misspelled CLI binaries)
            {"cat": "C1", "tool": "run_command", "args": {"CommandLine": "gti status"}},
            {"cat": "C1", "tool": "run_command", "args": {"CommandLine": "pyhton script.py"}},
            {"cat": "C1", "tool": "run_command", "args": {"CommandLine": "npn install"}},
            {"cat": "C1", "tool": "run_command", "args": {"CommandLine": "pnpn run build"}},
            {"cat": "C1", "tool": "run_command", "args": {"CommandLine": "cargoo build"}},
            {"cat": "C1", "tool": "run_command", "args": {"CommandLine": "doker run ubuntu"}},
            {"cat": "C1", "tool": "run_command", "args": {"CommandLine": "dokcer-compose up"}},
            {"cat": "C1", "tool": "run_command", "args": {"CommandLine": "cuel http://example.com"}},
            {"cat": "C1", "tool": "run_command", "args": {"CommandLine": "whch python"}},
            {"cat": "C1", "tool": "run_command", "args": {"CommandLine": "grpe pattern file.txt"}},
            {"cat": "C1", "tool": "run_command", "args": {"CommandLine": "catt file.txt"}},
            {"cat": "C1", "tool": "run_command", "args": {"CommandLine": "nodde app.js"}},
            {"cat": "C1", "tool": "run_command", "args": {"CommandLine": "gitk-misspelled"}},
            {"cat": "C1", "tool": "run_command", "args": {"CommandLine": "pytset tests/"}},
            {"cat": "C1", "tool": "run_command", "args": {"CommandLine": "targz -xf file.tar"}},

            # C2: 15 Path / File typos (nonexistent targets in real workspace)
            {"cat": "C2", "tool": "view_file", "args": {"TargetFile": str(tmp_path / "config.jsn")}},
            {"cat": "C2", "tool": "view_file", "args": {"TargetFile": str(tmp_path / "setting.yaml")}},
            {"cat": "C2", "tool": "view_file", "args": {"TargetFile": str(tmp_path / "requriements.txt")}},
            {"cat": "C2", "tool": "view_file", "args": {"TargetFile": str(tmp_path / "README.tx")}},
            {"cat": "C2", "tool": "view_file", "args": {"TargetFile": str(tmp_path / "package.jsn")}},
            {"cat": "C2", "tool": "view_file", "args": {"TargetFile": str(tmp_path / "src" / "indes.ts")}},
            {"cat": "C2", "tool": "view_file", "args": {"TargetFile": str(tmp_path / "docker-compoze.yml")}},
            {"cat": "C2", "tool": "view_file", "args": {"TargetFile": str(tmp_path / ".env.exampel")}},
            {"cat": "C2", "tool": "replace_file_content", "args": {"TargetFile": str(tmp_path / "real_file_typo.py")}},
            {"cat": "C2", "tool": "replace_file_content", "args": {"TargetFile": str(tmp_path / "src" / "missing.ts")}},
            {"cat": "C2", "tool": "replace_file_content", "args": {"TargetFile": str(tmp_path / "not_there.json")}},
            {"cat": "C2", "tool": "write_to_file", "args": {"TargetFile": str(tmp_path / "missing_dir_1" / "missing_dir_2" / "new.py")}},
            {"cat": "C2", "tool": "write_to_file", "args": {"TargetFile": str(tmp_path / "no_such_parent" / "out.txt")}},
            {"cat": "C2", "tool": "write_to_file", "args": {"TargetFile": str(tmp_path / "bogus_folder" / "sub" / "file.ts")}},
            {"cat": "C2", "tool": "view_file", "args": {"TargetFile": str(tmp_path / "Makfile")}},

            # C3: 13 Script typos (nonexistent scripts/targets in package.json/Makefile)
            {"cat": "C3", "tool": "run_command", "args": {"CommandLine": "npm run biuld"}},
            {"cat": "C3", "tool": "run_command", "args": {"CommandLine": "npm run tesst"}},
            {"cat": "C3", "tool": "run_command", "args": {"CommandLine": "npm run litn"}},
            {"cat": "C3", "tool": "run_command", "args": {"CommandLine": "npm run devv"}},
            {"cat": "C3", "tool": "run_command", "args": {"CommandLine": "npm run stat"}},
            {"cat": "C3", "tool": "run_command", "args": {"CommandLine": "pnpm run bulid"}},
            {"cat": "C3", "tool": "run_command", "args": {"CommandLine": "yarn run chek"}},
            {"cat": "C3", "tool": "run_command", "args": {"CommandLine": "yarn run buld"}},
            {"cat": "C3", "tool": "run_command", "args": {"CommandLine": "make complie"}},
            {"cat": "C3", "tool": "run_command", "args": {"CommandLine": "make testt"}},
            {"cat": "C3", "tool": "run_command", "args": {"CommandLine": "make alll"}},
            {"cat": "C3", "tool": "run_command", "args": {"CommandLine": "npm run release-nonexistent"}},
            {"cat": "C3", "tool": "run_command", "args": {"CommandLine": "npm run typecheck"}},  # not in package.json

            # C4: 12 Package install typos (typosquats within edit distance <= 2)
            {"cat": "C4", "tool": "run_command", "args": {"CommandLine": "pip install reqeusts"}},
            {"cat": "C4", "tool": "run_command", "args": {"CommandLine": "pip install flsak"}},
            {"cat": "C4", "tool": "run_command", "args": {"CommandLine": "pip install pyest"}},
            {"cat": "C4", "tool": "run_command", "args": {"CommandLine": "pip install nump"}},
            {"cat": "C4", "tool": "run_command", "args": {"CommandLine": "pip install requsts"}},
            {"cat": "C4", "tool": "run_command", "args": {"CommandLine": "npm install vitestt"}},
            {"cat": "C4", "tool": "run_command", "args": {"CommandLine": "npm install eslin"}},
            {"cat": "C4", "tool": "run_command", "args": {"CommandLine": "npm install vte"}},
            {"cat": "C4", "tool": "run_command", "args": {"CommandLine": "npm install mock-rep"}},
            {"cat": "C4", "tool": "run_command", "args": {"CommandLine": "cargo add serd"}},
            {"cat": "C4", "tool": "run_command", "args": {"CommandLine": "cargo add toklio"}},
            {"cat": "C4", "tool": "run_command", "args": {"CommandLine": "pip3 install reqeusts"}},
        ]

        print(f"\n=== SYNTHETIC HALLUCINATION-STYLE TYPO BENCHMARK (N={len(typos)}) ===")
        cat_total = defaultdict(int)
        cat_caught = defaultdict(int)

        for case in typos:
            cat = case["cat"]
            cat_total[cat] += 1
            res = engine.evaluate(
                case["tool"],
                case["args"],
                cwd=str(tmp_path),
                workspace_root=str(tmp_path)
            )
            if res.is_failed:
                cat_caught[cat] += 1
            else:
                print(f"  [MISSED] {cat}: {case['tool']} -> {case['args']} (Hint: {res.hint})")

        total_tested = len(typos)
        total_caught = sum(cat_caught.values())
        print(f"\nOverall Synthetic Typos Caught: {total_caught}/{total_tested} ({total_caught/total_tested*100:.1f}% recall)")
        for c in sorted(cat_total.keys()):
            caught = cat_caught[c]
            tot = cat_total[c]
            print(f"  {c}: {caught}/{tot} ({caught/tot*100:.1f}% recall)")


if __name__ == "__main__":
    analyze_trace_coverage()
    audit_12_known_failures()
    evaluate_synthetic_typos()
