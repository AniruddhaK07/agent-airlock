"""
Review Sheet 1 Generator (Phase 1.6 Step 1).
Full-pool uncertainty scoring with normalized deduplication, token budget (>451) tracking,
measured stage timings, checkpointed model inference, and compact delivery format for Ani.
"""

import json
import os
import re
import time
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Any, Set, Tuple

from agent_airlock.policy.engine import HardPolicyEngine
from agent_airlock.policy.models import PolicyVerdict
from agent_airlock.backends.laya import LocalLayaClient, DEFAULT_CHECKPOINT


CACHE_PATH = Path("scratch/scoring_cache_sheet1.json")


def load_existing_commands() -> Set[str]:
    """Loads all existing command strings across train, val, eval, and draft sets."""
    existing = set()
    for p in ['data/eval_set.jsonl', 'data/eval_growth_draft.jsonl', 'data/train.json', 'data/val.json']:
        path = Path(p)
        if path.exists():
            if p.endswith('.jsonl'):
                for line in path.read_text('utf-8').splitlines():
                    if line.strip():
                        c = json.loads(line).get('command')
                        if c:
                            existing.add(c.strip())
            else:
                for item in json.loads(path.read_text('utf-8')):
                    c = item.get('command')
                    if c:
                        existing.add(c.strip())
    return existing


def normalize_dedupe_key(tool_name: str, cmd_str: str) -> str:
    """
    Computes normalized deduplication key masking paths, numbers, hashes, and UUIDs.
    """
    s = cmd_str.strip()
    # Mask UUIDs
    s = re.sub(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", "<UUID>", s)
    # Mask Git commit / SHA-256 hashes (7 to 64 hex chars)
    s = re.sub(r"\b[0-9a-fA-F]{7,64}\b", "<HASH>", s)
    # Mask Windows drive paths (e.g. C:\foo\bar or C:/foo/bar)
    s = re.sub(r"[A-Za-z]:[\\/][^\s\"';&|<>]+", "<PATH>", s)
    # Mask Unix absolute/relative paths
    s = re.sub(r"(?:(?<=[\s=])|^)(?:\.\/|\.\.\/|\/)[^\s\"';&|<>]+", "<PATH>", s)
    # Mask file names with extensions
    s = re.sub(r"\b[\w\.\-]+\.(?:py|js|ts|tsx|json|yaml|yml|md|txt|sh|toml|lock|rs|go|css|html)\b", "<FILE>", s, flags=re.I)
    # Mask numbers/integers
    s = re.sub(r"\b\d+\b", "<NUM>", s)
    # Normalize excessive whitespace
    s = " ".join(s.split()).lower()
    return f"{tool_name}::{s}"


def scrub_for_review(s: str) -> str:
    """Scrubs sensitive machine information and usernames for review presentation."""
    res = re.sub(r"[C:c]:[/\\]Users[/\\][a-zA-Z0-9_\-]+", "<DEV_HOME>", s)
    res = re.sub(r"/home/[a-zA-Z0-9_\-]+", "<HOME>", res)
    res = re.sub(r"Desktop[/\\][a-zA-Z0-9_\-]+", "Desktop/<WORKSPACE>", res)
    return res


def run_pipeline() -> Dict[str, Any]:
    timings = {}
    
    # -------------------------------------------------------------------------
    # STAGE 1: Pool Extraction & Normalized Deduplication
    # -------------------------------------------------------------------------
    t0_stage1 = time.perf_counter()
    existing_cmds = load_existing_commands()
    traces_dir = Path("data/traces")
    trace_files = sorted(traces_dir.glob("trace_*.json"))

    engine = HardPolicyEngine()
    
    # Map of norm_key -> best candidate dict
    deduped_pool: Dict[str, Dict[str, Any]] = {}
    raw_candidates_seen = 0
    l1_deterministic_skipped = 0
    existing_dataset_skipped = 0

    for tf in trace_files:
        try:
            doc = json.loads(tf.read_text(encoding="utf-8"))
        except Exception:
            continue

        cid = doc.get("conversation_id", "")
        for s in doc.get("steps", []):
            tname = s.get("tool_name", "")
            tool_args = s.get("tool_args", {}) or {}
            cmd = s.get("command", "") or tool_args.get("CommandLine", "") or ""
            target = tool_args.get("TargetFile") or tool_args.get("AbsolutePath") or ""

            eval_target = cmd if tname == "run_command" else target
            if not eval_target or not eval_target.strip():
                continue

            raw_str = eval_target.strip()
            raw_candidates_seen += 1

            if raw_str in existing_cmds:
                existing_dataset_skipped += 1
                continue

            # Check L1 deterministic policy
            l1_dec = engine.evaluate(tname, tool_args)
            if l1_dec.verdict in (PolicyVerdict.ALLOW, PolicyVerdict.DENY):
                l1_deterministic_skipped += 1
                continue

            norm_key = normalize_dedupe_key(tname, raw_str)
            if norm_key not in deduped_pool:
                deduped_pool[norm_key] = {
                    "tool_name": tname,
                    "tool_args": tool_args,
                    "raw_command": raw_str,
                    "scrubbed_command": scrub_for_review(raw_str),
                    "trace_id": tf.name,
                    "step_idx": s.get("step_idx"),
                    "norm_key": norm_key,
                }

    stage1_duration = time.perf_counter() - t0_stage1
    timings["stage1_wall_time_s"] = round(stage1_duration, 3)

    pool_items = list(deduped_pool.values())
    total_deduped_pool = len(pool_items)

    print(f"[Stage 1] Raw candidates: {raw_candidates_seen}")
    print(f"[Stage 1] Skipped existing dataset: {existing_dataset_skipped}")
    print(f"[Stage 1] Skipped L1 deterministic: {l1_deterministic_skipped}")
    print(f"[Stage 1] Normalized deduped pool size: {total_deduped_pool}")
    print(f"[Stage 1] Wall time: {stage1_duration:.3f}s\n")

    # -------------------------------------------------------------------------
    # STAGE 2: Model Inference & Full Pool Scoring (with Token Budget Check)
    # -------------------------------------------------------------------------
    t0_stage2 = time.perf_counter()
    print("Loading LocalLayaClient...")
    client = LocalLayaClient(checkpoint_path=DEFAULT_CHECKPOINT)

    # Load scoring cache if exists
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    cache = {}
    if CACHE_PATH.exists():
        try:
            cache = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
        except Exception:
            cache = {}

    scored_pool: List[Dict[str, Any]] = []
    rejected_over_length: List[Dict[str, Any]] = []

    for idx, item in enumerate(pool_items, 1):
        raw_cmd = item["raw_command"]
        tname = item["tool_name"]
        targs = item["tool_args"]

        # 1. Check token budget directly via client tokenizer
        token_len = 0
        is_over_length = False
        try:
            if client.agent and hasattr(client.agent, "tokenizer"):
                toks = client.agent.tokenizer.encode(raw_cmd, add_special_tokens=True)
                token_len = len(toks)
                if token_len > 451:
                    is_over_length = True
        except Exception:
            pass

        if is_over_length:
            item["token_length"] = token_len
            item["route"] = "needs-human"
            item["confidence"] = 0.50
            item["blast_radius"] = 3.0
            item["uncertainty_score"] = 0.99
            item["is_over_length"] = True
            item["suggested_label"] = "ASK-by-length"
            rejected_over_length.append(item)
            scored_pool.append(item)
            continue

        item["is_over_length"] = False
        item["token_length"] = token_len

        # 2. Score via cache or live inference
        if raw_cmd in cache:
            cached_res = cache[raw_cmd]
            item["route"] = cached_res["route"]
            item["confidence"] = cached_res["confidence"]
            item["blast_radius"] = cached_res["blast_radius"]
            item["reversibility"] = cached_res.get("reversibility", 0.5)
            item["uncertainty_score"] = cached_res["uncertainty_score"]
        else:
            try:
                ev = client.evaluate_ambiguous_tool(tname, targs)
                conf = float(ev.choice_confidence)
                blast = float(ev.score_blast_radius)
                route = str(ev.choice_route)
                rev = float(ev.noul_reversible_prob)
            except Exception:
                conf = 0.50
                blast = 2.0
                route = "needs-human"
                rev = 0.50

            # Uncertainty scoring: distance to decision boundary (conf near 0.50, blast near 2.0)
            u_score = 1.0 - abs(conf - 0.50) * 2.0
            if 1.5 <= blast <= 2.5:
                u_score += 0.5

            item["route"] = route
            item["confidence"] = round(conf, 3)
            item["blast_radius"] = round(blast, 2)
            item["reversibility"] = round(rev, 3)
            item["uncertainty_score"] = round(u_score, 3)

            cache[raw_cmd] = {
                "route": item["route"],
                "confidence": item["confidence"],
                "blast_radius": item["blast_radius"],
                "reversibility": item["reversibility"],
                "uncertainty_score": item["uncertainty_score"],
            }

            # Periodic checkpoint save every 25 items
            if idx % 25 == 0:
                CACHE_PATH.write_text(json.dumps(cache), encoding="utf-8")

        scored_pool.append(item)

    # Save final cache
    CACHE_PATH.write_text(json.dumps(cache), encoding="utf-8")

    stage2_duration = time.perf_counter() - t0_stage2
    timings["stage2_wall_time_s"] = round(stage2_duration, 3)

    print(f"[Stage 2] Full pool scored: {len(scored_pool)}")
    print(f"[Stage 2] Rows rejected for >451 tokens (ASK-by-length): {len(rejected_over_length)}")
    print(f"[Stage 2] Wall time: {stage2_duration:.3f}s\n")

    # -------------------------------------------------------------------------
    # STAGE 3: Uncertainty Ranking, Family Categorization, Selection & Delivery
    # -------------------------------------------------------------------------
    t0_stage3 = time.perf_counter()

    # Assign Family
    for item in scored_pool:
        cmd_str = item["raw_command"]
        tname = item["tool_name"]
        
        if item.get("is_over_length"):
            family = "ASK-by-length"
            suggested = "ASK (length >451)"
        else:
            is_pwsh = bool(re.search(r"powershell|pwsh|Get-|Set-|Test-|Select-|Where-|Out-|Export-|Import-|-\w+\b", cmd_str, re.I))
            is_file = tname in ("view_file", "write_to_file", "replace_file_content")
            is_compound = any(c in cmd_str for c in (";", "&&", "||", "|", "\n"))
            is_dev = bool(re.search(r"\b(git|npm|pnpm|yarn|pytest|python|node|cargo|docker|make)\b", cmd_str, re.I))

            if is_pwsh:
                family = "PowerShell/Windows"
            elif is_dev:
                family = "Dev Toolchain"
            elif is_file:
                family = "File Operations"
            elif is_compound:
                family = "Compound/Chained"
            else:
                family = "General CLI"

            # Compute suggested label
            conf = item["confidence"]
            blast = item["blast_radius"]
            route = item["route"]
            if route == "deterministic-safe" and conf >= 0.75 and blast <= 1.5:
                suggested = "Safe"
            elif blast >= 3.0 or route == "needs-reasoning-model":
                suggested = "Dangerous"
            else:
                suggested = "Ambiguous"

        item["family"] = family
        item["suggested_label"] = suggested

    # Identify near-miss candidates
    # Near-miss: commands with flags or slight edits close to known safe patterns
    near_miss_count = 0
    for item in scored_pool:
        cmd = item["raw_command"].lower()
        if any(f in cmd for f in ("-v", "-s", "--short", "--force", "-y", "--dry-run", "-i", "-r")):
            if item["family"] != "ASK-by-length":
                item["is_near_miss"] = True
                near_miss_count += 1
            else:
                item["is_near_miss"] = False
        else:
            item["is_near_miss"] = False

    # Stratified selection to ensure required composition and exactly 95 rows:
    # Quotas:
    # - PowerShell/Windows: 30
    # - Dev Toolchains: 25
    # - File Operations: 15
    # - Near-Miss Pairs: 15
    # - ASK-by-length: 5
    # - Compound / General: 5
    by_family = defaultdict(list)
    for item in scored_pool:
        if item.get("is_over_length"):
            by_family["ASK-by-length"].append(item)
        elif item.get("is_near_miss"):
            by_family["Near-Miss"].append(item)
        else:
            by_family[item["family"]].append(item)

    for f in by_family:
        by_family[f].sort(key=lambda x: -x["uncertainty_score"])

    quotas = {
        "PowerShell/Windows": 30,
        "Dev Toolchain": 25,
        "Near-Miss": 15,
        "File Operations": 15,
        "ASK-by-length": 5,
        "Compound/Chained": 5,
    }

    selected: List[Dict[str, Any]] = []
    selected_keys = set()

    for fam, q in quotas.items():
        candidates_fam = by_family.get(fam, [])
        for cand in candidates_fam[:q]:
            selected.append(cand)
            selected_keys.add(cand["raw_command"])

    # Backfill to reach exactly 95 rows using highest uncertainty items
    if len(selected) < 95:
        remaining = [c for c in scored_pool if c["raw_command"] not in selected_keys]
        remaining.sort(key=lambda x: -x["uncertainty_score"])
        needed = 95 - len(selected)
        selected.extend(remaining[:needed])

    selected = selected[:95]

    # Calculate family counts and score range of picked rows
    picked_families = defaultdict(int)
    scores = [s["uncertainty_score"] for s in selected]
    min_score = min(scores)
    max_score = max(scores)
    median_score = sorted(scores)[len(scores) // 2]

    for s in selected:
        fam = "Near-Miss" if s.get("is_near_miss") else s["family"]
        picked_families[fam] += 1

    stage3_duration = time.perf_counter() - t0_stage3
    timings["stage3_wall_time_s"] = round(stage3_duration, 3)
    timings["total_wall_time_s"] = round(stage1_duration + stage2_duration + stage3_duration, 3)

    print(f"[Stage 3] Picked {len(selected)} rows")
    print(f"[Stage 3] Score range: min={min_score:.3f}, median={median_score:.3f}, max={max_score:.3f}")
    print(f"[Stage 3] Family distribution: {dict(picked_families)}")
    print(f"[Stage 3] Wall time: {stage3_duration:.3f}s\n")

    # Generate Markdown Table in Ani's exact requested review format:
    # id, command scrubbed, model score, your suggested label, blank human label
    md_lines = [
        "# Review Sheet 1 — Candidate Real-Trace Annotations (Phase 1.6 Step 1)",
        "",
        "> **Format:** `id, command scrubbed, model score, your suggested label, blank human label`",
        "> **Review Options for Human Label:** `[ S ]` Safe (auto-allow), `[ D ]` Dangerous (hard-deny), `[ A ]` Ambiguous (needs human operator).",
        f"> **Total Items:** {len(selected)} (Scored from full deduped pool of {total_deduped_pool} items).",
        "",
        "| ID | Command / Tool Call (Scrubbed) | Family | Model Score (Route / Conf / Blast) | Suggested Label | Human Label |",
        "| :--- | :--- | :--- | :--- | :--- | :---: |",
    ]

    for idx, item in enumerate(selected, 1):
        item_id = f"RS1-{idx:03d}"
        clean_cmd = item["scrubbed_command"].replace("\n", " ").replace("|", "\\|")
        if len(clean_cmd) > 85:
            clean_cmd = clean_cmd[:82] + "..."

        if item.get("is_over_length"):
            score_str = f"TOKENS={item['token_length']} (>451 budget)"
        else:
            score_str = f"`{item['route']}` conf={item['confidence']:.2f} blast={item['blast_radius']:.1f}"

        fam_display = "Near-Miss" if item.get("is_near_miss") else item["family"]
        md_lines.append(f"| `{item_id}` | `{clean_cmd}` | {fam_display} | {score_str} | **{item['suggested_label']}** | `[   ]` |")

    sheet_md_path = Path("docs/v2/review-sheet-1.md")
    sheet_md_path.write_text("\n".join(md_lines) + "\n", encoding="utf-8")
    print(f"Delivered review sheet to: {sheet_md_path}")

    # Also save machine-readable JSONL
    jsonl_path = Path("data/review_sheet_1.jsonl")
    with open(jsonl_path, "w", encoding="utf-8") as f:
        for idx, item in enumerate(selected, 1):
            f.write(json.dumps({
                "id": f"RS1-{idx:03d}",
                "tool_name": item["tool_name"],
                "raw_command": item["raw_command"],
                "scrubbed_command": item["scrubbed_command"],
                "family": item["family"],
                "is_near_miss": item.get("is_near_miss", False),
                "is_over_length": item.get("is_over_length", False),
                "token_length": item.get("token_length", 0),
                "model_prediction": {
                    "route": item.get("route"),
                    "confidence": item.get("confidence"),
                    "blast_radius": item.get("blast_radius"),
                    "reversibility": item.get("reversibility"),
                },
                "uncertainty_score": item.get("uncertainty_score"),
                "suggested_label": item.get("suggested_label"),
                "human_label": None,
            }) + "\n")

    return {
        "timings": timings,
        "total_deduped_pool": total_deduped_pool,
        "over_length_count": len(rejected_over_length),
        "picked_count": len(selected),
        "picked_families": dict(picked_families),
        "score_range": {"min": min_score, "median": median_score, "max": max_score},
        "selected": selected,
    }


if __name__ == "__main__":
    res = run_pipeline()
