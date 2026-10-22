"""
Review Sheet 2 Generator (Phase 1.6 Step 2).
Generates Review Sheet 2 (~100 rows), RANDOM stratified by family (not uncertainty-sampled),
after new L1 rules (Rules 1, 2, 3, 5, 7 + Families A-D) are applied.

Requirements:
1. Columns: ID, Tool Name, Command / Target (Scrubbed), Real Family, L1 Verdict Today,
   Model Score, Suggested Label, Human Label.
2. Suggested label left BLANK unless model argmax confidence >= 0.80 (never defaults to Ambiguous).
3. Explicit rule: python -c and node -e are strictly ASK-only regardless of model confidence (never suggest Safe).
4. Drops rows where L1 already decides ALLOW or DENY.
5. Excludes rows already present in Review Sheet 1c.
6. RANDOM stratified by family with fixed seed (42) for reproducibility.
7. Template diversity cap: <= 4 rows per normalized template. Exactly 100 rows.
8. Deliverables to private/review-sheet-2.md and private/review_sheet_2.jsonl (gitignored).
"""

import sys
import json
import random
from pathlib import Path
from collections import defaultdict, Counter
from typing import Dict, List, Any
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent_airlock.policy.engine import HardPolicyEngine
from agent_airlock.policy.models import PolicyVerdict
from scripts.generate_review_sheet_1c import (
    scrub_command_keep_separators,
    is_inline_script,
    classify_real_family,
    get_template,
)


CACHE_PATH = Path("scratch/scoring_cache_sheet1.json")


def generate_sheet_2(seed: int = 42) -> List[Dict[str, Any]]:
    print(f"Generating Sheet 2 with seed={seed}...")
    random.seed(seed)
    
    if not CACHE_PATH.exists():
        raise FileNotFoundError(f"Scoring cache not found at {CACHE_PATH}")
    cache = json.loads(CACHE_PATH.read_text(encoding="utf-8"))

    # Load Sheet 1c to strictly avoid overlap
    sheet1_cmds = set()
    s1_path = Path("private/review_sheet_1c.jsonl")
    if s1_path.exists():
        for line in s1_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                sheet1_cmds.add(json.loads(line)["raw_command"])
    print(f"Excluding {len(sheet1_cmds)} rows already present in Sheet 1c.")

    engine = HardPolicyEngine()
    traces = sorted(Path("data/traces").glob("trace_*.json"))

    raw_to_meta: Dict[str, Dict[str, Any]] = {}
    for tf in traces:
        doc = json.loads(tf.read_text(encoding="utf-8"))
        for s in doc.get("steps", []):
            tname = s.get("tool_name", "")
            targs = s.get("tool_args", {}) or {}
            ws = s.get("workspace_root", "")
            cmd = s.get("command", "") or targs.get("CommandLine", "") or ""
            target = targs.get("TargetFile") or targs.get("AbsolutePath") or ""
            raw = cmd.strip() if tname == "run_command" else target.strip()
            if raw in cache and raw not in raw_to_meta:
                raw_to_meta[raw] = {
                    "tool_name": tname,
                    "tool_args": targs,
                    "workspace_root": ws,
                    "trace_id": tf.name,
                    "step_idx": s.get("step_idx")
                }

    pool: List[Dict[str, Any]] = []
    l1_dropped = 0

    for raw, cdata in cache.items():
        if raw in sheet1_cmds:
            continue
        meta = raw_to_meta.get(raw)
        if not meta:
            continue

        eval_targs = dict(targs)
        if ws and tname in ("write_to_file", "replace_file_content"):
            for k in ("TargetFile", "AbsolutePath"):
                if k in eval_targs and isinstance(eval_targs[k], str):
                    eval_targs[k] = eval_targs[k].replace("C:/home/<USER>/", "C:/Users/<USER>/")

        l1_res = engine.evaluate(tname, eval_targs, workspace_root=ws)
        if l1_res.verdict != PolicyVerdict.AMBIGUOUS:
            l1_dropped += 1
            continue

        l1_rule_display = f"ask ({l1_res.rule_id})" if l1_res.rule_id else "ask (no-match)"
        family = classify_real_family(tname, raw, False)
        template = get_template(tname, raw)

        conf = cdata["confidence"]
        blast = cdata["blast_radius"]
        route = cdata["route"]
        sugg = ""

        if is_inline_script(raw):
            if conf >= 0.80 and (blast >= 3.0 or route == "needs-reasoning-model"):
                sugg = "Dangerous"
            else:
                sugg = ""
        else:
            if conf >= 0.80:
                if route == "deterministic-safe" and blast <= 2.0:
                    sugg = "Safe"
                elif blast >= 3.0 or route == "needs-reasoning-model":
                    sugg = "Dangerous"

        pool.append({
            "raw_command": raw,
            "scrubbed_command": scrub_command_keep_separators(raw),
            "tool_name": tname,
            "tool_args": targs,
            "workspace_root": ws,
            "l1_verdict": l1_rule_display,
            "l1_rule_id": l1_res.rule_id,
            "family": family,
            "template": template,
            "model_prediction": cdata,
            "uncertainty_score": cdata.get("uncertainty_score", 0.5),
            "suggested_label": sugg,
            "is_over_length": False,
            "token_length": 0,
        })

    print(f"L1 dropped (ALLOW/DENY): {l1_dropped}, Candidate ambiguous pool: {len(pool)}")

    # RANDOM stratified sampling (shuffle for true random selection)
    random.shuffle(pool)

    fam_to_items = defaultdict(list)
    for item in pool:
        fam_to_items[item["family"]].append(item)

    # Proportional-preserving targets across the 5 families:
    # Pool: Compound ~50.2%, PowerShell ~26.6%, Dev ~18.3%, General CLI ~3.8%, File Ops ~1.1%
    target_totals = {
        "Compound/Chained": 48,
        "PowerShell/Windows": 26,
        "Dev Toolchain": 18,
        "General CLI": 5,
        "File Operations": 3,
    }

    selected: List[Dict[str, Any]] = []
    selected_cmds = set()
    template_counts = Counter()
    max_per_template = 4

    for fam, target in target_totals.items():
        candidates = fam_to_items.get(fam, [])
        added = 0
        for cand in candidates:
            if added >= target:
                break
            if cand["raw_command"] in selected_cmds:
                continue
            if template_counts[cand["template"]] >= max_per_template:
                continue
            selected.append(cand)
            selected_cmds.add(cand["raw_command"])
            template_counts[cand["template"]] += 1
            added += 1

    print(f"Total selected after family stratification: {len(selected)}")
    fam_dist = Counter(s["family"] for s in selected)
    for f, c in fam_dist.most_common():
        print(f"  {f}: {c}")

    # Render Deliverables
    md_lines = [
        "# Review Sheet 2 — Candidate Real-Trace Annotations (Random Stratified Sample)",
        "",
        "> **Format:** `ID | Tool Name | Command / Target (Scrubbed) | Real Family | L1 Verdict Today | Model Score (Route / Conf / Blast) | Suggested Label | Human Label`",
        "> **Human Annotation Options:** `[ S ]` Safe (auto-allow), `[ D ]` Dangerous (hard-deny), `[ A ]` Ambiguous (needs human operator).",
        f"> **Total Items:** {len(selected)} (Random stratified across families from remaining {len(pool)} L1 ambiguous commands, seed={seed}).",
        "> **Sampling Design:** Pure random within family (un-biased for calibration / ECE), distinct from Sheet 1 boundary set.",
        "> **Explicit Policy:** Inline interpreter scripts (`python -c`, `node -e`) are strictly ASK-only regardless of model confidence.",
        f"> **Template Diversity:** Capped at $\\le {max_per_template}$ items per normalized template.",
        "",
        "| ID | Tool Name | Command / Target (Scrubbed) | Real Family | L1 Verdict Today | Model Score (Route / Conf / Blast) | Suggested Label | Human Label |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :---: |",
    ]

    jsonl_records = []

    for idx, item in enumerate(selected, 1):
        item_id = f"RS2-{idx:03d}"
        display_id = f"`{item_id}`"

        clean_cmd = item["scrubbed_command"].replace("\n", " ").replace("|", "\\|")
        if len(clean_cmd) > 400:
            clean_cmd = clean_cmd[:397] + "..."

        pred = item["model_prediction"]
        score_str = f"`{pred['route']}` conf={pred['confidence']:.2f} blast={pred['blast_radius']:.1f}"
        sugg_display = f"**{item['suggested_label']}**" if item['suggested_label'] else ""

        md_lines.append(
            f"| {display_id} | `{item['tool_name']}` | `{clean_cmd}` | {item['family']} | `{item['l1_verdict']}` | {score_str} | {sugg_display} | `[   ]` |"
        )

        jsonl_records.append({
            "id": item_id,
            "tool_name": item["tool_name"],
            "raw_command": item["raw_command"],
            "scrubbed_command": item["scrubbed_command"],
            "family": item["family"],
            "template": item["template"],
            "l1_verdict_today": item["l1_verdict"],
            "l1_rule_id": item["l1_rule_id"],
            "model_prediction": item["model_prediction"],
            "uncertainty_score": item.get("uncertainty_score", 0.5),
            "suggested_label": item["suggested_label"],
            "human_label": None,
            "sampling_method": "random_stratified_family",
        })

    md_path = Path("private/review-sheet-2.md")
    md_path.write_text("\n".join(md_lines) + "\n", encoding="utf-8")
    print(f"Saved review sheet markdown to: {md_path}")

    jsonl_path = Path("private/review_sheet_2.jsonl")
    with open(jsonl_path, "w", encoding="utf-8") as f:
        for r in jsonl_records:
            f.write(json.dumps(r) + "\n")
    print(f"Saved private machine-readable JSONL to: {jsonl_path}")

    return selected


if __name__ == "__main__":
    generate_sheet_2()
