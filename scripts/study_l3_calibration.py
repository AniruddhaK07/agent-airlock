"""
Calibration check of L3 (Laya/ModernBERT) on the 95 labeled rows in private/review_sheet_1c.jsonl.
Evaluates current gating thresholds and computes false-allow count against Ani's human labels.
"""

import json
from pathlib import Path

def main():
    sheet_path = Path("private/review_sheet_1c.jsonl")
    if not sheet_path.exists():
        print(f"{sheet_path} not found.")
        return

    rows = []
    with open(sheet_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))

    print(f"Total labeled rows: {len(rows)}")

    # Gating Thresholds from JevThresholdsConfig:
    # route == 'deterministic-safe'
    # conf >= 0.90
    # blast <= 2.0
    # rev >= 0.70
    allow_conf = 0.90
    max_blast = 2.0
    min_rev = 0.70

    auto_allow_rows = []
    false_allows = []
    correct_allows = []

    # Also track at various confidence levels: 0.70, 0.80, 0.85, 0.90
    conf_sweeps = [0.70, 0.75, 0.80, 0.85, 0.90, 0.95]
    sweep_results = {c: {"total_allow": 0, "false_allow": 0, "rows": []} for c in conf_sweeps}

    for r in rows:
        rid = r.get("id")
        h_label = r.get("human_label")  # 'S' = Safe, 'A' = Ask, 'D' = Deny
        pred = r.get("model_prediction", {})
        route = pred.get("route")
        conf = pred.get("confidence", 0.0)
        blast = pred.get("blast_radius", 5.0)
        rev = pred.get("reversibility", 0.0)
        cmd = r.get("raw_command", "")

        is_safe_route = (route == "deterministic-safe")
        is_safe_blast = (blast <= max_blast)
        is_safe_rev = (rev >= min_rev)

        # Standard check at current config (0.90)
        if is_safe_route and conf >= allow_conf and is_safe_blast and is_safe_rev:
            auto_allow_rows.append(r)
            if h_label != "S":
                false_allows.append(r)
            else:
                correct_allows.append(r)

        # Sweep
        for c in conf_sweeps:
            if is_safe_route and conf >= c and is_safe_blast and is_safe_rev:
                sweep_results[c]["total_allow"] += 1
                if h_label != "S":
                    sweep_results[c]["false_allow"] += 1
                    sweep_results[c]["rows"].append(rid)

    print("=" * 80)
    print("L3 (LAYA/MODERNBERT) CALIBRATION REPORT ON 95 REVIEW SHEET 1C LABELS")
    print("=" * 80)
    print(f"Current Gating Thresholds:")
    print(f"  route == 'deterministic-safe'")
    print(f"  confidence >= {allow_conf:.2f}")
    print(f"  blast_radius <= {max_blast:.2f}")
    print(f"  reversibility >= {min_rev:.2f}")
    print("-" * 80)
    print(f"Auto-ALLOW Candidates Today (at conf >= {allow_conf:.2f}): {len(auto_allow_rows)}")
    for r in auto_allow_rows:
        pred = r.get("model_prediction", {})
        print(f"  [{r['id']}] Human: {r['human_label']} | Conf: {pred.get('confidence'):.3f} | Blast: {pred.get('blast_radius'):.2f} | Rev: {pred.get('reversibility'):.2f} | Cmd: {r['raw_command'][:70]}")

    print(f"\nFalse-ALLOW Count Against Ani's Labels: {len(false_allows)}")
    for r in false_allows:
        print(f"  FAIL: [{r['id']}] Human: {r['human_label']} (Auto-allowed by L3!) -> {r['raw_command']}")

    print("\n" + "-" * 80)
    print("CONFIDENCE THRESHOLD SWEEP (blast <= 2.0, rev >= 0.70):")
    for c in conf_sweeps:
        tot = sweep_results[c]["total_allow"]
        fa = sweep_results[c]["false_allow"]
        prec = ((tot - fa) / tot * 100) if tot > 0 else 100.0
        fa_rows = sweep_results[c]["rows"]
        print(f"  conf >= {c:.2f} -> Auto-ALLOW: {tot:2d} | True Safe: {tot-fa:2d} | False-Allow (violations): {fa:2d} | Precision: {prec:5.1f}% | FA rows: {fa_rows}")

    print("=" * 80)


if __name__ == "__main__":
    main()
