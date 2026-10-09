"""
Dataset Validation Script for Agent Airlock v2.
Performs comprehensive data hygiene checks on dataset splits:
1. Schema verification (required fields, types, range bounds)
2. Label taxonomy validation (route, blast_level, reversible)
3. Internal deduplication
4. Category / Archetype balance report
5. Leakage check against held-out validation / eval set

Usage:
    python scripts/validate_dataset.py [--train data/train.json] [--val data/val.json]
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import List, Dict, Any, Tuple

ALLOWED_CATEGORIES = {
    "known-safe",
    "known-dangerous",
    "ambiguous-high-risk",
    "ambiguous-bounded",
    "low-confidence",
}

ALLOWED_ROUTES = {
    "deterministic-safe",
    "needs-human",
    "needs-reasoning-model",
}


def validate_split(name: str, path: Path) -> Tuple[List[Dict[str, Any]], List[str]]:
    if not path.exists():
        return [], [f"File {path} does not exist."]

    with open(path, "r", encoding="utf-8") as f:
        try:
            records = json.load(f)
        except Exception as e:
            return [], [f"JSON parsing error in {path}: {e}"]

    if not isinstance(records, list):
        return [], [f"Root in {path} must be a JSON array, got {type(records).__name__}"]

    errors = []
    seen_commands = set()

    for idx, r in enumerate(records):
        prefix = f"[{name} #{idx}]"
        if not isinstance(r, dict):
            errors.append(f"{prefix} Entry is not a dictionary.")
            continue

        cmd = r.get("command")
        if not cmd or not isinstance(cmd, str) or not cmd.strip():
            errors.append(f"{prefix} Missing or empty 'command'.")
        elif cmd.strip().lower() in seen_commands:
            errors.append(f"{prefix} Duplicate command: '{cmd.strip()}'.")
        else:
            seen_commands.add(cmd.strip().lower())

        cat = r.get("category")
        if cat not in ALLOWED_CATEGORIES:
            errors.append(f"{prefix} Invalid category '{cat}'. Allowed: {ALLOWED_CATEGORIES}")

        route = r.get("route")
        if route not in ALLOWED_ROUTES:
            errors.append(f"{prefix} Invalid route '{route}'. Allowed: {ALLOWED_ROUTES}")

        blast = r.get("blast_level")
        if blast is None or not isinstance(blast, (int, float)) or not (0 <= blast <= 4):
            errors.append(f"{prefix} Invalid blast_level '{blast}'. Must be in range [0, 4].")

        rev = r.get("reversible")
        if rev is None or not isinstance(rev, (int, float)) or not (0.0 <= rev <= 1.0):
            errors.append(f"{prefix} Invalid reversible '{rev}'. Must be float in range [0.0, 1.0].")

    return records, errors


def print_balance_report(name: str, records: List[Dict[str, Any]]) -> None:
    print(f"\n--- {name} Dataset Balance (N={len(records)}) ---")
    cat_counts = Counter(r.get("category") for r in records)
    route_counts = Counter(r.get("route") for r in records)

    print("Categories:")
    for cat in sorted(ALLOWED_CATEGORIES):
        print(f"  {cat:22s}: {cat_counts.get(cat, 0):3d} ({cat_counts.get(cat, 0)/len(records)*100:5.1f}%)")

    print("Routes:")
    for rt in sorted(ALLOWED_ROUTES):
        print(f"  {rt:22s}: {route_counts.get(rt, 0):3d} ({route_counts.get(rt, 0)/len(records)*100:5.1f}%)")


def main():
    parser = argparse.ArgumentParser(description="Validate Agent Airlock datasets.")
    parser.add_argument("--train", type=str, default="data/train.json")
    parser.add_argument("--val", type=str, default="data/val.json")
    args = parser.parse_args()

    train_path = Path(args.train)
    val_path = Path(args.val)

    train_records, train_errors = validate_split("train", train_path)
    val_records, val_errors = validate_split("val", val_path)

    all_errors = train_errors + val_errors

    if all_errors:
        print("[FAIL] Dataset validation encountered errors:")
        for err in all_errors:
            print(f"  - {err}")
        sys.exit(1)

    print("[PASS] Schema, taxonomy, and deduplication checks passed.")
    print_balance_report("Train", train_records)
    print_balance_report("Validation", val_records)

    # Check cross-split leakage
    train_cmds = {r["command"].strip().lower() for r in train_records}
    val_cmds = {r["command"].strip().lower() for r in val_records}
    overlap = train_cmds & val_cmds
    if overlap:
        print(f"\n[FAIL] Cross-split leakage: {len(overlap)} commands appear in both train and val splits!")
        for c in overlap:
            print(f"  - '{c}'")
        sys.exit(1)

    print(f"\n[PASS] Cross-split isolation: Zero command leakage between train ({len(train_records)}) and val ({len(val_records)}).")
    if len(val_records) < 100:
        print(f"[NOTE] Validation set size ({len(val_records)}) is noted as too small for confident threshold calibration (ADR-002).")
    sys.exit(0)


if __name__ == "__main__":
    from typing import Tuple
    main()
