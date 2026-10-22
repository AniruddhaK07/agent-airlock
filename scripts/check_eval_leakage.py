"""
Evaluation Leakage Checker for Agent Airlock v2.
Verifies that no evaluation commands (exact or normalized) appear in the training corpus
or expansion datasets.

Usage:
    python scripts/check_eval_leakage.py [--eval data/val.json] [--train data/train.json]
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import List, Dict, Set, Tuple


def normalize_command(cmd: str) -> str:
    """
    Normalizes command string to prevent syntactic evasion / near-duplicate leakage.
    - Strips leading/trailing whitespace
    - Collapses multiple whitespace characters
    - Normalizes common shell quotes
    """
    if not cmd:
        return ""
    # Normalize whitespace
    c = " ".join(cmd.strip().split())
    # Normalize redundant single/double quotes around simple tokens
    c = re.sub(r'["\']([a-zA-Z0-9_\-\./]+)["\']', r'\1', c)
    return c.lower()


def load_dataset(path: Path) -> List[Dict]:
    if not path.exists():
        raise FileNotFoundError(f"Dataset file not found: {path}")
    if path.suffix == ".jsonl":
        records = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        return records
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict) and "benchmark_15" in data:
        return data["benchmark_15"]
    if isinstance(data, list):
        return data
    raise ValueError(f"Unexpected data format in {path}")


def check_leakage(train_path: Path, eval_path: Path) -> Tuple[int, List[Dict]]:
    train_data = load_dataset(train_path)
    eval_data = load_dataset(eval_path)

    # Build normalized lookup for train
    train_lookup: Dict[str, List[Dict]] = {}
    for item in train_data:
        norm = normalize_command(item.get("command", ""))
        if norm:
            train_lookup.setdefault(norm, []).append(item)

    leaks = []
    for item in eval_data:
        cmd = item.get("command", "")
        norm = normalize_command(cmd)
        if norm in train_lookup:
            leaks.append({
                "eval_command": cmd,
                "eval_category": item.get("category") or item.get("label"),
                "train_matches": train_lookup[norm],
            })

    return len(eval_data), leaks


def main():
    parser = argparse.ArgumentParser(description="Check for data leakage between eval and train splits.")
    parser.add_argument("--train", type=str, default="data/train.json", help="Path to training dataset")
    parser.add_argument("--eval", type=str, default="data/val.json", help="Path to evaluation/validation dataset")
    args = parser.parse_args()

    train_path = Path(args.train)
    eval_path = Path(args.eval)

    print(f"Checking leakage between Eval ({eval_path}) and Train ({train_path})...")
    total_eval, leaks = check_leakage(train_path, eval_path)

    if leaks:
        print(f"\n[FAIL] LEAKAGE DETECTED! {len(leaks)} of {total_eval} eval items found in train set:")
        for leak in leaks:
            print(f"  - Eval command: '{leak['eval_command']}' ({leak['eval_category']})")
            for tm in leak["train_matches"]:
                print(f"      Matched train: '{tm.get('command')}' ({tm.get('category')})")
        sys.exit(1)
    else:
        print(f"[PASS] Zero leakage detected across {total_eval} evaluation items!")
        sys.exit(0)


if __name__ == "__main__":
    main()
