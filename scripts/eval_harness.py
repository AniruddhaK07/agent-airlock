"""
Evaluation Harness for Agent Airlock v2 (Phase 0.3 / 0.4).
Computes quantitative security, usability, and performance metrics against evaluation datasets:
- False-Allow Rate with 95% Clopper-Pearson / Rule-of-Three upper bound
- False-Deny and False-Ask Rates
- Auto-Allow Precision
- Expected Calibration Error (ECE) with bootstrap CI
- End-to-end decision latencies (p50, p95, p99)

Usage:
    python scripts/eval_harness.py [--eval data/eval_set_draft.jsonl] [--ml] [--output metrics.json]
"""

import argparse
import json
import math
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import numpy as np

from agent_airlock.policy.engine import HardPolicyEngine
from agent_airlock.policy.default_rules import get_default_rules
from agent_airlock.daemon.router import IPCRouter
from agent_airlock.config import GatewayConfig


def clopper_pearson_upper_bound(k: int, n: int, confidence: float = 0.95) -> float:
    """
    Computes exact Clopper-Pearson binomial 1-sided upper bound for confidence level.
    If k == 0, uses Rule of Three: 1 - (1 - confidence)^(1/n) ~= 3/n for 95%.
    """
    if n == 0:
        return 1.0
    if k == 0:
        return 1.0 - (1.0 - confidence) ** (1.0 / n)
    try:
        from scipy.stats import beta
        return float(beta.ppf(confidence, k + 1, n - k))
    except ImportError:
        # Wilson score upper bound fallback if scipy is not installed
        z = 1.95996  # 95%
        p_hat = k / n
        denom = 1 + z**2 / n
        centre = (p_hat + z**2 / (2 * n)) / denom
        spread = z * math.sqrt(p_hat * (1 - p_hat) / n + z**2 / (4 * n**2)) / denom
        return min(1.0, centre + spread)


def compute_ece(confidences: List[float], accuracies: List[bool], n_bins: int = 10) -> float:
    if not confidences:
        return 0.0
    bins = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    total = len(confidences)
    confs = np.array(confidences)
    accs = np.array(accuracies, dtype=float)

    for i in range(n_bins):
        bin_mask = (confs > bins[i]) & (confs <= bins[i + 1])
        bin_count = np.sum(bin_mask)
        if bin_count > 0:
            bin_acc = np.mean(accs[bin_mask])
            bin_conf = np.mean(confs[bin_mask])
            ece += (bin_count / total) * abs(bin_acc - bin_conf)
    return float(ece)


def bootstrap_ece_ci(confidences: List[float], accuracies: List[bool], n_bootstraps: int = 500) -> Tuple[float, float]:
    if len(confidences) < 10:
        return (0.0, 0.0)
    confs = np.array(confidences)
    accs = np.array(accuracies)
    n = len(confs)
    rng = np.random.default_rng(42)
    boot_eces = []
    for _ in range(n_bootstraps):
        idxs = rng.integers(0, n, size=n)
        boot_eces.append(compute_ece(confs[idxs].tolist(), accs[idxs].tolist()))
    return (float(np.percentile(boot_eces, 2.5)), float(np.percentile(boot_eces, 97.5)))


class AirlockEvaluator:
    def __init__(self, use_ml: bool = False, checkpoint_path: Optional[str] = None):
        self.use_ml = use_ml
        self.config = GatewayConfig()
        self.policy_engine = HardPolicyEngine(get_default_rules())

        self.jev_client = None
        self.jev_evaluator = None
        if use_ml:
            from agent_airlock.backends.laya import LocalLayaClient
            from agent_airlock.backends.evaluator import JevEvaluator
            ckpt = checkpoint_path or "checkpoints/laya-finetuned"
            print(f"Loading ML backend from {ckpt}...")
            self.jev_client = LocalLayaClient(checkpoint_path=ckpt)
            self.jev_evaluator = JevEvaluator(thresholds=self.config.jev.thresholds)

        self.router = IPCRouter(
            policy_engine=self.policy_engine,
            auth_token=None,
            jev_client=self.jev_client,
            jev_evaluator=self.jev_evaluator,
            circuit_breaker_config=self.config.circuit_breaker,
            audit_logger=None,
        )
        if self.use_ml:
            self.router.model_ready = True
            self.router.model_loading = False

    def evaluate_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        tool_name = item.get("tool") or item.get("tool_name", "run_command")
        cmd = item.get("command", "")
        tool_args = item.get("tool_args") or {}
        if not tool_args and tool_name == "run_command":
            tool_args = {"CommandLine": cmd}
        elif not tool_args and tool_name == "view_file":
            # Strip tool name prefix if present
            path = cmd.replace("view_file ", "").strip()
            tool_args = {"AbsolutePath": path}

        pre_req = {
            "version": "1.0",
            "event": "PreToolUse",
            "payload": {
                "conversationId": "eval-session",
                "stepIdx": 1,
                "workspace_root": "C:\\mock\\workspace",
                "toolCall": {
                    "name": tool_name,
                    "args": tool_args,
                }
            }
        }

        t0 = time.perf_counter_ns()
        res = self.router.dispatch(pre_req)
        latency_ns = time.perf_counter_ns() - t0

        return {
            "decision": res.get("decision", "ask"),
            "reason": res.get("reason", ""),
            "rule_id": res.get("ruleId"),
            "jev_eval": res.get("jevEvaluation"),
            "latency_ns": latency_ns,
        }


def run_evaluation(eval_path: Path, use_ml: bool = False, output_file: Optional[Path] = None) -> Dict[str, Any]:
    print("=" * 80)
    print(f"EVALUATION HARNESS: Evaluating {eval_path} (ML enabled: {use_ml})")
    print("=" * 80)

    # Load dataset
    items = []
    with open(eval_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                items.append(json.loads(line))

    evaluator = AirlockEvaluator(use_ml=use_ml)

    # Classify ground truth per Section 14 and Ani's rubric:
    # - "safe" (deterministic-safe): acceptable to auto-run unattended every time.
    # - "danger" (needs-human): dangerous actions requiring human gate.
    # - "ambiguous": excluded from false-allow/false-deny gating, reported separately.
    total_items = len(items)
    dangerous_items = []
    safe_items = []
    ambiguous_items = []

    for item in items:
        lbl = item.get("label") or item.get("reviewed_label") or item.get("proposed_label")
        if lbl == "ambiguous":
            ambiguous_items.append(item)
        elif lbl in ("deterministic-safe", "safe"):
            safe_items.append(item)
        else:
            dangerous_items.append(item)

    print(f"Total Items: {total_items} | Safe: {len(safe_items)} | Dangerous: {len(dangerous_items)} | Ambiguous: {len(ambiguous_items)}")

    # Run evaluations
    all_results = []
    latencies_ns = []
    confidences = []
    accuracies = []

    false_allows = []
    false_denies = []
    false_asks = []
    auto_allows = []
    ambiguous_decisions = {"allow": 0, "deny": 0, "ask": 0, "force_ask": 0}

    for idx, item in enumerate(items, 1):
        res = evaluator.evaluate_item(item)
        latencies_ns.append(res["latency_ns"])
        dec = res["decision"]
        is_danger = item in dangerous_items
        is_safe = item in safe_items
        is_ambiguous = item in ambiguous_items

        # Confidence
        jev_eval = res.get("jev_eval")
        conf = 1.0
        if jev_eval and isinstance(jev_eval, dict):
            conf = float(jev_eval.get("choice_confidence", 1.0))

        if dec == "allow":
            auto_allows.append((item, res))

        if is_danger:
            accuracies.append(dec != "allow")
            confidences.append(conf)
            if dec == "allow":
                false_allows.append((item, res))
        elif is_safe:
            accuracies.append(dec == "allow")
            confidences.append(conf)
            if dec == "deny":
                false_denies.append((item, res))
            elif dec in ("ask", "force_ask"):
                false_asks.append((item, res))
        elif is_ambiguous:
            ambiguous_decisions[dec] = ambiguous_decisions.get(dec, 0) + 1
            # Ambiguous items are excluded from false-allow / false-deny gating

    # Metric calculations
    n_danger = len(dangerous_items)
    n_safe = len(safe_items)
    n_ambiguous = len(ambiguous_items)

    fa_count = len(false_allows)
    fa_rate = fa_count / n_danger if n_danger else 0.0
    fa_ub_95 = clopper_pearson_upper_bound(fa_count, n_danger, confidence=0.95)

    fd_count = len(false_denies)
    fd_rate = fd_count / n_safe if n_safe else 0.0

    fask_count = len(false_asks)
    fask_rate = fask_count / n_safe if n_safe else 0.0

    # Auto-allow precision: fraction of auto-allowed items that were actually safe
    safe_auto_allows = sum(1 for it, _ in auto_allows if it in safe_items)
    auto_allow_prec = safe_auto_allows / len(auto_allows) if auto_allows else 1.0

    ece = compute_ece(confidences, accuracies) if accuracies else 0.0
    ece_ci = bootstrap_ece_ci(confidences, accuracies) if accuracies else (0.0, 0.0)

    lat_ms = np.array(latencies_ns) / 1e6
    p50 = float(np.percentile(lat_ms, 50))
    p95 = float(np.percentile(lat_ms, 95))
    p99 = float(np.percentile(lat_ms, 99))
    cold_lat = lat_ms[0]
    warm_p50 = float(np.percentile(lat_ms[1:], 50)) if len(lat_ms) > 1 else p50

    metrics_report = {
        "dataset": str(eval_path),
        "total_items": total_items,
        "n_safe": n_safe,
        "n_dangerous": n_danger,
        "n_ambiguous": n_ambiguous,
        "use_ml": use_ml,
        "false_allow_count": fa_count,
        "false_allow_rate": fa_rate,
        "false_allow_rate_95_upper_bound": fa_ub_95,
        "false_deny_count": fd_count,
        "false_deny_rate": fd_rate,
        "false_ask_count": fask_count,
        "false_ask_rate": fask_rate,
        "auto_allow_count": len(auto_allows),
        "auto_allow_precision": auto_allow_prec,
        "ambiguous_decisions": ambiguous_decisions,
        "ece": ece,
        "ece_95_ci": list(ece_ci),
        "latency_cold_ms": float(cold_lat),
        "latency_warm_p50_ms": float(warm_p50),
        "latency_p50_ms": p50,
        "latency_p95_ms": p95,
        "latency_p99_ms": p99,
    }

    print("\n" + "=" * 80)
    print("EVALUATION HARNESS METRICS SUMMARY (Human-Reviewed Split)")
    print("=" * 80)
    print(f"False-Allow Rate       : {fa_rate:.2%} ({fa_count}/{n_danger}) [95% CI upper bound: {fa_ub_95:.2%}]")
    print(f"False-Deny Rate        : {fd_rate:.2%} ({fd_count}/{n_safe})")
    print(f"False-Ask Rate         : {fask_rate:.2%} ({fask_count}/{n_safe})")
    print(f"Auto-Allow Precision   : {auto_allow_prec:.2%} ({safe_auto_allows}/{len(auto_allows)} auto-allows)")
    print(f"Ambiguous Decisions    : {ambiguous_decisions} (N={n_ambiguous}, excluded from gating)")
    print(f"ECE (Calibration Error): {ece:.4f} [95% CI: {ece_ci[0]:.4f} - {ece_ci[1]:.4f}]")
    print(f"Latency Cold           : {cold_lat:.3f} ms")
    print(f"Latency Warm p50       : {warm_p50:.3f} ms")
    print(f"Latency p95 / p99      : {p95:.3f} ms / {p99:.3f} ms")

    if false_allows:
        print(f"\n[CRITICAL WARNING] {len(false_allows)} False-Allows detected:")
        for it, r in false_allows:
            print(f"  - Command: '{it.get('command')}' | Decision: {r['decision']} | Reason: {r['reason']}")

    if output_file:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(metrics_report, f, indent=2)
        print(f"\n[PASS] Metrics written to {output_file}")

    return metrics_report


def main():
    parser = argparse.ArgumentParser(description="Agent Airlock Evaluation Harness")
    parser.add_argument("--eval", type=str, default="data/eval_set_draft.jsonl", help="Evaluation set path")
    parser.add_argument("--ml", action="store_true", help="Enable ML model during evaluation")
    parser.add_argument("--output", type=str, default="metrics_baseline.json", help="Output JSON metrics path")
    args = parser.parse_args()

    run_evaluation(Path(args.eval), use_ml=args.ml, output_file=Path(args.output) if args.output else None)


if __name__ == "__main__":
    main()
