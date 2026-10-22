"""
Trace Replay Harness for Agent Airlock v2 (Phase 0.2 / 0.3).
Replays scrubbed traces through an isolated pipeline with a simulated human approver.
Measures stateful pipeline behavior, circuit breaker dynamics, latency, and approval fatigue.

Usage:
    python scripts/replay.py [--trace data/traces/trace_<id>.json] [--all] [--ml]
"""

import argparse
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
import numpy as np

from agent_airlock.policy.engine import HardPolicyEngine
from agent_airlock.policy.default_rules import get_default_rules
from agent_airlock.daemon.router import IPCRouter
from agent_airlock.config import GatewayConfig, JevThresholdsConfig, CircuitBreakerConfig

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger("replay")


class TraceReplayer:
    def __init__(self, use_ml: bool = False, checkpoint_path: Optional[str] = None):
        self.use_ml = use_ml
        self.config = GatewayConfig()
        
        # Policy engine
        self.policy_engine = HardPolicyEngine(get_default_rules())
        
        # ML Backend
        self.jev_client = None
        self.jev_evaluator = None
        if use_ml:
            from agent_airlock.backends.laya import LocalLayaClient
            from agent_airlock.backends.evaluator import JevEvaluator
            ckpt = checkpoint_path or "checkpoints/laya-finetuned"
            print(f"Loading ML model from {ckpt}...")
            self.jev_client = LocalLayaClient(checkpoint_path=ckpt)
            self.jev_evaluator = JevEvaluator(thresholds=self.config.jev.thresholds)

        # Isolated router without writing to live audit log
        self.router = IPCRouter(
            policy_engine=self.policy_engine,
            auth_token=None,
            jev_client=self.jev_client,
            jev_evaluator=self.jev_evaluator,
            circuit_breaker_config=self.config.circuit_breaker,
            audit_logger=None,  # Hermetic: no audit log side effects
        )
        if self.use_ml:
            self.router.model_ready = True
            self.router.model_loading = False

    def replay_trace(self, trace_path: Path) -> Dict[str, Any]:
        with open(trace_path, "r", encoding="utf-8") as f:
            trace_doc = json.load(f)

        conv_id = trace_doc.get("conversation_id", "trace-conv")
        steps = trace_doc.get("steps", [])

        stats = {
            "conversation_id": conv_id,
            "total_steps": len(steps),
            "decisions": {"allow": 0, "deny": 0, "ask": 0, "force_ask": 0},
            "sources": {"policy": 0, "circuit_breaker": 0, "ml": 0},
            "simulated_human_approved": 0,
            "simulated_human_denied": 0,
            "circuit_breaker_trips": 0,
            "latencies_ns": [],
            "latency_class_breakdown": {},
            "latency_class_breakdown_delay_only": {},
            "latency_class_breakdown_retroactive": {},
            "latency_class_breakdown_first_match": {},
        }

        # Clear workspace state for fresh trace run
        self.router.workspaces.clear()

        for step in steps:
            sidx = step.get("step_idx", 0)
            tool_name = step.get("tool_name", "")
            tool_args = step.get("tool_args", {})
            ws_root = step.get("workspace_root") or trace_doc.get("workspace_root") or "C:\\mock\\workspace"
            real_outcome = step.get("outcome", "success")
            human_inferred = step.get("human_approved_inferred", False)
            lat_class = step.get("latency_class", "unknown")
            lc_delay_only = step.get("latency_class_delay_only", lat_class)
            lc_retroactive = step.get("latency_class_retroactive", lat_class)
            lc_first_match = step.get("latency_class_first_match", lat_class)

            pre_req = {
                "version": "1.0",
                "event": "PreToolUse",
                "payload": {
                    "conversationId": conv_id,
                    "stepIdx": sidx,
                    "workspace_root": ws_root,
                    "toolCall": {
                        "name": tool_name,
                        "args": tool_args,
                    }
                }
            }

            t0 = time.perf_counter_ns()
            res = self.router.dispatch(pre_req)
            t_delta = time.perf_counter_ns() - t0
            stats["latencies_ns"].append(t_delta)

            dec = res.get("decision", "ask")
            stats["decisions"][dec] = stats["decisions"].get(dec, 0) + 1

            for bk_key, c_val in [
                ("latency_class_breakdown", lc_first_match),
                ("latency_class_breakdown_first_match", lc_first_match),
                ("latency_class_breakdown_delay_only", lc_delay_only),
                ("latency_class_breakdown_retroactive", lc_retroactive),
            ]:
                if c_val not in stats[bk_key]:
                    stats[bk_key][c_val] = {"total": 0, "allow": 0, "deny": 0, "ask": 0, "force_ask": 0}
                stats[bk_key][c_val]["total"] += 1
                stats[bk_key][c_val][dec] = stats[bk_key][c_val].get(dec, 0) + 1

            if res.get("circuitBreakerTripped"):
                stats["circuit_breaker_trips"] += 1
                stats["sources"]["circuit_breaker"] += 1
            elif res.get("ruleId"):
                stats["sources"]["policy"] += 1
            elif res.get("jevEvaluation"):
                stats["sources"]["ml"] += 1
            else:
                stats["sources"]["policy"] += 1

            # Simulated Approver
            if dec in ("ask", "force_ask"):
                if human_inferred:
                    stats["simulated_human_approved"] += 1
                    # Execute tool -> dispatch PostToolUse
                    self._dispatch_post(conv_id, sidx, ws_root, tool_name, real_outcome)
                else:
                    stats["simulated_human_denied"] += 1
                    # Tool does not execute -> no PostToolUse
            elif dec == "allow":
                # Auto-executed -> dispatch PostToolUse
                self._dispatch_post(conv_id, sidx, ws_root, tool_name, real_outcome)
            elif dec == "deny":
                # Hard denied -> no execution
                pass

        return stats

    def _dispatch_post(self, conv_id: str, sidx: int, ws_root: str, tool_name: str, real_outcome: str):
        is_error = (real_outcome == "failure")
        tool_res = {"exit_code": 1 if is_error else 0, "error": "Simulated failure" if is_error else None}
        post_req = {
            "version": "1.0",
            "event": "PostToolUse",
            "payload": {
                "conversationId": conv_id,
                "stepIdx": sidx,
                "workspace_root": ws_root,
                "toolCall": {"name": tool_name},
                "status": "error" if is_error else "success",
                "toolResult": tool_res,
            }
        }
        self.router.dispatch(post_req)


def main():
    parser = argparse.ArgumentParser(description="Agent Airlock Trace Replay Harness")
    parser.add_argument("--trace", type=str, help="Path to single trace JSON file")
    parser.add_argument("--all", action="store_true", help="Replay all traces in data/traces/")
    parser.add_argument("--ml", action="store_true", help="Enable ML model during replay (requires checkpoints)")
    args = parser.parse_args()

    replayer = TraceReplayer(use_ml=args.ml)

    if args.trace:
        trace_files = [Path(args.trace)]
    else:
        trace_files = sorted(Path("data/traces").glob("trace_*.json"))
        if not args.all and len(trace_files) > 1:
            trace_files = trace_files[:1]

    if not trace_files:
        print("No traces found to replay. Run scripts/build_traces.py first.")
        return

    print("=" * 80)
    print(f"REPLAY HARNESS: Replaying {len(trace_files)} trace(s) (ML enabled: {args.ml})")
    print("=" * 80)

    total_steps = 0
    total_asks = 0
    total_allows = 0
    total_denies = 0
    all_latencies = []
    agg_first_match: Dict[str, Dict[str, int]] = {}
    agg_delay_only: Dict[str, Dict[str, int]] = {}
    agg_retroactive: Dict[str, Dict[str, int]] = {}

    for tf in trace_files:
        stats = replayer.replay_trace(tf)
        total_steps += stats["total_steps"]
        total_asks += (stats["decisions"].get("ask", 0) + stats["decisions"].get("force_ask", 0))
        total_allows += stats["decisions"].get("allow", 0)
        total_denies += stats["decisions"].get("deny", 0)
        all_latencies.extend(stats["latencies_ns"])

        for agg_dict, stat_key in [
            (agg_first_match, "latency_class_breakdown_first_match"),
            (agg_delay_only, "latency_class_breakdown_delay_only"),
            (agg_retroactive, "latency_class_breakdown_retroactive"),
        ]:
            for lc, ccounts in stats[stat_key].items():
                if lc not in agg_dict:
                    agg_dict[lc] = {"total": 0, "allow": 0, "deny": 0, "ask": 0, "force_ask": 0}
                for k, v in ccounts.items():
                    agg_dict[lc][k] = agg_dict[lc].get(k, 0) + v

        cid_short = stats["conversation_id"][:16]
        hp_stats = stats["latency_class_breakdown_first_match"].get("human_prompt", {})
        hp_asks = hp_stats.get("ask", 0) + hp_stats.get("force_ask", 0)
        hp_fatigue = (hp_asks / stats["total_steps"] * 100) if stats["total_steps"] else 0
        print(f"[{cid_short}..] {stats['total_steps']:3d} steps | ALLOW: {stats['decisions'].get('allow', 0):3d} | DENY: {stats['decisions'].get('deny', 0):2d} | ASK: {stats['decisions'].get('ask', 0):3d} | Human Prompts (mid): {hp_asks:2d} ({hp_fatigue:4.1f}/100 cmds)")

    # Aggregate stats
    lat_ms = np.array(all_latencies) / 1e6 if all_latencies else np.array([0.0])
    p50 = float(np.percentile(lat_ms, 50))
    p95 = float(np.percentile(lat_ms, 95))
    p99 = float(np.percentile(lat_ms, 99))

    def calc_metrics(agg_dict: Dict[str, Dict[str, int]]):
        hp = agg_dict.get("human_prompt", {})
        base = hp.get("total", 0)
        rem = hp.get("ask", 0) + hp.get("force_ask", 0)
        saved = base - rem
        base_rate = (base / total_steps * 100) if total_steps else 0.0
        rem_rate = (rem / total_steps * 100) if total_steps else 0.0
        saved_rate = (saved / total_steps * 100) if total_steps else 0.0
        return base, rem, saved, base_rate, rem_rate, saved_rate

    lower_base, lower_rem, lower_saved, lower_base_rate, lower_rem_rate, lower_saved_rate = calc_metrics(agg_retroactive)
    mid_base, mid_rem, mid_saved, mid_base_rate, mid_rem_rate, mid_saved_rate = calc_metrics(agg_first_match)
    upper_base, upper_rem, upper_saved, upper_base_rate, upper_rem_rate, upper_saved_rate = calc_metrics(agg_delay_only)

    print("=" * 80)
    print("AGGREGATE REPLAY METRICS")
    print("=" * 80)
    print(f"Total Steps Replayed    : {total_steps}")
    print(f"Total ALLOW             : {total_allows} ({total_allows/total_steps*100:.2f}%)")
    print(f"Total DENY              : {total_denies} ({total_denies/total_steps*100:.2f}%)")
    print(f"Total ASK               : {total_asks} ({total_asks/total_steps*100:.2f}%)")
    print("-" * 80)
    print("APPROVAL FATIGUE RANGE REPORT (Human Prompts per 100 commands)")
    print("-" * 80)
    print(f"1. Retroactive Host-Rule (Lower Bound):")
    print(f"   Baseline Human Prompts : {lower_base:5d} ({lower_base_rate:5.2f} per 100 commands)")
    print(f"   Replay Human Prompts   : {lower_rem:5d} ({lower_rem_rate:5.2f} per 100 commands)")
    print(f"   Human Prompts Saved    : {lower_saved:5d} ({lower_saved_rate:5.2f} per 100 commands saved)")
    print()
    print(f"2. First-Match Host-Rule (Middle):")
    print(f"   Baseline Human Prompts : {mid_base:5d} ({mid_base_rate:5.2f} per 100 commands)")
    print(f"   Replay Human Prompts   : {mid_rem:5d} ({mid_rem_rate:5.2f} per 100 commands)")
    print(f"   Human Prompts Saved    : {mid_saved:5d} ({mid_saved_rate:5.2f} per 100 commands saved)")
    print()
    print(f"3. Delay-Only Latency >=1.5s (Upper Bound):")
    print(f"   Baseline Human Prompts : {upper_base:5d} ({upper_base_rate:5.2f} per 100 commands)")
    print(f"   Replay Human Prompts   : {upper_rem:5d} ({upper_rem_rate:5.2f} per 100 commands)")
    print(f"   Human Prompts Saved    : {upper_saved:5d} ({upper_saved_rate:5.2f} per 100 commands saved)")
    print("-" * 80)
    print("RANGE SUMMARY [Lower, Middle, Upper]:")
    print(f"  Baseline Human Prompts : [{lower_base_rate:.2f}, {mid_base_rate:.2f}, {upper_base_rate:.2f}] per 100 commands")
    print(f"  Replay Human Prompts   : [{lower_rem_rate:.2f}, {mid_rem_rate:.2f}, {upper_rem_rate:.2f}] per 100 commands")
    print(f"  Human Prompts Saved    : [{lower_saved_rate:.2f}, {mid_saved_rate:.2f}, {upper_saved_rate:.2f}] per 100 commands saved")
    print("-" * 80)
    print(f"Decision Latency (ms)   : p50={p50:.3f} ms | p95={p95:.3f} ms | p99={p99:.3f} ms")


if __name__ == "__main__":
    main()
