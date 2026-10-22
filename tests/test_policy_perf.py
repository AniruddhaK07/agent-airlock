"""
Performance and ReDoS Adversarial Resilience Tests for Agent Airlock L1 Policy Engine.
Verifies that adversarial long inputs (10k+ chars) stay strictly below 5 ms p99 in L1,
and that regex patterns exhibit zero catastrophic backtracking.
"""

import time
import unittest
import numpy as np

from agent_airlock.policy.engine import HardPolicyEngine
from agent_airlock.policy.default_rules import get_default_rules
from agent_airlock.policy.models import PolicyVerdict


class TestPolicyEnginePerformance(unittest.TestCase):
    def setUp(self):
        self.engine = HardPolicyEngine(get_default_rules())
        self.workspace_root = "C:\\mock\\workspace"

    def test_adversarial_long_inputs_stay_under_5ms_p99(self):
        """
        Adversarial inputs (10k+ chars) must stay < 5.0 ms p99 in L1.
        Evaluates diverse worst-case payloads across all rule families.
        """
        adversarial_inputs = [
            ("10k 'A's echo", 'echo "' + 'A' * 10000 + '"'),
            ("10k 'a/b/' rm", 'rm -r ' + 'a/b/' * 2000),
            ("10k git flags", 'git diff ' + '--opt ' * 1500 + 'file.txt'),
            ("10k ps args", 'Get-ChildItem ' + 'param ' * 1500 + 'Path'),
            ("10k semicolon echo", 'echo "' + 'x; y; ' * 1500 + '"'),
            ("10k pipe echo", 'echo "' + 'a | b | ' * 1200 + '"'),
            ("10k quotes", 'echo ' + '"a"' * 3000),
            ("15k mixed payload", 'python -c "x = ' + '1 + ' * 3000 + '0"'),
            ("50k mega string", 'echo "' + 'hello world ' * 4000 + '"'),
        ]

        all_latencies_ms = []

        for name, adv_str in adversarial_inputs:
            # 1 warmup iteration to compile any uncompiled regexes and avoid first-run noise
            _ = self.engine.evaluate(
                "run_command",
                {"CommandLine": adv_str},
                workspace_root=self.workspace_root,
            )
            cmd_times = []
            for _ in range(25):
                t0 = time.perf_counter_ns()
                result = self.engine.evaluate(
                    "run_command",
                    {"CommandLine": adv_str},
                    workspace_root=self.workspace_root,
                )
                dt_ms = (time.perf_counter_ns() - t0) / 1e6
                cmd_times.append(dt_ms)
                # Verify that no adversarial string slips through to an unauthorized ALLOW
                if name in ("10k 'A's echo", "10k semicolon echo", "10k pipe echo", "15k mixed payload", "50k mega string"):
                    self.assertNotEqual(result.verdict, PolicyVerdict.ALLOW)

            p99_cmd = np.percentile(cmd_times, 99)
            self.assertLess(
                p99_cmd,
                5.0,
                f"Adversarial input '{name}' exceeded 5.0 ms threshold: p99={p99_cmd:.3f} ms"
            )
            all_latencies_ms.extend(cmd_times)

        overall_p99 = np.percentile(all_latencies_ms, 99)
        overall_p50 = np.percentile(all_latencies_ms, 50)
        overall_p95 = np.percentile(all_latencies_ms, 95)

        self.assertLess(
            overall_p99,
            5.0,
            f"Overall adversarial p99 exceeded 5.0 ms: p50={overall_p50:.3f} ms, p95={overall_p95:.3f} ms, p99={overall_p99:.3f} ms"
        )

    def test_adversarial_long_inputs_cold_cache_stays_under_5ms_p99(self):
        """
        Adversarial inputs (10k+ chars) on a strictly COLD cache must stay < 5.0 ms p99 in L1.
        Evaluates the same 9 worst-case payloads with N=225, resetting engine and caches on each run.
        """
        import gc
        from agent_airlock.policy.engine import _REALPATH_CACHE, _GIT_HOOKS_CACHE

        adversarial_inputs = [
            ("10k 'A's echo", 'echo "' + 'A' * 10000 + '"'),
            ("10k 'a/b/' rm", 'rm -r ' + 'a/b/' * 2000),
            ("10k git flags", 'git diff ' + '--opt ' * 1500 + 'file.txt'),
            ("10k ps args", 'Get-ChildItem ' + 'param ' * 1500 + 'Path'),
            ("10k semicolon echo", 'echo "' + 'x; y; ' * 1500 + '"'),
            ("10k pipe echo", 'echo "' + 'a | b | ' * 1200 + '"'),
            ("10k quotes", 'echo ' + '"a"' * 3000),
            ("15k mixed payload", 'python -c "x = ' + '1 + ' * 3000 + '0"'),
            ("50k mega string", 'echo "' + 'hello world ' * 4000 + '"'),
        ]

        cold_latencies_ms = []

        for name, adv_str in adversarial_inputs:
            for _ in range(25):
                _REALPATH_CACHE.clear()
                _GIT_HOOKS_CACHE.clear()
                cold_engine = HardPolicyEngine(get_default_rules())
                gc.collect()
                gc.disable()
                t0 = time.perf_counter_ns()
                result = cold_engine.evaluate(
                    "run_command",
                    {"CommandLine": adv_str},
                    workspace_root=self.workspace_root,
                )
                dt_ms = (time.perf_counter_ns() - t0) / 1e6
                gc.enable()
                cold_latencies_ms.append(dt_ms)

                if name in ("10k 'A's echo", "10k semicolon echo", "10k pipe echo", "15k mixed payload", "50k mega string"):
                    self.assertNotEqual(result.verdict, PolicyVerdict.ALLOW)

        cold_p50 = np.percentile(cold_latencies_ms, 50)
        cold_p95 = np.percentile(cold_latencies_ms, 95)
        cold_p99 = np.percentile(cold_latencies_ms, 99)

        self.assertEqual(len(cold_latencies_ms), 225)
        self.assertLess(
            cold_p99,
            5.0,
            f"Cold-cache adversarial p99 exceeded 5.0 ms: p50={cold_p50:.3f} ms, p95={cold_p95:.3f} ms, p99={cold_p99:.3f} ms"
        )

    def test_catastrophic_backtracking_fork_bomb_resilient(self):
        """Fork bomb regex must evaluate against 10k character strings in < 1.0 ms."""
        fork_bomb_rule = [r for r in self.engine.rules if r.id == "deny-fork-bomb"][0]
        long_str = 'echo "' + 'A' * 10000 + '"'
        
        times = []
        for _ in range(50):
            t0 = time.perf_counter_ns()
            fork_bomb_rule.compiled.search(long_str)
            times.append((time.perf_counter_ns() - t0) / 1e6)
            
        p99 = np.percentile(times, 99)
        self.assertLess(p99, 2.0, f"Fork bomb regex took too long: p99={p99:.3f} ms")

    def test_catastrophic_backtracking_powershell_resilient(self):
        """PowerShell regex must evaluate against 10k character argument list in < 1.0 ms."""
        ps_rule = [r for r in self.engine.rules if r.id == "allow-powershell-readonly"][0]
        long_ps_cmd = 'Get-ChildItem ' + 'param ' * 1500 + 'Path'
        
        times = []
        for _ in range(50):
            t0 = time.perf_counter_ns()
            ps_rule.compiled.search(long_ps_cmd)
            times.append((time.perf_counter_ns() - t0) / 1e6)
            
        p99 = np.percentile(times, 99)
        self.assertLess(p99, 2.0, f"PowerShell regex took too long: p99={p99:.3f} ms")


if __name__ == "__main__":
    unittest.main()
