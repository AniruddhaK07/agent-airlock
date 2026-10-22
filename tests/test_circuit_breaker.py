"""
Unit and integration tests for Phase 4: Stateful Circuit Breaker.
Verifies error signature hashing, ephemeral token normalization,
Tier 1 hash pre-filter, Tier 2 Noul escalation via local Laya,
workspace isolation, dispatch order invariants, and end-to-end daemon IPC loop halting.
"""

import unittest
import asyncio
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from agent_airlock.config import (
    GatewayConfig,
    DaemonConfig,
    CircuitBreakerConfig,
    JevConfig,
    AuditConfig,
)
from agent_airlock.circuit_breaker.hasher import (
    normalize_error,
    normalize_command,
    hash_string,
    create_error_signature,
    compute_similarity,
)
from agent_airlock.circuit_breaker.breaker import (
    CircuitBreaker,
    CircuitBreakerResult,
)
from agent_airlock.daemon.server import DaemonServer
from agent_airlock.hooks.stub_client import StubHookClient

try:
    import laya
    LAYA_AVAILABLE = True
except ImportError:
    LAYA_AVAILABLE = False


class TestCircuitBreakerHashing(unittest.TestCase):
    """
    Unit tests for error signature normalization and hashing.
    """

    def test_normalize_error_ephemeral_tokens(self):
        """Verifies timestamps, memory addresses, PIDs, and line numbers are normalized."""
        raw_error_1 = "Error at 2026-09-27T00:50:14.123Z in process PID 12345 (0x7fff5fbff820): connection timed out at line 45:12"
        raw_error_2 = "Error at 2026-09-27T01:15:22.999Z in process PID 98765 (0x7fff1234abcd): connection timed out at line 99:01"

        norm_1 = normalize_error(raw_error_1)
        norm_2 = normalize_error(raw_error_2)

        # Both should normalize to identical text
        self.assertEqual(norm_1, norm_2)
        self.assertIn("<TIMESTAMP>", norm_1)
        self.assertIn("<PID>", norm_1)
        self.assertIn("<ADDR>", norm_1)
        self.assertIn("<LINE>", norm_1)

        # Hashes of normalized errors should match exactly
        self.assertEqual(hash_string(norm_1), hash_string(norm_2))

    def test_normalize_command_quotes_and_spaces(self):
        """Verifies cosmetic quotes and repeated whitespace are normalized."""
        cmd_1 = '  "npm   install   express"  '
        cmd_2 = "'npm install express'"
        cmd_3 = "npm install express"

        norm_1 = normalize_command(cmd_1)
        norm_2 = normalize_command(cmd_2)
        norm_3 = normalize_command(cmd_3)

        self.assertEqual(norm_1, norm_2)
        self.assertEqual(norm_2, norm_3)
        self.assertEqual(norm_1, "npm install express")

    def test_compute_similarity_metrics(self):
        """Verifies string similarity ratios."""
        cmd_orig = "npm install my-package"
        cmd_near = "npm install my-package --force"
        cmd_diff = "python scripts/test.py"

        sim_near = compute_similarity(cmd_orig, cmd_near)
        sim_diff = compute_similarity(cmd_orig, cmd_diff)

        self.assertGreater(sim_near, 0.75)
        self.assertLess(sim_diff, 0.30)


class TestCircuitBreakerLogic(unittest.TestCase):
    """
    Unit tests for CircuitBreaker state management and two-tier detection.
    """

    def setUp(self):
        self.cfg = CircuitBreakerConfig(
            enabled=True,
            hash_window=3,
            similarity_threshold=0.80,
            noul_confidence=0.80,
            break_action="force_ask",
        )
        self.breaker = CircuitBreaker(workspace_root="/test/workspace", config=self.cfg)

    def test_non_repeating_failure_does_not_trip(self):
        """A failure followed by a completely different command does not trip the breaker."""
        # 1. Record failure for python migrate
        self.breaker.record_failure(
            tool_name="run_command",
            tool_args={"CommandLine": "python manage.py migrate"},
            error="OperationalError: database is locked",
        )

        # 2. Check candidate command: git status
        res = self.breaker.check_pre_tool(
            tool_name="run_command",
            tool_args={"CommandLine": "git status"},
        )
        self.assertFalse(res.is_tripped)
        self.assertEqual(res.action, "none")

    def test_exact_repeating_failure_trips(self):
        """Repeated identical failures in recent window trip the circuit breaker."""
        cmd = "npm run test"
        err = "AssertionError: expected true but got false at 0x4891"

        # Record first failure
        self.breaker.record_failure("run_command", {"CommandLine": cmd}, err)

        # Candidate check for same command
        res = self.breaker.check_pre_tool("run_command", {"CommandLine": cmd})
        self.assertTrue(res.is_tripped)
        self.assertEqual(res.action, "force_ask")
        self.assertIn("Identical action", res.reason)
        self.assertIn("npm run test", res.reason)

    def test_disabled_circuit_breaker_does_not_trip(self):
        """When enabled=False, breaker never trips."""
        cfg_disabled = CircuitBreakerConfig(enabled=False)
        breaker_disabled = CircuitBreaker(workspace_root="/test/workspace", config=cfg_disabled)

        breaker_disabled.record_failure("run_command", {"CommandLine": "fail_cmd"}, "err")
        res = breaker_disabled.check_pre_tool("run_command", {"CommandLine": "fail_cmd"})
        self.assertFalse(res.is_tripped)

    def test_noul_escalation_on_structural_similarity(self):
        """
        When surface text differs but similarity >= threshold,
        escalates to local Laya client for Noul semantic confirmation.
        """
        mock_laya = MagicMock()
        mock_laya.agent.predict.return_value = {
            "answers": {
                "is_semantic_repeat": {
                    "type": "noul",
                    "noul": 0.85,
                    "confidence": 0.88,
                }
            }
        }
        breaker = CircuitBreaker(
            workspace_root="/test/workspace",
            config=self.cfg,
            local_laya_client=mock_laya,
        )

        # Prior failure
        breaker.record_failure(
            tool_name="run_command",
            tool_args={"CommandLine": "npm install pkg-name"},
            error="E404 Not Found",
        )

        # Near repeat with added flag
        candidate = "npm install pkg-name --force"
        res = breaker.check_pre_tool(
            tool_name="run_command",
            tool_args={"CommandLine": candidate},
        )

        self.assertTrue(res.is_tripped)
        self.assertEqual(res.action, "force_ask")
        self.assertIn("Laya Noul", res.reason)
        mock_laya.agent.predict.assert_called_once()

    def test_noul_rejection_when_confident_not_repeat(self):
        """
        Regression test: When Laya Noul evaluates that an action is NOT a repeat
        (e.g., noul_prob=0.35 leaning 'not a repeat', with high confidence=0.88),
        the circuit breaker must NOT trip.

        Under the old buggy condition (conf >= 0.80 OR noul >= 0.35), this would
        have falsely tripped because conf >= 0.80 was satisfied even though the model
        confidently answered NO.
        Under the corrected condition (noul_prob >= 0.60 AND noul_conf >= 0.80),
        the breaker correctly permits execution without tripping.
        """
        mock_laya = MagicMock()
        mock_laya.agent.predict.return_value = {
            "answers": {
                "is_semantic_repeat": {
                    "type": "noul",
                    "noul": 0.35,        # 65% probability NOT a repeat
                    "confidence": 0.88,  # Confidently not a repeat
                }
            }
        }
        breaker = CircuitBreaker(
            workspace_root="/test/workspace",
            config=self.cfg,
            local_laya_client=mock_laya,
        )

        breaker.record_failure(
            tool_name="run_command",
            tool_args={"CommandLine": "npm install pkg-name"},
            error="E404 Not Found",
        )

        candidate = "npm install pkg-name --prod"
        res = breaker.check_pre_tool(
            tool_name="run_command",
            tool_args={"CommandLine": candidate},
        )

        self.assertFalse(res.is_tripped, "Breaker tripped despite Noul answering NOT a repeat!")
        self.assertEqual(res.action, "none")
        mock_laya.agent.predict.assert_called_once()

    def test_workspace_isolation(self):
        """Failures in Workspace A do not trip the circuit breaker in Workspace B."""
        breaker_a = CircuitBreaker(workspace_root="/projects/repo_a", config=self.cfg)
        breaker_b = CircuitBreaker(workspace_root="/projects/repo_b", config=self.cfg)

        cmd = "build_and_deploy.sh"
        # Workspace A fails twice
        breaker_a.record_failure("run_command", {"CommandLine": cmd}, "Failed in A")
        breaker_a.record_failure("run_command", {"CommandLine": cmd}, "Failed in A again")

        # Workspace A trips
        res_a = breaker_a.check_pre_tool("run_command", {"CommandLine": cmd})
        self.assertTrue(res_a.is_tripped)

        # Workspace B is pristine and does NOT trip
        res_b = breaker_b.check_pre_tool("run_command", {"CommandLine": cmd})
        self.assertFalse(res_b.is_tripped)
        self.assertEqual(res_b.action, "none")

    def test_repeating_failure_with_differing_prefix_wrappers_trips(self):
        """
        Regression test: 4 attempts with differing 'Write-Output === Attempt N ===' prefixes
        and identical underlying failure. Verifies that normalized command hashes match
        and the circuit breaker trips on subsequent attempts.
        """
        script_path = r"C:\project\bench-airlock\broken_script.py"
        err_template = (
            "=== Attempt {n} ===\n"
            "Traceback (most recent call last):\n"
            "  File \"{path}\", line 1, in <module>\n"
            "    import non_existent_module_xyz\n"
            "ModuleNotFoundError: No module named 'non_existent_module_xyz'"
        )

        # Attempt 1: check_pre_tool (should NOT trip, history is empty)
        cmd_1 = f'Write-Output "=== Attempt 1 ==="; python "{script_path}" 2>&1'
        res_1 = self.breaker.check_pre_tool("run_command", {"CommandLine": cmd_1})
        self.assertFalse(res_1.is_tripped)

        # Attempt 1 fails: record failure
        sig_1 = self.breaker.record_failure(
            "run_command",
            {"CommandLine": cmd_1},
            err_template.format(n=1, path=script_path),
        )

        # Attempt 2: differing prefix, check_pre_tool (should TRIP!)
        cmd_2 = f'Write-Output "=== Attempt 2 ==="; python "{script_path}" 2>&1'
        res_2 = self.breaker.check_pre_tool("run_command", {"CommandLine": cmd_2})
        self.assertTrue(res_2.is_tripped, "Breaker failed to trip on Attempt 2 with differing prefix!")
        self.assertEqual(res_2.action, "force_ask")
        self.assertIn("Identical action", res_2.reason)

        sig_2 = self.breaker.record_failure(
            "run_command",
            {"CommandLine": cmd_2},
            err_template.format(n=2, path=script_path),
        )

        # Attempt 3: differing prefix (should TRIP!)
        cmd_3 = f'Write-Output "=== Attempt 3 ==="; python "{script_path}" 2>&1'
        res_3 = self.breaker.check_pre_tool("run_command", {"CommandLine": cmd_3})
        self.assertTrue(res_3.is_tripped)
        self.assertEqual(res_3.action, "force_ask")

        sig_3 = self.breaker.record_failure(
            "run_command",
            {"CommandLine": cmd_3},
            err_template.format(n=3, path=script_path),
        )

        # Attempt 4: differing prefix (should TRIP!)
        cmd_4 = f'Write-Output "=== Attempt 4 ==="; python "{script_path}" 2>&1'
        res_4 = self.breaker.check_pre_tool("run_command", {"CommandLine": cmd_4})
        self.assertTrue(res_4.is_tripped)
        self.assertEqual(res_4.action, "force_ask")

        sig_4 = self.breaker.record_failure(
            "run_command",
            {"CommandLine": cmd_4},
            err_template.format(n=4, path=script_path),
        )

        # Assert command hashes and error hashes are identical across all 4 attempts
        self.assertEqual(sig_1.command_hash, sig_2.command_hash)
        self.assertEqual(sig_2.command_hash, sig_3.command_hash)
        self.assertEqual(sig_3.command_hash, sig_4.command_hash)

        self.assertEqual(sig_1.error_hash, sig_2.error_hash)
        self.assertEqual(sig_2.error_hash, sig_3.error_hash)
        self.assertEqual(sig_3.error_hash, sig_4.error_hash)


class TestCircuitBreakerDaemonIntegration(unittest.IsolatedAsyncioTestCase):
    """
    Integration tests verifying end-to-end loop halting through live DaemonServer.
    """

    async def asyncSetUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp_dir.name)
        self.token_file = self.tmp_path / ".daemon_test.token"
        self.pid_file = self.tmp_path / "daemon_test.pid"
        self.audit_file = self.tmp_path / "test-audit.jsonl"

        self.cfg = GatewayConfig(
            daemon=DaemonConfig(
                token_file=str(self.token_file),
                pid_file=str(self.pid_file),
                tcp_port=0,
                transport="tcp",
                host="127.0.0.1",
            ),
            circuit_breaker=CircuitBreakerConfig(
                enabled=True,
                hash_window=3,
                similarity_threshold=0.80,
                break_action="force_ask",
            ),
            jev=JevConfig(provider="none"),
            audit=AuditConfig(
                log_file=str(self.audit_file),
            ),
        )

        self.server = DaemonServer(config=self.cfg)
        await self.server.start()

        self.client = StubHookClient(
            config=self.cfg,
            port=self.server.tcp_port,
            token_file=str(self.token_file),
        )

    async def asyncTearDown(self):
        await self.server.stop()
        self.tmp_dir.cleanup()

    async def test_end_to_end_repeating_failure_loop_halt(self):
        """
        Simulates:
        1. PreToolUse -> Ambiguous action (passes to human/ask)
        2. PostToolUse -> Action failed (recorded into circuit breaker)
        3. PreToolUse -> Same ambiguous action attempted again
        4. Verifies loop is halted and daemon returns 'force_ask' with circuitBreakerTripped=True.
        """
        ws_root = str(self.tmp_path / "project_x")
        failing_cmd = "python scripts/flaky_build.py --target=all"

        # Step 1: Initial PreToolUse
        pre_payload_1 = {
            "toolCall": {"name": "run_command", "args": {"CommandLine": failing_cmd}},
            "workspace_root": ws_root,
            "stepIdx": 1,
        }
        res_pre1 = await asyncio.to_thread(self.client.send_request, "PreToolUse", pre_payload_1)
        self.assertEqual(res_pre1.get("status"), "success")
        self.assertFalse(res_pre1.get("circuitBreakerTripped", False))

        # Step 2: PostToolUse reporting failure
        post_payload_1 = {
            "toolCall": {"name": "run_command", "args": {"CommandLine": failing_cmd}},
            "toolResult": {"exitCode": 1, "stderr": "BuildFailed: syntax error in generated code at 0x1234"},
            "workspace_root": ws_root,
            "stepIdx": 1,
        }
        res_post1 = await asyncio.to_thread(self.client.send_request, "PostToolUse", post_payload_1)
        self.assertEqual(res_post1.get("status"), "success")

        # Step 3: Candidate PreToolUse repeating the exact failing command
        pre_payload_2 = {
            "toolCall": {"name": "run_command", "args": {"CommandLine": failing_cmd}},
            "workspace_root": ws_root,
            "stepIdx": 2,
        }
        res_pre2 = await asyncio.to_thread(self.client.send_request, "PreToolUse", pre_payload_2)

        # Step 4: Verify Circuit Breaker tripped
        self.assertEqual(res_pre2.get("status"), "success")
        self.assertEqual(res_pre2.get("decision"), "force_ask")
        self.assertTrue(res_pre2.get("circuitBreakerTripped"))
        self.assertIn("Circuit breaker tripped", res_pre2.get("reason", ""))
        self.assertIsNotNone(res_pre2.get("circuitBreakerSummary"))

    async def test_dispatch_order_hard_deny_preempts_circuit_breaker(self):
        """
        Hard-deny takes absolute precedence over circuit breaker.
        Even if circuit breaker would evaluate or trip, a hard deny rule
        always returns 'deny' deterministically.
        """
        ws_root = str(self.tmp_path / "project_y")
        dangerous_cmd = "rm -rf /"

        payload = {
            "toolCall": {"name": "run_command", "args": {"CommandLine": dangerous_cmd}},
            "workspace_root": ws_root,
            "stepIdx": 1,
        }
        res = await asyncio.to_thread(self.client.send_request, "PreToolUse", payload)
        self.assertEqual(res.get("decision"), "deny")
        self.assertEqual(res.get("ruleId"), "deny-destructive-fs-posix")
        # Circuit breaker was not the reason; hard policy was
        self.assertFalse(res.get("circuitBreakerTripped", False))

    async def test_dispatch_order_hard_allow_preempts_circuit_breaker(self):
        """
        Hard-allow takes precedence over circuit breaker.
        Read-only commands like 'git status' are permitted immediately.
        """
        ws_root = str(self.tmp_path / "project_z")
        safe_cmd = "git status"

        payload = {
            "toolCall": {"name": "run_command", "args": {"CommandLine": safe_cmd}},
            "workspace_root": ws_root,
            "stepIdx": 1,
        }
        res = await asyncio.to_thread(self.client.send_request, "PreToolUse", payload)
        self.assertEqual(res.get("decision"), "allow")
        self.assertEqual(res.get("ruleId"), "allow-git-status-diff-log")
        self.assertFalse(res.get("circuitBreakerTripped", False))


if __name__ == "__main__":
    unittest.main()
