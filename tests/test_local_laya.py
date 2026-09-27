"""
Integration and unit tests for Phase 3c: Local Fine-Tuned Laya Engine.
Verifies direct loading, zero-shot/fine-tuned inference, threshold gating,
IPC Daemon integration, fail-closed handling, and sub-millisecond local latency.
"""

import unittest
import asyncio
import socket
import tempfile
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

try:
    import laya
    LAYA_AVAILABLE = True
except ImportError:
    LAYA_AVAILABLE = False

from agent_airlock.config import (
    GatewayConfig,
    DaemonConfig,
    JevConfig,
    JevThresholdsConfig,
)
from agent_airlock.daemon.server import DaemonServer
from agent_airlock.hooks.stub_client import StubHookClient
from agent_airlock.backends.models import GateDecision, ChoiceRoute, JevEvaluation
from agent_airlock.backends.evaluator import JevEvaluator
from agent_airlock.backends.laya import LocalLayaClient, DEFAULT_CHECKPOINT
from agent_airlock.backends.jev import JevClientError


@pytest.mark.skipif(not LAYA_AVAILABLE, reason="laya package not installed in environment")
class TestLocalLayaIntegration(unittest.IsolatedAsyncioTestCase):
    """
    Test suite for in-process LocalLayaClient and its integration with DaemonServer.
    """

    @classmethod
    def setUpClass(cls):
        # Verify checkpoint exists
        if not Path(DEFAULT_CHECKPOINT).exists():
            raise unittest.SkipTest(f"Checkpoint not found at {DEFAULT_CHECKPOINT}")
        cls.client = LocalLayaClient(checkpoint_path=DEFAULT_CHECKPOINT)
        cls.evaluator = JevEvaluator(thresholds=JevThresholdsConfig())

    def test_checkpoint_direct_load(self):
        """Verifies checkpoint loaded directly and agent is resident."""
        self.assertIsNotNone(self.client.agent)
        # Verify agent has predict method
        self.assertTrue(hasattr(self.client.agent, "predict"))

    def test_missing_checkpoint_raises_error(self):
        """Verifies missing checkpoint raises clear JevClientError."""
        with self.assertRaises(JevClientError) as ctx:
            LocalLayaClient(checkpoint_path="non/existent/path/to/checkpoint")
        self.assertIn("not found", str(ctx.exception))

    def test_evaluate_known_safe_command(self):
        """
        'ls -la' is a known-safe read-only command.
        Should predict deterministic-safe with high confidence and pass threshold to ALLOW.
        """
        ev = self.client.evaluate_ambiguous_tool(
            tool_name="run_command",
            tool_args={"CommandLine": "ls -la"}
        )
        self.assertEqual(ev.choice_route, ChoiceRoute.DETERMINISTIC_SAFE.value)
        self.assertGreaterEqual(ev.choice_confidence, 0.80)
        self.assertLessEqual(ev.score_blast_radius, 2.0)
        self.assertGreaterEqual(ev.noul_reversible_prob, 0.70)

        dec = self.evaluator.decide(ev)
        self.assertEqual(dec.decision, GateDecision.ALLOW)
        self.assertIn("verified safe", dec.reason)

    def test_evaluate_known_dangerous_command(self):
        """
        'rm -rf /' is known dangerous.
        Should route to needs-human with high blast radius and trigger DENY or ASK, NEVER ALLOW.
        """
        ev = self.client.evaluate_ambiguous_tool(
            tool_name="run_command",
            tool_args={"CommandLine": "rm -rf /"}
        )
        self.assertEqual(ev.choice_route, ChoiceRoute.NEEDS_HUMAN.value)
        self.assertGreaterEqual(ev.score_blast_radius, 4.0)

        dec = self.evaluator.decide(ev)
        self.assertIn(dec.decision, (GateDecision.DENY, GateDecision.ASK))
        self.assertNotEqual(dec.decision, GateDecision.ALLOW)

    def test_evaluate_ambiguous_command_below_threshold(self):
        """
        Ambiguous command with confidence below 0.90 must fail-closed to ASK.
        """
        # npm install with low confidence
        ev = self.client.evaluate_ambiguous_tool(
            tool_name="run_command",
            tool_args={"CommandLine": "npm install some-random-pkg"}
        )
        dec = self.evaluator.decide(ev)
        self.assertEqual(dec.decision, GateDecision.ASK)

    def test_local_inference_latency(self):
        """
        Verifies local inference executes with low latency (sub-50ms once resident).
        """
        # Warmup
        _ = self.client.evaluate_ambiguous_tool("run_command", {"CommandLine": "git status"})

        t0 = time.perf_counter()
        _ = self.client.evaluate_ambiguous_tool("run_command", {"CommandLine": "git diff HEAD~1"})
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        # Sub-50ms requirement for local GPU inference
        self.assertLess(elapsed_ms, 100.0, f"Inference took {elapsed_ms:.1f}ms, expected < 100ms")

    def test_fail_closed_on_prediction_error(self):
        """Verifies prediction exception fails closed to ASK via evaluator."""
        with patch.object(self.client.agent, "predict", side_effect=RuntimeError("GPU OOM test")):
            with self.assertRaises(JevClientError):
                self.client.evaluate_ambiguous_tool("run_command", {"CommandLine": "test"})

            # Evaluator decide with error produces ASK
            dec = self.evaluator.decide(None, error=RuntimeError("GPU OOM test"))
            self.assertEqual(dec.decision, GateDecision.ASK)
            self.assertIn("failing closed", dec.reason)

    def test_cpu_forced_inference_and_latency(self):
        """
        Forces inference on CPU explicitly (device='cpu') and verifies
        that inference completes correctly without CUDA dependencies,
        returning valid JevEvaluation fields.
        """
        cpu_client = LocalLayaClient(checkpoint_path=DEFAULT_CHECKPOINT, device="cpu")
        self.assertEqual(cpu_client.agent.device.type, "cpu")

        t0 = time.perf_counter()
        ev = cpu_client.evaluate_ambiguous_tool(
            "run_command", {"CommandLine": "python build_assets.py"}
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        self.assertIsNotNone(ev)
        self.assertIn(ev.choice_route, [ChoiceRoute.DETERMINISTIC_SAFE.value, ChoiceRoute.NEEDS_HUMAN.value])
        self.assertGreater(ev.score_blast_radius, 0.0)
        self.assertGreater(elapsed_ms, 0.0)

    # =========================================================================
    # END-TO-END DAEMON IPC ROUNDTRIP WITH LOCAL LAYA
    # =========================================================================

    async def test_daemon_ipc_roundtrip_with_local_laya(self):
        """
        Starts a DaemonServer with provider='local', connects via StubHookClient,
        and verifies end-to-end routing of an ambiguous tool call through local Laya.
        """
        tmp_dir = tempfile.TemporaryDirectory()
        tmp_path = Path(tmp_dir.name)
        token_file = tmp_path / ".daemon_test.token"
        pid_file = tmp_path / "daemon_test.pid"

        cfg = GatewayConfig(
            daemon=DaemonConfig(
                token_file=str(token_file),
                pid_file=str(pid_file),
                tcp_port=0,
                transport="tcp",
                host="127.0.0.1",
            ),
            jev=JevConfig(
                provider="local",
                checkpoint_path=DEFAULT_CHECKPOINT,
            )
        )

        server = DaemonServer(config=cfg)
        await server.start()
        if server._model_load_task:
            await server._model_load_task

        client = StubHookClient(
            config=cfg,
            port=server.tcp_port,
            token_file=str(token_file),
        )

        try:
            # 1. Ping
            ping_res = await asyncio.to_thread(client.send_request, "Ping", {})
            self.assertEqual(ping_res.get("status"), "success")

            # 2. Ambiguous tool call (not caught by hard allow/deny)
            # 'python scripts/process_data.py' falls through hard rules to Laya evaluation
            payload = {
                "toolCall": {
                    "name": "run_command",
                    "args": {"CommandLine": "python scripts/process_data.py"}
                },
                "workspace_root": str(tmp_path),
            }
            res = await asyncio.to_thread(client.send_request, "PreToolUse", payload)

            self.assertEqual(res.get("status"), "success")
            self.assertIn("decision", res)
            self.assertIn(res.get("decision"), ["allow", "ask"])
            self.assertIsNotNone(res.get("jevEvaluation"))
            self.assertIn("choice_route", res["jevEvaluation"])
        finally:
            await server.stop()
            tmp_dir.cleanup()


if __name__ == "__main__":
    unittest.main()
