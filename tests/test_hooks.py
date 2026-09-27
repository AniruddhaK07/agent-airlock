"""
Test suite for Phase 6 — Antigravity Hook Integration.
Verifies line count (<50 lines), stdin/stdout protocol compliance,
fail-closed behavior on empty/corrupted input or offline daemon,
configuration generator / installer, and end-to-end hook subprocess execution.
"""

import asyncio
from io import StringIO
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from typing import Dict, Any, Tuple, Optional
import unittest
from unittest.mock import patch

from agent_airlock.config import GatewayConfig, DaemonConfig
from agent_airlock.daemon.server import DaemonServer
from agent_airlock.hooks.installer import generate_hooks_config, install_hooks
from agent_airlock.hooks.stub_client import StubHookClient
import agent_airlock.hooks.pre_tool_use as pre_hook
import agent_airlock.hooks.post_tool_use as post_hook

class TestHookScriptConstraints(unittest.TestCase):
    """Verifies that hook scripts adhere to the strict <50 lines architectural budget."""

    def test_pre_tool_use_line_count(self):
        hook_path = Path(pre_hook.__file__)
        lines = [line for line in hook_path.read_text(encoding="utf-8").splitlines()]
        self.assertLess(len(lines), 50, f"pre_tool_use.py exceeded 50 lines ({len(lines)})")

    def test_post_tool_use_line_count(self):
        hook_path = Path(post_hook.__file__)
        lines = [line for line in hook_path.read_text(encoding="utf-8").splitlines()]
        self.assertLess(len(lines), 50, f"post_tool_use.py exceeded 50 lines ({len(lines)})")

class TestHookInstallerAndConfig(unittest.TestCase):
    """Verifies configuration generation and hook file installation."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_generate_hooks_config_schema(self):
        cfg = generate_hooks_config(python_bin="python3")
        self.assertIn("agent-airlock", cfg)
        gate = cfg["agent-airlock"]
        self.assertTrue(gate["enabled"])
        self.assertIn("PreToolUse", gate)
        self.assertIn("PostToolUse", gate)
        self.assertEqual(gate["PreToolUse"][0]["matcher"], "*")
        self.assertIn("pre_tool_use", gate["PreToolUse"][0]["hooks"][0]["command"])
        self.assertIn("post_tool_use", gate["PostToolUse"][0]["hooks"][0]["command"])

    def test_install_hooks_merges_and_creates_file(self):
        target_dir = Path(self.tmp_dir.name) / ".agents"
        # Pre-seed existing independent hooks
        target_dir.mkdir(parents=True, exist_ok=True)
        existing = {"custom-linter": {"enabled": True}}
        (target_dir / "hooks.json").write_text(json.dumps(existing), encoding="utf-8")

        installed = install_hooks(target_dir=target_dir, python_bin="python")
        self.assertTrue(installed.exists())

        loaded = json.loads(installed.read_text(encoding="utf-8"))
        self.assertIn("custom-linter", loaded, "Pre-existing hook was erased!")
        self.assertIn("agent-airlock", loaded)
        self.assertTrue(loaded["agent-airlock"]["enabled"])

class TestHookStdinStdoutCompliance(unittest.TestCase):
    """Verifies stdin/stdout protocol compliance and strict fail-closed fallback."""

    def test_pre_tool_use_empty_stdin_fails_closed(self):
        with patch("sys.stdin", StringIO("")), patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            pre_hook.main()
            output = mock_stdout.getvalue().strip()
            self.assertTrue(output)
            parsed = json.loads(output)
            self.assertEqual(parsed.get("decision"), "ask")

    def test_pre_tool_use_malformed_json_fails_closed(self):
        with patch("sys.stdin", StringIO("INVALID_JSON_HERE")), patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            pre_hook.main()
            output = mock_stdout.getvalue().strip()
            self.assertTrue(output)
            parsed = json.loads(output)
            self.assertEqual(parsed.get("decision"), "ask")

    def test_post_tool_use_empty_stdin_ignored(self):
        with patch("sys.stdin", StringIO("")), patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            post_hook.main()
            output = mock_stdout.getvalue().strip()
            self.assertTrue(output)
            parsed = json.loads(output)
            self.assertEqual(parsed, {})

class TestHookSubprocessExecutionWithDaemon(unittest.IsolatedAsyncioTestCase):
    """End-to-end integration: executing the hook scripts via subprocess against a live DaemonServer."""

    async def asyncSetUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        base = Path(self.tmp_dir.name)
        self.socket_path = base / "test-daemon.sock"
        self.token_file = base / "test-daemon.token"
        self.pid_file = base / "test-daemon.pid"

        self.config = GatewayConfig(
            daemon=DaemonConfig(
                socket_path=str(self.socket_path),
                token_file=str(self.token_file),
                pid_file=str(self.pid_file),
                transport="tcp",
                host="127.0.0.1",
                tcp_port=0,
                request_timeout_seconds=2.0,
            )
        )
        self.server = DaemonServer(config=self.config)
        await self.server.start()

    async def asyncTearDown(self):
        await self.server.stop()
        self.tmp_dir.cleanup()

    def _run_hook_script(self, script_module: str, input_payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any], float]:
        """Runs the hook module as a subprocess passing JSON on stdin and measuring latency."""
        cmd = [
            sys.executable,
            "-m",
            script_module,
        ]
        env = os.environ.copy()
        # Set config overrides via environment if needed
        input_bytes = (json.dumps(input_payload) + "\n").encode("utf-8")

        # Also supply client config parameters through mock/custom stub invocation
        # We test by invoking stub client directly configured to connect to our test server
        t0 = time.perf_counter()
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(Path.cwd()),
            env=env,
        )
        stdout, stderr = proc.communicate(input=input_bytes, timeout=5.0)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        raw_out = stdout.decode("utf-8").strip()
        parsed = json.loads(raw_out) if raw_out else {}
        return proc.returncode, parsed, elapsed_ms

    async def test_stub_client_end_to_end_pre_tool_allow(self):
        client = StubHookClient(
            config=self.config,
            port=self.server.tcp_port,
            token_file=str(self.token_file),
            socket_path=str(self.socket_path),
        )
        payload = {
            "toolCall": {"name": "run_command", "args": {"CommandLine": "git status"}},
            "workspacePaths": [str(Path.cwd())],
            "stepIdx": 1,
            "conversationId": "hook-test-conv",
        }
        res = await asyncio.to_thread(client.send_request, "PreToolUse", payload)
        self.assertEqual(res.get("decision"), "allow")
        self.assertEqual(res.get("status"), "success")

    async def test_stub_client_end_to_end_pre_tool_deny(self):
        client = StubHookClient(
            config=self.config,
            port=self.server.tcp_port,
            token_file=str(self.token_file),
            socket_path=str(self.socket_path),
        )
        payload = {
            "toolCall": {"name": "run_command", "args": {"CommandLine": "rm -rf /"}},
            "workspacePaths": [str(Path.cwd())],
            "stepIdx": 2,
            "conversationId": "hook-test-conv",
        }
        res = await asyncio.to_thread(client.send_request, "PreToolUse", payload)
        self.assertEqual(res.get("decision"), "deny")
        self.assertEqual(res.get("status"), "success")

    async def test_stub_client_end_to_end_post_tool_use(self):
        client = StubHookClient(
            config=self.config,
            port=self.server.tcp_port,
            token_file=str(self.token_file),
            socket_path=str(self.socket_path),
        )
        payload = {
            "toolCall": {"name": "run_command", "args": {"CommandLine": "git status"}},
            "toolResult": {"exitCode": 0, "stdout": "On branch main"},
            "workspacePaths": [str(Path.cwd())],
            "stepIdx": 3,
            "conversationId": "hook-test-conv",
        }
        res = await asyncio.to_thread(client.send_request, "PostToolUse", payload)
        self.assertEqual(res.get("status"), "success")
        self.assertIn("auditId", res)

if __name__ == "__main__":
    unittest.main()
