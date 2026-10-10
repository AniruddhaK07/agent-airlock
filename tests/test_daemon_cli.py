"""
Hermetic unit tests for agent-airlock-daemon CLI entrypoints (Phase 1.0).
Tests --status, --stop, and --foreground options using isolated temporary directories
without touching the live system daemon.
"""

import unittest
import tempfile
import io
import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

from agent_airlock.config import GatewayConfig, DaemonConfig, AuditConfig
from agent_airlock.daemon.server import main
from agent_airlock.daemon.pid import PIDManager

class TestDaemonCLI(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp_dir.name)

        self.socket_path = self.tmp_path / "test-cli.sock"
        self.token_file = self.tmp_path / ".test-cli.token"
        self.pid_file = self.tmp_path / "test-cli.pid"
        self.audit_file = self.tmp_path / "test-cli-audit.jsonl"

        self.config = GatewayConfig(
            daemon=DaemonConfig(
                socket_path=str(self.socket_path),
                token_file=str(self.token_file),
                pid_file=str(self.pid_file),
                transport="tcp",
                host="127.0.0.1",
                tcp_port=59999,
            ),
            audit=AuditConfig(
                log_file=str(self.audit_file),
            ),
        )

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_status_when_not_running(self):
        """--status should exit with code 1 when daemon is not running."""
        stdout = io.StringIO()
        with patch("sys.stdout", stdout):
            code = main(["--status"], config=self.config)
        self.assertEqual(code, 1)
        self.assertIn("not running", stdout.getvalue())

    def test_status_when_running(self):
        """--status should display PID, transport, and exit 0 when daemon is running."""
        pid_mgr = PIDManager(
            pid_file=self.pid_file,
            socket_path=self.socket_path,
            token_file=self.token_file,
        )
        pid_mgr.write_pid(metadata={"started_at": 1700000000.0, "transport": "tcp", "port": 59999})

        stdout = io.StringIO()
        with patch.object(PIDManager, "is_running", return_value=True):
            with patch("sys.stdout", stdout):
                code = main(["--status"], config=self.config)

        self.assertEqual(code, 0)
        output = stdout.getvalue()
        self.assertIn("daemon is running", output)
        self.assertIn(str(os.getpid()), output)
        self.assertIn("127.0.0.1:59999", output)

    def test_stop_when_not_running(self):
        """--stop should report no daemon active and exit 0."""
        stdout = io.StringIO()
        with patch("sys.stdout", stdout):
            code = main(["--stop"], config=self.config)
        self.assertEqual(code, 0)
        self.assertIn("No daemon instance is currently active", stdout.getvalue())

    def test_stop_when_running_daemon(self):
        """--stop should terminate running daemon when command line matches agent_airlock.daemon."""
        self.pid_file.write_text('{"pid": 999999, "transport": "tcp", "port": 59999}', encoding="utf-8")

        stdout = io.StringIO()
        with patch("agent_airlock.daemon.server.is_process_running", return_value=True), \
             patch("agent_airlock.daemon.server.get_process_cmdline", return_value="python -m agent_airlock.daemon.server"), \
             patch("ctypes.windll.kernel32.OpenProcess" if sys.platform == "win32" else "os.kill") as mock_term:
            if sys.platform == "win32":
                mock_term.return_value = 1234
                with patch("ctypes.windll.kernel32.TerminateProcess") as mock_kill, \
                     patch("ctypes.windll.kernel32.CloseHandle"):
                    with patch("sys.stdout", stdout):
                        code = main(["--stop"], config=self.config)
                    mock_kill.assert_called_once()
            else:
                with patch("sys.stdout", stdout):
                    code = main(["--stop"], config=self.config)
                mock_term.assert_called_once()

        self.assertEqual(code, 0)
        self.assertIn("stopped (PID 999999)", stdout.getvalue())
        self.assertFalse(self.pid_file.exists())

    def test_stop_when_recycled_or_unrelated_pid(self):
        """--stop must NOT terminate an active process if command line is not agent_airlock.daemon."""
        self.pid_file.write_text('{"pid": 888888, "transport": "tcp", "port": 59999}', encoding="utf-8")

        stdout = io.StringIO()
        with patch("agent_airlock.daemon.server.is_process_running", return_value=True), \
             patch("agent_airlock.daemon.server.get_process_cmdline", return_value="notepad.exe C:\\notes.txt"), \
             patch("ctypes.windll.kernel32.OpenProcess" if sys.platform == "win32" else "os.kill") as mock_term:
            with patch("sys.stdout", stdout):
                code = main(["--stop"], config=self.config)

            # Verification: Termination MUST NOT be attempted on recycled PID
            mock_term.assert_not_called()

        self.assertEqual(code, 0)
        output = stdout.getvalue()
        self.assertIn("stale/recycled PID", output)
        self.assertIn("Not terminating", output)
        # PID file should be cleaned up
        self.assertFalse(self.pid_file.exists())

    def test_stop_when_stale_dead_pid(self):
        """--stop cleans up PID file if recorded PID process is no longer alive."""
        self.pid_file.write_text('{"pid": 777777, "transport": "tcp", "port": 59999}', encoding="utf-8")

        stdout = io.StringIO()
        with patch("agent_airlock.daemon.server.is_process_running", return_value=False):
            with patch("sys.stdout", stdout):
                code = main(["--stop"], config=self.config)

        self.assertEqual(code, 0)
        self.assertIn("stale PID", stdout.getvalue())
        self.assertFalse(self.pid_file.exists())
