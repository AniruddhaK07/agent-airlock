"""
Test suite for Phase 5 — Audit Log.
Verifies immutable append-only JSONL format, event schema completeness, thread-safe writes,
query filtering, integrity verification, statistics aggregation, retention cleanup,
and end-to-end daemon IPC integration.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock

from jev_gateway.audit.models import AuditEvent
from jev_gateway.audit.logger import AuditLogger
from jev_gateway.audit.reader import AuditReader
from jev_gateway.policy.engine import HardPolicyEngine
from jev_gateway.policy.models import PolicyRule, PolicyVerdict
from jev_gateway.daemon.router import IPCRouter, WorkspaceState
from jev_gateway.config import CircuitBreakerConfig

class TestAuditEventModel(unittest.TestCase):
    """Verifies AuditEvent schema serialization and parsing."""

    def test_serialization_round_trip(self):
        event = AuditEvent(
            event_id="evt_123456_abcdef",
            timestamp=datetime.now(timezone.utc).isoformat(),
            conversation_id="conv-001",
            step_idx=3,
            event_type="PreToolUse",
            tool_name="run_command",
            tool_args={"CommandLine": "git status"},
            policy_verdict="allow",
            matched_rule_id="allow-safe-git",
            circuit_breaker_tripped=False,
            jev_evaluation=None,
            final_decision="allow",
            reason="Read-only git query",
            latency_ms=1.25,
            workspace_root="/test/repo",
            metadata={"source": "unit_test"},
        )

        d = event.to_dict()
        self.assertEqual(d["event_id"], "evt_123456_abcdef")
        self.assertEqual(d["final_decision"], "allow")
        self.assertEqual(d["workspace_root"], "/test/repo")

        json_str = event.to_json()
        reconstructed = AuditEvent.from_json(json_str)
        self.assertEqual(reconstructed.event_id, event.event_id)
        self.assertEqual(reconstructed.timestamp, event.timestamp)
        self.assertEqual(reconstructed.tool_args, event.tool_args)
        self.assertEqual(reconstructed.policy_verdict, "allow")
        self.assertFalse(reconstructed.circuit_breaker_tripped)
        self.assertEqual(reconstructed.metadata, {"source": "unit_test"})

    def test_missing_required_fields_validation(self):
        with self.assertRaises(ValueError):
            AuditEvent.from_dict({"timestamp": "2026-09-27T00:00:00Z"})

    def test_backward_compatibility_with_extra_fields(self):
        data = {
            "event_id": "evt_legacy_01",
            "timestamp": "2026-09-27T01:00:00Z",
            "conversation_id": "conv-999",
            "step_idx": 1,
            "event_type": "PreToolUse",
            "tool_name": "run_command",
            "tool_args": {"CommandLine": "ls"},
            "policy_verdict": "allow",
            "final_decision": "allow",
            "reason": "OK",
            "unexpected_new_field": "some_value",
        }
        ev = AuditEvent.from_dict(data)
        self.assertEqual(ev.event_id, "evt_legacy_01")
        self.assertFalse(hasattr(ev, "unexpected_new_field"))

class TestAuditLogger(unittest.TestCase):
    """Verifies thread-safe append-only writes, directory creation, and rotation."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.log_file = Path(self.tmp_dir.name) / "logs" / "audit.jsonl"
        self.logger = AuditLogger(log_path=self.log_file, flush_immediate=True)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_auto_creates_directories_and_writes(self):
        ev = AuditEvent(
            event_id="evt_01",
            timestamp=datetime.now(timezone.utc).isoformat(),
            conversation_id="conv-1",
            step_idx=0,
            event_type="PreToolUse",
            tool_name="view_file",
            tool_args={"AbsolutePath": "/test/file.txt"},
            policy_verdict="allow",
            final_decision="allow",
            reason="Read file",
            latency_ms=0.5,
        )
        returned_id = self.logger.log(ev)
        self.assertEqual(returned_id, "evt_01")
        self.assertTrue(self.log_file.exists())

        # Verify exact line contents
        lines = self.log_file.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 1)
        parsed = json.loads(lines[0])
        self.assertEqual(parsed["event_id"], "evt_01")
        self.assertEqual(parsed["tool_name"], "view_file")

    def test_log_dict_input(self):
        raw_dict = {
            "event_id": "evt_dict_01",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "conversation_id": "conv-dict",
            "step_idx": 2,
            "event_type": "PostToolUse",
            "tool_name": "run_command",
            "tool_args": {"CommandLine": "npm test"},
            "policy_verdict": "none",
            "final_decision": "recorded",
            "reason": "Execution finished",
        }
        res_id = self.logger.log(raw_dict)
        self.assertEqual(res_id, "evt_dict_01")

        lines = self.log_file.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0])["event_id"], "evt_dict_01")

    def test_concurrent_multithreaded_writes(self):
        """10 threads writing 20 events each concurrently: zero interleaving, exactly 200 valid lines."""
        num_threads = 10
        records_per_thread = 20
        total_expected = num_threads * records_per_thread

        def worker(thread_idx: int):
            for i in range(records_per_thread):
                ev = AuditEvent(
                    event_id=f"evt_t{thread_idx}_r{i}",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    conversation_id=f"conv-{thread_idx}",
                    step_idx=i,
                    event_type="PreToolUse",
                    tool_name="run_command",
                    tool_args={"CommandLine": f"echo thread_{thread_idx}_run_{i}"},
                    policy_verdict="allow",
                    final_decision="allow",
                    reason="thread test",
                )
                self.logger.log(ev)

        with ThreadPoolExecutor(max_workers=num_threads) as pool:
            futures = [pool.submit(worker, t) for t in range(num_threads)]
            for f in futures:
                f.result()

        lines = self.log_file.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), total_expected)

        # Every single line must be valid JSON
        event_ids = set()
        for idx, line in enumerate(lines):
            try:
                rec = json.loads(line)
                event_ids.add(rec["event_id"])
            except Exception as e:
                self.fail(f"Line {idx} corrupted during concurrent write: {e}")

        self.assertEqual(len(event_ids), total_expected)

    def test_cleanup_retention(self):
        """Verifies that cleanup_old_events removes expired events and preserves valid recent ones."""
        now = datetime.now(timezone.utc)
        old_time = (now - timedelta(days=45)).isoformat()
        recent_time = (now - timedelta(days=5)).isoformat()

        # Log old event
        self.logger.log(AuditEvent(
            event_id="evt_old",
            timestamp=old_time,
            conversation_id="conv-old",
            step_idx=0,
            event_type="PreToolUse",
            tool_name="run_command",
            tool_args={"CommandLine": "old"},
            policy_verdict="allow",
            final_decision="allow",
            reason="Old",
        ))

        # Log recent event
        self.logger.log(AuditEvent(
            event_id="evt_recent",
            timestamp=recent_time,
            conversation_id="conv-recent",
            step_idx=1,
            event_type="PreToolUse",
            tool_name="run_command",
            tool_args={"CommandLine": "recent"},
            policy_verdict="allow",
            final_decision="allow",
            reason="Recent",
        ))

        reader = AuditReader(self.log_file)
        self.assertEqual(len(reader.read_all()), 2)

        # Prune events older than 30 days
        pruned = self.logger.cleanup_old_events(max_days=30)
        self.assertEqual(pruned, 1)

        remaining = reader.read_all()
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0].event_id, "evt_recent")

class TestAuditReaderAndVerification(unittest.TestCase):
    """Verifies querying, integrity checking, and statistics calculations."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.log_file = Path(self.tmp_dir.name) / "audit.jsonl"
        self.logger = AuditLogger(log_path=self.log_file)
        self.reader = AuditReader(log_path=self.log_file)

        # Seed data
        self.base_time = datetime(2026, 9, 27, 10, 0, 0, tzinfo=timezone.utc)
        self.seed_events = [
            AuditEvent(
                event_id="evt_01",
                timestamp=(self.base_time + timedelta(seconds=10)).isoformat(),
                conversation_id="conv-alpha",
                step_idx=1,
                event_type="PreToolUse",
                tool_name="run_command",
                tool_args={"CommandLine": "git status"},
                policy_verdict="allow",
                matched_rule_id="allow-safe-git",
                circuit_breaker_tripped=False,
                final_decision="allow",
                reason="Permitted",
                latency_ms=0.2,
                workspace_root="/workspaces/project_a",
            ),
            AuditEvent(
                event_id="evt_02",
                timestamp=(self.base_time + timedelta(seconds=20)).isoformat(),
                conversation_id="conv-alpha",
                step_idx=2,
                event_type="PreToolUse",
                tool_name="run_command",
                tool_args={"CommandLine": "rm -rf /"},
                policy_verdict="deny",
                matched_rule_id="deny-destructive-fs",
                circuit_breaker_tripped=False,
                final_decision="deny",
                reason="Blocked dangerous",
                latency_ms=0.1,
                workspace_root="/workspaces/project_a",
            ),
            AuditEvent(
                event_id="evt_03",
                timestamp=(self.base_time + timedelta(seconds=30)).isoformat(),
                conversation_id="conv-beta",
                step_idx=1,
                event_type="PreToolUse",
                tool_name="run_command",
                tool_args={"CommandLine": "pytest"},
                policy_verdict="ambiguous",
                matched_rule_id=None,
                circuit_breaker_tripped=True,
                final_decision="force_ask",
                reason="Fix loop repeat",
                latency_ms=1.5,
                workspace_root="/workspaces/project_b",
            ),
            AuditEvent(
                event_id="evt_04",
                timestamp=(self.base_time + timedelta(seconds=40)).isoformat(),
                conversation_id="conv-beta",
                step_idx=2,
                event_type="PostToolUse",
                tool_name="run_command",
                tool_args={"CommandLine": "pytest"},
                policy_verdict="none",
                matched_rule_id=None,
                circuit_breaker_tripped=False,
                final_decision="recorded",
                reason="Exit code 1",
                latency_ms=0.0,
                workspace_root="/workspaces/project_b",
            ),
        ]
        for ev in self.seed_events:
            self.logger.log(ev)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_query_by_conversation(self):
        res = self.reader.query(conversation_id="conv-alpha")
        self.assertEqual(len(res), 2)
        self.assertTrue(all(e.conversation_id == "conv-alpha" for e in res))

    def test_query_by_decision(self):
        res = self.reader.query(final_decision="deny")
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].event_id, "evt_02")

        res_ask = self.reader.query(final_decision="force_ask")
        self.assertEqual(len(res_ask), 1)
        self.assertEqual(res_ask[0].event_id, "evt_03")

    def test_query_by_circuit_breaker(self):
        res = self.reader.query(circuit_breaker_tripped=True)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].event_id, "evt_03")

    def test_query_by_time_window(self):
        start = self.base_time + timedelta(seconds=15)
        end = self.base_time + timedelta(seconds=35)
        res = self.reader.query(start_time=start, end_time=end)
        self.assertEqual(len(res), 2)
        self.assertEqual([e.event_id for e in res], ["evt_02", "evt_03"])

    def test_integrity_verification_clean_file(self):
        report = self.reader.verify_integrity()
        self.assertTrue(report["is_valid"])
        self.assertEqual(report["total_lines"], 4)
        self.assertEqual(report["valid_events"], 4)
        self.assertEqual(report["corrupted_lines"], 0)
        self.assertEqual(report["first_timestamp"], self.seed_events[0].timestamp)
        self.assertEqual(report["last_timestamp"], self.seed_events[-1].timestamp)

    def test_integrity_verification_with_corrupted_lines(self):
        # Inject corrupted lines into the file
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write("NOT_VALID_JSON_LINE\n")
            f.write('{"incomplete": \n')

        report = self.reader.verify_integrity()
        self.assertFalse(report["is_valid"])
        self.assertEqual(report["total_lines"], 6)
        self.assertEqual(report["valid_events"], 4)
        self.assertEqual(report["corrupted_lines"], 2)
        self.assertEqual(report["corrupted_line_numbers"], [5, 6])

        # skip_corrupted=True still retrieves valid records
        valid = self.reader.read_all(skip_corrupted=True)
        self.assertEqual(len(valid), 4)

        # skip_corrupted=False raises ValueError
        with self.assertRaises(ValueError):
            self.reader.read_all(skip_corrupted=False)

    def test_statistics_aggregation(self):
        stats = self.reader.get_statistics()
        self.assertEqual(stats["total_events"], 4)
        self.assertEqual(stats["decisions"]["allow"], 1)
        self.assertEqual(stats["decisions"]["deny"], 1)
        self.assertEqual(stats["decisions"]["force_ask"], 1)
        self.assertEqual(stats["decisions"]["recorded"], 1)
        self.assertEqual(stats["circuit_breaker_tripped_count"], 1)
        self.assertEqual(stats["unique_conversations"], 2)
        self.assertEqual(stats["unique_workspaces"], 2)

class TestDaemonIPCIntegrationWithAuditLogger(unittest.TestCase):
    """Verifies that IPCRouter automatically writes structured audit events during request handling."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.log_file = Path(self.tmp_dir.name) / "audit.jsonl"
        self.audit_logger = AuditLogger(log_path=self.log_file)
        self.reader = AuditReader(log_path=self.log_file)

        self.policy_engine = HardPolicyEngine()
        self.router = IPCRouter(
            policy_engine=self.policy_engine,
            audit_logger=self.audit_logger,
            circuit_breaker_config=CircuitBreakerConfig(),
        )

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_pre_tool_use_hard_deny_is_logged(self):
        payload = {
            "toolCall": {
                "name": "run_command",
                "args": {"CommandLine": "rm -rf /"},
            },
            "conversationId": "conv-test-deny",
            "stepIdx": 1,
            "workspacePaths": ["/workspace/test"],
        }
        req = {
            "version": "1.0",
            "event": "PreToolUse",
            "payload": payload,
        }

        res = self.router.dispatch(req)
        self.assertEqual(res["decision"], "deny")

        events = self.reader.read_all()
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev.event_id, res["auditId"])
        self.assertEqual(ev.conversation_id, "conv-test-deny")
        self.assertEqual(ev.tool_name, "run_command")
        self.assertEqual(ev.policy_verdict, "deny")
        self.assertEqual(ev.final_decision, "deny")
        self.assertEqual(ev.matched_rule_id, "deny-destructive-fs-posix")
        self.assertFalse(ev.circuit_breaker_tripped)

    def test_pre_tool_use_hard_allow_is_logged(self):
        payload = {
            "toolCall": {
                "name": "run_command",
                "args": {"CommandLine": "git status"},
            },
            "conversationId": "conv-test-allow",
            "stepIdx": 2,
            "workspacePaths": ["/workspace/test"],
        }
        req = {
            "version": "1.0",
            "event": "PreToolUse",
            "payload": payload,
        }

        res = self.router.dispatch(req)
        self.assertEqual(res["decision"], "allow")

        events = self.reader.read_all()
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev.event_id, res["auditId"])
        self.assertEqual(ev.policy_verdict, "allow")
        self.assertEqual(ev.final_decision, "allow")
        self.assertEqual(ev.matched_rule_id, "allow-git-status-diff-log")

    def test_circuit_breaker_tripped_event_is_logged(self):
        ws_root = "/workspace/project_cb"
        ws_state = self.router.get_workspace_state(ws_root)

        # Record repeating error in breaker
        for i in range(3):
            ws_state.circuit_breaker.record_failure(
                tool_name="run_command",
                tool_args={"CommandLine": "npm test"},
                error="AssertionError: failed",
                step_idx=i,
            )

        payload = {
            "toolCall": {
                "name": "run_command",
                "args": {"CommandLine": "npm test"},
            },
            "conversationId": "conv-cb-trip",
            "stepIdx": 4,
            "workspace_root": ws_root,
        }
        req = {
            "version": "1.0",
            "event": "PreToolUse",
            "payload": payload,
        }

        res = self.router.dispatch(req)
        self.assertEqual(res["decision"], "force_ask")
        self.assertTrue(res.get("circuitBreakerTripped"))

        events = self.reader.read_all()
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev.event_id, res["auditId"])
        self.assertEqual(ev.final_decision, "force_ask")
        self.assertTrue(ev.circuit_breaker_tripped)
        self.assertIn("Circuit breaker tripped", ev.reason)

    def test_post_tool_use_is_logged(self):
        payload = {
            "toolCall": {
                "name": "run_command",
                "args": {"CommandLine": "python test.py"},
            },
            "toolResult": {
                "exitCode": 1,
                "stderr": "RuntimeError: Division by zero",
            },
            "conversationId": "conv-post-fail",
            "stepIdx": 5,
            "workspacePaths": ["/workspace/test"],
        }
        req = {
            "version": "1.0",
            "event": "PostToolUse",
            "payload": payload,
        }

        res = self.router.dispatch(req)
        self.assertEqual(res["status"], "success")

        events = self.reader.read_all()
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev.event_id, res["auditId"])
        self.assertEqual(ev.event_type, "PostToolUse")
        self.assertEqual(ev.final_decision, "recorded")
        self.assertIn("Division by zero", ev.reason)

    def test_unresolved_workspace_fail_closed_is_logged(self):
        payload = {
            "toolCall": {"name": "run_command", "args": {"CommandLine": "ls"}},
            "conversationId": "conv-no-ws",
            "stepIdx": 1,
            # No workspace_root or workspacePaths provided
        }
        req = {
            "version": "1.0",
            "event": "PreToolUse",
            "payload": payload,
        }

        res = self.router.dispatch(req)
        self.assertEqual(res["status"], "fail_closed")
        self.assertEqual(res["decision"], "force_ask")

        events = self.reader.read_all()
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev.event_id, res["auditId"])
        self.assertEqual(ev.final_decision, "force_ask")
        self.assertEqual(ev.reason, "workspace context unresolved")

if __name__ == "__main__":
    unittest.main()
