"""
Unit and integration tests for Phase 1.3: Audit-Log Rule Suggester.
Verifies conservative generalization, safety gating, dangerous neighbor rejection,
ML-allow exclusion, trust-root warnings, and backward-compatible audit log parsing.
"""

import json
import tempfile
import unittest
from pathlib import Path

import yaml

from agent_airlock.policy.suggester import RuleSuggester, SuggestedRule
from agent_airlock.policy.engine import HardPolicyEngine
from agent_airlock.policy.default_rules import get_default_rules


class TestRuleSuggester(unittest.TestCase):
    def setUp(self):
        self.engine = HardPolicyEngine(get_default_rules())
        self.suggester = RuleSuggester(policy_engine=self.engine)

    def test_exact_command_generalization(self):
        """Verifies exact command is safely anchored and escaped."""
        rule = self.suggester._create_candidate_rule(
            raw_cmd="npm run build",
            count=5,
            samples=["npm run build"],
        )
        self.assertIsNotNone(rule)
        self.assertEqual(rule.pattern, "^npm\\ run\\ build$")
        self.assertTrue(rule.executes_repo_controlled_code)
        self.assertIn("package.json", rule.invalidation_guidance or "source files")

        safe, reason = self.suggester.safety_gate(rule)
        self.assertTrue(safe)
        self.assertIsNone(reason)

    def test_safety_gate_rejects_unanchored_and_wildcard(self):
        """Verifies safety gate rejects unanchored patterns or open .* wildcards."""
        bad_rule_1 = SuggestedRule(
            id="bad-wildcard",
            description="Bad wildcard",
            tools=["run_command"],
            field="CommandLine",
            pattern="^rm\\s+.*$",
            approvals_count=5,
            sample_commands=["rm foo"],
        )
        safe, reason = self.suggester.safety_gate(bad_rule_1)
        self.assertFalse(safe)
        self.assertIn("wildcard '.*'", reason)

        bad_rule_2 = SuggestedRule(
            id="bad-unanchored",
            description="Bad unanchored",
            tools=["run_command"],
            field="CommandLine",
            pattern="echo hello",
            approvals_count=5,
            sample_commands=["echo hello"],
        )
        safe, reason = self.suggester.safety_gate(bad_rule_2)
        self.assertFalse(safe)
        self.assertIn("anchored", reason)

    def test_safety_gate_rejects_dangerous_matches(self):
        """Verifies safety gate rejects patterns that could match dangerous commands."""
        dangerous_rule = SuggestedRule(
            id="bad-dangerous-rm",
            description="Dangerous rm",
            tools=["run_command"],
            field="CommandLine",
            pattern="^rm\\ -rf\\ /$",
            approvals_count=5,
            sample_commands=["rm -rf /"],
        )
        safe, reason = self.suggester.safety_gate(dangerous_rule)
        self.assertFalse(safe)
        self.assertTrue("hard-deny" in reason.lower() or "dangerous" in reason.lower())

    def test_safety_gate_rejects_credentials_conflict(self):
        """Verifies safety gate rejects commands targeting credentials/secrets."""
        secret_rule = SuggestedRule(
            id="bad-cat-env",
            description="Exposes .env",
            tools=["run_command"],
            field="CommandLine",
            pattern="^cat\\ \\.env$",
            approvals_count=5,
            sample_commands=["cat .env"],
        )
        safe, reason = self.suggester.safety_gate(secret_rule)
        self.assertFalse(safe)
        self.assertTrue("conflicts with hard-deny" in reason.lower() or "dangerous" in reason.lower())

    def test_mine_audit_log_legacy_and_new_schema(self):
        """Verifies mining from synthetic audit log with both legacy and new schema records."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_path = Path(tmp_dir) / "test_audit.jsonl"
            records = [
                # 1. New schema human-approved command (3 approvals)
                {
                    "event_type": "PreToolUse",
                    "conversation_id": "conv-1",
                    "step_idx": 1,
                    "tool_name": "run_command",
                    "tool_args": {"CommandLine": "npm run check"},
                    "final_decision": "ask",
                    "policy_verdict": "ambiguous",
                    "human_approved": "inferred",
                    "latency_class": "human_prompt",
                    "timestamp": "2026-10-10T01:00:00+00:00",
                },
                {
                    "event_type": "PreToolUse",
                    "conversation_id": "conv-2",
                    "step_idx": 2,
                    "tool_name": "run_command",
                    "tool_args": {"CommandLine": "npm run check"},
                    "final_decision": "ask",
                    "policy_verdict": "ambiguous",
                    "human_approved": "inferred",
                    "latency_class": "human_prompt",
                    "timestamp": "2026-10-10T01:01:00+00:00",
                },
                {
                    "event_type": "PreToolUse",
                    "conversation_id": "conv-3",
                    "step_idx": 3,
                    "tool_name": "run_command",
                    "tool_args": {"CommandLine": "npm run check"},
                    "final_decision": "ask",
                    "policy_verdict": "ambiguous",
                    "human_approved": "inferred",
                    "latency_class": "human_prompt",
                    "timestamp": "2026-10-10T01:02:00+00:00",
                },
                # 2. Legacy schema human-approved command via Pre+Post correlation
                {
                    "event_type": "PreToolUse",
                    "conversation_id": "conv-4",
                    "step_idx": 10,
                    "tool_name": "run_command",
                    "tool_args": {"CommandLine": "node scripts/smoke.js"},
                    "final_decision": "ask",
                    "policy_verdict": "ambiguous",
                    "timestamp": "2026-10-10T02:00:00+00:00",
                },
                {
                    "event_type": "PostToolUse",
                    "conversation_id": "conv-4",
                    "step_idx": 10,
                    "tool_name": "run_command",
                    "timestamp": "2026-10-10T02:00:05+00:00",  # 5s delay -> human_prompt
                },
                # 3. Already L1-allowed command (should be excluded)
                {
                    "event_type": "PreToolUse",
                    "conversation_id": "conv-5",
                    "step_idx": 20,
                    "tool_name": "run_command",
                    "tool_args": {"CommandLine": "git status"},
                    "final_decision": "allow",
                    "policy_verdict": "allow",
                    "human_approved": None,
                    "timestamp": "2026-10-10T03:00:00+00:00",
                },
            ]

            with open(log_path, "w", encoding="utf-8") as f:
                for r in records:
                    f.write(json.dumps(r) + "\n")

            suggestions = self.suggester.mine_audit_log(log_path, min_approvals=3)
            # Exactly 1 suggestion: npm run check (approved 3 times)
            self.assertEqual(len(suggestions), 1)
            self.assertIn("npm", suggestions[0].pattern)
            self.assertEqual(suggestions[0].approvals_count, 3)

    def test_export_yaml_format_validity(self):
        """Verifies YAML output conforms to policy.hard_allow schema."""
        rule = SuggestedRule(
            id="custom-allow-pytest",
            description="Auto-allow pytest execution",
            tools=["run_command"],
            field="CommandLine",
            pattern="^pytest\\ -v$",
            approvals_count=4,
            sample_commands=["pytest -v"],
            executes_repo_controlled_code=True,
            invalidation_guidance="Invalidate if tests change.",
        )
        yaml_output = self.suggester.export_yaml([rule])
        self.assertIn("policy:", yaml_output)
        self.assertIn("hard_allow:", yaml_output)
        self.assertIn("custom-allow-pytest", yaml_output)
        self.assertIn("MANDATORY REVIEW", yaml_output)

        # Parse with PyYAML to verify structure
        parsed = yaml.safe_load(yaml_output)
        self.assertIn("policy", parsed)
        self.assertIn("hard_allow", parsed["policy"])
        self.assertEqual(len(parsed["policy"]["hard_allow"]), 1)
        self.assertEqual(parsed["policy"]["hard_allow"][0]["pattern"], "^pytest\\ -v$")


    def test_skip_candidates_covered_by_host_rules(self):
        """Verifies candidate rules covered by host allow rules are skipped."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            host_file = Path(tmp_dir) / "host-rules.txt"
            host_file.write_text('{"allow": ["command(npm run)"]}', encoding="utf-8")

            log_path = Path(tmp_dir) / "test_audit.jsonl"
            records = [
                {
                    "event_type": "PreToolUse",
                    "conversation_id": f"conv-{i}",
                    "step_idx": i,
                    "tool_name": "run_command",
                    "tool_args": {"CommandLine": "npm run build"},
                    "final_decision": "ask",
                    "policy_verdict": "ambiguous",
                    "human_approved": "inferred",
                    "latency_class": "human_prompt",
                    "timestamp": f"2026-10-10T01:0{i}:00+00:00",
                }
                for i in range(1, 5)
            ]
            with open(log_path, "w", encoding="utf-8") as f:
                for r in records:
                    f.write(json.dumps(r) + "\n")

            host_aware_suggester = RuleSuggester(
                policy_engine=self.engine, host_rules_path=host_file
            )
            suggestions = host_aware_suggester.mine_audit_log(log_path, min_approvals=3)
            # Should be skipped because "npm run" covers "npm run build"
            self.assertEqual(len(suggestions), 0)

    def test_workspace_code_exact_only_with_warning(self):
        """
        Verifies that commands executing workspace code (pytest, make, python, etc.)
        are emitted as exact-command rules only, with the warning tag.
        """
        workspace_commands = [
            "pytest -v tests/test_foo.py",
            "make build",
            "cargo test",
            "python scripts/migrate.py",
            "node dist/bundle.js",
        ]
        for cmd in workspace_commands:
            with self.subTest(cmd=cmd):
                self.assertTrue(
                    RuleSuggester.is_workspace_code_command(cmd),
                    f"Command '{cmd}' must be identified as executing workspace code"
                )
                candidate = self.suggester._create_candidate_rule(cmd, count=5, samples=[cmd])
                self.assertTrue(candidate.executes_repo_controlled_code)
                self.assertIn("[WARN] executes repo-controlled code", candidate.invalidation_guidance)
                # Must be exact match, no wildcards
                self.assertTrue(candidate.pattern.startswith("^"))
                self.assertTrue(candidate.pattern.endswith("$"))
                self.assertNotIn(".*", candidate.pattern)


if __name__ == "__main__":
    unittest.main()
