"""
Unit and integration tests for Phase 1.4: Exact-Key Decision Cache.
Verifies:
- Exact key components (tool, normalized_cmd, cwd, workspace, policy_hash, trust_epoch)
- TTL expiration and LRU eviction
- Invariant: Never caches ASK as ALLOW
- Invariant: Never caches oversized commands (>4096 chars)
- Invariant: Never caches fallback/error decisions
- Trust-epoch invalidation on trust-root file modification
- R1 Invariant: Repeated failing command still trips the circuit breaker before cache
- Router integration: Cache hit emits decision_source='cache' and records cache_key_hash
"""

import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import MagicMock

from agent_airlock.cache.decision_cache import DecisionCache, CachedDecision
from agent_airlock.config import CircuitBreakerConfig
from agent_airlock.daemon.router import IPCRouter
from agent_airlock.policy.engine import HardPolicyEngine
from agent_airlock.policy.models import PolicyVerdict, PolicyResult


class TestDecisionCacheUnit(unittest.TestCase):
    """Unit tests for standalone DecisionCache logic."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.ws_root = self.tmp_dir.name
        self.cache = DecisionCache(enabled=True, ttl_seconds=10, max_entries=3)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_cache_key_determinism_and_components(self):
        """Verifies cache key includes all 6 specified components deterministically."""
        k1 = self.cache.compute_cache_key(
            tool_name="run_command",
            normalized_target="git status",
            cwd="/repo",
            workspace_root="/repo",
            policy_hash="hash1",
            trust_epoch="epoch1",
        )
        k2 = self.cache.compute_cache_key(
            tool_name="run_command",
            normalized_target="git status",
            cwd="/repo",
            workspace_root="/repo",
            policy_hash="hash1",
            trust_epoch="epoch1",
        )
        self.assertEqual(k1, k2)

        # Varying any single component changes the key
        k_diff_tool = self.cache.compute_cache_key("view_file", "git status", "/repo", "/repo", "hash1", "epoch1")
        k_diff_cmd = self.cache.compute_cache_key("run_command", "git diff", "/repo", "/repo", "hash1", "epoch1")
        k_diff_cwd = self.cache.compute_cache_key("run_command", "git status", "/other", "/repo", "hash1", "epoch1")
        k_diff_ws = self.cache.compute_cache_key("run_command", "git status", "/repo", "/other", "hash1", "epoch1")
        k_diff_pol = self.cache.compute_cache_key("run_command", "git status", "/repo", "/repo", "hash2", "epoch1")
        k_diff_ep = self.cache.compute_cache_key("run_command", "git status", "/repo", "/repo", "hash1", "epoch2")

        self.assertNotEqual(k1, k_diff_tool)
        self.assertNotEqual(k1, k_diff_cmd)
        self.assertNotEqual(k1, k_diff_cwd)
        self.assertNotEqual(k1, k_diff_ws)
        self.assertNotEqual(k1, k_diff_pol)
        self.assertNotEqual(k1, k_diff_ep)

    def test_put_and_get_allow(self):
        """Verifies basic put and get for ALLOW decision."""
        key = self.cache.put(
            tool_name="run_command",
            normalized_target="npm test",
            cwd=self.ws_root,
            workspace_root=self.ws_root,
            policy_hash="pol_a",
            decision="allow",
            source="ml",
            reason="Safe test command",
        )
        self.assertIsNotNone(key)

        entry = self.cache.get(
            tool_name="run_command",
            normalized_target="npm test",
            cwd=self.ws_root,
            workspace_root=self.ws_root,
            policy_hash="pol_a",
        )
        self.assertIsNotNone(entry)
        self.assertEqual(entry.decision, "allow")
        self.assertEqual(entry.source, "ml")
        self.assertEqual(entry.key, key)

    def test_invariant_never_caches_ask_as_allow(self):
        """Verifies that ASK decisions are NEVER cached."""
        key1 = self.cache.put(
            tool_name="run_command",
            normalized_target="rm -rf /",
            cwd=self.ws_root,
            workspace_root=self.ws_root,
            policy_hash="pol_a",
            decision="ask",
            source="fallback",
            reason="Ambiguous",
        )
        self.assertIsNone(key1)

        key2 = self.cache.put(
            tool_name="run_command",
            normalized_target="rm -rf /",
            cwd=self.ws_root,
            workspace_root=self.ws_root,
            policy_hash="pol_a",
            decision="force_ask",
            source="l2",
            reason="Breaker tripped",
        )
        self.assertIsNone(key2)
        self.assertEqual(len(self.cache), 0)

    def test_invariant_never_caches_oversized_payloads(self):
        """Verifies commands > 4096 chars are rejected from caching."""
        oversized = "echo " + ("A" * 4100)
        key = self.cache.put(
            tool_name="run_command",
            normalized_target=oversized,
            cwd=self.ws_root,
            workspace_root=self.ws_root,
            policy_hash="pol_a",
            decision="allow",
            source="ml",
            reason="Oversized",
            raw_length=len(oversized),
        )
        self.assertIsNone(key)
        self.assertEqual(len(self.cache), 0)

    def test_lru_eviction(self):
        """Verifies LRU eviction removes the oldest entry when max_entries is exceeded."""
        self.cache.put("run_command", "cmd1", self.ws_root, self.ws_root, "p", "allow", "ml", "r1")
        self.cache.put("run_command", "cmd2", self.ws_root, self.ws_root, "p", "allow", "ml", "r2")
        self.cache.put("run_command", "cmd3", self.ws_root, self.ws_root, "p", "allow", "ml", "r3")
        self.assertEqual(len(self.cache), 3)

        # Access cmd1 to make it most recently used; cmd2 becomes oldest
        self.cache.get("run_command", "cmd1", self.ws_root, self.ws_root, "p")

        # Put cmd4 -> cmd2 should be evicted
        self.cache.put("run_command", "cmd4", self.ws_root, self.ws_root, "p", "allow", "ml", "r4")
        self.assertEqual(len(self.cache), 3)

        self.assertIsNotNone(self.cache.get("run_command", "cmd1", self.ws_root, self.ws_root, "p"))
        self.assertIsNone(self.cache.get("run_command", "cmd2", self.ws_root, self.ws_root, "p"))
        self.assertIsNotNone(self.cache.get("run_command", "cmd3", self.ws_root, self.ws_root, "p"))
        self.assertIsNotNone(self.cache.get("run_command", "cmd4", self.ws_root, self.ws_root, "p"))

    def test_ttl_expiration(self):
        """Verifies entries expire after ttl_seconds."""
        cache_short_ttl = DecisionCache(enabled=True, ttl_seconds=0.05, max_entries=10)
        cache_short_ttl.put("run_command", "cmd1", self.ws_root, self.ws_root, "p", "allow", "ml", "r1")

        self.assertIsNotNone(cache_short_ttl.get("run_command", "cmd1", self.ws_root, self.ws_root, "p"))
        time.sleep(0.08)
        self.assertIsNone(cache_short_ttl.get("run_command", "cmd1", self.ws_root, self.ws_root, "p"))

    def test_trust_epoch_invalidation_on_file_change(self):
        """Verifies modifying a trust-root file changes the epoch and causes cache miss."""
        pkg_json = Path(self.ws_root) / "package.json"
        pkg_json.write_text('{"name": "test"}', encoding="utf-8")

        epoch1 = self.cache.get_trust_epoch(self.ws_root)

        self.cache.put("run_command", "build", self.ws_root, self.ws_root, "p", "allow", "ml", "r1")
        self.assertIsNotNone(self.cache.get("run_command", "build", self.ws_root, self.ws_root, "p"))

        # Modify package.json
        time.sleep(0.01)
        pkg_json.write_text('{"name": "test-modified", "scripts": {"build": "tsc"}}', encoding="utf-8")
        epoch2 = self.cache.get_trust_epoch(self.ws_root)
        self.assertNotEqual(epoch1, epoch2)

        # Lookup now misses because epoch changed
        self.assertIsNone(self.cache.get("run_command", "build", self.ws_root, self.ws_root, "p"))


class TestDecisionCacheRouterIntegration(unittest.TestCase):
    """Integration tests for DecisionCache inside IPCRouter."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.ws_root = self.tmp_dir.name
        self.engine = HardPolicyEngine()
        self.cb_config = CircuitBreakerConfig(hash_window=3, break_action="force_ask")
        self.cache = DecisionCache(enabled=True, ttl_seconds=3600, max_entries=100)

        self.router = IPCRouter(
            policy_engine=self.engine,
            circuit_breaker_config=self.cb_config,
            decision_cache=self.cache,
            audit_logger=None,
        )

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_r1_invariant_repeated_failing_command_still_trips_breaker(self):
        """
        MANDATORY R1 INVARIANT TEST:
        A repeated failing command must trip the circuit breaker even if it was cached as ALLOW.
        Verifies breaker evaluates BEFORE cache lookup.
        """
        failing_cmd = "python fail_script.py"

        # Prime the cache with an ALLOW decision for this exact command
        norm_cmd = self.cache.normalize_target("run_command", {"CommandLine": failing_cmd})
        self.cache.put(
            tool_name="run_command",
            normalized_target=norm_cmd,
            cwd=self.ws_root,
            workspace_root=self.ws_root,
            policy_hash=self.router.policy_hash,
            decision="allow",
            source="ml",
            reason="Previously approved",
        )

        # Verify it is in cache
        cached = self.cache.get("run_command", norm_cmd, self.ws_root, self.ws_root, self.router.policy_hash)
        self.assertIsNotNone(cached)

        # Simulate 1st execution failure
        req1 = {
            "version": "1.0",
            "event": "PreToolUse",
            "payload": {
                "conversationId": "c1",
                "stepIdx": 1,
                "workspace_root": self.ws_root,
                "toolCall": {"name": "run_command", "args": {"CommandLine": failing_cmd}},
            },
        }
        res1 = self.router.dispatch(req1)
        self.assertEqual(res1["decision"], "allow")
        self.assertEqual(res1.get("cacheKeyHash"), cached.key)

        # PostToolUse: execution failed
        post1 = {
            "version": "1.0",
            "event": "PostToolUse",
            "payload": {
                "conversationId": "c1",
                "stepIdx": 1,
                "workspace_root": self.ws_root,
                "toolCall": {"name": "run_command", "args": {"CommandLine": failing_cmd}},
                "status": "error",
                "toolResult": {"exitCode": 1, "stderr": "Traceback: ZeroDivisionError: division by zero"},
            },
        }
        self.router.dispatch(post1)

        # 2nd execution: repeating the command that just failed!
        req2 = {
            "version": "1.0",
            "event": "PreToolUse",
            "payload": {
                "conversationId": "c1",
                "stepIdx": 2,
                "workspace_root": self.ws_root,
                "toolCall": {"name": "run_command", "args": {"CommandLine": failing_cmd}},
            },
        }
        res2 = self.router.dispatch(req2)

        # BREAKER MUST TRIP TO FORCE_ASK, BYPASSING THE CACHED ALLOW!
        self.assertTrue(res2.get("circuitBreakerTripped"), "Circuit breaker must trip on repeated failing command!")
        self.assertEqual(res2["decision"], "force_ask", "Breaker must emit force_ask!")
        self.assertIsNone(res2.get("cacheKeyHash"), "Cache must NOT rubber-stamp a looping failure past the breaker!")

    def test_post_tool_use_writing_trust_root_invalidates_cache(self):
        """Verifies that write_to_file modifying a trust-root file invalidates cached decisions."""
        cmd = "pytest tests/test_fast.py"
        norm_cmd = self.cache.normalize_target("run_command", {"CommandLine": cmd})

        self.cache.put(
            tool_name="run_command",
            normalized_target=norm_cmd,
            cwd=self.ws_root,
            workspace_root=self.ws_root,
            policy_hash=self.router.policy_hash,
            decision="allow",
            source="ml",
            reason="Fast tests",
        )

        # Cache hit before write
        cached_before = self.cache.get("run_command", norm_cmd, self.ws_root, self.ws_root, self.router.policy_hash)
        self.assertIsNotNone(cached_before)

        # PostToolUse: writing pyproject.toml (trust root)
        post_write = {
            "version": "1.0",
            "event": "PostToolUse",
            "payload": {
                "conversationId": "c1",
                "stepIdx": 10,
                "workspace_root": self.ws_root,
                "toolCall": {
                    "name": "write_to_file",
                    "args": {"TargetFile": str(Path(self.ws_root) / "pyproject.toml"), "CodeContent": "[tool.pytest]"},
                },
                "status": "success",
            },
        }
        self.router.dispatch(post_write)

        # Cache lookup after write must miss
        cached_after = self.cache.get("run_command", norm_cmd, self.ws_root, self.ws_root, self.router.policy_hash)
        self.assertIsNone(cached_after, "Modifying trust-root file must invalidate cached decision!")


if __name__ == "__main__":
    unittest.main()
