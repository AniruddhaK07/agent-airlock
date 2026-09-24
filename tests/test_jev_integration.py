"""
Comprehensive test suite for Phase 3 — Jev Integration Layer.
Tests model pinning, calibrated rubrics, client transport, parsing,
threshold evaluation, fail-closed behavior, and daemon router integration.
"""

import pytest
import time
from typing import Dict, Any, Optional

from jev_gateway.config import GatewayConfig, JevThresholdsConfig
from jev_gateway.jev.models import (
    GateDecision,
    ChoiceRoute,
    JevEvaluation,
    JevDecisionResult,
)
from jev_gateway.jev.client import (
    JevClient,
    JevClientError,
    JevTimeoutError,
    JevParseError,
    PINNED_MODEL,
)
from jev_gateway.jev.prompts import (
    SCORE_RUBRIC,
    NOUL_RUBRIC,
    CHOICE_RUBRIC,
    format_jev_evaluation_prompt,
)
from jev_gateway.jev.evaluator import JevEvaluator
from jev_gateway.daemon.router import IPCRouter
from jev_gateway.policy.engine import HardPolicyEngine


class TestJevIntegration:
    """Unit and integration tests for Jev Integration Layer."""

    # -------------------------------------------------------------------------
    # 1. Model Pinning and Validation
    # -------------------------------------------------------------------------

    def test_pinned_model_identity_enforced(self):
        """Verify that only the strictly pinned model `jev-1.13.0` is accepted."""
        # Allowed pinned model
        client = JevClient(api_key="test-key", model="jev-1.13.0")
        assert client.model == "jev-1.13.0"

        # Forbidden silent upgrades or replacements
        with pytest.raises(ValueError, match="strictly pins model"):
            JevClient(api_key="test-key", model="jev-latest")

        with pytest.raises(ValueError, match="strictly pins model"):
            JevClient(api_key="test-key", model="jev-1.14.0")

        with pytest.raises(ValueError, match="strictly pins model"):
            JevClient(api_key="test-key", model="gemini-2.0")

    def test_response_model_mismatch_rejected(self):
        """Verify that if the API response claims an unpinned model, it is rejected."""
        def mock_transport(payload: Dict[str, Any]) -> Dict[str, Any]:
            return {
                "model": "jev-2.0.0-unpinned",
                "score_blast_radius": 1.0,
                "score_confidence": 0.95,
                "noul_reversible_prob": 1.0,
                "choice_route": "deterministic-safe",
                "choice_confidence": 0.95,
            }

        client = JevClient(transport=mock_transport)
        with pytest.raises(JevParseError, match="does not match pinned model"):
            client.evaluate_ambiguous_tool("run_command", {"CommandLine": "npm test"})

    # -------------------------------------------------------------------------
    # 2. Rubric and Prompt Formatting
    # -------------------------------------------------------------------------

    def test_prompt_formatting_structure(self):
        """Verify prompt bundling includes all required rubrics and metadata."""
        prompt = format_jev_evaluation_prompt(
            tool_name="run_command",
            tool_args={"CommandLine": "pip install requests"},
            context={"workspace_root": "/app", "stepIdx": 3},
        )

        assert "run_command" in prompt["action_summary"]
        assert "pip install requests" in prompt["action_summary"]
        assert "/app" in prompt["action_summary"]
        assert "questions" in prompt
        assert "score" in prompt["questions"]
        assert "noul" in prompt["questions"]
        assert "choice" in prompt["questions"]

        # Verify rubrics match specifications
        assert "1.0 - 5.0" in SCORE_RUBRIC["scale"]
        assert "0.0 - 1.0" in NOUL_RUBRIC["scale"]
        assert "deterministic-safe" in CHOICE_RUBRIC["options"]
        assert "needs-human" in CHOICE_RUBRIC["options"]
        assert "needs-reasoning-model" in CHOICE_RUBRIC["options"]

    # -------------------------------------------------------------------------
    # 3. Client Transport, Schema Parsing, and Range Validation
    # -------------------------------------------------------------------------

    def test_client_parses_nested_results_schema(self):
        """Verify parsing of nested results payload."""
        def mock_transport(payload: Dict[str, Any]) -> Dict[str, Any]:
            assert payload["model"] == "jev-1.13.0"
            return {
                "model": "jev-1.13.0",
                "results": {
                    "score": {"value": 1.5, "confidence": 0.92},
                    "noul": {"probability": 0.88, "confidence": 0.90},
                    "choice": {"selection": "deterministic-safe", "confidence": 0.95},
                },
            }

        client = JevClient(transport=mock_transport)
        eval_res = client.evaluate_ambiguous_tool("run_command", {"CommandLine": "cargo check"})

        assert eval_res.score_blast_radius == 1.5
        assert eval_res.score_confidence == 0.92
        assert eval_res.noul_reversible_prob == 0.88
        assert eval_res.choice_route == "deterministic-safe"
        assert eval_res.choice_confidence == 0.95

    def test_client_parses_flat_schema(self):
        """Verify parsing of flat results payload."""
        def mock_transport(payload: Dict[str, Any]) -> Dict[str, Any]:
            return {
                "model": "jev-1.13.0",
                "score_blast_radius": 2.0,
                "score_confidence": 0.91,
                "noul_reversible_prob": 0.75,
                "choice_route": "deterministic-safe",
                "choice_confidence": 0.94,
            }

        client = JevClient(transport=mock_transport)
        eval_res = client.evaluate_ambiguous_tool("run_command", {"CommandLine": "touch test.txt"})

        assert eval_res.score_blast_radius == 2.0
        assert eval_res.score_confidence == 0.91
        assert eval_res.noul_reversible_prob == 0.75
        assert eval_res.choice_route == "deterministic-safe"
        assert eval_res.choice_confidence == 0.94

    def test_client_rejects_out_of_bounds_values(self):
        """Verify that invalid numeric ranges or unknown routes raise JevParseError."""
        # Blast radius > 5.0
        c1 = JevClient(transport=lambda p: {
            "score_blast_radius": 6.0,
            "score_confidence": 0.9,
            "noul_reversible_prob": 0.8,
            "choice_route": "deterministic-safe",
            "choice_confidence": 0.9,
        })
        with pytest.raises(JevParseError, match="Blast radius 6.0 out of valid range"):
            c1.evaluate_ambiguous_tool("run_command", {"CommandLine": "echo"})

        # Reversibility prob > 1.0
        c2 = JevClient(transport=lambda p: {
            "score_blast_radius": 2.0,
            "score_confidence": 0.9,
            "noul_reversible_prob": 1.5,
            "choice_route": "deterministic-safe",
            "choice_confidence": 0.9,
        })
        with pytest.raises(JevParseError, match="Reversible probability 1.5 out of valid range"):
            c2.evaluate_ambiguous_tool("run_command", {"CommandLine": "echo"})

        # Invalid route
        c3 = JevClient(transport=lambda p: {
            "score_blast_radius": 2.0,
            "score_confidence": 0.9,
            "noul_reversible_prob": 0.8,
            "choice_route": "auto-allow-everything",
            "choice_confidence": 0.9,
        })
        with pytest.raises(JevParseError, match="Choice route 'auto-allow-everything' is not one of valid routes"):
            c3.evaluate_ambiguous_tool("run_command", {"CommandLine": "echo"})

    def test_client_timeout_and_retries(self):
        """Verify that timeout errors trigger configured retries and raise JevTimeoutError."""
        attempts = 0

        def timeout_transport(payload: Dict[str, Any]) -> Dict[str, Any]:
            nonlocal attempts
            attempts += 1
            raise JevTimeoutError("Socket timeout simulating slow API response")

        client = JevClient(max_retries=1, transport=timeout_transport)
        with pytest.raises(JevTimeoutError, match="Socket timeout"):
            client.evaluate_ambiguous_tool("run_command", {"CommandLine": "sleep 10"})

        # 1 initial attempt + 1 retry = 2 attempts total
        assert attempts == 2

    # -------------------------------------------------------------------------
    # 4. Threshold Evaluator Logic
    # -------------------------------------------------------------------------

    def test_evaluator_confident_safe_allows(self):
        """Verify that confident safe evaluation returns ALLOW."""
        evaluator = JevEvaluator(JevThresholdsConfig(
            allow_confidence=0.90,
            max_safe_blast_radius=2.0,
            min_safe_reversible_prob=0.70,
        ))

        evaluation = JevEvaluation(
            score_blast_radius=1.8,
            score_confidence=0.95,
            noul_reversible_prob=0.85,
            choice_route="deterministic-safe",
            choice_confidence=0.93,
        )

        result = evaluator.decide(evaluation=evaluation)
        assert result.decision == GateDecision.ALLOW
        assert "verified safe" in result.reason

    def test_evaluator_low_confidence_fails_closed_to_ask(self):
        """Verify that choice confidence below threshold fails closed to ASK."""
        evaluator = JevEvaluator(JevThresholdsConfig(allow_confidence=0.90))

        evaluation = JevEvaluation(
            score_blast_radius=1.5,
            score_confidence=0.95,
            noul_reversible_prob=0.85,
            choice_route="deterministic-safe",
            choice_confidence=0.84,  # Below 0.90 threshold
        )

        result = evaluator.decide(evaluation=evaluation)
        assert result.decision == GateDecision.ASK
        assert "choice confidence (0.84) < required threshold (0.90)" in result.reason

    def test_evaluator_excessive_blast_radius_fails_closed_to_ask(self):
        """Verify that blast radius > max_safe_blast_radius fails closed to ASK."""
        evaluator = JevEvaluator(JevThresholdsConfig(max_safe_blast_radius=2.0))

        evaluation = JevEvaluation(
            score_blast_radius=2.5,  # Exceeds 2.0 max safe
            score_confidence=0.95,
            noul_reversible_prob=0.85,
            choice_route="deterministic-safe",
            choice_confidence=0.95,
        )

        result = evaluator.decide(evaluation=evaluation)
        assert result.decision == GateDecision.ASK
        assert "blast radius (2.5) exceeds safe maximum (2.0)" in result.reason

    def test_evaluator_low_reversibility_fails_closed_to_ask(self):
        """Verify that reversibility probability < min_safe_reversible_prob fails closed to ASK."""
        evaluator = JevEvaluator(JevThresholdsConfig(min_safe_reversible_prob=0.70))

        evaluation = JevEvaluation(
            score_blast_radius=1.5,
            score_confidence=0.95,
            noul_reversible_prob=0.60,  # Below 0.70 min reversible
            choice_route="deterministic-safe",
            choice_confidence=0.95,
        )

        result = evaluator.decide(evaluation=evaluation)
        assert result.decision == GateDecision.ASK
        assert "reversibility probability (0.60) < required minimum (0.70)" in result.reason

    def test_evaluator_explicit_needs_human_routes_to_ask(self):
        """Verify that needs-human route produces ASK decision."""
        evaluator = JevEvaluator()
        evaluation = JevEvaluation(
            score_blast_radius=2.0,
            score_confidence=0.95,
            noul_reversible_prob=0.80,
            choice_route="needs-human",
            choice_confidence=0.95,
        )

        result = evaluator.decide(evaluation=evaluation)
        assert result.decision == GateDecision.ASK
        assert "needs-human" in result.reason

    def test_evaluator_needs_reasoning_model_routes_to_ask(self):
        """Verify that needs-reasoning-model route produces ASK decision."""
        evaluator = JevEvaluator()
        evaluation = JevEvaluation(
            score_blast_radius=2.0,
            score_confidence=0.95,
            noul_reversible_prob=0.80,
            choice_route="needs-reasoning-model",
            choice_confidence=0.95,
        )

        result = evaluator.decide(evaluation=evaluation)
        assert result.decision == GateDecision.ASK
        assert "needs-reasoning-model" in result.reason

    def test_evaluator_confident_high_blast_radius_denies(self):
        """Verify that blast radius >= 4.0 with high confidence produces DENY."""
        evaluator = JevEvaluator(JevThresholdsConfig(deny_confidence=0.85))
        evaluation = JevEvaluation(
            score_blast_radius=4.5,
            score_confidence=0.92,  # >= 0.85 deny confidence
            noul_reversible_prob=0.10,
            choice_route="needs-human",
            choice_confidence=0.95,
        )

        result = evaluator.decide(evaluation=evaluation)
        assert result.decision == GateDecision.DENY
        assert "high blast radius (4.5 >= 4.0)" in result.reason

    def test_evaluator_low_confidence_high_blast_radius_asks(self):
        """Verify that blast radius >= 4.0 with low confidence produces ASK, never ALLOW."""
        evaluator = JevEvaluator(JevThresholdsConfig(deny_confidence=0.85))
        evaluation = JevEvaluation(
            score_blast_radius=4.2,
            score_confidence=0.60,  # < 0.85 deny confidence
            noul_reversible_prob=0.10,
            choice_route="needs-human",
            choice_confidence=0.70,
        )

        result = evaluator.decide(evaluation=evaluation)
        assert result.decision == GateDecision.ASK
        assert result.decision != GateDecision.ALLOW
        assert "potential high blast radius" in result.reason

    def test_evaluator_error_or_none_strictly_fails_closed(self):
        """Verify that None evaluation or exceptions strictly fail closed to ASK."""
        evaluator = JevEvaluator()

        res1 = evaluator.decide(evaluation=None)
        assert res1.decision == GateDecision.ASK
        assert "failing closed" in res1.reason

        res2 = evaluator.decide(evaluation=None, error=RuntimeError("API gateway connection dropped"))
        assert res2.decision == GateDecision.ASK
        assert "API gateway connection dropped" in res2.reason

    # -------------------------------------------------------------------------
    # 5. IPCRouter Integration with Jev
    # -------------------------------------------------------------------------

    def test_router_ambiguous_evaluation_allow_flow(self):
        """Ambiguous command passing Jev thresholds is returned as ALLOW."""
        def safe_jev_transport(payload: Dict[str, Any]) -> Dict[str, Any]:
            return {
                "model": "jev-1.13.0",
                "score_blast_radius": 1.5,
                "score_confidence": 0.95,
                "noul_reversible_prob": 0.85,
                "choice_route": "deterministic-safe",
                "choice_confidence": 0.94,
            }

        client = JevClient(transport=safe_jev_transport)
        evaluator = JevEvaluator()
        router = IPCRouter(
            policy_engine=HardPolicyEngine(),
            jev_client=client,
            jev_evaluator=evaluator,
        )

        req = {
            "version": "1.0",
            "event": "PreToolUse",
            "payload": {
                "toolCall": {"name": "run_command", "args": {"CommandLine": "python generate_docs.py"}},
                "workspace_root": "/project",
            },
        }

        res = router.dispatch(req)
        assert res["status"] == "success"
        assert res["decision"] == "allow"
        assert "verified safe" in res["reason"]
        assert res["jevEvaluation"] is not None
        assert res["jevEvaluation"]["score_blast_radius"] == 1.5

    def test_router_ambiguous_evaluation_deny_flow(self):
        """Ambiguous command assessed by Jev as catastrophic is returned as DENY."""
        def dangerous_jev_transport(payload: Dict[str, Any]) -> Dict[str, Any]:
            return {
                "model": "jev-1.13.0",
                "score_blast_radius": 4.8,
                "score_confidence": 0.95,
                "noul_reversible_prob": 0.05,
                "choice_route": "needs-human",
                "choice_confidence": 0.95,
            }

        client = JevClient(transport=dangerous_jev_transport)
        evaluator = JevEvaluator()
        router = IPCRouter(
            policy_engine=HardPolicyEngine(),
            jev_client=client,
            jev_evaluator=evaluator,
        )

        req = {
            "version": "1.0",
            "event": "PreToolUse",
            "payload": {
                "toolCall": {"name": "run_command", "args": {"CommandLine": "custom_db_drop_tool --all"}},
                "workspace_root": "/project",
            },
        }

        res = router.dispatch(req)
        assert res["status"] == "success"
        assert res["decision"] == "deny"
        assert "high blast radius" in res["reason"]

    def test_router_ambiguous_evaluation_ask_flow(self):
        """Ambiguous command requiring human confirmation returns ASK."""
        def human_jev_transport(payload: Dict[str, Any]) -> Dict[str, Any]:
            return {
                "model": "jev-1.13.0",
                "score_blast_radius": 3.0,
                "score_confidence": 0.95,
                "noul_reversible_prob": 0.60,
                "choice_route": "needs-human",
                "choice_confidence": 0.95,
            }

        client = JevClient(transport=human_jev_transport)
        evaluator = JevEvaluator()
        router = IPCRouter(
            policy_engine=HardPolicyEngine(),
            jev_client=client,
            jev_evaluator=evaluator,
        )

        req = {
            "version": "1.0",
            "event": "PreToolUse",
            "payload": {
                "toolCall": {"name": "run_command", "args": {"CommandLine": "git push --force"}},
                "workspace_root": "/project",
            },
        }

        res = router.dispatch(req)
        assert res["status"] == "success"
        assert res["decision"] == "ask"
        assert "needs-human" in res["reason"]

    def test_router_jev_network_timeout_fails_closed(self):
        """API timeout during Jev evaluation strictly fails closed to ASK with status fail_closed."""
        def timeout_transport(payload: Dict[str, Any]) -> Dict[str, Any]:
            raise JevTimeoutError("Jev API request timed out after 3.0s")

        client = JevClient(max_retries=0, transport=timeout_transport)
        evaluator = JevEvaluator()
        router = IPCRouter(
            policy_engine=HardPolicyEngine(),
            jev_client=client,
            jev_evaluator=evaluator,
        )

        req = {
            "version": "1.0",
            "event": "PreToolUse",
            "payload": {
                "toolCall": {"name": "run_command", "args": {"CommandLine": "docker build ."}},
                "workspace_root": "/project",
            },
        }

        res = router.dispatch(req)
        assert res["status"] == "fail_closed"
        assert res["decision"] == "ask"
        assert "failing closed to human confirmation" in res["reason"]

    def test_router_deterministic_rules_preempt_jev(self):
        """Hard deny and allow rules must run first and NEVER call Jev."""
        jev_called = False

        def spy_transport(payload: Dict[str, Any]) -> Dict[str, Any]:
            nonlocal jev_called
            jev_called = True
            return {}

        client = JevClient(transport=spy_transport)
        evaluator = JevEvaluator()
        router = IPCRouter(
            policy_engine=HardPolicyEngine(),
            jev_client=client,
            jev_evaluator=evaluator,
        )

        # 1. Hard deny: rm -rf /
        res_deny = router.dispatch({
            "version": "1.0",
            "event": "PreToolUse",
            "payload": {
                "toolCall": {"name": "run_command", "args": {"CommandLine": "rm -rf /"}},
                "workspace_root": "/project",
            },
        })
        assert res_deny["decision"] == "deny"
        assert not jev_called

        # 2. Hard allow: git status
        res_allow = router.dispatch({
            "version": "1.0",
            "event": "PreToolUse",
            "payload": {
                "toolCall": {"name": "run_command", "args": {"CommandLine": "git status"}},
                "workspace_root": "/project",
            },
        })
        assert res_allow["decision"] == "allow"
        assert not jev_called

    def test_router_unresolved_workspace_fails_closed_before_jev(self):
        """Unresolved workspace context must fail closed to force_ask without invoking Jev."""
        jev_called = False

        def spy_transport(payload: Dict[str, Any]) -> Dict[str, Any]:
            nonlocal jev_called
            jev_called = True
            return {}

        client = JevClient(transport=spy_transport)
        evaluator = JevEvaluator()
        router = IPCRouter(
            policy_engine=HardPolicyEngine(),
            jev_client=client,
            jev_evaluator=evaluator,
        )

        res = router.dispatch({
            "version": "1.0",
            "event": "PreToolUse",
            "payload": {
                "toolCall": {"name": "run_command", "args": {"CommandLine": "python script.py"}},
                # workspace_root omitted
            },
        })
        assert res["status"] == "fail_closed"
        assert res["decision"] == "force_ask"
        assert res["reason"] == "workspace context unresolved"
        assert not jev_called

    # -------------------------------------------------------------------------
    # 6. HTTP Transport Simulation (Urllib)
    # -------------------------------------------------------------------------

    def test_http_post_success(self, monkeypatch):
        """Verify _http_post handles valid 200 HTTP response."""
        import io
        import urllib.request
        from unittest.mock import MagicMock

        response_json = (
            '{"model": "jev-1.13.0", "score_blast_radius": 1.5, "score_confidence": 0.95, '
            '"noul_reversible_prob": 0.90, "choice_route": "deterministic-safe", "choice_confidence": 0.95}'
        )

        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.read.return_value = response_json.encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.__exit__.return_value = False

        monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout: mock_resp)

        client = JevClient(api_key="ts-secret-key")
        evaluation = client.evaluate_ambiguous_tool("run_command", {"CommandLine": "cargo test"})
        assert evaluation.score_blast_radius == 1.5
        assert evaluation.choice_route == "deterministic-safe"

    def test_http_post_invalid_json(self, monkeypatch):
        """Verify _http_post raises JevParseError on non-JSON response."""
        import urllib.request
        from unittest.mock import MagicMock

        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.read.return_value = b"<html>502 Bad Gateway</html>"
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.__exit__.return_value = False

        monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout: mock_resp)

        client = JevClient()
        with pytest.raises(JevParseError, match="Failed to parse Jev API JSON response"):
            client.evaluate_ambiguous_tool("run_command", {"CommandLine": "cargo test"})

    def test_http_post_http_error(self, monkeypatch):
        """Verify _http_post raises JevClientError on HTTP error status."""
        import urllib.request
        import urllib.error

        def raise_http_error(req, timeout):
            raise urllib.error.HTTPError("http://api.typesafe.ai", 401, "Unauthorized", {}, None)

        monkeypatch.setattr(urllib.request, "urlopen", raise_http_error)

        client = JevClient()
        with pytest.raises(JevClientError, match="Jev API HTTP error 401"):
            client.evaluate_ambiguous_tool("run_command", {"CommandLine": "cargo test"})

    def test_total_request_latency_under_400ms_budget(self):
        """
        Asserts total request-to-decision latency (including any retries) stays
        under the 400ms fail-closed budget by enforcing a wall-clock-total deadline.
        """
        attempt_count = 0

        def slow_failing_transport(payload: Dict[str, Any], timeout: float = 0.400) -> Dict[str, Any]:
            nonlocal attempt_count
            attempt_count += 1
            # Simulate a socket that blocks up to the attempt's remaining timeout budget
            sleep_time = min(timeout, 0.250)
            time.sleep(sleep_time)
            if sleep_time >= timeout:
                raise JevTimeoutError(f"Socket timed out after {timeout * 1000:.1f}ms")
            raise JevTimeoutError("Transient socket disconnect")

        client = JevClient(timeout=0.400, max_retries=2, transport=slow_failing_transport)
        evaluator = JevEvaluator()
        router = IPCRouter(
            policy_engine=HardPolicyEngine(),
            jev_client=client,
            jev_evaluator=evaluator,
        )

        t_start = time.time()
        res = router.dispatch({
            "version": "1.0",
            "event": "PreToolUse",
            "payload": {
                "toolCall": {"name": "run_command", "args": {"CommandLine": "python build.py"}},
                "workspace_root": "/project",
            },
        })
        elapsed = time.time() - t_start

        assert res["status"] == "fail_closed"
        assert res["decision"] == "ask"
        assert "failing closed to human confirmation" in res["reason"]
        # Total latency must not exceed the 400ms fail-closed budget + minimal scheduling jitter
        assert elapsed <= 0.460, f"Total latency {elapsed * 1000:.1f}ms exceeded fail-closed budget"
        # Must have attempted retries within the budget
        assert attempt_count >= 2


