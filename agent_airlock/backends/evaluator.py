"""
Threshold evaluator and fail-closed decision logic for Jev evaluations.
Applies configured confidence, blast-radius, and reversibility thresholds.
"""

from typing import Optional
from agent_airlock.config import JevThresholdsConfig
from agent_airlock.backends.models import (
    GateDecision,
    ChoiceRoute,
    JevEvaluation,
    JevDecisionResult,
)


class JevEvaluator:
    """
    Evaluates Jev probabilistic outputs against strict safety thresholds.
    Enforces non-negotiable fail-closed invariant: any failure, timeout,
    or sub-threshold metric routes to human confirmation (ASK), never ALLOW.
    """

    def __init__(self, thresholds: Optional[JevThresholdsConfig] = None):
        self.thresholds = thresholds or JevThresholdsConfig()

    def decide(
        self,
        evaluation: Optional[JevEvaluation],
        error: Optional[Exception] = None,
        latency_ms: float = 0.0,
    ) -> JevDecisionResult:
        """
        Applies gating thresholds to Jev response:
        - If error is present or evaluation is None -> 'ask' (Fail-Closed)
        - If score_blast_radius >= 4.0:
          - If score_confidence >= deny_confidence -> 'deny'
          - Else -> 'ask'
        - If choice_route == 'needs-human' -> 'ask'
        - If choice_route == 'needs-reasoning-model' -> 'ask'
        - If choice_route == 'deterministic-safe':
          - If choice_confidence < allow_confidence -> 'ask'
          - If score_blast_radius > max_safe_blast_radius -> 'ask'
          - If noul_reversible_prob < min_safe_reversible_prob -> 'ask'
          - All pass -> 'allow'
        - Default fallback -> 'ask'
        """
        # Invariant 1: Strict Fail-Closed on error or missing evaluation
        if error is not None or evaluation is None:
            err_msg = str(error) if error else "No evaluation provided"
            return JevDecisionResult(
                decision=GateDecision.ASK,
                reason=f"Laya evaluation failure ({err_msg}); failing closed to human confirmation.",
                evaluation=None,
                latency_ms=latency_ms,
                error=err_msg,
            )

        # 2. Check for high blast radius (Major / Catastrophic danger)
        if evaluation.score_blast_radius >= 4.0:
            if evaluation.score_confidence >= self.thresholds.deny_confidence:
                return JevDecisionResult(
                    decision=GateDecision.DENY,
                    reason=(
                        f"Laya detected high blast radius ({evaluation.score_blast_radius:.1f} >= 4.0) "
                        f"with confidence {evaluation.score_confidence:.2f}; blocking execution."
                    ),
                    evaluation=evaluation,
                    latency_ms=latency_ms,
                )
            else:
                return JevDecisionResult(
                    decision=GateDecision.ASK,
                    reason=(
                        f"Laya detected potential high blast radius ({evaluation.score_blast_radius:.1f} >= 4.0) "
                        f"with confidence {evaluation.score_confidence:.2f}; requiring human confirmation."
                    ),
                    evaluation=evaluation,
                    latency_ms=latency_ms,
                )

        # 3. Check explicit human-in-the-loop route
        if evaluation.choice_route == ChoiceRoute.NEEDS_HUMAN.value:
            return JevDecisionResult(
                decision=GateDecision.ASK,
                reason="Laya routed action to human confirmation (needs-human).",
                evaluation=evaluation,
                latency_ms=latency_ms,
            )

        # 4. Check reasoning model route
        if evaluation.choice_route == ChoiceRoute.NEEDS_REASONING_MODEL.value:
            return JevDecisionResult(
                decision=GateDecision.ASK,
                reason="Laya routed action to reasoning model / human review (needs-reasoning-model).",
                evaluation=evaluation,
                latency_ms=latency_ms,
            )

        # 5. Check deterministic-safe route against calibrated thresholds
        if evaluation.choice_route == ChoiceRoute.DETERMINISTIC_SAFE.value:
            # 5a. Choice confidence check
            if evaluation.choice_confidence < self.thresholds.allow_confidence:
                return JevDecisionResult(
                    decision=GateDecision.ASK,
                    reason=(
                        f"Laya choice confidence ({evaluation.choice_confidence:.2f}) < required threshold "
                        f"({self.thresholds.allow_confidence:.2f}); failing closed to human confirmation."
                    ),
                    evaluation=evaluation,
                    latency_ms=latency_ms,
                )

            # 5b. Blast radius check
            if evaluation.score_blast_radius > self.thresholds.max_safe_blast_radius:
                return JevDecisionResult(
                    decision=GateDecision.ASK,
                    reason=(
                        f"Laya blast radius ({evaluation.score_blast_radius:.1f}) exceeds safe maximum "
                        f"({self.thresholds.max_safe_blast_radius:.1f}); failing closed to human confirmation."
                    ),
                    evaluation=evaluation,
                    latency_ms=latency_ms,
                )

            # 5c. Reversibility check
            if evaluation.noul_reversible_prob < self.thresholds.min_safe_reversible_prob:
                return JevDecisionResult(
                    decision=GateDecision.ASK,
                    reason=(
                        f"Laya reversibility probability ({evaluation.noul_reversible_prob:.2f}) < required minimum "
                        f"({self.thresholds.min_safe_reversible_prob:.2f}); failing closed to human confirmation."
                    ),
                    evaluation=evaluation,
                    latency_ms=latency_ms,
                )

            # All threshold gates passed -> ALLOW
            return JevDecisionResult(
                decision=GateDecision.ALLOW,
                reason=(
                    f"Laya verified safe: blast_radius={evaluation.score_blast_radius:.1f}, "
                    f"reversible_prob={evaluation.noul_reversible_prob:.2f}, "
                    f"confidence={evaluation.choice_confidence:.2f}."
                ),
                evaluation=evaluation,
                latency_ms=latency_ms,
            )

        # 6. Default fallback
        fallback_decision = (
            GateDecision(self.thresholds.default)
            if self.thresholds.default in GateDecision._value2member_map_
            else GateDecision.ASK
        )
        return JevDecisionResult(
            decision=fallback_decision,
            reason=f"Default fallback policy ({self.thresholds.default}); requiring human confirmation.",
            evaluation=evaluation,
            latency_ms=latency_ms,
        )
