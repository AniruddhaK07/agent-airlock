"""
Circuit Breaker implementation for Jev Airlock.
Provides two-tier loop detection:
  Tier 1: Hash-based error and command pre-filter (in-code, zero latency).
  Tier 2: Probabilistic Noul confirmation via local Laya when surface text differs.
Halts runaway fix loops and returns structured human escalation (force_ask).
"""

from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
import time
import logging

from jev_gateway.config import CircuitBreakerConfig
from jev_gateway.circuit_breaker.hasher import (
    ErrorSignature,
    create_error_signature,
    normalize_command,
    hash_string,
    compute_similarity,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CircuitBreakerResult:
    """
    Result returned by CircuitBreaker.check_pre_tool.
    """
    is_tripped: bool
    action: str  # "force_ask", "deny", or "none"
    reason: Optional[str] = None
    repeat_count: int = 0
    noul_confidence: Optional[float] = None
    history_summary: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_tripped": self.is_tripped,
            "action": self.action,
            "reason": self.reason,
            "repeat_count": self.repeat_count,
            "noul_confidence": self.noul_confidence,
            "history_summary": self.history_summary,
        }


class CircuitBreaker:
    """
    Stateful circuit breaker partitioned per workspace root.
    Tracks recent tool failures and prevents autoregressive retry thrashing.
    """

    def __init__(
        self,
        workspace_root: str,
        config: Optional[CircuitBreakerConfig] = None,
        local_laya_client: Optional[Any] = None,
    ):
        self.workspace_root = workspace_root
        self.config = config or CircuitBreakerConfig()
        self.local_laya_client = local_laya_client
        self.history: List[ErrorSignature] = []

    def record_failure(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        error: str,
        step_idx: int = 0,
        timestamp: Optional[float] = None,
    ) -> ErrorSignature:
        """
        Records a tool execution error into the rolling history window.
        """
        ts = timestamp if timestamp is not None else time.time()
        target = self._extract_target(tool_name, tool_args)

        sig = create_error_signature(
            tool_name=tool_name,
            command_or_target=target,
            error_message=str(error),
            step_idx=step_idx,
            timestamp=ts,
        )

        self.history.append(sig)

        # Retain bounded history window (2x hash_window to allow trend analysis)
        max_retained = max(self.config.hash_window * 3, 10)
        if len(self.history) > max_retained:
            self.history = self.history[-max_retained:]

        logger.info(
            "Circuit breaker recorded failure for [%s] in '%s' (history depth: %d)",
            target, self.workspace_root, len(self.history)
        )
        return sig

    def check_pre_tool(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        step_idx: int = 0,
    ) -> CircuitBreakerResult:
        """
        Evaluates whether a candidate tool call represents a repeating failure loop.
        Applies Tier 1 (Hash Pre-Filter) followed by Tier 2 (Noul Escalation) if needed.
        """
        if not self.config.enabled or not self.history:
            return CircuitBreakerResult(is_tripped=False, action="none")

        candidate_target = self._extract_target(tool_name, tool_args)
        norm_candidate = normalize_command(candidate_target)
        candidate_hash = hash_string(norm_candidate)

        # Inspect rolling window (last N failures)
        window = self.history[-self.config.hash_window:]
        history_summary = [h.to_dict() for h in window]

        # ---------------------------------------------------------------------
        # Tier 1a: Exact Repeat Detection (In-Code Hash Match)
        # ---------------------------------------------------------------------
        exact_matches = [h for h in window if h.command_hash == candidate_hash]
        if exact_matches:
            match_count = len(exact_matches)
            # Trip if repeated in recent window
            trip_reason = (
                f"Circuit breaker tripped: Identical action '{candidate_target}' has failed "
                f"{match_count} time(s) in recent window (last {len(window)} failures). "
                f"Halting fix loop to prevent autoregressive thrashing."
            )
            logger.warning(trip_reason)
            return CircuitBreakerResult(
                is_tripped=True,
                action=self.config.break_action,
                reason=trip_reason,
                repeat_count=match_count,
                noul_confidence=1.0,
                history_summary=history_summary,
            )

        # ---------------------------------------------------------------------
        # Tier 1b: Structural Similarity Pre-Filter
        # ---------------------------------------------------------------------
        similar_failures: List[Tuple[ErrorSignature, float]] = []
        for h in window:
            sim = compute_similarity(norm_candidate, h.normalized_command)
            if sim >= self.config.similarity_threshold:
                similar_failures.append((h, sim))

        if not similar_failures:
            # Completely novel action compared to recent failures
            return CircuitBreakerResult(
                is_tripped=False,
                action="none",
                history_summary=history_summary,
            )

        # ---------------------------------------------------------------------
        # Tier 2: Escalate to Local Laya Noul for Semantic Confirmation
        # ---------------------------------------------------------------------
        most_similar_sig, best_sim = max(similar_failures, key=lambda x: x[1])

        # If Laya client is resident, invoke Noul question
        if self.local_laya_client is not None and hasattr(self.local_laya_client, "agent"):
            try:
                state = {"tool": tool_name, "command": candidate_target}
                q_noul = {
                    "is_semantic_repeat": {
                        "type": "noul",
                        "instructions": (
                            f"Is this action an escalating or repeating fix attempt of the "
                            f"previously failed command: '{most_similar_sig.command_or_target}'?"
                        )
                    }
                }
                res = self.local_laya_client.agent.predict(state, q_noul)
                ans = res.get("answers", {}).get("is_semantic_repeat", {})
                noul_prob = float(ans.get("noul", 0.0))
                noul_conf = float(ans.get("confidence", 0.0))

                logger.debug(
                    "Laya Noul repeat evaluation for '%s' vs '%s': prob=%.3f, conf=%.3f",
                    candidate_target, most_similar_sig.command_or_target, noul_prob, noul_conf
                )

                # If Noul confirms semantic repetition above threshold
                if noul_conf >= self.config.noul_confidence or noul_prob >= 0.35:
                    trip_reason = (
                        f"Circuit breaker tripped: Semantic repeat loop confirmed by Laya Noul "
                        f"(prob={noul_prob:.2f}, conf={noul_conf:.2f} >= {self.config.noul_confidence}) "
                        f"on '{candidate_target}' (similarity={best_sim:.2f} to prior failure "
                        f"'{most_similar_sig.command_or_target}'). Halting fix loop."
                    )
                    logger.warning(trip_reason)
                    return CircuitBreakerResult(
                        is_tripped=True,
                        action=self.config.break_action,
                        reason=trip_reason,
                        repeat_count=len(similar_failures),
                        noul_confidence=noul_conf,
                        history_summary=history_summary,
                    )
            except Exception as e:
                logger.warning("Local Laya Noul evaluation encountered error: %s; falling back to hash filter.", e)

        # Fallback if Laya is absent: trip if high structural similarity (>= 0.85)
        if best_sim >= 0.85:
            trip_reason = (
                f"Circuit breaker tripped: Near-identical command pattern detected "
                f"(similarity={best_sim:.2f} >= 0.85) to prior failure "
                f"'{most_similar_sig.command_or_target}'. Halting fix loop."
            )
            logger.warning(trip_reason)
            return CircuitBreakerResult(
                is_tripped=True,
                action=self.config.break_action,
                reason=trip_reason,
                repeat_count=len(similar_failures),
                noul_confidence=None,
                history_summary=history_summary,
            )

        return CircuitBreakerResult(
            is_tripped=False,
            action="none",
            history_summary=history_summary,
        )

    def reset(self) -> None:
        """Clears the failure history for this workspace."""
        self.history.clear()

    @staticmethod
    def _extract_target(tool_name: str, tool_args: Dict[str, Any]) -> str:
        """Extracts primary target string (CommandLine, AbsolutePath, or TargetFile)."""
        if tool_name == "run_command":
            return tool_args.get("CommandLine", "")
        return (
            tool_args.get("AbsolutePath")
            or tool_args.get("TargetFile")
            or tool_args.get("path")
            or str(tool_args)
        )
