"""
Data models and typed structures for Jev Integration Layer.
"""

from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, Optional


class GateDecision(str, Enum):
    """
    Possible gating decisions returned by the safety layer.
    """
    ALLOW = "allow"
    DENY = "deny"
    ASK = "ask"
    FORCE_ASK = "force_ask"


class ChoiceRoute(str, Enum):
    """
    Calibrated routing choices produced by Jev Choice evaluation.
    """
    DETERMINISTIC_SAFE = "deterministic-safe"
    NEEDS_HUMAN = "needs-human"
    NEEDS_REASONING_MODEL = "needs-reasoning-model"


@dataclass(frozen=True)
class JevEvaluation:
    """
    Standardized result of a Jev evaluation combining Score, Noul, and Choice.
    """
    score_blast_radius: float       # Value from Score rubric (1.0 to 5.0)
    score_confidence: float         # Confidence for Score (0.0 to 1.0)
    noul_reversible_prob: float     # Probability action is reversible (0.0 to 1.0)
    choice_route: str               # "deterministic-safe", "needs-human", "needs-reasoning-model"
    choice_confidence: float        # Confidence for Choice (0.0 to 1.0)
    raw_payload: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert evaluation to serializable dictionary."""
        return {
            "score_blast_radius": self.score_blast_radius,
            "score_confidence": self.score_confidence,
            "noul_reversible_prob": self.noul_reversible_prob,
            "choice_route": self.choice_route,
            "choice_confidence": self.choice_confidence,
            "raw_payload": self.raw_payload,
        }


@dataclass(frozen=True)
class JevDecisionResult:
    """
    Final decision produced by JevEvaluator after applying confidence thresholds.
    """
    decision: GateDecision
    reason: str
    evaluation: Optional[JevEvaluation] = None
    latency_ms: float = 0.0
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert decision result to dictionary."""
        return {
            "decision": self.decision.value if isinstance(self.decision, GateDecision) else str(self.decision),
            "reason": self.reason,
            "evaluation": self.evaluation.to_dict() if self.evaluation else None,
            "latency_ms": self.latency_ms,
            "error": self.error,
        }
