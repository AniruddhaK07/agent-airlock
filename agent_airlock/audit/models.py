"""
Data models for the Jev Airlock audit logging subsystem.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import json
from typing import Dict, Any, Optional, Union

@dataclass
class AuditEvent:
    event_id: str
    timestamp: str  # ISO 8601 string, e.g. "2026-09-27T01:30:00.123456+00:00"
    conversation_id: str
    step_idx: int
    event_type: str  # "PreToolUse" | "PostToolUse"
    tool_name: str
    tool_args: Dict[str, Any]
    policy_verdict: str  # "allow" | "deny" | "ambiguous" | "none"
    matched_rule_id: Optional[str] = None
    circuit_breaker_tripped: bool = False
    jev_evaluation: Optional[Dict[str, Any]] = None
    final_decision: str = "allow"  # "allow" | "deny" | "ask" | "force_ask" | "recorded"
    reason: str = ""
    latency_ms: float = 0.0
    workspace_root: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Converts AuditEvent to standard dictionary."""
        return asdict(self)

    def to_json(self) -> str:
        """Converts AuditEvent to JSON string."""
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuditEvent":
        """Instantiates an AuditEvent from a dictionary, handling extra or missing fields gracefully."""
        if not isinstance(data, dict):
            raise TypeError(f"Expected dict, got {type(data).__name__}")

        # Required fields validation
        event_id = data.get("event_id")
        if not event_id:
            raise ValueError("AuditEvent missing required field 'event_id'")

        timestamp = data.get("timestamp")
        if not timestamp:
            timestamp = datetime.now(timezone.utc).isoformat()

        return cls(
            event_id=str(event_id),
            timestamp=str(timestamp),
            conversation_id=str(data.get("conversation_id", "")),
            step_idx=int(data.get("step_idx", 0)),
            event_type=str(data.get("event_type", "PreToolUse")),
            tool_name=str(data.get("tool_name", "")),
            tool_args=dict(data.get("tool_args", {})),
            policy_verdict=str(data.get("policy_verdict", "none")),
            matched_rule_id=data.get("matched_rule_id"),
            circuit_breaker_tripped=bool(data.get("circuit_breaker_tripped", False)),
            jev_evaluation=data.get("jev_evaluation"),
            final_decision=str(data.get("final_decision", "allow")),
            reason=str(data.get("reason", "")),
            latency_ms=float(data.get("latency_ms", 0.0)),
            workspace_root=data.get("workspace_root"),
            metadata=dict(data.get("metadata", {})),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "AuditEvent":
        """Instantiates an AuditEvent from a JSON string."""
        return cls.from_dict(json.loads(json_str))
