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

    # Phase 1.1 Extended Fields
    decision_source: Optional[str] = None  # "l0" | "l1" | "l2" | "cache" | "l2_5" | "l3" | "l3_5" | "human" | "fallback"
    cwd: Optional[str] = None
    policy_hash: Optional[str] = None
    layer_latencies_ms: Optional[Dict[str, float]] = None
    human_approved: Optional[str] = None  # "inferred" | None
    latency_class: Optional[str] = None   # "host_auto" | "human_prompt" | "unapproved"
    cache_key_hash: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Converts AuditEvent to standard dictionary with camelCase parity."""
        d = asdict(self)
        # Ensure Section 8 camelCase field aliases
        d["decisionSource"] = self.decision_source
        d["policyHash"] = self.policy_hash
        d["layerLatenciesMs"] = self.layer_latencies_ms
        d["humanApproved"] = self.human_approved
        d["latencyClass"] = self.latency_class
        d["cacheKeyHash"] = self.cache_key_hash
        return d

    def to_json(self) -> str:
        """Converts AuditEvent to JSON string."""
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuditEvent":
        """Instantiates an AuditEvent from a dictionary, handling extra or missing fields gracefully."""
        if not isinstance(data, dict):
            raise TypeError(f"Expected dict, got {type(data).__name__}")

        # Required fields validation
        event_id = data.get("event_id") or data.get("eventId")
        if not event_id:
            raise ValueError("AuditEvent missing required field 'event_id'")

        timestamp = data.get("timestamp")
        if not timestamp:
            timestamp = datetime.now(timezone.utc).isoformat()

        return cls(
            event_id=str(event_id),
            timestamp=str(timestamp),
            conversation_id=str(data.get("conversation_id", "") or data.get("conversationId", "")),
            step_idx=int(data.get("step_idx", 0) if data.get("step_idx") is not None else data.get("stepIdx", 0)),
            event_type=str(data.get("event_type", "") or data.get("eventType", "PreToolUse")),
            tool_name=str(data.get("tool_name", "") or data.get("toolName", "")),
            tool_args=dict(data.get("tool_args", {}) or data.get("toolArgs", {})),
            policy_verdict=str(data.get("policy_verdict", "") or data.get("policyVerdict", "none")),
            matched_rule_id=data.get("matched_rule_id") or data.get("matchedRuleId"),
            circuit_breaker_tripped=bool(data.get("circuit_breaker_tripped", False) if data.get("circuit_breaker_tripped") is not None else data.get("circuitBreakerTripped", False)),
            jev_evaluation=data.get("jev_evaluation") or data.get("jevEvaluation"),
            final_decision=str(data.get("final_decision", "") or data.get("finalDecision", "allow")),
            reason=str(data.get("reason", "")),
            latency_ms=float(data.get("latency_ms", 0.0) if data.get("latency_ms") is not None else data.get("latencyMs", 0.0)),
            workspace_root=data.get("workspace_root") or data.get("workspaceRoot"),
            metadata=dict(data.get("metadata", {})),
            decision_source=data.get("decision_source") or data.get("decisionSource"),
            cwd=data.get("cwd") or data.get("Cwd"),
            policy_hash=data.get("policy_hash") or data.get("policyHash"),
            layer_latencies_ms=data.get("layer_latencies_ms") or data.get("layerLatenciesMs"),
            human_approved=data.get("human_approved") or data.get("humanApproved"),
            latency_class=data.get("latency_class") or data.get("latencyClass"),
            cache_key_hash=data.get("cache_key_hash") or data.get("cacheKeyHash"),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "AuditEvent":
        """Instantiates an AuditEvent from a JSON string."""
        return cls.from_dict(json.loads(json_str))
