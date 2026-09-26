"""
IPC request router and dispatcher for Jev Gateway daemon.
Processes ndjson requests, validates authentication, dispatches PreToolUse
through HardPolicyEngine, partitions in-memory state by workspace root,
and formats structured responses.
"""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime, timezone
import json
import time
import uuid
import logging

from jev_gateway.policy.engine import HardPolicyEngine
from jev_gateway.policy.models import PolicyVerdict, PolicyResult

logger = logging.getLogger(__name__)

@dataclass
class WorkspaceState:
    """
    Isolated in-memory state partitioned per workspace root.
    Holds circuit-breaker failure history, hash windows, and audit buffers.
    """
    workspace_root: str
    failure_history: List[Any] = field(default_factory=list)
    audit_buffer: List[Dict[str, Any]] = field(default_factory=list)
    circuit_breaker: Optional[Any] = None
    created_at: float = field(default_factory=time.time)

class IPCRouter:
    """
    Coordinates incoming IPC messages, route validation, workspace state isolation,
    and policy dispatch.
    """

    def __init__(
        self,
        policy_engine: Optional[HardPolicyEngine] = None,
        auth_token: Optional[str] = None,
        jev_client: Optional[Any] = None,
        jev_evaluator: Optional[Any] = None,
        circuit_breaker_config: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
    ):
        self.policy_engine = policy_engine or HardPolicyEngine()
        self.auth_token = auth_token
        self.jev_client = jev_client
        self.jev_evaluator = jev_evaluator
        self.circuit_breaker_config = circuit_breaker_config
        self.audit_logger = audit_logger
        self.start_time = time.time()
        self.workspaces: Dict[str, WorkspaceState] = {}

    def get_workspace_state(self, workspace_root: str) -> WorkspaceState:
        """
        Retrieves or initializes the isolated in-memory state for a given workspace root.
        Partitioned by normalized string path. Raises ValueError if workspace_root is empty or unresolved.
        """
        if not workspace_root or not str(workspace_root).strip():
            raise ValueError("workspace_root is required and cannot be empty.")

        try:
            norm_key = str(Path(workspace_root).resolve())
        except Exception:
            norm_key = str(workspace_root).strip()

        if norm_key not in self.workspaces:
            cb = None
            try:
                from jev_gateway.circuit_breaker.breaker import CircuitBreaker
                cb = CircuitBreaker(
                    workspace_root=norm_key,
                    config=self.circuit_breaker_config,
                    local_laya_client=self.jev_client,
                )
            except Exception as e:
                logger.warning("Could not initialize CircuitBreaker for %s: %s", norm_key, e)

            self.workspaces[norm_key] = WorkspaceState(
                workspace_root=norm_key,
                circuit_breaker=cb,
            )
        return self.workspaces[norm_key]

    def _extract_workspace_root(self, payload: Dict[str, Any]) -> Optional[str]:
        """
        Extracts workspace root from payload without defaulting.
        Returns None if workspace context cannot be resolved.
        """
        ws = payload.get("workspace_root")
        if ws and str(ws).strip():
            return str(ws).strip()

        ws_paths = payload.get("workspacePaths")
        if isinstance(ws_paths, list):
            for p in ws_paths:
                if p and str(p).strip():
                    return str(p).strip()

        return None

    def handle_raw_message(self, raw_line: str) -> str:
        """
        Receives a single newline-delimited JSON line, processes it,
        and returns a single newline-delimited JSON response line.
        """
        raw_line = raw_line.strip()
        if not raw_line:
            return json.dumps({
                "version": "1.0",
                "status": "error",
                "decision": "ask",
                "reason": "Empty request line received; failing closed."
            }) + "\n"

        try:
            req_data = json.loads(raw_line)
        except Exception as e:
            return json.dumps({
                "version": "1.0",
                "status": "error",
                "decision": "ask",
                "reason": f"Malformed JSON: {e}; failing closed."
            }) + "\n"

        response = self.dispatch(req_data)
        return json.dumps(response) + "\n"

    def dispatch(self, req: Dict[str, Any]) -> Dict[str, Any]:
        """
        Dispatches typed request payload to specific event handler.
        """
        version = req.get("version", "1.0")

        # 1. Bearer Token Authentication (when auth_token is configured)
        if self.auth_token:
            client_token = req.get("auth_token")
            if not client_token or client_token != self.auth_token:
                return {
                    "version": version,
                    "status": "error",
                    "decision": "deny",
                    "reason": "Unauthorized: Invalid or missing bearer authentication token.",
                    "auditId": self._generate_audit_id(),
                }

        event = req.get("event")
        payload = req.get("payload", {})

        if event in ("PreToolUse", "PostToolUse"):
            ws_root = self._extract_workspace_root(payload)
            if not ws_root:
                audit_id = self._generate_audit_id()
                res = {
                    "version": version,
                    "status": "fail_closed",
                    "decision": "force_ask",
                    "reason": "workspace context unresolved",
                    "ruleId": None,
                    "permissionOverrides": [],
                    "overwrite": None,
                    "auditId": audit_id,
                    "workspaceRoot": None,
                }
                if self.audit_logger:
                    try:
                        from jev_gateway.audit.models import AuditEvent
                        tool_call = payload.get("toolCall", {})
                        ev = AuditEvent(
                            event_id=audit_id,
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            conversation_id=str(payload.get("conversationId", "")),
                            step_idx=int(payload.get("stepIdx", 0)),
                            event_type=str(event),
                            tool_name=str(tool_call.get("name", "")),
                            tool_args=dict(tool_call.get("args", {})),
                            policy_verdict="none",
                            final_decision="force_ask",
                            reason="workspace context unresolved",
                            latency_ms=0.0,
                            workspace_root=None,
                        )
                        self.audit_logger.log(ev)
                    except Exception as e:
                        logger.warning("Failed to log unresolved workspace audit event: %s", e)
                return res

            ws_state = self.get_workspace_state(ws_root)
            if event == "PreToolUse":
                return self._handle_pre_tool_use(payload, ws_state, version)
            else:
                return self._handle_post_tool_use(payload, ws_state, version)
        elif event == "Ping":
            return self._handle_ping(version)
        else:
            return {
                "version": version,
                "status": "error",
                "decision": "ask",
                "reason": f"Unknown IPC event '{event}'; failing closed.",
                "auditId": self._generate_audit_id(),
            }

    def _handle_pre_tool_use(
        self,
        payload: Dict[str, Any],
        ws_state: WorkspaceState,
        version: str,
    ) -> Dict[str, Any]:
        t_start = time.time()
        tool_call = payload.get("toolCall", {})
        tool_name = tool_call.get("name", "")
        tool_args = tool_call.get("args", {})
        audit_id = self._generate_audit_id()

        # Deterministic evaluation via HardPolicyEngine
        policy_result: PolicyResult = self.policy_engine.evaluate(tool_name, tool_args)

        if policy_result.verdict == PolicyVerdict.DENY:
            latency_ms = (time.time() - t_start) * 1000.0
            res = {
                "version": version,
                "status": "success",
                "decision": "deny",
                "reason": policy_result.reason or "Blocked by hard policy deny rule.",
                "ruleId": policy_result.rule_id,
                "permissionOverrides": [],
                "overwrite": None,
                "auditId": audit_id,
                "workspaceRoot": ws_state.workspace_root,
            }
            self._log_pre_tool_event(payload, ws_state, policy_result, res, latency_ms=latency_ms)
            return res
        elif policy_result.verdict == PolicyVerdict.ALLOW:
            latency_ms = (time.time() - t_start) * 1000.0
            res = {
                "version": version,
                "status": "success",
                "decision": "allow",
                "reason": policy_result.reason or "Permitted by hard policy allow rule.",
                "ruleId": policy_result.rule_id,
                "permissionOverrides": [],
                "overwrite": None,
                "auditId": audit_id,
                "workspaceRoot": ws_state.workspace_root,
            }
            self._log_pre_tool_event(payload, ws_state, policy_result, res, latency_ms=latency_ms)
            return res
        elif policy_result.rule_id == "unparseable-command-syntax":
            latency_ms = (time.time() - t_start) * 1000.0
            res = {
                "version": version,
                "status": "fail_closed",
                "decision": "ask",
                "reason": policy_result.reason,
                "ruleId": policy_result.rule_id,
                "permissionOverrides": [],
                "overwrite": None,
                "auditId": audit_id,
                "workspaceRoot": ws_state.workspace_root,
            }
            self._log_pre_tool_event(payload, ws_state, policy_result, res, latency_ms=latency_ms)
            return res
        else:
            # PolicyVerdict.AMBIGUOUS:
            # 1. Circuit Breaker: check for repeating failure loops before probabilistic gating
            if ws_state.circuit_breaker:
                cb_res = ws_state.circuit_breaker.check_pre_tool(
                    tool_name=tool_name,
                    tool_args=tool_args,
                    step_idx=payload.get("stepIdx", 0),
                )
                if cb_res.is_tripped:
                    latency_ms = (time.time() - t_start) * 1000.0
                    res = {
                        "version": version,
                        "status": "success",
                        "decision": cb_res.action,
                        "reason": cb_res.reason,
                        "ruleId": None,
                        "permissionOverrides": [],
                        "overwrite": None,
                        "auditId": audit_id,
                        "workspaceRoot": ws_state.workspace_root,
                        "circuitBreakerTripped": True,
                        "circuitBreakerSummary": cb_res.to_dict(),
                    }
                    self._log_pre_tool_event(
                        payload, ws_state, policy_result, res,
                        circuit_breaker_tripped=True,
                        latency_ms=latency_ms,
                    )
                    return res

            # 2. Route through Jev Integration Layer if configured
            if self.jev_client and self.jev_evaluator:
                t0 = time.time()
                try:
                    context = {
                        "workspace_root": ws_state.workspace_root,
                        "stepIdx": payload.get("stepIdx"),
                        "conversationId": payload.get("conversationId"),
                    }
                    evaluation = self.jev_client.evaluate_ambiguous_tool(
                        tool_name=tool_name,
                        tool_args=tool_args,
                        context=context,
                    )
                    latency = (time.time() - t0) * 1000.0
                    jev_decision = self.jev_evaluator.decide(
                        evaluation=evaluation,
                        latency_ms=latency,
                    )
                    dec_val = (
                        jev_decision.decision.value
                        if hasattr(jev_decision.decision, "value")
                        else str(jev_decision.decision)
                    )
                    total_latency = (time.time() - t_start) * 1000.0
                    res = {
                        "version": version,
                        "status": "success",
                        "decision": dec_val,
                        "reason": jev_decision.reason,
                        "ruleId": None,
                        "permissionOverrides": [],
                        "overwrite": None,
                        "auditId": audit_id,
                        "workspaceRoot": ws_state.workspace_root,
                        "jevEvaluation": evaluation.to_dict() if hasattr(evaluation, "to_dict") else None,
                    }
                    self._log_pre_tool_event(
                        payload, ws_state, policy_result, res,
                        circuit_breaker_tripped=False,
                        jev_evaluation=res["jevEvaluation"],
                        latency_ms=total_latency,
                    )
                    return res
                except Exception as e:
                    logger.warning("Jev evaluation error, failing closed to ask: %s", e)
                    latency = (time.time() - t0) * 1000.0
                    jev_decision = self.jev_evaluator.decide(
                        evaluation=None,
                        error=e,
                        latency_ms=latency,
                    )
                    dec_val = (
                        jev_decision.decision.value
                        if hasattr(jev_decision.decision, "value")
                        else str(jev_decision.decision)
                    )
                    total_latency = (time.time() - t_start) * 1000.0
                    res = {
                        "version": version,
                        "status": "fail_closed",
                        "decision": dec_val,
                        "reason": f"Jev evaluation failure ({e}); failing closed to human confirmation.",
                        "ruleId": None,
                        "permissionOverrides": [],
                        "overwrite": None,
                        "auditId": audit_id,
                        "workspaceRoot": ws_state.workspace_root,
                    }
                    self._log_pre_tool_event(
                        payload, ws_state, policy_result, res,
                        circuit_breaker_tripped=False,
                        latency_ms=total_latency,
                    )
                    return res
            else:
                # No Jev client configured -> default fail-closed to "ask"
                latency_ms = (time.time() - t_start) * 1000.0
                res = {
                    "version": version,
                    "status": "success",
                    "decision": "ask",
                    "reason": policy_result.reason or "Ambiguous action requires user confirmation.",
                    "ruleId": None,
                    "permissionOverrides": [],
                    "overwrite": None,
                    "auditId": audit_id,
                    "workspaceRoot": ws_state.workspace_root,
                }
                self._log_pre_tool_event(payload, ws_state, policy_result, res, latency_ms=latency_ms)
                return res

    def _handle_post_tool_use(
        self,
        payload: Dict[str, Any],
        ws_state: WorkspaceState,
        version: str,
    ) -> Dict[str, Any]:
        audit_id = self._generate_audit_id()
        # Record into partitioned workspace buffer
        ws_state.audit_buffer.append({
            "audit_id": audit_id,
            "timestamp": time.time(),
            "payload": payload,
        })

        # Check for tool execution failure to record in circuit breaker
        tool_call = payload.get("toolCall", {})
        tool_result = payload.get("toolResult", {})
        error_msg = None

        if payload.get("status") == "error":
            error_msg = payload.get("error") or "Execution failed with status error"
        elif isinstance(tool_result, dict):
            exit_code = tool_result.get("exitCode")
            if exit_code not in (0, None):
                error_msg = (
                    tool_result.get("stderr")
                    or tool_result.get("error")
                    or f"Command failed with exit code {exit_code}"
                )
            elif tool_result.get("error"):
                error_msg = str(tool_result.get("error"))
        elif payload.get("error"):
            error_msg = str(payload.get("error"))

        if error_msg and ws_state.circuit_breaker:
            step_idx = payload.get("stepIdx", 0)
            ws_state.circuit_breaker.record_failure(
                tool_name=tool_call.get("name", "run_command"),
                tool_args=tool_call.get("args", {}),
                error=error_msg,
                step_idx=step_idx,
            )

        res = {
            "version": version,
            "status": "success",
            "auditId": audit_id,
            "workspaceRoot": ws_state.workspace_root,
        }
        self._log_post_tool_event(payload, ws_state, audit_id, error_msg)
        return res

    def _log_pre_tool_event(
        self,
        payload: Dict[str, Any],
        ws_state: WorkspaceState,
        policy_result: PolicyResult,
        res: Dict[str, Any],
        circuit_breaker_tripped: bool = False,
        jev_evaluation: Optional[Dict[str, Any]] = None,
        latency_ms: float = 0.0,
    ) -> None:
        if not self.audit_logger:
            return

        try:
            from jev_gateway.audit.models import AuditEvent
            tool_call = payload.get("toolCall", {})
            event = AuditEvent(
                event_id=res.get("auditId") or self._generate_audit_id(),
                timestamp=datetime.now(timezone.utc).isoformat(),
                conversation_id=str(payload.get("conversationId", "")),
                step_idx=int(payload.get("stepIdx", 0)),
                event_type="PreToolUse",
                tool_name=str(tool_call.get("name", "")),
                tool_args=dict(tool_call.get("args", {})),
                policy_verdict=policy_result.verdict.value,
                matched_rule_id=policy_result.rule_id,
                circuit_breaker_tripped=circuit_breaker_tripped,
                jev_evaluation=jev_evaluation,
                final_decision=str(res.get("decision", "ask")),
                reason=str(res.get("reason", "")),
                latency_ms=round(float(latency_ms), 2),
                workspace_root=ws_state.workspace_root,
            )
            self.audit_logger.log(event)
        except Exception as e:
            logger.warning("Failed to log PreToolUse audit event: %s", e)

    def _log_post_tool_event(
        self,
        payload: Dict[str, Any],
        ws_state: WorkspaceState,
        audit_id: str,
        error_msg: Optional[str] = None,
    ) -> None:
        if not self.audit_logger:
            return

        try:
            from jev_gateway.audit.models import AuditEvent
            tool_call = payload.get("toolCall", {})
            event = AuditEvent(
                event_id=audit_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                conversation_id=str(payload.get("conversationId", "")),
                step_idx=int(payload.get("stepIdx", 0)),
                event_type="PostToolUse",
                tool_name=str(tool_call.get("name", "")),
                tool_args=dict(tool_call.get("args", {})),
                policy_verdict="none",
                matched_rule_id=None,
                circuit_breaker_tripped=False,
                jev_evaluation=None,
                final_decision="recorded",
                reason=str(error_msg or "Execution recorded successfully"),
                latency_ms=0.0,
                workspace_root=ws_state.workspace_root,
            )
            self.audit_logger.log(event)
        except Exception as e:
            logger.warning("Failed to log PostToolUse audit event: %s", e)

    def _handle_ping(self, version: str) -> Dict[str, Any]:
        return {
            "version": version,
            "status": "success",
            "uptime_seconds": round(time.time() - self.start_time, 3),
            "active_workspaces": list(self.workspaces.keys()),
        }

    def _generate_audit_id(self) -> str:
        return f"evt_{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}"
