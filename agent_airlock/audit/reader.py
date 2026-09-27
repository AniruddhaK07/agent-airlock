"""
Verification reader and query engine for Jev Airlock audit logs.
"""

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
from typing import Dict, Any, List, Optional, Union

from agent_airlock.audit.models import AuditEvent

logger = logging.getLogger(__name__)

class AuditReader:
    """
    Reader and verification engine for audit.jsonl log files.
    Supports querying by conversation, workspace, decision, and time range,
    as well as verifying file format integrity and aggregating audit statistics.
    """

    def __init__(self, log_path: Union[str, Path] = "~/.gemini/antigravity-cli/audit.jsonl"):
        raw_path = Path(os.path.expanduser(str(log_path)))
        self.log_path = raw_path.resolve()

    def exists(self) -> bool:
        """Returns True if the audit log file exists on disk."""
        return self.log_path.exists()

    def read_all(self, skip_corrupted: bool = True) -> List[AuditEvent]:
        """
        Reads and parses all audit events in the log file.
        If skip_corrupted is True, corrupt JSON lines are ignored; otherwise raises ValueError.
        """
        if not self.exists():
            return []

        events: List[AuditEvent] = []
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line_idx, line in enumerate(f, start=1):
                raw = line.strip()
                if not raw:
                    continue
                try:
                    ev = AuditEvent.from_json(raw)
                    events.append(ev)
                except Exception as e:
                    if not skip_corrupted:
                        raise ValueError(f"Corrupted audit line {line_idx}: {e}") from e
                    logger.warning("Skipping corrupted audit line %d: %s", line_idx, e)

        return events

    def query(
        self,
        conversation_id: Optional[str] = None,
        workspace_root: Optional[str] = None,
        event_type: Optional[str] = None,
        final_decision: Optional[str] = None,
        policy_verdict: Optional[str] = None,
        tool_name: Optional[str] = None,
        circuit_breaker_tripped: Optional[bool] = None,
        rule_id: Optional[str] = None,
        start_time: Optional[Union[datetime, str]] = None,
        end_time: Optional[Union[datetime, str]] = None,
        limit: Optional[int] = None,
    ) -> List[AuditEvent]:
        """
        Filters and retrieves matching audit events based on specified criteria.
        """
        # Parse start_time and end_time if provided as str
        start_dt = None
        if start_time:
            if isinstance(start_time, str):
                start_dt = datetime.fromisoformat(start_time)
            else:
                start_dt = start_time
            if start_dt.tzinfo is None:
                start_dt = start_dt.replace(tzinfo=timezone.utc)

        end_dt = None
        if end_time:
            if isinstance(end_time, str):
                end_dt = datetime.fromisoformat(end_time)
            else:
                end_dt = end_time
            if end_dt.tzinfo is None:
                end_dt = end_dt.replace(tzinfo=timezone.utc)

        results: List[AuditEvent] = []
        all_events = self.read_all(skip_corrupted=True)

        for ev in all_events:
            if conversation_id and ev.conversation_id != conversation_id:
                continue
            if workspace_root:
                # Compare normalized paths if both can be resolved
                try:
                    if ev.workspace_root and str(Path(ev.workspace_root).resolve()) != str(Path(workspace_root).resolve()):
                        continue
                except Exception:
                    if ev.workspace_root != workspace_root:
                        continue
            if event_type and ev.event_type.lower() != event_type.lower():
                continue
            if final_decision and ev.final_decision.lower() != final_decision.lower():
                continue
            if policy_verdict and ev.policy_verdict.lower() != policy_verdict.lower():
                continue
            if tool_name and ev.tool_name != tool_name:
                continue
            if circuit_breaker_tripped is not None and ev.circuit_breaker_tripped != circuit_breaker_tripped:
                continue
            if rule_id and ev.matched_rule_id != rule_id:
                continue

            # Time range checks
            if start_dt or end_dt:
                try:
                    ev_dt = datetime.fromisoformat(ev.timestamp)
                    if ev_dt.tzinfo is None:
                        ev_dt = ev_dt.replace(tzinfo=timezone.utc)
                    if start_dt and ev_dt < start_dt:
                        continue
                    if end_dt and ev_dt > end_dt:
                        continue
                except Exception:
                    pass

            results.append(ev)
            if limit is not None and len(results) >= limit:
                break

        return results

    def verify_integrity(self) -> Dict[str, Any]:
        """
        Validates the syntactic and structural integrity of the audit log file.
        Returns a verification summary detailing valid events, corrupted lines, and timestamps.
        """
        if not self.exists():
            return {
                "is_valid": True,
                "total_lines": 0,
                "valid_events": 0,
                "corrupted_lines": 0,
                "corrupted_line_numbers": [],
                "first_timestamp": None,
                "last_timestamp": None,
            }

        total_lines = 0
        valid_events = 0
        corrupted_lines: List[int] = []
        first_ts = None
        last_ts = None

        with open(self.log_path, "r", encoding="utf-8") as f:
            for line_idx, line in enumerate(f, start=1):
                raw = line.strip()
                if not raw:
                    continue
                total_lines += 1
                try:
                    ev = AuditEvent.from_json(raw)
                    valid_events += 1
                    if first_ts is None:
                        first_ts = ev.timestamp
                    last_ts = ev.timestamp
                except Exception:
                    corrupted_lines.append(line_idx)

        return {
            "is_valid": len(corrupted_lines) == 0,
            "total_lines": total_lines,
            "valid_events": valid_events,
            "corrupted_lines": len(corrupted_lines),
            "corrupted_line_numbers": corrupted_lines,
            "first_timestamp": first_ts,
            "last_timestamp": last_ts,
        }

    def get_statistics(self) -> Dict[str, Any]:
        """
        Computes aggregate metrics across all valid audit events in the log.
        """
        events = self.read_all(skip_corrupted=True)
        if not events:
            return {
                "total_events": 0,
                "decisions": {},
                "policy_verdicts": {},
                "circuit_breaker_tripped_count": 0,
                "jev_evaluated_count": 0,
                "avg_latency_ms": 0.0,
                "tool_distribution": {},
                "unique_conversations": 0,
                "unique_workspaces": 0,
            }

        decisions: Dict[str, int] = {}
        policy_verdicts: Dict[str, int] = {}
        tool_dist: Dict[str, int] = {}
        cb_trips = 0
        jev_evals = 0
        total_latency = 0.0
        conversations = set()
        workspaces = set()

        for ev in events:
            decisions[ev.final_decision] = decisions.get(ev.final_decision, 0) + 1
            policy_verdicts[ev.policy_verdict] = policy_verdicts.get(ev.policy_verdict, 0) + 1
            tool_dist[ev.tool_name] = tool_dist.get(ev.tool_name, 0) + 1
            if ev.circuit_breaker_tripped:
                cb_trips += 1
            if ev.jev_evaluation is not None:
                jev_evals += 1
            total_latency += ev.latency_ms
            if ev.conversation_id:
                conversations.add(ev.conversation_id)
            if ev.workspace_root:
                workspaces.add(ev.workspace_root)

        return {
            "total_events": len(events),
            "decisions": decisions,
            "policy_verdicts": policy_verdicts,
            "circuit_breaker_tripped_count": cb_trips,
            "jev_evaluated_count": jev_evals,
            "avg_latency_ms": round(total_latency / max(len(events), 1), 2),
            "tool_distribution": tool_dist,
            "unique_conversations": len(conversations),
            "unique_workspaces": len(workspaces),
        }
