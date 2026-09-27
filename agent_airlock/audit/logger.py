"""
Immutable append-only JSONL logger for Jev Airlock gateway events.
"""

from datetime import datetime, timezone, timedelta
import json
import logging
import os
from pathlib import Path
import tempfile
import threading
from typing import Dict, Any, Optional, Union

from agent_airlock.audit.models import AuditEvent

logger = logging.getLogger(__name__)

class AuditLogger:
    """
    Thread-safe, append-only JSONL audit logger.
    Guarantees atomic line writes and immediate flushing to disk.
    """

    def __init__(
        self,
        log_path: Union[str, Path] = "~/.gemini/antigravity-cli/audit.jsonl",
        flush_immediate: bool = True,
        retention_days: int = 30,
    ):
        raw_path = Path(os.path.expanduser(str(log_path)))
        self.log_path = raw_path.resolve()
        self.flush_immediate = flush_immediate
        self.retention_days = retention_days
        self._lock = threading.Lock()

        # Ensure parent directory exists
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.error("Failed to create audit log directory %s: %s", self.log_path.parent, e)

    def log(self, event: Union[AuditEvent, Dict[str, Any]]) -> str:
        """
        Thread-safe append of a structured audit event to audit.jsonl.
        Returns the event_id of the logged record.
        Never raises exceptions to caller (fails open for logging errors, preserving safety gating).
        """
        try:
            if isinstance(event, AuditEvent):
                event_obj = event
                line = event.to_json()
                event_id = event.event_id
            elif isinstance(event, dict):
                event_obj = AuditEvent.from_dict(event)
                line = event_obj.to_json()
                event_id = event_obj.event_id
            else:
                raise TypeError(f"Expected AuditEvent or dict, got {type(event).__name__}")

            with self._lock:
                # Ensure directory exists in case it was deleted
                self.log_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
                    if self.flush_immediate:
                        f.flush()

            return event_id
        except Exception as e:
            logger.error("AuditLogger error writing event: %s", e)
            # Fallback event_id if event has one
            if isinstance(event, AuditEvent):
                return event.event_id
            elif isinstance(event, dict) and "event_id" in event:
                return str(event["event_id"])
            return "evt_unlogged_error"

    def cleanup_old_events(self, max_days: Optional[int] = None) -> int:
        """
        Prunes audit entries older than max_days (defaults to self.retention_days).
        Performs an atomic rewrite of the JSONL file.
        Returns the count of pruned events.
        """
        days = max_days if max_days is not None else self.retention_days
        if days <= 0 or not self.log_path.exists():
            return 0

        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        pruned_count = 0

        with self._lock:
            temp_file = self.log_path.with_suffix(".tmp")
            try:
                with open(self.log_path, "r", encoding="utf-8") as in_f, \
                     open(temp_file, "w", encoding="utf-8") as out_f:
                    for line in in_f:
                        raw = line.strip()
                        if not raw:
                            continue
                        try:
                            record = json.loads(raw)
                            ts_str = record.get("timestamp")
                            if ts_str:
                                # Parse ISO timestamp
                                ts = datetime.fromisoformat(ts_str)
                                if ts.tzinfo is None:
                                    ts = ts.replace(tzinfo=timezone.utc)
                                if ts < cutoff:
                                    pruned_count += 1
                                    continue
                            out_f.write(raw + "\n")
                        except Exception:
                            # Keep line if cannot parse timestamp to avoid data loss
                            out_f.write(raw + "\n")
                
                # Atomic replace
                os.replace(temp_file, self.log_path)
            except Exception as e:
                logger.error("Failed during audit log cleanup: %s", e)
                if temp_file.exists():
                    try:
                        temp_file.unlink()
                    except Exception:
                        pass
                return 0

        return pruned_count

    def clear(self) -> None:
        """Empties the log file. Useful for testing and environment resets."""
        with self._lock:
            if self.log_path.exists():
                with open(self.log_path, "w", encoding="utf-8") as f:
                    pass
