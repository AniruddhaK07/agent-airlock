"""
Data models and result definitions for L0 Grounding subsystem.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class GroundingCheckType(str, Enum):
    C1_BINARY = "C1"
    C2_FILES = "C2"
    C3_SCRIPTS = "C3"
    C4_INSTALLS = "C4"


@dataclass
class GroundingResult:
    """
    Result returned by the L0 Grounding subsystem.
    status: 'pass' | 'fail'
    mode: 'shadow' | 'enforce'
    """
    status: str = "pass"
    check_id: Optional[str] = None
    hint: str = ""
    target: str = ""
    latency_ms: float = 0.0
    mode: str = "shadow"

    @property
    def is_failed(self) -> bool:
        return self.status == "fail"

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "check_id": self.check_id,
            "hint": self.hint,
            "target": self.target,
            "latency_ms": self.latency_ms,
            "mode": self.mode,
        }
