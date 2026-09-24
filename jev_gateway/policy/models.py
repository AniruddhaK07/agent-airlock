from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Pattern
import re

class PolicyVerdict(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    AMBIGUOUS = "ambiguous"

@dataclass
class PolicyRule:
    id: str
    description: str
    verdict: PolicyVerdict
    tools: List[str]  # e.g. ["run_command"], ["view_file"], ["*"]
    field: str        # e.g. "CommandLine", "AbsolutePath", "TargetFile", "ANY"
    pattern: str      # regex string
    flags: int = re.IGNORECASE
    _compiled: Optional[Pattern] = field(default=None, init=False, repr=False)

    def __post_init__(self):
        if self._compiled is None and self.pattern:
            self._compiled = re.compile(self.pattern, self.flags)

    @property
    def compiled(self) -> Pattern:
        if self._compiled is None:
            self._compiled = re.compile(self.pattern, self.flags)
        return self._compiled

@dataclass
class PolicyResult:
    verdict: PolicyVerdict
    rule_id: Optional[str] = None
    reason: Optional[str] = None
    matched_pattern: Optional[str] = None
    is_chained: bool = False
