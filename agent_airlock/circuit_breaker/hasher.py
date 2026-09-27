"""
Error signature hasher and normalizer for the Circuit Breaker.
Normalizes ephemeral variations (timestamps, PIDs, memory addresses, line numbers)
and produces reproducible hash digests and similarity metrics.
"""

from typing import Tuple
from dataclasses import dataclass
import hashlib
import re
import difflib


@dataclass(frozen=True)
class ErrorSignature:
    """
    Structured signature of a tool execution failure.
    """
    tool_name: str
    command_or_target: str
    error_message: str
    normalized_command: str
    normalized_error: str
    command_hash: str
    error_hash: str
    step_idx: int
    timestamp: float

    def to_dict(self):
        return {
            "tool_name": self.tool_name,
            "command_or_target": self.command_or_target,
            "error_message": self.error_message[:200],
            "step_idx": self.step_idx,
            "timestamp": self.timestamp,
        }


def normalize_error(raw_error: str) -> str:
    """
    Strips ephemeral tokens such as ISO timestamps, hex memory pointers,
    process IDs, ephemeral ports, and file line/column positions.
    """
    if not raw_error:
        return ""

    text = str(raw_error).strip()

    # 1. Normalize ISO / standard timestamps
    text = re.sub(r'\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b', '<TIMESTAMP>', text)
    text = re.sub(r'\b\d{2}:\d{2}:\d{2}(?:\.\d+)?\b', '<TIME>', text)

    # 2. Normalize memory addresses (e.g. 0x7fff5fbff820, 0x000001)
    text = re.sub(r'\b0x[0-9a-fA-F]{4,16}\b', '<ADDR>', text)

    # 3. Normalize PIDs (e.g. PID 12345, pid: 4892)
    text = re.sub(r'\b(?:pid|PID|process)\s*[=:]?\s*\d+\b', '<PID>', text)

    # 4. Normalize file line numbers (e.g. line 45, line 45:12, :45:12)
    text = re.sub(r'\b(?:line|Line)\s+\d+(?::\d+)?\b', 'line <LINE>', text)
    text = re.sub(r':\d+:\d+', ':<LINE>:<COL>', text)
    text = re.sub(r':\d+\b', ':<LINE>', text)

    # 5. Normalize ephemeral IP / port combinations
    text = re.sub(r'\b\d{1,3}(?:\.\d{1,3}){3}:\d{2,5}\b', '<IP>:<PORT>', text)

    # 6. Normalize whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def normalize_command(raw_cmd: str) -> str:
    """
    Normalizes command string by stripping cosmetic quotes, extra spaces,
    and standardizing option order where possible.
    """
    if not raw_cmd:
        return ""

    text = str(raw_cmd).strip()
    # Strip cosmetic wrapping quotes
    if (text.startswith('"') and text.endswith('"')) or (text.startswith("'") and text.endswith("'")):
        text = text[1:-1].strip()

    # Normalize repeated whitespace
    text = re.sub(r'\s+', ' ', text)
    return text.lower()


def hash_string(text: str) -> str:
    """Computes SHA-256 digest of normalized text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def create_error_signature(
    tool_name: str,
    command_or_target: str,
    error_message: str,
    step_idx: int = 0,
    timestamp: float = 0.0,
) -> ErrorSignature:
    """
    Builds a normalized ErrorSignature with hashes for exact and near-repeat checks.
    """
    norm_cmd = normalize_command(command_or_target)
    norm_err = normalize_error(error_message)

    cmd_hash = hash_string(norm_cmd)
    err_hash = hash_string(norm_err)

    return ErrorSignature(
        tool_name=tool_name,
        command_or_target=command_or_target,
        error_message=error_message,
        normalized_command=norm_cmd,
        normalized_error=norm_err,
        command_hash=cmd_hash,
        error_hash=err_hash,
        step_idx=step_idx,
        timestamp=timestamp,
    )


def compute_similarity(str1: str, str2: str) -> float:
    """
    Computes normalized string similarity in [0.0, 1.0] using SequenceMatcher.
    """
    if not str1 and not str2:
        return 1.0
    if not str1 or not str2:
        return 0.0
    return difflib.SequenceMatcher(None, str1, str2).ratio()
