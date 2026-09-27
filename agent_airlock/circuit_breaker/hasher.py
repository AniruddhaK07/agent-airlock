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
    process IDs, ephemeral ports, file line/column positions,
    attempt/run banners, and PowerShell wrapper noise.
    """
    if not raw_error:
        return ""

    text = str(raw_error).strip()

    # 1. Strip attempt banners / run headers (e.g. === Attempt 1 ===, --- Run 1 ---)
    text = re.sub(r'(?:===|---)\s*(?:Attempt|Run)?\s*[\$\w\d_]*\s*(?:===|---)', '', text, flags=re.IGNORECASE)

    # 2. Strip PowerShell NativeCommandError metadata wrapper blocks
    text = re.sub(r'At line:\d+ char:\d+.*?\+ FullyQualifiedErrorId\s*:\s*\w+', '', text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'\b\w+\s*:\s*Traceback', 'Traceback', text, flags=re.IGNORECASE)

    # 3. Normalize file paths (e.g. File "...", or C:\...)
    text = re.sub(r'File\s+\"[^\"]+\"', 'File "<PATH>"', text)
    text = re.sub(r'[a-zA-Z]:[/\\][^ \t\r\n:\"\'\(\)]+', '<PATH>', text)

    # 4. Normalize ISO / standard timestamps
    text = re.sub(r'\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b', '<TIMESTAMP>', text)
    text = re.sub(r'\b\d{2}:\d{2}:\d{2}(?:\.\d+)?\b', '<TIME>', text)

    # 5. Normalize memory addresses (e.g. 0x7fff5fbff820, 0x000001)
    text = re.sub(r'\b0x[0-9a-fA-F]{4,16}\b', '<ADDR>', text)

    # 6. Normalize PIDs (e.g. PID 12345, pid: 4892)
    text = re.sub(r'\b(?:pid|PID|process)\s*[=:]?\s*\d+\b', '<PID>', text)

    # 7. Normalize file line numbers (e.g. line 45, line 45:12, :45:12)
    text = re.sub(r'\b(?:line|Line)\s+\d+(?::\d+)?\b', 'line <LINE>', text)
    text = re.sub(r':\d+:\d+', ':<LINE>:<COL>', text)
    text = re.sub(r':\d+\b', ':<LINE>', text)

    # 8. Normalize ephemeral IP / port combinations
    text = re.sub(r'\b\d{1,3}(?:\.\d{1,3}){3}:\d{2,5}\b', '<IP>:<PORT>', text)

    # 9. Normalize whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def normalize_command(raw_cmd: str) -> str:
    """
    Normalizes command string by stripping cosmetic quotes, extra spaces,
    ignoring informational wrapper commands (echo, Write-Output, Write-Host),
    shell comments, path separators, and error redirection.
    """
    if not raw_cmd:
        return ""

    text = str(raw_cmd).strip()
    # Strip cosmetic wrapping quotes
    if (text.startswith('"') and text.endswith('"')) or (text.startswith("'") and text.endswith("'")):
        text = text[1:-1].strip()

    # Unwrap PowerShell foreach loops if wrapping a single command
    m_loop = re.match(
        r'^\s*\d+\.\.\d+\s*\|\s*ForEach-Object\s*\{\s*(?:Write-Host|Write-Output|echo)[^;}\n]*[;\n]+\s*([^}]+)\s*\}\s*$',
        text,
        flags=re.IGNORECASE,
    )
    if m_loop:
        text = m_loop.group(1).strip()

    # Strip comments (# or // or rem)
    lines = [l for l in text.splitlines() if not l.strip().startswith(('#', '//', 'rem '))]
    text = ' '.join(lines)

    # Strip prefix informational commands: Write-Output, Write-Host, echo, printf
    # e.g., Write-Output "=== Attempt 1 ==="; cmd
    prefix_pat = r'^\s*(?:Write-Output|Write-Host|echo|printf)\s+(?:\"[^\"]*\"|\'[^\']*\'|[^\s;&|]+)\s*(?:[;&\n]|&&)\s*'
    while re.match(prefix_pat, text, flags=re.IGNORECASE):
        text = re.sub(prefix_pat, '', text, count=1, flags=re.IGNORECASE)

    # Strip trailing error/stream redirections
    text = re.sub(r'\s+2>&1\b', '', text)
    text = re.sub(r'\s+2>\$null\b', '', text, flags=re.IGNORECASE)
    text = re.sub(r'\s+2>/dev/null\b', '', text)
    text = re.sub(r'\s+>\$null\b', '', text, flags=re.IGNORECASE)
    text = re.sub(r'\s+>/dev/null\b', '', text)

    # Normalize backslashes in paths
    text = text.replace('\\', '/')

    # Normalize repeated whitespace
    text = re.sub(r'\s+', ' ', text)
    return text.lower().strip()


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
