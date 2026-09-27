"""
Command normalization and anti-evasion helpers for the Hard Policy Engine.
"""

import shlex
import re
from typing import List, Tuple, Optional

# Regex to detect command chaining and subshell execution
CHAINING_PATTERN = re.compile(
    r'(?:;|&&|\|\||\||&|\n|\r|\$\([^\)]*\)|\`[^\`]*\`)'
)

# Regex to detect command substitution specifically
SUBSHELL_PATTERN = re.compile(r'(?:\$\(([^\)]*)\)|\`([^\`]*)\`)')

def tokenize_command(cmd: str) -> Tuple[List[str], Optional[str]]:
    """
    Primary command tokenization path using standard shlex.
    Wraps shlex.split in try/except ValueError and any other parse exceptions.
    Returns:
        (tokens, None) on successful parsing.
        ([], error_message) on parse failure (e.g. unclosed quotation or escape errors).
    """
    if not cmd or not cmd.strip():
        return [], None

    try:
        tokens = shlex.split(cmd, posix=True)
        return tokens, None
    except ValueError as e:
        return [], f"shlex parse error: {e}"
    except Exception as e:
        return [], f"shlex tokenization error: {e}"

def normalize_command(cmd: str) -> str:
    """
    Normalizes a command string to mitigate common evasion techniques:
    - Strips Windows caret escapes (e.g., c^m^d -> cmd)
    - Strips line continuations (\\ followed by newline)
    - Strips syntactic/obfuscation quotes around tokens (e.g. "rm" -> rm, r"m" -> rm, 'r'm -> rm)
    - Normalizes excessive whitespace
    """
    if not cmd:
        return ""

    # Replace Windows caret escapes
    s = cmd.replace("^", "")

    # Replace line continuations
    s = re.sub(r'\\\r?\n', ' ', s)

    # Strip quotes from words/tokens that contain no spaces
    # (e.g. "rm" -> rm, '-rf' -> -rf)
    s = re.sub(r'["\']([^\s"\']+)["\']', r'\1', s)

    # Strip any remaining quote characters within non-whitespace tokens (e.g. r"m" -> rm)
    s = re.sub(r'[\'"](?=\S)', '', s)
    s = re.sub(r'(?<=\S)[\'"]', '', s)

    # Normalize whitespace
    s = " ".join(s.strip().split())
    return s

def strip_all_quotes(cmd: str) -> str:
    """
    Returns a copy of the command with all quotation marks removed.
    Useful for secondary pattern matching against obfuscated commands.
    """
    return re.sub(r'[\'"]', '', cmd)

def has_command_chaining(cmd: str) -> bool:
    """
    Returns True if the command contains any chaining operators (; , &&, ||, |, &, newline)
    or subshell command substitutions ($(cmd), `cmd`).
    Any command with chaining is disqualified from hard-allow.
    """
    if not cmd:
        return False
    return bool(CHAINING_PATTERN.search(cmd))

def split_command_chain(cmd: str) -> List[str]:
    """
    Splits a compound command string into individual sub-commands and extracted subshells.
    Ensures that every part of a chained payload can be checked against hard-deny rules.
    """
    if not cmd:
        return []

    sub_commands: List[str] = []

    # 1. Extract subshell command substitutions
    for match in SUBSHELL_PATTERN.finditer(cmd):
        sub_cmd = match.group(1) or match.group(2)
        if sub_cmd and sub_cmd.strip():
            sub_commands.append(sub_cmd.strip())

    # 2. Split on chain operators: ;, &&, ||, |, &, \n, \r
    parts = re.split(r';|&&|\|\||\||&|\n|\r', cmd)
    for part in parts:
        cleaned = part.strip()
        if cleaned:
            sub_commands.append(cleaned)

    return sub_commands
