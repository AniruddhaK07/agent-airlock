"""
Command normalization and anti-evasion helpers for the Hard Policy Engine.
"""

import shlex
import re
import base64
from typing import List, Tuple, Optional

# Shell redirection operators and PowerShell file-writing cmdlets
REDIRECT_TARGET_PATTERN = re.compile(
    r'(?:>>?|[12]>>?|&>|>&)\s*[\'"]?([^\'"\s;&|]+)|'
    r'\b(?:Out-File|Set-Content|Add-Content)\b(?:\s+-[a-zA-Z0-9_\-]+)*\s+(?:-FilePath\s+)?[\'"]?([^\'"\s;&|]+)|'
    r'\btee(?:\s+-a)?\s+[\'"]?([^\'"\s;&|]+)',
    re.IGNORECASE
)

# Mutating and file modification commands
MUTATING_CMD_PATTERN = re.compile(
    r'\b(?:rm|del|erase|rmdir|rd|Remove-Item|ri|unlink|truncate|touch|sed\s+-i|mv|move|Move-Item|mi|cp|copy|Copy-Item)\b',
    re.IGNORECASE
)

# Python inline file-writing patterns
PYTHON_WRITE_PATTERN = re.compile(
    r'(?:open\s*\(\s*[\'"]([^\'"]+)[\'"]\s*,\s*[\'"][wa\+]|Path\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)\.write)',
    re.IGNORECASE
)

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

def decode_powershell_base64(b64_str: str) -> Optional[str]:
    """
    Decodes a base64 encoded PowerShell command payload.
    PowerShell uses UTF-16LE encoding for -EncodedCommand strings.
    Also handles UTF-8 fallbacks and strips null bytes.
    """
    if not b64_str:
        return None
    try:
        cleaned = b64_str.strip().strip("'\"")
        rem = len(cleaned) % 4
        if rem > 0:
            cleaned += "=" * (4 - rem)
        raw_bytes = base64.b64decode(cleaned)

        # 1. If bytes contain null bytes or characteristic UTF-16LE, try UTF-16LE first
        if len(raw_bytes) >= 2 and b"\x00" in raw_bytes:
            try:
                decoded = raw_bytes.decode("utf-16le").strip()
                if decoded:
                    return decoded
            except UnicodeDecodeError:
                pass

        # 2. Try UTF-8 decode
        try:
            decoded = raw_bytes.decode("utf-8").strip()
            if decoded and all(32 <= ord(c) < 127 or c in "\t\r\n" for c in decoded):
                return decoded
        except UnicodeDecodeError:
            pass

        # 3. Fallback to UTF-16LE (standard PowerShell)
        try:
            decoded = raw_bytes.decode("utf-16le").strip()
            if decoded:
                return decoded
        except UnicodeDecodeError:
            pass
    except Exception:
        pass
    return None

def _extract_direct_payloads(cmd: str) -> List[str]:
    """
    Extracts one layer of inner command payloads from subshell, encoded, or interpreter wrappers.
    """
    if not cmd:
        return []

    payloads: List[str] = []

    # 1. PowerShell EncodedCommand / -enc
    for match in re.finditer(r'(?:^|\s)(?:-|/)(?:encodedcommand|enc)\s+[\'"]?([A-Za-z0-9+/=]{4,})[\'"]?', cmd, re.IGNORECASE):
        b64_payload = match.group(1)
        decoded = decode_powershell_base64(b64_payload)
        if decoded:
            payloads.append(decoded)

    for match in re.finditer(r'(?:powershell|pwsh)(?:\.exe)?\s+.*?(?:-|/)(?:e|en|enco)\s+[\'"]?([A-Za-z0-9+/=]{4,})[\'"]?', cmd, re.IGNORECASE):
        b64_payload = match.group(1)
        decoded = decode_powershell_base64(b64_payload)
        if decoded:
            payloads.append(decoded)

    # 2. bash / sh / zsh -c "..."
    for match in re.finditer(r'(?:^|[;&|]\s*|\b)(?:/bin/|/usr/bin/)?(?:bash|sh|zsh)\s+(?:-[a-zA-Z0-9_\-]+\s+)*-c\s+([\'"])(.*?)\1', cmd, re.DOTALL | re.IGNORECASE):
        inner = match.group(2).strip()
        if inner:
            payloads.append(inner)
    for match in re.finditer(r'(?:^|[;&|]\s*|\b)(?:/bin/|/usr/bin/)?(?:bash|sh|zsh)\s+(?:-[a-zA-Z0-9_\-]+\s+)*-c\s+([^\'"\n\r;&|]+)', cmd, re.IGNORECASE):
        inner = match.group(1).strip()
        if inner and not inner.startswith("-"):
            payloads.append(inner)

    # 3. cmd.exe /c "..." or cmd /c ...
    for match in re.finditer(r'(?:^|[;&|]\s*|\b)cmd(?:\.exe)?\s+/[ck]\s+([\'"])(.*?)\1', cmd, re.DOTALL | re.IGNORECASE):
        inner = match.group(2).strip()
        if inner:
            payloads.append(inner)
    for match in re.finditer(r'(?:^|[;&|]\s*|\b)cmd(?:\.exe)?\s+/[ck]\s+([^\'"\n\r]+)', cmd, re.IGNORECASE):
        inner = match.group(1).strip()
        if inner and not inner.startswith("-"):
            payloads.append(inner)

    # 4. wsl <command>
    for match in re.finditer(r'(?:^|[;&|]\s*|\b)wsl(?:\.exe)?(?:\s+(?:-e|--exec|--|-[a-zA-Z0-9_\-]+))*\s+([\'"])(.*?)\1', cmd, re.DOTALL | re.IGNORECASE):
        inner = match.group(2).strip()
        if inner:
            payloads.append(inner)
    for match in re.finditer(r'(?:^|[;&|]\s*|\b)wsl(?:\.exe)?(?:\s+(?:-e|--exec|--))*\s+([^\'"\n\r]+)', cmd, re.IGNORECASE):
        inner = match.group(1).strip()
        if inner and not inner.startswith("-"):
            payloads.append(inner)

    # 5. Invoke-Expression / iex
    for match in re.finditer(r'(?:^|[;&|]\s*|\b)(?:Invoke-Expression|iex)\s+([\'"\(\[])(.*?)(?:[\'"]|\)\])', cmd, re.DOTALL | re.IGNORECASE):
        inner = match.group(2).strip()
        if inner:
            payloads.append(inner)
    for match in re.finditer(r'(?:^|[;&|]\s*|\b)(?:Invoke-Expression|iex)\s+([^\'"\(\[\n\r;&|]+)', cmd, re.IGNORECASE):
        inner = match.group(1).strip()
        if inner and not inner.startswith("-"):
            payloads.append(inner)

    # 6. python -c "..."
    for match in re.finditer(r'(?:^|[;&|]\s*|\b)python[23]?(?:\.exe)?\s+(?:-[a-zA-Z0-9_\-]+\s+)*-c\s+([\'"])(.*?)\1', cmd, re.DOTALL | re.IGNORECASE):
        py_code = match.group(2).strip()
        if py_code:
            payloads.append(py_code)
            for sys_match in re.finditer(r'(?:os\.system|os\.popen|subprocess\.(?:run|call|Popen|check_call|check_output))\s*\(\s*([\'"])(.*?)\1', py_code, re.DOTALL):
                inner_cmd = sys_match.group(2).strip()
                if inner_cmd:
                    payloads.append(inner_cmd)
            for list_match in re.finditer(r'subprocess\.(?:run|call|Popen|check_call|check_output)\s*\(\s*\[(.*?)\]', py_code, re.DOTALL):
                list_content = list_match.group(1)
                items = re.findall(r'[\'"]([^\'"]+)[\'"]', list_content)
                if items:
                    payloads.append(" ".join(items))

    return payloads

def extract_subshell_and_encoded_payloads(cmd: str, max_depth: int = 3) -> List[str]:
    """
    Recursively extracts inner command strings from subshells, encoded commands,
    and interpreter wrappers up to max_depth.
    """
    if not cmd:
        return []

    all_payloads: List[str] = []
    seen = {cmd}
    current_layer = [cmd]

    for _ in range(max_depth):
        next_layer = []
        for c in current_layer:
            extracted = _extract_direct_payloads(c)
            for item in extracted:
                if item and item not in seen:
                    seen.add(item)
                    all_payloads.append(item)
                    next_layer.append(item)
        if not next_layer:
            break
        current_layer = next_layer

    return all_payloads

def is_protected_runtime_path(path_str: str) -> bool:
    """
    Identifies whether a file path targets Agent Airlock's own runtime surface:
      - .agents/hooks.json (or active hooks configuration)
      - *policy.yaml / *policy.yml / *policy.json (workspace and global policy files)
      - daemon runtime files (*.sock, *.pid, *.token)

    CRITICAL SCOPE LIMIT:
      Explicitly does NOT protect agent_airlock/ source code files or *.py/*.pyc files
      to allow normal development within Antigravity.
    """
    if not path_str or not isinstance(path_str, str):
        return False

    norm = path_str.replace("\\", "/").strip().strip("'\"")

    # Explicit scope exclusion: normal code development
    if norm.endswith((".py", ".pyc", ".pyd")) or "/agent_airlock/" in norm or norm.startswith("agent_airlock/"):
        return False

    norm_lower = norm.lower()
    basename = norm.split("/")[-1].lower()

    # 1. Active hooks configuration
    if basename == "hooks.json" or norm_lower.endswith(".agents/hooks.json"):
        return True

    # 2. Workspace and global policy configuration files (*policy.yaml, *policy.yml, *policy.json)
    if basename.endswith((".yaml", ".yml", ".json")) and "policy" in basename:
        return True

    # 3. Daemon runtime files (socket, PID, and bearer token files)
    if basename.endswith((".sock", ".pid", ".token")):
        return True
    if any(sig in basename for sig in ("daemon.sock", "daemon.pid", "daemon.token", "airlock.sock", "airlock.pid", "airlock.token")):
        return True

    return False

def is_tampering_command(cmd: str) -> bool:
    """
    Checks if a shell command attempts to write, mutate, delete, or redirect to
    any protected Agent Airlock runtime surface file.
    """
    if not cmd or not cmd.strip():
        return False

    norm = normalize_command(cmd)

    # 1. Shell redirection and PowerShell output cmdlets
    for match in REDIRECT_TARGET_PATTERN.finditer(cmd):
        target = match.group(1) or match.group(2) or match.group(3)
        if target and is_protected_runtime_path(target.strip()):
            return True
    for match in REDIRECT_TARGET_PATTERN.finditer(norm):
        target = match.group(1) or match.group(2) or match.group(3)
        if target and is_protected_runtime_path(target.strip()):
            return True

    # 2. Deletion / mutation commands
    if MUTATING_CMD_PATTERN.search(cmd) or MUTATING_CMD_PATTERN.search(norm):
        tokens, _ = tokenize_command(cmd)
        raw_words = cmd.split()
        for word in list(tokens) + raw_words:
            cleaned_word = word.strip().strip("'\",;()")
            if not cleaned_word:
                continue
            if is_protected_runtime_path(cleaned_word):
                return True
            norm_word = cleaned_word.replace("\\", "/").rstrip("/").lower()
            if norm_word in (".agents", "./.agents", "../.agents") or norm_word.endswith("/.agents"):
                return True

    # 3. Python inline writes targeting protected paths
    for match in PYTHON_WRITE_PATTERN.finditer(cmd):
        path = match.group(1) or match.group(2)
        if path and is_protected_runtime_path(path):
            return True

    return False
