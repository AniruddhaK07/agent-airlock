"""
Command normalization and anti-evasion helpers for the Hard Policy Engine.
"""

import shlex
import re
import base64
from dataclasses import dataclass, field
from typing import List, Tuple, Optional, Dict

# Shell redirection operators and PowerShell file-writing cmdlets
REDIRECT_TARGET_PATTERN = re.compile(
    r'(?:(?<=[\s\d"\'\)])>>?|(?<=[\s])&>|(?<=[\s])>&|(?<=[\s])[12]>>?|^>>?)\s*[\'"]?([^\'"\s;&|<>]+)|'
    r'\b(?:Out-File|Set-Content|Add-Content)\b(?:\s+-[a-zA-Z0-9_\-]+)*\s+(?:-FilePath\s+)?[\'"]?([^\'"\s;&|]+)|'
    r'\btee(?:\s+-a)?\s+[\'"]?([^\'"\s;&|]+)',
    re.IGNORECASE
)

# Pure shell output redirection operators (>, >>, 1>, 2>, &>, >&) for command segment cleaning
PURE_SHELL_REDIRECT_PATTERN = re.compile(
    r'(?:(?<=[\s\d"\'\)])>>?|(?<=[\s])&>|(?<=[\s])>&|(?<=[\s])[12]>>?|^>>?)\s*[\'"]?([^\'"\s;&|<>]+)'
)


# Mutating and file modification commands
MUTATING_CMD_PATTERN = re.compile(
    r'\b(?:rm|del|erase|rmdir|rd|Remove-Item|ri|unlink|truncate|touch|sed\s+-i|mv|move|Move-Item|mi|cp|copy|Copy-Item)\b',
    re.IGNORECASE
)

# Read file commands targeting files
READ_FILE_CMD_PATTERN = re.compile(
    r'\b(?:Get-Content|gc|cat|type|Test-Path|head|tail|more|less)\b',
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
    Bounded to prevent DoS from massive chains.
    """
    if not cmd:
        return []

    # Fast guard: if no chaining characters present, single command
    if not any(c in cmd for c in (';', '&', '|', '\n', '\r', '$', '`')):
        return [cmd.strip()] if cmd.strip() else []

    sub_commands: List[str] = []

    # 1. Extract subshell command substitutions (bounded)
    for match in SUBSHELL_PATTERN.finditer(cmd):
        sub_cmd = match.group(1) or match.group(2)
        if sub_cmd and sub_cmd.strip():
            sub_commands.append(sub_cmd.strip())
            if len(sub_commands) >= 16:
                break

    # 2. Split on chain operators: ;, &&, ||, |, &, \n, \r (bounded to 32)
    parts = re.split(r';|&&|\|\||\||&|\n|\r', cmd)
    for part in parts[:32]:
        cleaned = part.strip()
        if cleaned:
            sub_commands.append(cleaned)
            if len(sub_commands) >= 32:
                break

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

    cmd_lower = cmd.lower()
    if not any(k in cmd_lower for k in ("-c", "/c", "-enc", "-encodedcommand", "wsl", "iex", "invoke-expression", "powershell", "pwsh", "$(", "`")):
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
                    if len(all_payloads) >= 16:
                        return all_payloads
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

    cmd_lower = cmd.lower()
    # Fast guard: if no airlock runtime signature exists in the string, it cannot be tampering
    if not any(sig in cmd_lower for sig in ("policy", "hooks", ".sock", ".pid", ".token", "airlock")):
        return False

    # Git commit messages never target filesystem files
    if re.match(r'^\s*git\s+commit\b', cmd, re.IGNORECASE):
        return False

    # Inline interpreter script bodies (e.g. python -c, node -e) are code text, not shell file targets
    if re.search(r'^(?:[a-zA-Z0-9_\-\\/\.:]+\s+)?(?:python[23]?|node|perl|ruby)(?:\.exe)?\s+(?:-[a-zA-Z0-9_\-]+\s+)*(-c|-e|--eval)\b', cmd_lower):
        # Only check explicit inline python file write patterns
        for match in PYTHON_WRITE_PATTERN.finditer(cmd):
            path = match.group(1) or match.group(2)
            if path and is_protected_runtime_path(path):
                return True
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

    # 2. Deletion / mutation or read commands targeting protected runtime paths
    if MUTATING_CMD_PATTERN.search(cmd) or MUTATING_CMD_PATTERN.search(norm) or READ_FILE_CMD_PATTERN.search(cmd) or READ_FILE_CMD_PATTERN.search(norm):
        tokens, _ = tokenize_command(cmd)
        raw_words = cmd.split()
        for word in list(tokens) + raw_words:
            cleaned_word = word.strip().strip("'\",;()")
            if not cleaned_word:
                continue
            if is_protected_runtime_path(cleaned_word):
                return True

    # 3. Python inline writes targeting protected paths
    for match in PYTHON_WRITE_PATTERN.finditer(cmd):
        path = match.group(1) or match.group(2)
        if path and is_protected_runtime_path(path):
            return True

    return False


@dataclass
class CommandSegment:
    raw: str
    binary: str
    args: List[str] = field(default_factory=list)
    redirections: List[str] = field(default_factory=list)
    env_vars: Dict[str, str] = field(default_factory=dict)
    wrappers: List[str] = field(default_factory=list)
    preceded_by_build_step: bool = False
    is_dynamic_or_unparseable: bool = False


KNOWN_SHELL_WRAPPERS = {"sudo", "time", "nohup", "xargs", "env", "command", "builtin", "exec"}
BUILD_COMMAND_BINARIES = {"make", "cmake", "gcc", "g++", "clang", "touch", "truncate", "new-item", "tar", "unzip"}


def split_command_chain_quote_aware(cmd: str) -> List[str]:
    """
    Splits compound commands into individual execution commands respecting shell quotation.
    Semicolons, pipes, and newlines inside single or double quotes (e.g. python -c "...")
    are NOT treated as command delimiters.
    """
    if not cmd or not cmd.strip():
        return []

    # Fast guard: if no chaining operators present
    if not any(c in cmd for c in (';', '&', '|', '\n', '\r')):
        return [cmd.strip()]

    parts: List[str] = []
    current: List[str] = []
    in_single = False
    in_double = False
    brace_depth = 0
    paren_depth = 0
    bracket_depth = 0
    i = 0
    n = len(cmd)

    while i < n:
        c = cmd[i]
        if c == "'" and not in_double:
            in_single = not in_single
            current.append(c)
            i += 1
        elif c == '"' and not in_single:
            in_double = not in_double
            current.append(c)
            i += 1
        elif not in_single and not in_double:
            if c == '{':
                brace_depth += 1
                current.append(c)
                i += 1
            elif c == '}':
                brace_depth = max(0, brace_depth - 1)
                current.append(c)
                i += 1
            elif c == '(':
                paren_depth += 1
                current.append(c)
                i += 1
            elif c == ')':
                paren_depth = max(0, paren_depth - 1)
                current.append(c)
                i += 1
            elif c == '[':
                bracket_depth += 1
                current.append(c)
                i += 1
            elif c == ']':
                bracket_depth = max(0, bracket_depth - 1)
                current.append(c)
                i += 1
            elif brace_depth == 0 and paren_depth == 0 and bracket_depth == 0:
                if c in (';', '\n', '\r'):
                    chunk = "".join(current).strip()
                    if chunk and not chunk.startswith("#"):
                        parts.append(chunk)
                    current = []
                    i += 1
                elif c == '&':
                    if i + 1 < n and cmd[i + 1] == '&':
                        chunk = "".join(current).strip()
                        if chunk and not chunk.startswith("#"):
                            parts.append(chunk)
                        current = []
                        i += 2
                    else:
                        chunk = "".join(current).strip()
                        if chunk and not chunk.startswith("#"):
                            parts.append(chunk)
                        current = []
                        i += 1
                elif c == '|':
                    if i + 1 < n and cmd[i + 1] == '|':
                        chunk = "".join(current).strip()
                        if chunk and not chunk.startswith("#"):
                            parts.append(chunk)
                        current = []
                        i += 2
                    else:
                        chunk = "".join(current).strip()
                        if chunk and not chunk.startswith("#"):
                            parts.append(chunk)
                        current = []
                        i += 1
                else:
                    current.append(c)
                    i += 1
            else:
                current.append(c)
                i += 1
        else:
            current.append(c)
            i += 1

    last = "".join(current).strip()
    if last and not last.startswith("#"):
        parts.append(last)

    return parts


def tokenize_command_preserve_windows(cmd: str) -> Tuple[List[str], Optional[str]]:
    """
    Tokenizes a command segment while preserving Windows backslashes in paths.
    """
    if not cmd or not cmd.strip():
        return [], None
    try:
        import sys
        is_posix = (sys.platform != "win32") and ("\\" not in cmd)
        return shlex.split(cmd, posix=is_posix), None
    except ValueError as e:
        return [], f"shlex parse error: {e}"
    except Exception as e:
        return [], f"shlex tokenization error: {e}"


def parse_command_segments(cmd: str) -> List[CommandSegment]:
    """
    Parses a normalized or compound command line into individual execution segments (Section 9.2).
    Extracts base binary, arguments, redirections, env assignments, and wrapper commands.
    Tracks whether a segment is preceded by a build/install/create step in the same chain.
    """
    if not cmd or not cmd.strip():
        return []

    stripped = cmd.strip()

    # 1. PowerShell scriptblock / call operator fast path (& { ... })
    if stripped.startswith("&"):
        return [CommandSegment(
            raw=stripped,
            binary="&",
            is_dynamic_or_unparseable=True,
        )]

    # 2. Inline interpreter script fast path (python -c, node -e, npx tsx -e, etc.)
    # Treat entire command as single segment rather than splitting internal script logic
    norm_cmd_lower = stripped.lower()
    if (
        re.search(r'^(?:[a-zA-Z0-9_\-\\/\.:]+\s+)?(?:python[23]?|node|perl|ruby)(?:\.exe)?\s+(?:-[a-zA-Z0-9_\-]+\s+)*(-c|-e|--eval)\b', norm_cmd_lower)
        or re.search(r'^npx\s+(?:tsx|ts-node)\s+-e\b', norm_cmd_lower)
    ):
        tokens, _ = tokenize_command_preserve_windows(stripped)
        if tokens:
            return [CommandSegment(
                raw=stripped,
                binary=tokens[0],
                args=tokens[1:],
            )]

    sub_cmds = split_command_chain_quote_aware(cmd)
    if not sub_cmds:
        sub_cmds = [stripped]

    segments: List[CommandSegment] = []
    had_build_step = False

    for sc in sub_cmds:
        raw_sc = sc.strip()
        if not raw_sc:
            continue

        # 1. Extract redirections
        redirections: List[str] = []
        for match in REDIRECT_TARGET_PATTERN.finditer(raw_sc):
            target = match.group(1) or match.group(2) or match.group(3)
            if target:
                redirections.append(target.strip())

        # Strip output redirection syntax for tokenization (only pure shell redirections, not cmdlets)
        clean_sc = PURE_SHELL_REDIRECT_PATTERN.sub(" ", raw_sc).strip()

        # 2. Tokenize segment (respecting Windows backslashes)
        tokens, parse_err = tokenize_command_preserve_windows(clean_sc)
        is_dynamic = False
        if parse_err or not tokens:
            # Fall back to whitespace splitting
            raw_tokens = clean_sc.split()
            if not raw_tokens:
                continue
            tokens = raw_tokens
            is_dynamic = True

        # Property or variable assignment (e.g. Key = Value or $var = value)
        if len(tokens) >= 2 and tokens[1] == "=":
            is_dynamic = True

        # 3. Extract environment variable prefixes (e.g. VAR=val cmd)
        env_vars: Dict[str, str] = {}
        idx = 0
        while idx < len(tokens):
            tok = tokens[idx]
            if "=" in tok and not tok.startswith("-") and not tok.startswith("/"):
                k, _, v = tok.partition("=")
                if re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', k):
                    env_vars[k] = v
                    idx += 1
                    continue
            break

        remaining = tokens[idx:]
        if not remaining:
            continue

        # 4. Unwrap known wrappers (sudo, time, env, nohup, xargs, etc.)
        wrappers: List[str] = []
        while remaining:
            first_tok = remaining[0].lower()
            if first_tok in KNOWN_SHELL_WRAPPERS:
                wrappers.append(remaining[0])
                remaining = remaining[1:]
                # Skip flags for wrapper
                if first_tok == "sudo":
                    while remaining and remaining[0].startswith("-"):
                        flag = remaining[0]
                        remaining = remaining[1:]
                        if flag in ("-u", "-g", "-C", "-D") and remaining:
                            remaining = remaining[1:]
                elif first_tok == "time":
                    if remaining and remaining[0] in ("-p", "-f", "-o", "-v"):
                        remaining = remaining[1:]
                elif first_tok == "env":
                    while remaining and (remaining[0].startswith("-") or ("=" in remaining[0] and not remaining[0].startswith("-"))):
                        if "=" in remaining[0]:
                            ek, _, ev = remaining[0].partition("=")
                            env_vars[ek] = ev
                        remaining = remaining[1:]
                continue
            break

        if not remaining:
            continue

        binary = remaining[0]
        args = remaining[1:]

        # 5. Check if binary is dynamic / unparseable syntax
        if is_dynamic or any(c in binary for c in ("$", "%", "{", "}", "(", ")", "=", "&", "@", "*", "?", "^")):
            is_dynamic = True

        # 6. Check if segment constitutes a build/create/install step
        b_lower = binary.lower()
        if (
            b_lower in BUILD_COMMAND_BINARIES
            or (b_lower in ("npm", "pnpm", "yarn") and any(a in ("install", "i", "add", "build") for a in args))
            or (b_lower in ("pip", "pip3") and "install" in args)
            or (b_lower == "cargo" and any(a in ("build", "install") for a in args))
            or (b_lower == "go" and any(a in ("build", "install") for a in args))
            or (b_lower == "git" and "clone" in args)
        ):
            seg_is_build = True
        else:
            seg_is_build = False

        seg = CommandSegment(
            raw=raw_sc,
            binary=binary,
            args=args,
            redirections=redirections,
            env_vars=env_vars,
            wrappers=wrappers,
            preceded_by_build_step=had_build_step,
            is_dynamic_or_unparseable=is_dynamic,
        )
        segments.append(seg)

        if seg_is_build:
            had_build_step = True

    return segments
