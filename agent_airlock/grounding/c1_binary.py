"""
Check C1: Binary & Toolchain Grounding (Section 9.4).
Verifies that commands do not invoke hallucinated or missing binaries.
Skips builtins, keywords, aliases, relative/absolute paths, wrappers, and
segments preceded by a build/install step in the same chain.
Caches PATH indexing to ensure sub-millisecond execution.
"""

import os
import sys
import time
from pathlib import Path
from typing import Dict, Optional, Set, Tuple

from agent_airlock.policy.normalizer import CommandSegment

# Shell builtins, keywords, and standard built-in aliases
POWERSHELL_BUILTINS: Set[str] = {
    # Keywords
    "if", "else", "elseif", "switch", "foreach", "for", "in", "while", "do", "until",
    "break", "continue", "return", "exit", "try", "catch", "finally", "throw", "trap",
    "function", "filter", "workflow", "configuration", "class", "enum", "param",
    "begin", "process", "end", "dynamicparam", "using", "hidden", "static",
    # Standard cmdlets & functions
    "get-command", "get-help", "get-process", "get-service", "get-member",
    "get-content", "set-content", "add-content", "clear-content",
    "get-childitem", "get-item", "get-itemproperty", "set-item", "set-itemproperty",
    "new-item", "remove-item", "copy-item", "move-item", "rename-item",
    "select-object", "where-object", "sort-object", "measure-object", "group-object",
    "format-table", "format-list", "format-wide", "format-custom",
    "out-string", "out-file", "out-null", "out-host", "out-default",
    "write-host", "write-output", "write-error", "write-warning", "write-verbose",
    "test-path", "test-connection", "invoke-expression", "invoke-command",
    "start-process", "stop-process", "wait-process", "start-job", "stop-job", "get-job",
    "push-location", "pop-location", "get-location", "set-location",
    "convert-path", "resolve-path", "join-path", "split-path",
    # Built-in PowerShell aliases
    "cat", "dir", "ls", "type", "copy", "cp", "move", "mv", "del", "rm", "rmdir",
    "cls", "clear", "echo", "write", "curl", "wget", "iwr", "irm", "select", "where",
    "measure", "sort", "cd", "chdir", "pwd", "popd", "pushd", "kill", "ps", "gps",
    "saps", "sls", "select-string", "sc", "gc", "ac", "clc", "gci", "gi", "ni", "ri",
    "mi", "cpi", "ren", "rni", "h", "history", "clh", "clear-history",
    "foreach-object", "where-object", "select-object", "tee-object", "group-object",
    "sort-object", "measure-object", "compare-object", "%", "?",
}

POSIX_BUILTINS: Set[str] = {
    "cd", "echo", "printf", "read", "exit", "export", "set", "unset", "source", ".",
    "alias", "unalias", "eval", "exec", "test", "[", "[[", "true", "false", "shift",
    "trap", "type", "hash", "pwd", "kill", "wait", "jobs", "bg", "fg", "history",
    "ulimit", "umask", "builtin", "command", "enable", "help", "shopt", "bind",
    "declare", "typeset", "local", "return", "times", "dirs", "let", "source",
    "awk", "sed", "grep", "xargs", "tar", "gzip", "gunzip", "zip", "unzip", "curl",
    "wget", "which", "where", "head", "tail", "sort", "uniq", "wc", "tr", "cut", "tee",
}

CMD_BUILTINS: Set[str] = {
    "dir", "cd", "chdir", "md", "mkdir", "rd", "rmdir", "copy", "del", "erase",
    "ren", "rename", "type", "echo", "cls", "set", "path", "pause", "rem", "exit",
    "call", "start", "ver", "vol", "assoc", "ftype", "prompt", "color", "shift",
    "goto", "if", "for", "pushd", "popd", "title", "verify", "setlocal", "endlocal",
    "findstr", "tasklist", "taskkill", "netstat", "ipconfig", "whoami", "attrib",
    "robocopy", "xcopy", "reg", "powershell", "pwsh", "cmd", "wmic", "timeout",
    "clip", "choice", "certutil", "nslookup", "ping", "tracert", "conhost",
}

ALL_SHELL_BUILTINS: Set[str] = {b.lower() for b in POWERSHELL_BUILTINS | POSIX_BUILTINS | CMD_BUILTINS}

WINDOWS_PATHEXT: Tuple[str, ...] = (
    ".com", ".exe", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".msc", ".ps1"
)


class PathIndexCache:
    """
    Thread-safe, time-bounded cache for PATH directory scans.
    Prevents repeated expensive disk access during rapid evaluations.
    """
    def __init__(self, ttl_seconds: float = 30.0):
        self.ttl_seconds = ttl_seconds
        self._cache: Dict[str, Tuple[float, Set[str]]] = {}

    def get_binaries_in_path(self, path_str: str) -> Set[str]:
        now = time.monotonic()
        if path_str in self._cache:
            ts, bins = self._cache[path_str]
            if (now - ts) < self.ttl_seconds:
                return bins

        indexed = self._index_path(path_str)
        self._cache[path_str] = (now, indexed)
        return indexed

    def _index_path(self, path_str: str) -> Set[str]:
        binaries: Set[str] = set()
        dirs = [d.strip() for d in path_str.split(os.pathsep) if d.strip()]
        for d in dirs:
            try:
                p = Path(d)
                if not p.is_dir():
                    continue
                for entry in os.scandir(p):
                    try:
                        if entry.is_file(follow_symlinks=True):
                            name_lower = entry.name.lower()
                            binaries.add(name_lower)
                            # On Windows, index without extension as well
                            for ext in WINDOWS_PATHEXT:
                                if name_lower.endswith(ext):
                                    binaries.add(name_lower[:-len(ext)])
                                    break
                    except (PermissionError, OSError):
                        continue
            except (PermissionError, OSError):
                continue
        return binaries

    def clear(self) -> None:
        self._cache.clear()


# Global PATH cache singleton
_GLOBAL_PATH_CACHE = PathIndexCache()


COMMON_DEVELOPMENT_BINARIES: Set[str] = {
    "python", "python3", "python.exe", "python3.exe",
    "pip", "pip3", "pip.exe", "pip3.exe",
    "node", "node.exe", "npm", "npm.cmd", "npx", "npx.cmd",
    "yarn", "yarn.cmd", "pnpm", "pnpm.cmd",
    "git", "git.exe",
    "cargo", "cargo.exe", "rustc", "rustc.exe",
    "go", "go.exe",
    "uv", "uv.exe", "ruff", "black", "pytest", "pytest.exe", "mypy", "flake8",
    "dotnet", "dotnet.exe", "java", "javac", "mvn", "gradle",
    "docker", "docker.exe", "docker-compose", "kubectl", "helm", "terraform",
    "ffmpeg", "ffmpeg.exe", "ffprobe", "ffprobe.exe",
    "bash", "sh", "zsh", "powershell", "pwsh", "cmd",
}

POWERSHELL_PREFIXES: Set[str] = {
    "get", "set", "new", "remove", "start", "stop", "test", "out",
    "write", "invoke", "clear", "copy", "move", "rename", "convert",
    "convertfrom", "convertto", "export", "import", "add", "measure",
    "sort", "select", "where", "format", "register", "unregister",
    "enable", "disable", "update", "join", "split", "resolve",
    "show", "enter", "exit", "wait", "read", "push", "pop", "find",
    "search", "install", "uninstall", "save", "publish", "receive",
    "send", "submit", "disconnect", "connect", "step", "tee", "checkpoint",
}


def check_binary(
    segment: CommandSegment,
    cwd: str,
    env: Optional[Dict[str, str]] = None,
    path_cache: Optional[PathIndexCache] = None,
) -> Tuple[bool, str, str]:
    """
    Evaluates Check C1 on a single CommandSegment.
    Returns:
        (is_grounded, hint, target_binary)
    """
    if segment.is_dynamic_or_unparseable:
        # Dynamic tokens, variables, or unparseable subexpressions pass conservatively
        return True, "", segment.binary

    if segment.preceded_by_build_step:
        # Segment preceded in the same chain by a build/install/create step
        return True, "", segment.binary

    raw_bin = segment.binary.strip().strip("'\"")
    if not raw_bin:
        return True, "", ""

    # Shell comments (#...) or operators (+, -, etc.)
    if raw_bin.startswith("#") or all(c in "+-*/%=&|!<>~^:()[]{}" for c in raw_bin):
        return True, "", raw_bin

    # Numeric expressions or range operators (1..4)
    if raw_bin[0].isdigit() or ".." in raw_bin:
        return True, "", raw_bin

    # Scrubbed placeholders (<USER>, <WS>, <HOME>) or dynamic angle brackets
    if "<" in raw_bin and ">" in raw_bin:
        return True, "", raw_bin

    bin_lower = raw_bin.lower()

    # Ephemeral virtual environment binaries or scrubbed paths
    if any(k in bin_lower for k in (".venv", "/venv/", "\\venv\\", "/env/", "\\env\\", "<user>", "<ws>", "<home>", "<scrubbed>")):
        return True, "", raw_bin

    # Standard development toolchain binaries
    if bin_lower in COMMON_DEVELOPMENT_BINARIES:
        return True, "", raw_bin

    # 1. Shell builtins, cmdlets, and keywords
    if bin_lower in ALL_SHELL_BUILTINS:
        return True, "", raw_bin

    # Common PowerShell cmdlet prefixes
    if "-" in bin_lower:
        prefix, _, _ = bin_lower.partition("-")
        if prefix in POWERSHELL_PREFIXES:
            return True, "", raw_bin

    # 2. Relative or absolute path check
    has_path_sep = ("/" in raw_bin) or ("\\" in raw_bin) or raw_bin.startswith(".")
    is_windows = sys.platform == "win32" or (len(raw_bin) >= 2 and raw_bin[1] == ":")

    if has_path_sep or (is_windows and (raw_bin.startswith("\\") or (len(raw_bin) >= 2 and raw_bin[1] == ":"))):
        try:
            cwd_path = Path(cwd).resolve() if cwd else Path.cwd()
            target_path = Path(raw_bin)
            if not target_path.is_absolute():
                target_path = (cwd_path / target_path).resolve()
            else:
                target_path = target_path.resolve()

            # Check exact file existence
            if target_path.is_file():
                return True, "", raw_bin

            # On Windows, check with PATHEXT extensions
            if is_windows and not target_path.suffix:
                for ext in WINDOWS_PATHEXT:
                    cand = target_path.with_suffix(ext)
                    if cand.is_file():
                        return True, "", raw_bin

            # Path was explicit and definitely does not exist
            return False, f"Executable or script not found at path: '{raw_bin}'", raw_bin
        except Exception:
            # On path resolution failure, pass conservatively
            return True, "", raw_bin

    # 3. Bare binary lookup in PATH and cwd
    caller_path = None
    if env and isinstance(env, dict):
        caller_path = env.get("PATH") or env.get("Path")

    if not caller_path:
        caller_path = os.environ.get("PATH", "")

    if not caller_path:
        # If PATH is unavailable, resolve conservatively and do not deny (Section 9.4)
        return True, "", raw_bin

    cache = path_cache or _GLOBAL_PATH_CACHE
    available_bins = cache.get_binaries_in_path(caller_path)

    # Check if binary is in PATH
    if bin_lower in available_bins or raw_bin in available_bins:
        return True, "", raw_bin

    # Also check if it exists in caller's cwd as an executable or script
    try:
        cwd_path = Path(cwd).resolve() if cwd else Path.cwd()
        cand_in_cwd = cwd_path / raw_bin
        if cand_in_cwd.is_file():
            return True, "", raw_bin
        if is_windows and not cand_in_cwd.suffix:
            for ext in WINDOWS_PATHEXT:
                if cand_in_cwd.with_suffix(ext).is_file():
                    return True, "", raw_bin
    except Exception:
        pass

    # Binary is certain to be missing from PATH and cwd
    return False, f"Binary '{raw_bin}' not found in PATH or cwd", raw_bin
