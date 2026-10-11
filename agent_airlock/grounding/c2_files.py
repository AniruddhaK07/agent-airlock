"""
Check C2: Files Grounding (Section 9.4).
Verifies that:
- view_file: the file itself must exist.
- write_to_file: parent directory exists (creating a new file is legal).
- replace_file_content: the target file itself must exist.
"""

from pathlib import Path
from typing import Any, Dict, Optional, Tuple


def extract_target_path(tool_args: Dict[str, Any]) -> str:
    """Extracts target path parameter across varied tool call schemas."""
    for key in ("TargetFile", "FilePath", "AbsolutePath", "file_path", "path", "target_file"):
        val = tool_args.get(key)
        if val and isinstance(val, str) and val.strip():
            return val.strip()
    return ""


def resolve_file_path(path_str: str, cwd: str, workspace_root: Optional[str] = None) -> Optional[Path]:
    """Resolves path against cwd and workspace_root."""
    if not path_str:
        return None
    try:
        p = Path(path_str)
        if p.is_absolute():
            return p.resolve()
        cwd_path = Path(cwd).resolve() if cwd else Path.cwd()
        resolved = (cwd_path / p).resolve()
        if resolved.exists():
            return resolved
        if workspace_root:
            ws_path = Path(workspace_root).resolve()
            ws_resolved = (ws_path / p).resolve()
            if ws_resolved.exists():
                return ws_resolved
        return resolved
    except Exception:
        return None


def check_files(
    tool_name: str,
    tool_args: Dict[str, Any],
    cwd: str,
    workspace_root: Optional[str] = None,
) -> Tuple[bool, str, str]:
    """
    Evaluates Check C2 on file inspection and mutation tool calls.
    Returns:
        (is_grounded, hint, target_file)
    """
    target_str = extract_target_path(tool_args)
    if not target_str:
        return True, "", ""

    # Pass through scrubbed paths containing placeholders like <USER>, <WS>, <HOME>
    if any(marker in target_str for marker in ("<USER>", "<WS>", "<HOME>", "<REPO>", "<TMP>")):
        return True, "", target_str

    # If workspace_root is provided but does not exist on disk (e.g. offline trace replay from another system),
    # pass conservatively per design rule (only deny when certain).
    if workspace_root and not Path(workspace_root).exists():
        return True, "", target_str

    # If cwd is provided but does not exist on disk, pass conservatively
    if cwd and not Path(cwd).exists():
        return True, "", target_str

    resolved = resolve_file_path(target_str, cwd, workspace_root)
    if resolved is None:
        # Unresolvable path syntax passes conservatively
        return True, "", target_str

    # 1. view_file: file itself must exist
    if tool_name == "view_file":
        if not resolved.is_file():
            return False, f"File does not exist: '{target_str}'", target_str
        return True, "", target_str

    # 2. replace_file_content: target file itself must exist to be edited
    if tool_name == "replace_file_content":
        if not resolved.is_file():
            return False, f"Target file for replacement does not exist: '{target_str}'", target_str
        return True, "", target_str

    # 3. write_to_file: parent directory must exist (creating new file is valid)
    if tool_name == "write_to_file":
        parent = resolved.parent
        if not parent.is_dir():
            return False, f"Parent directory does not exist: '{parent}'", target_str
        return True, "", target_str

    return True, "", target_str
