"""
Installer and configuration generator for Antigravity hooks.
Mounts PreToolUse and PostToolUse lifecycle hooks into .agents/hooks.json.
"""

import json
import logging
import os
from pathlib import Path
import sys
from typing import Dict, Any, Optional, Union

logger = logging.getLogger(__name__)

def generate_hooks_config(
    python_bin: Optional[str] = None,
    pre_script: Optional[str] = None,
    post_script: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Generates the hook definition dictionary matching Antigravity's lifecycle schema.
    """
    py_exec = python_bin or sys.executable or "python"
    # Normalize python path with quotes if spaces exist
    if " " in py_exec and not (py_exec.startswith('"') and py_exec.endswith('"')):
        py_exec = f'"{py_exec}"'

    hooks_dir = Path(__file__).resolve().parent
    pre_cmd_path = pre_script or str(hooks_dir / "pre_tool_use.py")
    post_cmd_path = post_script or str(hooks_dir / "post_tool_use.py")

    if " " in pre_cmd_path and not (pre_cmd_path.startswith('"') and pre_cmd_path.endswith('"')):
        pre_cmd_path = f'"{pre_cmd_path}"'
    if " " in post_cmd_path and not (post_cmd_path.startswith('"') and post_cmd_path.endswith('"')):
        post_cmd_path = f'"{post_cmd_path}"'

    return {
        "jev-safety-gate": {
            "enabled": True,
            "PreToolUse": [
                {
                    "matcher": "*",
                    "hooks": [
                        {
                            "type": "command",
                            "command": f"{py_exec} {pre_cmd_path}",
                            "timeout": 10,
                        }
                    ],
                }
            ],
            "PostToolUse": [
                {
                    "matcher": "*",
                    "hooks": [
                        {
                            "type": "command",
                            "command": f"{py_exec} {post_cmd_path}",
                            "timeout": 10,
                        }
                    ],
                }
            ],
        }
    }

def install_hooks(
    target_dir: Union[str, Path] = ".agents",
    python_bin: Optional[str] = None,
) -> Path:
    """
    Installs or updates the jev-safety-gate hook inside .agents/hooks.json.
    Preserves any existing independent hooks.
    """
    out_dir = Path(target_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    hooks_file = out_dir / "hooks.json"

    existing_config: Dict[str, Any] = {}
    if hooks_file.exists():
        try:
            with open(hooks_file, "r", encoding="utf-8") as f:
                existing_config = json.load(f)
        except Exception as e:
            logger.warning("Could not parse existing %s (%s); overwriting.", hooks_file, e)

    new_gate = generate_hooks_config(python_bin=python_bin)
    existing_config.update(new_gate)

    with open(hooks_file, "w", encoding="utf-8") as f:
        json.dump(existing_config, f, indent=2)

    logger.info("Successfully installed jev-safety-gate hooks to %s", hooks_file)
    return hooks_file

def main():
    dest = sys.argv[1] if len(sys.argv) > 1 else ".agents"
    path = install_hooks(target_dir=dest)
    print(f"Installed hooks to {path}")

if __name__ == "__main__":
    main()
