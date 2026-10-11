"""
Check C3: Scripts Grounding (Section 9.4).
Verifies that:
- npm|pnpm|yarn run <script> references a script defined in package.json "scripts".
- make <target> references a target defined in Makefile.
Suggests closest valid names via edit-distance ranking.
"""

import difflib
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from agent_airlock.policy.normalizer import CommandSegment


def load_package_json_scripts(cwd: str, workspace_root: Optional[str] = None) -> Optional[Dict[str, str]]:
    """Attempts to load 'scripts' dict from package.json in cwd or workspace_root."""
    candidates = []
    if cwd:
        candidates.append(Path(cwd) / "package.json")
    if workspace_root:
        candidates.append(Path(workspace_root) / "package.json")

    for cand in candidates:
        if cand.is_file():
            try:
                data = json.loads(cand.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    scripts = data.get("scripts")
                    if isinstance(scripts, dict):
                        return scripts
                    return {}
            except Exception:
                return None
    return None


def load_makefile_targets(cwd: str, workspace_root: Optional[str] = None) -> Optional[List[str]]:
    """Attempts to parse build targets from Makefile in cwd or workspace_root."""
    candidates = []
    for base in [cwd, workspace_root]:
        if base:
            p = Path(base)
            candidates.extend([p / "Makefile", p / "makefile", p / "GNUmakefile"])

    for cand in candidates:
        if cand.is_file():
            try:
                lines = cand.read_text(encoding="utf-8", errors="ignore").splitlines()
                targets = []
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    m = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*:(?!=)", line)
                    if m:
                        targets.append(m.group(1))
                return targets
            except Exception:
                return None
    return None


def check_scripts(
    segment: CommandSegment,
    cwd: str,
    workspace_root: Optional[str] = None,
) -> Tuple[bool, str, str]:
    """
    Evaluates Check C3 on a CommandSegment.
    Returns:
        (is_grounded, hint, target_script)
    """
    raw_bin = segment.binary.lower()
    args = [a.strip() for a in segment.args if a.strip()]

    # 1. npm / pnpm / yarn run <script>
    if raw_bin in ("npm", "pnpm", "yarn"):
        script_name = None
        if len(args) >= 2 and args[0] == "run":
            # npm run <script>
            script_name = args[1]
        elif len(args) == 1 and args[0] in ("test", "t", "start", "build"):
            # npm test / npm start
            script_name = args[0]
        elif raw_bin == "yarn" and len(args) >= 1 and not args[0].startswith("-"):
            if args[0] not in ("add", "install", "remove", "upgrade", "init", "config", "cache", "version"):
                script_name = args[0]

        if script_name:
            # Strip extra flags or options
            if script_name.startswith("-"):
                return True, "", ""

            scripts = load_package_json_scripts(cwd, workspace_root)
            if scripts is None:
                # package.json missing or unparseable: pass conservatively
                return True, "", script_name

            if script_name in scripts:
                return True, "", script_name

            # Script definitely missing: suggest closest matches
            available = list(scripts.keys())
            closest = difflib.get_close_matches(script_name, available, n=3, cutoff=0.5)
            if closest:
                hint = f"Script '{script_name}' not found in package.json. Did you mean: {', '.join(closest)}?"
            else:
                hint = f"Script '{script_name}' not found in package.json 'scripts'."

            return False, hint, script_name

    # 2. make <target>
    elif raw_bin in ("make", "mingw32-make"):
        if args and not args[0].startswith("-"):
            target_name = args[0]
            targets = load_makefile_targets(cwd, workspace_root)
            if targets is not None:
                if target_name in targets:
                    return True, "", target_name

                closest = difflib.get_close_matches(target_name, targets, n=3, cutoff=0.5)
                if closest:
                    hint = f"Target '{target_name}' not found in Makefile. Did you mean: {', '.join(closest)}?"
                else:
                    hint = f"Target '{target_name}' not found in Makefile."

                return False, hint, target_name

    return True, "", ""
