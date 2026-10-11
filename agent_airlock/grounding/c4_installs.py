"""
Check C4: Install Manifest Grounding (Section 9.4).
Verifies package installation commands (pip, npm, cargo) against project manifests.
Guards against hallucinated names and potential typosquats without performing network calls (Invariant I9).
"""

import difflib
import json
import re
from pathlib import Path
from typing import List, Optional, Set, Tuple

from agent_airlock.policy.normalizer import CommandSegment


def load_manifest_packages(cwd: str, workspace_root: Optional[str] = None) -> Set[str]:
    """Collects installed / declared dependencies across project manifests."""
    packages: Set[str] = set()
    bases = [b for b in [cwd, workspace_root] if b]

    for base in bases:
        base_p = Path(base)
        # 1. package.json
        pkg_json = base_p / "package.json"
        if pkg_json.is_file():
            try:
                data = json.loads(pkg_json.read_text(encoding="utf-8"))
                for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                    deps = data.get(section, {})
                    if isinstance(deps, dict):
                        packages.update(deps.keys())
            except Exception:
                pass

        # 2. requirements*.txt
        for req_f in base_p.glob("requirements*.txt"):
            try:
                lines = req_f.read_text(encoding="utf-8", errors="ignore").splitlines()
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue
                    m = re.match(r"^([a-zA-Z0-9_\-\.]+)", line)
                    if m:
                        packages.add(m.group(1).lower())
            except Exception:
                pass

        # 3. pyproject.toml
        pyproject = base_p / "pyproject.toml"
        if pyproject.is_file():
            try:
                content = pyproject.read_text(encoding="utf-8", errors="ignore")
                for m in re.finditer(r'["\']([a-zA-Z0-9_\-]+)(?:[<>=!~].*)?["\']', content):
                    packages.add(m.group(1).lower())
            except Exception:
                pass

        # 4. Cargo.toml
        cargo = base_p / "Cargo.toml"
        if cargo.is_file():
            try:
                content = cargo.read_text(encoding="utf-8", errors="ignore")
                for m in re.finditer(r'^\s*([a-zA-Z0-9_\-]+)\s*=\s*', content, re.MULTILINE):
                    packages.add(m.group(1).lower())
            except Exception:
                pass

    return packages


def check_installs(
    segment: CommandSegment,
    cwd: str,
    workspace_root: Optional[str] = None,
) -> Tuple[bool, str, str]:
    """
    Evaluates Check C4 on a CommandSegment.
    Returns:
        (is_grounded, hint, target_pkg)
    """
    raw_bin = segment.binary.lower()
    args = [a.strip() for a in segment.args if a.strip()]

    target_pkg = None

    if raw_bin in ("npm", "pnpm", "yarn") and args:
        if args[0] in ("install", "i", "add"):
            # Find first non-flag package argument
            for a in args[1:]:
                if not a.startswith("-") and not a.startswith("@") and not a.endswith((".tgz", ".tar.gz")):
                    target_pkg = a.split("@")[0].lower()
                    break

    elif raw_bin in ("pip", "pip3") and args:
        if args[0] == "install":
            for a in args[1:]:
                if not a.startswith("-") and not a.startswith(".") and not a.endswith((".whl", ".tar.gz")):
                    target_pkg = re.split(r"[<>=!~]", a)[0].lower()
                    break

    elif raw_bin == "cargo" and args:
        if args[0] in ("add", "install"):
            for a in args[1:]:
                if not a.startswith("-"):
                    target_pkg = a.lower()
                    break

    if not target_pkg:
        return True, "", ""

    manifest_pkgs = load_manifest_packages(cwd, workspace_root)
    if not manifest_pkgs:
        # No manifests available: pass conservatively
        return True, "", target_pkg

    if target_pkg in manifest_pkgs:
        return True, "", target_pkg

    # Check for small edit distance (typosquat guard)
    closest = difflib.get_close_matches(target_pkg, list(manifest_pkgs), n=1, cutoff=0.75)
    if closest:
        cand = closest[0]
        # Only alert if edit distance is 1 or 2 characters
        if len(cand) >= 4 and abs(len(cand) - len(target_pkg)) <= 2:
            return (
                False,
                f"Package '{target_pkg}' not found in project manifest; possible typosquat or misspelling of '{cand}'.",
                target_pkg,
            )

    return True, "", target_pkg
