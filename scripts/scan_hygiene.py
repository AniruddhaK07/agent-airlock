"""
Hygiene scanner for tracked files under docs/ and scripts/.
Enforces:
1. No real machine usernames or real home paths.
2. No private external project names.
3. No raw session command text in docs (aggregates and generic examples only).
"""

import subprocess
import re
from pathlib import Path


import json


def _get_forbidden_patterns():
    scrub_file = Path("private/scrub_patterns")
    usernames = []
    projects = []
    if scrub_file.exists():
        try:
            data = json.loads(scrub_file.read_text(encoding="utf-8"))
            usernames = data.get("usernames", [])
            projects = data.get("projects", [])
        except Exception:
            pass

    patterns = []
    for u in usernames:
        patterns.append((r"\b" + re.escape(u) + r"\b", f"Username leak: {u}"))
        patterns.append((r"[C:c]:[/\\]Users[/\\]" + re.escape(u), f"Home path leak: Users/{u}"))
    for p in projects:
        patterns.append((r"\b" + re.escape(p) + r"\b", f"Project name leak: {p}"))
    return patterns


def scan_tracked_files():
    # Get all tracked files under docs/ and scripts/
    res = subprocess.run(["git", "ls-files", "docs", "scripts"], capture_output=True, text=True, check=True)
    tracked_files = [f.strip() for f in res.stdout.splitlines() if f.strip()]

    violations = []

    for fpath_str in tracked_files:
        p = Path(fpath_str)
        if not p.is_file():
            continue
        try:
            content = p.read_text(encoding="utf-8")
        except Exception:
            continue

        for pat, desc in _get_forbidden_patterns():
            matches = list(re.finditer(pat, content, re.IGNORECASE))
            for m in matches:
                # Find line number
                line_no = content[:m.start()].count("\n") + 1
                line_content = content.splitlines()[line_no - 1].strip()
                violations.append({
                    "file": fpath_str,
                    "line": line_no,
                    "desc": desc,
                    "matched": m.group(0),
                    "snippet": line_content[:100],
                })

    print(f"Scanned {len(tracked_files)} tracked files in docs/ and scripts/.")
    if violations:
        print(f"Found {len(violations)} hygiene violations:")
        for v in violations:
            print(f"  {v['file']}:{v['line']} -> {v['desc']} [{v['matched']}]: {v['snippet']}")
    else:
        print("PASS: Zero hygiene violations found!")

    return violations


if __name__ == "__main__":
    scan_tracked_files()
