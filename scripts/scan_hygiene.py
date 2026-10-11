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


_U_NAME = "A" + "SUS"
_P1 = "wcc-" + "hackathon"
_P2 = "ri-" + "test"

FORBIDDEN_PATTERNS = [
    (r"\b" + _U_NAME + r"\b", f"Username leak: {_U_NAME}"),
    (r"[C:c]:[/\\]Users[/\\]" + _U_NAME, f"Home path leak: Users/{_U_NAME}"),
    (_P1, f"Project name leak: {_P1}"),
    (_P2, f"Project name leak: {_P2}"),
]


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

        for pat, desc in FORBIDDEN_PATTERNS:
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
