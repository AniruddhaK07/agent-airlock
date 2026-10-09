"""
Repo Hygiene Invariant Tests for Agent Airlock v2.
Verifies that no private data, traces, checkpoints, or heavy binary weights
are tracked in Git.
"""

import subprocess
from pathlib import Path
import pytest


def get_tracked_files() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True,
    )
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def test_no_forbidden_paths_tracked():
    tracked = get_tracked_files()

    forbidden_prefixes = [
        "data/traces/",
        "data\\traces\\",
        "private/",
        "private\\",
        "checkpoints/",
        "checkpoints\\",
    ]

    forbidden_extensions = {".onnx", ".pt", ".safetensors", ".bin"}
    allowlisted_fixtures = set()  # Allowlist any tiny mock fixtures here if ever needed

    violations = []

    for f in tracked:
        norm_f = f.replace("\\", "/")
        # Prefix check
        for p in forbidden_prefixes:
            norm_p = p.replace("\\", "/")
            if norm_f.startswith(norm_p):
                violations.append(f"Forbidden directory: {f}")

        # Extension check
        ext = Path(f).suffix.lower()
        if ext in forbidden_extensions and norm_f not in allowlisted_fixtures:
            violations.append(f"Forbidden model/weight extension ({ext}): {f}")

    assert not violations, "Tracked file repo hygiene violations found:\n" + "\n".join(violations)


def test_traces_directory_empty_in_git():
    result = subprocess.run(
        ["git", "ls-files", "data/traces"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True,
    )
    assert not result.stdout.strip(), f"data/traces has tracked files: {result.stdout.strip()}"
