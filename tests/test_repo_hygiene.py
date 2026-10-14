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


def test_docs_and_scripts_hygiene_no_leaks():
    """Scans all tracked files under docs/ and scripts/ for sensitive usernames, home paths, and project names."""
    import re
    result = subprocess.run(
        ["git", "ls-files", "docs", "scripts"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True,
    )
    tracked = [line.strip() for line in result.stdout.splitlines() if line.strip()]

    forbidden_patterns = [
        (r"\bASUS\b", "Username leak: ASUS"),
        (r"[C:c]:[/\\]Users[/\\]ASUS", "Home path leak: Users/ASUS"),
        (r"wcc-hackathon", "Project name leak: wcc-hackathon"),
        (r"ri-test", "Project name leak: ri-test"),
    ]

    violations = []
    for f in tracked:
        p = Path(f)
        if not p.is_file():
            continue
        try:
            content = p.read_text(encoding="utf-8")
        except Exception:
            continue

        for pat, desc in forbidden_patterns:
            matches = list(re.finditer(pat, content, re.IGNORECASE))
            for m in matches:
                line_no = content[:m.start()].count("\n") + 1
                violations.append(f"{f}:{line_no} [{desc}] -> {m.group(0)}")

    assert not violations, "Docs/scripts hygiene violations found:\n" + "\n".join(violations)


def test_no_real_session_commands_in_tracked_files():
    """Verifies that tracked files never contain review sheets or real session command text."""
    result = subprocess.run(
        ["git", "ls-files"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True,
    )
    tracked = [line.strip() for line in result.stdout.splitlines() if line.strip()]

    # 1. Real trace review sheets must never be tracked
    for f in tracked:
        norm_f = f.replace("\\", "/").lower()
        if f.endswith((".jsonl", ".md", ".csv")):
            assert not ("review-sheet-1" in norm_f or "review_sheet" in norm_f), (
                f"Real trace review sheet file must not be tracked in git: {f}"
            )

    # 2. Tracked docs must never hold raw session command scripts or session audit reads
    session_indicators = [
        "AuditReader().read_all()",
        "condA = '401271c2-",
        "condB = '630290f8-",
        "test_verify_quantity_log.py",
        "post_tool_debug.json",
        "smoke-nav-test.js",
    ]

    doc_files = [f for f in tracked if f.startswith("docs/") or f.startswith("docs\\")]
    for doc_f in doc_files:
        p = Path(doc_f)
        if not p.is_file():
            continue
        try:
            content = p.read_text(encoding="utf-8")
        except Exception:
            continue
        for indicator in session_indicators:
            assert indicator not in content, (
                f"Tracked doc '{doc_f}' contains real session command text / indicator: '{indicator}'"
            )


def test_fixtures_hygiene_no_leaks():
    """Scans all tracked fixture files under tests/ for sensitive usernames, home paths, project names, and real UUIDs."""
    import re
    result = subprocess.run(
        ["git", "ls-files", "tests"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True,
    )
    tracked = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    fixture_files = [f for f in tracked if "fixture" in f.lower() or f.endswith((".json", ".jsonl", ".yaml", ".yml"))]

    forbidden_patterns = [
        (r"\bASUS\b", "Username leak: ASUS"),
        (r"\bAniruddha(K07)?\b", "Username leak: Aniruddha"),
        (r"aniruddhadiware5@gmail\.com", "Email leak"),
        (r"[C:c]:[/\\]Users[/\\](?!dev_user\b)[a-zA-Z0-9_\-]+", "Real user home path leak"),
        (r"/home/(?!dev_user\b)[a-zA-Z0-9_\-]+", "Real posix home path leak"),
        (r"\bsva-harness\b", "Project name leak: sva-harness"),
        (r"\bkaizen\b", "Project name leak: kaizen"),
        (r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "Real UUID leak"),
    ]

    violations = []
    for f in fixture_files:
        p = Path(f)
        if not p.is_file():
            continue
        try:
            content = p.read_text(encoding="utf-8")
        except Exception:
            continue

        # Ignore placeholder zero-UUIDs like 00000000-0000-0000-0000-000000000000
        scrubbed_for_check = content.replace("00000000-0000-0000-0000-000000000000", "")

        for pat, desc in forbidden_patterns:
            matches = list(re.finditer(pat, scrubbed_for_check, re.IGNORECASE))
            for m in matches:
                line_no = scrubbed_for_check[:m.start()].count("\n") + 1
                violations.append(f"{f}:{line_no} [{desc}] -> {m.group(0)}")

    assert not violations, "Tests fixture hygiene violations found:\n" + "\n".join(violations)

