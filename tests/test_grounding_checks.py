"""
Unit and integration tests for L0 Grounding subsystem (Section 9.4).
Verifies Checks C1, C2, C3, C4, shadow mode logging, and enforce mode denial.
"""

import json
from pathlib import Path
import tempfile
import pytest

from agent_airlock.config import GroundingConfig, GroundingChecksConfig
from agent_airlock.grounding import GroundingEngine, GroundingCheckType, GroundingResult
from agent_airlock.daemon.router import IPCRouter
from agent_airlock.policy.engine import HardPolicyEngine
from agent_airlock.policy.normalizer import parse_command_segments


@pytest.fixture
def temp_workspace():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir).resolve()


class TestC1BinaryGrounding:
    def test_builtins_and_cmdlets_pass(self, temp_workspace):
        engine = GroundingEngine(GroundingConfig(mode="enforce"))
        # PowerShell cmdlets and builtins
        for cmd in ["Get-ChildItem", "Get-Content", "Select-Object -First 5", "echo hello", "dir", "ls", "cd ..", "exit 0"]:
            res = engine.evaluate("run_command", {"CommandLine": cmd}, cwd=str(temp_workspace))
            assert res.status == "pass", f"Expected '{cmd}' to pass as builtin, got: {res.hint}"

    def test_known_system_binaries_pass(self, temp_workspace):
        engine = GroundingEngine(GroundingConfig(mode="enforce"))
        for cmd in ["python --version", "git status"]:
            res = engine.evaluate("run_command", {"CommandLine": cmd}, cwd=str(temp_workspace))
            assert res.status == "pass", f"Expected '{cmd}' to pass, got: {res.hint}"

    def test_nonexistent_binary_fails_enforce(self, temp_workspace):
        engine = GroundingEngine(GroundingConfig(mode="enforce"))
        res = engine.evaluate("run_command", {"CommandLine": "nonexistent_cli_tool_999 --version"}, cwd=str(temp_workspace))
        assert res.status == "fail"
        assert res.check_id == GroundingCheckType.C1_BINARY.value
        assert "Binary 'nonexistent_cli_tool_999' not found in PATH or cwd" in res.hint

    def test_relative_path_resolution(self, temp_workspace):
        engine = GroundingEngine(GroundingConfig(mode="enforce"))
        # 1. Existing script in cwd
        script_file = temp_workspace / "run_test.py"
        script_file.write_text("print(1)")

        res = engine.evaluate("run_command", {"CommandLine": "./run_test.py"}, cwd=str(temp_workspace))
        assert res.status == "pass"

        # 2. Missing script in cwd
        res_missing = engine.evaluate("run_command", {"CommandLine": "./missing_exec.sh"}, cwd=str(temp_workspace))
        assert res_missing.status == "fail"
        assert res_missing.check_id == GroundingCheckType.C1_BINARY.value
        assert "Executable or script not found at path" in res_missing.hint

    def test_preceded_by_build_step_passes(self, temp_workspace):
        # Create dummy make build tool in cwd so C1 binary check passes
        (temp_workspace / "make.bat").write_text("@echo off\n")
        engine = GroundingEngine(GroundingConfig(mode="enforce"))
        # In a build chain, the target binary will be produced by make/cargo/npm
        cmd = "make && ./build/output_binary"
        res = engine.evaluate("run_command", {"CommandLine": cmd}, cwd=str(temp_workspace))
        assert res.status == "pass", f"Chain with build step should pass, got: {res.hint}"

    def test_dynamic_syntax_passes_conservatively(self, temp_workspace):
        engine = GroundingEngine(GroundingConfig(mode="enforce"))
        for cmd in ["$cmd_var --arg", "=(Get-Process)", "=live : not recognized"]:
            res = engine.evaluate("run_command", {"CommandLine": cmd}, cwd=str(temp_workspace))
            assert res.status == "pass", f"Dynamic syntax '{cmd}' must pass conservatively"

    def test_shell_wrappers_unwrapped(self, temp_workspace):
        engine = GroundingEngine(GroundingConfig(mode="enforce"))
        # Sudo unwrapping with valid binary
        res_ok = engine.evaluate("run_command", {"CommandLine": "sudo git status"}, cwd=str(temp_workspace))
        assert res_ok.status == "pass"

        # Sudo unwrapping with missing binary
        res_fail = engine.evaluate("run_command", {"CommandLine": "sudo missing_daemon_bin start"}, cwd=str(temp_workspace))
        assert res_fail.status == "fail"
        assert "missing_daemon_bin" in res_fail.hint


class TestC2FilesGrounding:
    def test_view_file_existing_passes(self, temp_workspace):
        engine = GroundingEngine(GroundingConfig(mode="enforce"))
        f = temp_workspace / "README.md"
        f.write_text("# Hello")
        res = engine.evaluate("view_file", {"TargetFile": str(f)}, cwd=str(temp_workspace))
        assert res.status == "pass"

    def test_view_file_nonexistent_fails(self, temp_workspace):
        engine = GroundingEngine(GroundingConfig(mode="enforce"))
        missing = temp_workspace / "phantom_file.txt"
        res = engine.evaluate("view_file", {"TargetFile": str(missing)}, cwd=str(temp_workspace))
        assert res.status == "fail"
        assert res.check_id == GroundingCheckType.C2_FILES.value
        assert "File does not exist" in res.hint

    def test_write_to_file_parent_exists_passes(self, temp_workspace):
        engine = GroundingEngine(GroundingConfig(mode="enforce"))
        # Target file does not exist yet, but parent directory does
        new_file = temp_workspace / "new_file.py"
        res = engine.evaluate("write_to_file", {"TargetFile": str(new_file)}, cwd=str(temp_workspace))
        assert res.status == "pass"

    def test_write_to_file_parent_missing_fails(self, temp_workspace):
        engine = GroundingEngine(GroundingConfig(mode="enforce"))
        deep_missing = temp_workspace / "missing_dir" / "subdir" / "new_file.py"
        res = engine.evaluate("write_to_file", {"TargetFile": str(deep_missing)}, cwd=str(temp_workspace))
        assert res.status == "fail"
        assert res.check_id == GroundingCheckType.C2_FILES.value
        assert "Parent directory does not exist" in res.hint

    def test_replace_file_content_missing_fails(self, temp_workspace):
        engine = GroundingEngine(GroundingConfig(mode="enforce"))
        missing = temp_workspace / "not_found.py"
        res = engine.evaluate("replace_file_content", {"TargetFile": str(missing)}, cwd=str(temp_workspace))
        assert res.status == "fail"
        assert "Target file for replacement does not exist" in res.hint


class TestC3ScriptsGrounding:
    def test_npm_run_valid_script_passes(self, temp_workspace):
        pkg = temp_workspace / "package.json"
        pkg.write_text(json.dumps({"scripts": {"build": "tsc", "test": "jest"}}))

        engine = GroundingEngine(GroundingConfig(mode="enforce"))
        res = engine.evaluate("run_command", {"CommandLine": "npm run build"}, cwd=str(temp_workspace))
        assert res.status == "pass"

    def test_npm_run_missing_script_with_typo_suggests(self, temp_workspace):
        pkg = temp_workspace / "package.json"
        pkg.write_text(json.dumps({"scripts": {"build": "tsc", "test": "jest"}}))

        engine = GroundingEngine(GroundingConfig(mode="enforce"))
        res = engine.evaluate("run_command", {"CommandLine": "npm run buidl"}, cwd=str(temp_workspace))
        assert res.status == "fail"
        assert res.check_id == GroundingCheckType.C3_SCRIPTS.value
        assert "Did you mean: build?" in res.hint

    def test_make_target_grounding(self, temp_workspace):
        (temp_workspace / "make.bat").write_text("@echo off\n")
        makefile = temp_workspace / "Makefile"
        makefile.write_text("build:\n\t@echo ok\ntest:\n\t@echo test\n")

        engine = GroundingEngine(GroundingConfig(mode="enforce"))
        # Valid target
        res_ok = engine.evaluate("run_command", {"CommandLine": "make build"}, cwd=str(temp_workspace))
        assert res_ok.status == "pass"

        # Missing target with typo
        res_typo = engine.evaluate("run_command", {"CommandLine": "make bulid"}, cwd=str(temp_workspace))
        assert res_typo.status == "fail"
        assert res_typo.check_id == GroundingCheckType.C3_SCRIPTS.value
        assert "Did you mean: build?" in res_typo.hint


class TestC4InstallsGrounding:
    def test_installed_manifest_package_passes(self, temp_workspace):
        pkg = temp_workspace / "package.json"
        pkg.write_text(json.dumps({"dependencies": {"lodash": "^4.17.21"}}))

        engine = GroundingEngine(GroundingConfig(mode="enforce"))
        res = engine.evaluate("run_command", {"CommandLine": "npm install lodash"}, cwd=str(temp_workspace))
        assert res.status == "pass"

    def test_typosquat_package_detected(self, temp_workspace):
        reqs = temp_workspace / "requirements.txt"
        reqs.write_text("requests==2.31.0\npytest>=8.0.0\n")

        engine = GroundingEngine(GroundingConfig(mode="enforce"))
        # Misspelling of requests
        res = engine.evaluate("run_command", {"CommandLine": "pip install reqeusts"}, cwd=str(temp_workspace))
        assert res.status == "fail"
        assert res.check_id == GroundingCheckType.C4_INSTALLS.value
        assert "possible typosquat or misspelling of 'requests'" in res.hint


class TestRouterGroundingIntegration:
    def test_shadow_mode_does_not_deny_and_logs_metadata(self, temp_workspace):
        # Default shadow mode
        g_cfg = GroundingConfig(enabled=True, mode="shadow")
        router = IPCRouter(
            policy_engine=HardPolicyEngine(),
            grounding_config=g_cfg,
        )

        req = {
            "version": "1.0",
            "event": "PreToolUse",
            "payload": {
                "workspace_root": str(temp_workspace),
                "cwd": str(temp_workspace),
                "toolCall": {
                    "name": "run_command",
                    "args": {"CommandLine": "nonexistent_bin_xyz --test"},
                },
            },
        }

        resp = router.dispatch(req)
        # In shadow mode, it must NOT deny; falls through to normal pipeline decision (ask)
        assert resp["decision"] == "ask"
        assert resp["decision"] != "deny"

    def test_enforce_mode_denies_would_ask_with_hint(self, temp_workspace):
        g_cfg = GroundingConfig(enabled=True, mode="enforce")
        router = IPCRouter(
            policy_engine=HardPolicyEngine(),
            grounding_config=g_cfg,
        )

        req = {
            "version": "1.0",
            "event": "PreToolUse",
            "payload": {
                "workspace_root": str(temp_workspace),
                "cwd": str(temp_workspace),
                "toolCall": {
                    "name": "run_command",
                    "args": {"CommandLine": "nonexistent_bin_xyz --test"},
                },
            },
        }

        resp = router.dispatch(req)
        assert resp["decision"] == "deny"
        assert resp["ruleId"] == "grounding-c1"
        assert "Binary 'nonexistent_bin_xyz' not found in PATH or cwd" in resp["reason"]

    def test_enforce_mode_preserves_l1_security_hard_deny(self, temp_workspace):
        g_cfg = GroundingConfig(enabled=True, mode="enforce")
        router = IPCRouter(
            policy_engine=HardPolicyEngine(),
            grounding_config=g_cfg,
        )

        # Command targets credentials/secrets: L1 hard-deny must win over L0
        req = {
            "version": "1.0",
            "event": "PreToolUse",
            "payload": {
                "workspace_root": str(temp_workspace),
                "cwd": str(temp_workspace),
                "toolCall": {
                    "name": "run_command",
                    "args": {"CommandLine": "nonexistent_bin .ssh/id_rsa"},
                },
            },
        }

        resp = router.dispatch(req)
        assert resp["decision"] == "deny"
        # Must be denied by security rule, not L0 grounding!
        assert "credentials" in resp["ruleId"]
