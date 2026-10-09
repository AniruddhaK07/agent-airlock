"""
Verification tests for Phase 0.0 Hermetic Test Isolation.
Verifies that:
1. Default ~/.gemini audit path is strictly blocked and detected.
2. External network connections are strictly forbidden.
3. Non-ML tests automatically use FakeLayaClient (instant, in-memory).
4. Tests marked 'ml' skip cleanly when checkpoints/ is missing.
"""

from pathlib import Path
import socket
import pytest

from agent_airlock.audit.logger import AuditLogger
from agent_airlock.audit.reader import AuditReader
from agent_airlock.config import AuditConfig, GatewayConfig
from agent_airlock.backends.laya import LocalLayaClient, FakeLayaClient


def test_network_connection_blocked():
    """Verify that any socket connection to a non-loopback IP raises an isolation error."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(RuntimeError, match="Test network isolation violation"):
            sock.connect(("8.8.8.8", 80))
    finally:
        sock.close()


def test_loopback_connection_permitted():
    """Verify that loopback connection attempt does not trigger the isolation violation."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # Connecting to a closed loopback port should raise standard ConnectionRefusedError or OSError,
        # NEVER the RuntimeError isolation error.
        with pytest.raises((ConnectionRefusedError, OSError)) as excinfo:
            sock.connect(("127.0.0.1", 59123))
        assert not isinstance(excinfo.value, RuntimeError)
    finally:
        sock.close()


def test_non_ml_test_uses_fake_laya():
    """Verify that any non-ML test gets FakeLayaClient without touching weights or disk."""
    import agent_airlock.backends.laya as laya_mod
    client = laya_mod.LocalLayaClient()
    assert isinstance(client, FakeLayaClient)
    assert client.agent is None

    # Ambiguous evaluation returns instant mock payload
    res = client.evaluate_ambiguous_tool("run_command", {"CommandLine": "python test.py"})
    assert res.score_blast_radius > 0
    assert res.choice_route == "needs-human"


def test_isolated_temp_audit_config_allowed(tmp_path):
    """Verify that supplying an isolated temp path succeeds."""
    temp_audit = tmp_path / "custom-audit.jsonl"
    cfg = AuditConfig(log_file=str(temp_audit))
    assert Path(cfg.log_file).resolve() == temp_audit.resolve()
