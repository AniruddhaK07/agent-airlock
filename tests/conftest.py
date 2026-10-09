"""
Hermetic test isolation and safety fixtures for Agent Airlock.
Enforces:
1. Zero access to the default/live ~/.gemini/... audit log path.
2. Complete network isolation (blocks non-loopback socket connections).
3. Automatic substitution of FakeLayaClient for non-ML daemon tests to eliminate ~12s teardown blocks.
4. Auto-skipping of tests marked 'ml' when local checkpoints/ are missing.
"""

from pathlib import Path
import socket
import sys
import pytest

from agent_airlock.audit.logger import AuditLogger
from agent_airlock.audit.reader import AuditReader
from agent_airlock.config import AuditConfig
from agent_airlock.backends.laya import FakeLayaClient, DEFAULT_CHECKPOINT
import agent_airlock.backends.laya as laya_module


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "ml: mark test as requiring the real local ML model checkpoint"
    )


def pytest_runtest_setup(item):
    if item.get_closest_marker("ml"):
        if not Path(DEFAULT_CHECKPOINT).exists():
            pytest.skip(
                f"Real ML checkpoint missing at {DEFAULT_CHECKPOINT}; skipping ml test '{item.name}'"
            )


@pytest.fixture(autouse=True)
def guard_test_isolation(request, monkeypatch):
    """
    Autouse fixture that strictly prevents tests from touching live user configurations,
    making external network requests, or waiting for heavy model loads in non-ML tests.
    """
    gemini_dir = Path("~/.gemini").expanduser().resolve()
    default_audit_file = (gemini_dir / "antigravity-cli" / "audit.jsonl").resolve()

    def assert_safe_audit_path(path_val, origin_cls):
        if not path_val:
            return
        try:
            resolved = Path(path_val).expanduser().resolve()
        except Exception:
            return
        if resolved == default_audit_file or gemini_dir in resolved.parents or str(gemini_dir) in str(resolved):
            pytest.fail(
                f"Test isolation violation in '{request.node.name}': {origin_cls} "
                f"attempted to use default/live audit log path: '{path_val}'. "
                f"All tests must use an isolated temp path."
            )

    # 1. Audit log isolation guard
    orig_logger_init = AuditLogger.__init__
    def guarded_logger_init(self, *args, **kwargs):
        log_path = kwargs.get("log_path") if "log_path" in kwargs else (args[0] if args else None)
        assert_safe_audit_path(log_path, "AuditLogger")
        return orig_logger_init(self, *args, **kwargs)

    orig_reader_init = AuditReader.__init__
    def guarded_reader_init(self, *args, **kwargs):
        log_path = kwargs.get("log_path") if "log_path" in kwargs else (args[0] if args else None)
        assert_safe_audit_path(log_path, "AuditReader")
        return orig_reader_init(self, *args, **kwargs)

    orig_config_init = AuditConfig.__init__
    def guarded_config_init(self, *args, **kwargs):
        res = orig_config_init(self, *args, **kwargs)
        if hasattr(self, "log_file"):
            assert_safe_audit_path(self.log_file, "AuditConfig")
        return res

    monkeypatch.setattr(AuditLogger, "__init__", guarded_logger_init)
    monkeypatch.setattr(AuditReader, "__init__", guarded_reader_init)
    monkeypatch.setattr(AuditConfig, "__init__", guarded_config_init)

    # 2. Network guard: prevent any external network access in tests
    orig_connect = socket.socket.connect
    def guarded_connect(sock_self, address):
        if isinstance(address, str):
            # AF_UNIX domain socket path
            return orig_connect(sock_self, address)
        if isinstance(address, tuple) and len(address) >= 2:
            host, _port = address[0], address[1]
            if host in ("127.0.0.1", "localhost", "::1", "0.0.0.0"):
                return orig_connect(sock_self, address)
        raise RuntimeError(
            f"Test network isolation violation in '{request.node.name}': "
            f"attempted connection to external address {address}. No network allowed in tests."
        )

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setenv("HF_HUB_OFFLINE", "1")
    monkeypatch.setenv("TRANSFORMERS_OFFLINE", "1")

    # 3. Fake Laya client for non-ML tests (eliminates ~12s model loading wait during teardown)
    if not request.node.get_closest_marker("ml"):
        monkeypatch.setattr(laya_module, "LocalLayaClient", FakeLayaClient)
        if "agent_airlock.backends" in sys.modules:
            monkeypatch.setattr(sys.modules["agent_airlock.backends"], "LocalLayaClient", FakeLayaClient)
        monkeypatch.setattr(laya_module, "get_laya_agent", lambda *a, **kw: FakeLayaClient())

    yield
