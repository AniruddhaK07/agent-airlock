"""
Hooks package for Antigravity lifecycle hooks.
"""

from agent_airlock.hooks.stub_client import StubHookClient
from agent_airlock.hooks.installer import generate_hooks_config, install_hooks

__all__ = ["StubHookClient", "generate_hooks_config", "install_hooks"]
