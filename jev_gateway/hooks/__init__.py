"""
Hooks package for Antigravity lifecycle hooks.
"""

from jev_gateway.hooks.stub_client import StubHookClient
from jev_gateway.hooks.installer import generate_hooks_config, install_hooks

__all__ = ["StubHookClient", "generate_hooks_config", "install_hooks"]
