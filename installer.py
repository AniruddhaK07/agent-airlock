"""
Root entrypoint for Agent Airlock hook installer.
Provides convenient CLI execution: python installer.py [--global]
"""

from agent_airlock.hooks.installer import main

if __name__ == "__main__":
    main()
