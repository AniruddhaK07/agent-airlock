"""
Antigravity CLI PostToolUse Lifecycle Hook.
Reads tool execution results from stdin and sends them to the Jev Airlock daemon
for rolling error recording and audit logging.
"""

import sys
import json
from pathlib import Path

_root = str(Path(__file__).resolve().parents[2])
if _root not in sys.path:
    sys.path.insert(0, _root)

from jev_gateway.hooks.stub_client import StubHookClient

def main():
    try:
        raw_in = sys.stdin.read()
        if raw_in and raw_in.strip():
            payload = json.loads(raw_in)
            client = StubHookClient(enable_autospawn=False)
            client.send_request("PostToolUse", payload)
    except Exception:
        pass
    finally:
        sys.stdout.write("{}\n")

if __name__ == "__main__":
    main()
