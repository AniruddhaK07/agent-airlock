"""
Antigravity CLI PreToolUse Lifecycle Hook.
Reads tool call payload from stdin, queries the running Jev Airlock daemon,
and writes the gating decision JSON to stdout. Strictly fails closed to 'ask'.
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
        if not raw_in or not raw_in.strip():
            sys.stdout.write(json.dumps({
                "version": "1.0",
                "status": "fail_closed",
                "decision": "ask",
                "reason": "Empty hook input received; failing closed to human confirmation.",
            }) + "\n")
            return

        payload = json.loads(raw_in)
        client = StubHookClient()
        res = client.send_request("PreToolUse", payload)
        sys.stdout.write(json.dumps(res) + "\n")
    except Exception as e:
        sys.stdout.write(json.dumps({
            "version": "1.0",
            "status": "fail_closed",
            "decision": "ask",
            "reason": f"PreToolUse hook exception ({e}); failing closed to human confirmation.",
        }) + "\n")

if __name__ == "__main__":
    main()
