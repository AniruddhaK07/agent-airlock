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
        if not raw_in or not raw_in.strip():
            sys.stdout.write(json.dumps({
                "version": "1.0",
                "status": "ignored",
                "reason": "Empty PostToolUse input received.",
            }) + "\n")
            return

        payload = json.loads(raw_in)
        client = StubHookClient(enable_autospawn=False)
        res = client.send_request("PostToolUse", payload)
        sys.stdout.write(json.dumps(res) + "\n")
    except Exception as e:
        sys.stdout.write(json.dumps({
            "version": "1.0",
            "status": "error",
            "reason": f"PostToolUse hook exception: {e}",
        }) + "\n")

if __name__ == "__main__":
    main()
