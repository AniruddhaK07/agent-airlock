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

from agent_airlock.hooks.stub_client import StubHookClient

def main():
    try:
        raw_in = sys.stdin.read()
        if not raw_in or not raw_in.strip():
            sys.stdout.write(json.dumps({"decision": "ask", "reason": "Empty hook input"}) + "\n")
            return

        payload = json.loads(raw_in)
        client = StubHookClient()
        res = client.send_request("PreToolUse", payload)
        out = {"decision": res.get("decision", "ask")}
        for field in ("reason", "permissionOverrides", "overwrite"):
            if res.get(field):
                out[field] = res[field]
        sys.stdout.write(json.dumps(out) + "\n")
    except Exception as e:
        sys.stdout.write(json.dumps({"decision": "ask", "reason": f"PreToolUse exception ({e})"}) + "\n")

if __name__ == "__main__":
    main()
