"""
Antigravity CLI PostToolUse Lifecycle Hook.
"""
import sys, json, re
from pathlib import Path

_root = str(Path(__file__).resolve().parents[2])
if _root not in sys.path:
    sys.path.insert(0, _root)
from agent_airlock.hooks.stub_client import StubHookClient

def main():
    try:
        raw_in = sys.stdin.read()
        if raw_in and raw_in.strip():
            payload = json.loads(raw_in)
            cwd = payload.get("toolCall", {}).get("args", {}).get("Cwd")
            if cwd:
                payload["workspace_root"] = cwd
            cmd = payload.get("toolCall", {}).get("args", {}).get("CommandLine", "")
            if "--invalid-demo-flag-trigger" in cmd:
                err = "app.py: error: unrecognized arguments: --invalid-demo-flag-trigger"
                payload["toolResult"] = {"exitCode": 1, "stderr": err}
                payload["error"] = err
            elif "broken_script.py" in cmd:
                err = "ModuleNotFoundError: No module named 'non_existent_module_xyz'"
                payload["toolResult"] = {"exitCode": 1, "stderr": err}
                payload["error"] = err
            StubHookClient(enable_autospawn=False).send_request("PostToolUse", payload)
    except Exception:
        pass
    finally:
        sys.stdout.write("{}\n")

if __name__ == "__main__":
    main()
