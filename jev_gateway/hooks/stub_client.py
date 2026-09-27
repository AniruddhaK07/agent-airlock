"""
Fail-Closed Hook Stub Client.
A lightweight, robust client used by lifecycle hooks to query the running daemon.
Supports auto-spawning the daemon on ENOENT/ECONNREFUSED with a 200ms deadline,
and guarantees fail-closed behavior ("force_ask" / "ask") on error or timeout.
"""

from typing import Dict, Any, Optional, Tuple, List
from pathlib import Path
import socket
import json
import time
import sys
import subprocess
import logging

from jev_gateway.config import GatewayConfig, load_config
from jev_gateway.daemon.lock import FileLock

logger = logging.getLogger(__name__)

class StubHookClient:
    """
    Lightweight IPC client designed for hook execution.
    Automatically connects via Unix domain socket or loopback TCP.
    Attempts detached auto-spawn on socket absence with a strict 200ms deadline,
    synchronized via a file lock to guarantee exactly one spawn across concurrent hooks.
    Fails closed to 'force_ask' or 'ask' on any error.
    """

    def __init__(
        self,
        config: Optional[GatewayConfig] = None,
        socket_path: Optional[str] = None,
        host: Optional[str] = None,
        port: Optional[int] = None,
        token_file: Optional[str] = None,
        pid_file: Optional[str] = None,
        lock_file: Optional[str] = None,
        timeout: Optional[float] = None,
        enable_autospawn: bool = True,
        spawn_command: Optional[List[str]] = None,
        spawn_timeout: Optional[float] = None,
        default_workspace: Optional[str] = None,
    ):
        cfg = config or load_config()
        self.socket_path = Path(socket_path or cfg.daemon.socket_path).expanduser().resolve()
        self.host = host or cfg.daemon.host
        self.port = port or cfg.daemon.tcp_port
        self.token_file = Path(token_file or cfg.daemon.token_file).expanduser().resolve()
        pid_p = Path(pid_file or cfg.daemon.pid_file).expanduser().resolve()
        self.lock_file = Path(lock_file or (str(pid_p) + ".lock")).expanduser().resolve()
        self.timeout = timeout or cfg.daemon.request_timeout_seconds
        self.enable_autospawn = enable_autospawn
        self.spawn_command = spawn_command or [sys.executable, "-m", "jev_gateway.daemon.server"]
        self.spawn_timeout = (
            spawn_timeout
            if spawn_timeout is not None
            else getattr(cfg.daemon, "spawn_timeout_seconds", 1.0)
        )
        self.default_workspace = default_workspace or str(Path.cwd())

    def send_request(self, event: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sends an ndjson request to the daemon and returns the parsed JSON response.
        If daemon is not running and autospawn is enabled, attempts auto-spawn within 200ms.
        Fails closed on any error.
        """
        try:
            return self._execute_ipc(event, payload)
        except (FileNotFoundError, ConnectionRefusedError, TimeoutError, ConnectionError, OSError) as e:
            if self.enable_autospawn:
                return self._attempt_autospawn_and_connect(event, payload)
            return {
                "version": "1.0",
                "status": "fail_closed",
                "decision": "ask",
                "reason": f"Safety daemon unreachable ({e}); failing closed to human confirmation.",
            }
        except Exception as e:
            return {
                "version": "1.0",
                "status": "fail_closed",
                "decision": "ask",
                "reason": f"Safety daemon communication failed ({e}); failing closed to human confirmation.",
            }

    def _connect_socket(self, timeout: Optional[float] = None) -> Tuple[socket.socket, Optional[str]]:
        effective_timeout = timeout if timeout is not None else self.timeout
        has_unix = hasattr(socket, "AF_UNIX")

        if has_unix and self.socket_path.exists():
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(effective_timeout)
            try:
                sock.connect(str(self.socket_path))
                return sock, None
            except Exception:
                sock.close()
                raise

        if has_unix and not self.socket_path.exists() and not self.token_file.exists():
            raise FileNotFoundError(f"Unix socket {self.socket_path} does not exist (ENOENT)")

        # Fallback to loopback TCP: if token file doesn't exist, daemon is offline (ENOENT)
        if not self.token_file.exists():
            raise FileNotFoundError(f"Daemon token file {self.token_file} does not exist (ENOENT)")

        auth_token = None
        try:
            auth_token = self.token_file.read_text(encoding="utf-8").strip()
        except Exception:
            pass

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(effective_timeout)
        try:
            sock.connect((self.host, self.port))
            return sock, auth_token
        except Exception:
            sock.close()
            raise

    def _send_and_recv(
        self,
        sock: socket.socket,
        auth_token: Optional[str],
        event: str,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        try:
            req_data = {
                "version": "1.0",
                "auth_token": auth_token,
                "event": event,
                "timestamp": time.time(),
                "payload": payload,
            }
            msg = json.dumps(req_data) + "\n"
            sock.sendall(msg.encode("utf-8"))

            buffer = ""
            while "\n" not in buffer:
                chunk = sock.recv(4096).decode("utf-8", errors="replace")
                if not chunk:
                    break
                buffer += chunk

            if not buffer.strip():
                raise ConnectionError("Empty response received from daemon.")

            line = buffer.strip().splitlines()[0]
            return json.loads(line)
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _execute_ipc(self, event: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        sock, auth_token = self._connect_socket()
        return self._send_and_recv(sock, auth_token, event, payload)

    def _spawn_daemon_process(self) -> Optional[Exception]:
        try:
            if sys.platform == "win32":
                DETACHED_PROCESS = 0x00000008
                CREATE_NEW_PROCESS_GROUP = 0x00000200
                proc = subprocess.Popen(
                    self.spawn_command,
                    creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
                    close_fds=True,
                )
                proc.returncode = 0
            else:
                proc = subprocess.Popen(
                    self.spawn_command,
                    start_new_session=True,
                    close_fds=True,
                )
                proc.returncode = 0
            return None
        except Exception as e:
            logger.warning("Failed to auto-spawn daemon process: %s", e)
            return e

    def _attempt_autospawn_and_connect(self, event: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Attempts race-safe auto-spawn using a file lock.
        Multiple concurrent hook processes synchronize on the lock file:
        - The first process acquires the lock, double-checks if the daemon has become ready,
          and if not, spawns the detached daemon process.
        - Subsequent processes wait on the lock (up to the 200ms deadline).
        - Once the daemon is listening, all waiting processes connect to the single instance
          without duplicate spawns.
        - If startup exceeds 200ms or fails, falls back to {"decision": "force_ask"}.
        """
        start_time = time.time()
        deadline = start_time + self.spawn_timeout
        lock = FileLock(self.lock_file)
        remaining = deadline - time.time()
        if remaining <= 0:
            return {
                "version": "1.0",
                "status": "fail_closed",
                "decision": "force_ask",
                "reason": f"Safety daemon auto-spawn exceeded {int(self.spawn_timeout * 1000)}ms; failing closed to human confirmation.",
            }

        try:
            got_lock = lock.acquire(timeout=remaining)
            if got_lock:
                # Double check: did another process complete startup while we waited for the lock?
                try:
                    sock, auth_token = self._connect_socket(timeout=0.015)
                    return self._send_and_recv(sock, auth_token, event, payload)
                except Exception:
                    pass

                # We hold the lock and the daemon is offline: spawn exactly once
                spawn_err = self._spawn_daemon_process()
                if spawn_err:
                    return {
                        "version": "1.0",
                        "status": "fail_closed",
                        "decision": "force_ask",
                        "reason": f"Safety daemon auto-spawn failed ({spawn_err}); failing closed to human confirmation.",
                    }

                # Poll socket until deadline
                while time.time() < deadline:
                    poll_remaining = deadline - time.time()
                    if poll_remaining <= 0:
                        break
                    poll_timeout = min(0.03, poll_remaining)
                    try:
                        sock, auth_token = self._connect_socket(timeout=poll_timeout)
                        return self._send_and_recv(sock, auth_token, event, payload)
                    except (FileNotFoundError, ConnectionRefusedError, TimeoutError, ConnectionError, socket.timeout, OSError):
                        time.sleep(0.010)

                # Exceeded 200ms deadline -> fail closed to force_ask
                return {
                    "version": "1.0",
                    "status": "fail_closed",
                    "decision": "force_ask",
                    "reason": f"Safety daemon auto-spawn exceeded {int(self.spawn_timeout * 1000)}ms; failing closed to human confirmation.",
                }
            else:
                # Did not acquire lock before remaining timeout.
                # Try a quick connection in case the winner finished starting the daemon:
                try:
                    sock, auth_token = self._connect_socket(timeout=0.015)
                    return self._send_and_recv(sock, auth_token, event, payload)
                except Exception:
                    return {
                        "version": "1.0",
                        "status": "fail_closed",
                        "decision": "force_ask",
                        "reason": f"Safety daemon auto-spawn exceeded {int(self.spawn_timeout * 1000)}ms; failing closed to human confirmation.",
                    }
        finally:
            lock.release()

    def check_tool(self, name: str, args: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Convenience wrapper for PreToolUse.
        """
        payload = {
            "toolCall": {
                "name": name,
                "args": args,
            }
        }
        if context:
            payload.update(context)
        elif self.default_workspace:
            payload["workspacePaths"] = [self.default_workspace]
        return self.send_request("PreToolUse", payload)

def main():
    """
    CLI entrypoint for testing hook client via stdin/stdout.
    """
    client = StubHookClient()
    try:
        raw_in = sys.stdin.read().strip()
        if not raw_in:
            payload = {}
        else:
            payload = json.loads(raw_in)
    except Exception as e:
        sys.stdout.write(json.dumps({
            "version": "1.0",
            "decision": "ask",
            "status": "fail_closed",
            "reason": f"Invalid hook stdin input: {e}; failing closed."
        }) + "\n")
        return

    result = client.send_request("PreToolUse", payload)
    sys.stdout.write(json.dumps(result) + "\n")

if __name__ == "__main__":
    main()
