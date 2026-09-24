"""
PID and lifecycle management for the Jev Gateway daemon.
Handles PID tracking, stale process detection, and clean file teardown.
"""

from typing import Optional, Dict, Any
from pathlib import Path
import os
import sys
import json
import logging

logger = logging.getLogger(__name__)

def is_process_running(pid: int) -> bool:
    """
    Cross-platform check whether a process with given PID is currently active.
    """
    if pid <= 0:
        return False

    if sys.platform == "win32":
        try:
            import ctypes
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            SYNCHRONIZE = 0x00100000
            handle = ctypes.windll.kernel32.OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, False, pid
            )
            if not handle:
                return False
            try:
                exit_code = ctypes.c_ulong()
                if ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                    STILL_ACTIVE = 259
                    return exit_code.value == STILL_ACTIVE
                return False
            finally:
                ctypes.windll.kernel32.CloseHandle(handle)
        except Exception:
            # Fallback to os.kill if ctypes fails
            try:
                os.kill(pid, 0)
                return True
            except (OSError, SystemError):
                return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except (ProcessLookupError, PermissionError):
            return True
        except OSError:
            return False

class PIDManager:
    """
    Manages the lifecycle of PID, token, and socket files for the daemon.
    """

    def __init__(
        self,
        pid_file: Path,
        socket_path: Optional[Path] = None,
        token_file: Optional[Path] = None,
    ):
        self.pid_file = Path(pid_file).expanduser().resolve()
        self.socket_path = Path(socket_path).expanduser().resolve() if socket_path else None
        self.token_file = Path(token_file).expanduser().resolve() if token_file else None

    def read_pid(self) -> Optional[int]:
        """
        Reads the PID from the PID file if it exists and is valid.
        """
        if not self.pid_file.is_file():
            return None
        try:
            content = self.pid_file.read_text(encoding="utf-8").strip()
            if not content:
                return None
            # If JSON, extract "pid", otherwise parse first line as int
            if content.startswith("{"):
                data = json.loads(content)
                return int(data.get("pid", 0))
            return int(content.splitlines()[0].strip())
        except Exception as e:
            logger.warning("Failed to parse PID file %s: %s", self.pid_file, e)
            return None

    def is_running(self) -> bool:
        """
        Returns True if another instance of the daemon is actively running.
        If a stale PID file exists, it is cleaned up automatically.
        """
        pid = self.read_pid()
        if pid is None:
            return False

        if is_process_running(pid):
            return True

        # Process is dead; clean up stale files
        logger.info("Found stale PID file for dead process %d. Cleaning up.", pid)
        self.cleanup()
        return False

    def write_pid(self, metadata: Optional[Dict[str, Any]] = None) -> None:
        """
        Writes current process PID and metadata to the PID file.
        """
        self.pid_file.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "pid": os.getpid(),
            "started_at": metadata.get("started_at") if metadata else None,
            "transport": metadata.get("transport") if metadata else None,
            "port": metadata.get("port") if metadata else None,
        }
        self.pid_file.write_text(json.dumps(record, indent=2), encoding="utf-8")

    def cleanup(self) -> None:
        """
        Safely removes the PID file, socket file, and token file.
        """
        for path in (self.pid_file, self.socket_path, self.token_file):
            if path and path.exists():
                try:
                    if path.is_file() or path.is_socket():
                        path.unlink()
                except Exception as e:
                    logger.warning("Failed to delete %s during cleanup: %s", path, e)
