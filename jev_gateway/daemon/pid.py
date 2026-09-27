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

def get_process_cmdline(pid: int) -> Optional[str]:
    """
    Retrieves the command line string for a process by PID across platforms.
    On Windows: uses NtQueryInformationProcess (class 60) with PROCESS_QUERY_LIMITED_INFORMATION.
    On Linux: reads /proc/{pid}/cmdline.
    On macOS / BSD: invokes 'ps -p {pid} -o command='.
    Guaranteed never to access ctypes.windll on non-Windows platforms.
    """
    if pid <= 0:
        return None

    if sys.platform == "win32":
        try:
            import ctypes
            from ctypes import wintypes

            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

            class UNICODE_STRING(ctypes.Structure):
                _fields_ = [
                    ("Length", wintypes.USHORT),
                    ("MaximumLength", wintypes.USHORT),
                    ("Buffer", wintypes.LPWSTR),
                ]

            handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if not handle:
                return None
            try:
                ret_len = wintypes.ULONG()
                # ProcessCommandLineInformation = 60
                status = ctypes.windll.ntdll.NtQueryInformationProcess(
                    handle, 60, None, 0, ctypes.byref(ret_len)
                )
                if ret_len.value == 0:
                    return None
                buf = ctypes.create_string_buffer(ret_len.value)
                status2 = ctypes.windll.ntdll.NtQueryInformationProcess(
                    handle, 60, buf, ret_len.value, ctypes.byref(ret_len)
                )
                if status2 == 0:
                    p_unicode = ctypes.cast(buf, ctypes.POINTER(UNICODE_STRING))
                    raw_chars = buf[ctypes.sizeof(UNICODE_STRING):ctypes.sizeof(UNICODE_STRING) + p_unicode.contents.Length]
                    return raw_chars.decode("utf-16le", errors="replace")
                return None
            finally:
                ctypes.windll.kernel32.CloseHandle(handle)
        except Exception:
            return None
    else:
        # POSIX (Linux / macOS / BSD)
        # 1. Linux /proc filesystem
        proc_cmdline = Path(f"/proc/{pid}/cmdline")
        if proc_cmdline.exists():
            try:
                raw = proc_cmdline.read_bytes()
                # Arguments in /proc/cmdline are separated by null bytes (\x00)
                cmd = raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
                if cmd:
                    return cmd
            except Exception:
                pass

        # 2. macOS / BSD fallback via ps command
        try:
            import subprocess
            res = subprocess.run(
                ["ps", "-p", str(pid), "-o", "command="],
                capture_output=True,
                text=True,
                timeout=1.0,
            )
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout.strip()
        except Exception:
            pass

        return None


def is_process_running(pid: int, expected_signature: Optional[str] = None) -> bool:
    """
    Cross-platform check whether a process with given PID is currently active.
    If expected_signature is specified, verifies that the process's command line
    matches the daemon invocation (e.g. 'jev_gateway.daemon.server' or 'jev-daemon'),
    preventing recycled-PID false positives when another Python process reuses the PID.
    """
    if pid <= 0:
        return False

    is_alive = False
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
                    is_alive = (exit_code.value == STILL_ACTIVE)
            finally:
                ctypes.windll.kernel32.CloseHandle(handle)
        except Exception:
            try:
                os.kill(pid, 0)
                is_alive = True
            except (OSError, SystemError):
                return False
    else:
        try:
            os.kill(pid, 0)
            is_alive = True
        except (ProcessLookupError, PermissionError):
            is_alive = True
        except OSError:
            return False

    if not is_alive:
        return False

    # If an expected signature is required, verify process command line
    if expected_signature:
        # Same process is always accepted
        if pid == os.getpid():
            return True

        cmdline = get_process_cmdline(pid)
        if cmdline is None:
            # If command line could not be inspected, verify at least image name is Python on Windows
            if sys.platform == "win32":
                try:
                    import ctypes
                    from ctypes import wintypes
                    handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
                    if handle:
                        try:
                            buf = ctypes.create_unicode_buffer(1024)
                            size = wintypes.DWORD(1024)
                            if ctypes.windll.kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
                                return "python" in Path(buf.value).name.lower()
                        finally:
                            ctypes.windll.kernel32.CloseHandle(handle)
                except Exception:
                    pass
            return False

        sig_lower = expected_signature.lower()
        cmd_lower = cmdline.lower()
        return (
            sig_lower in cmd_lower
            or "jev_gateway.daemon.server" in cmd_lower
            or "jev-daemon" in cmd_lower
            or "jev_gateway" in cmd_lower
        )

    return True

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
        If a stale PID file exists (dead or unrelated process), it is cleaned up automatically.
        """
        pid = self.read_pid()
        if pid is None:
            return False

        if is_process_running(pid, expected_signature="jev_gateway.daemon.server"):
            return True

        # Process is dead or unrelated; clean up stale files
        logger.info("Found stale PID file for non-daemon or dead process %d. Cleaning up.", pid)
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
