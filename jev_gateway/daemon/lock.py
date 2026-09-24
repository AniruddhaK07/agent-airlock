"""
Cross-platform file locking for daemon synchronization and race-safe auto-spawn.
Uses msvcrt on Windows and fcntl on POSIX.
"""

from pathlib import Path
import os
import sys
import time
import logging

logger = logging.getLogger(__name__)

class FileLock:
    """
    Cross-platform inter-process file lock.
    """

    def __init__(self, lock_file: Path):
        self.lock_file = Path(lock_file).resolve()
        self._fd = None

    def acquire(self, timeout: float = 0.200, poll_interval: float = 0.010) -> bool:
        """
        Attempts to acquire the file lock within the timeout (in seconds).
        Returns True if acquired, False if timed out.
        """
        self.lock_file.parent.mkdir(parents=True, exist_ok=True)
        start = time.time()
        while True:
            if self._try_lock():
                return True
            if (time.time() - start) >= timeout:
                return False
            time.sleep(poll_interval)

    def _try_lock(self) -> bool:
        if self._fd is None:
            try:
                self._fd = os.open(str(self.lock_file), os.O_CREAT | os.O_RDWR)
            except Exception as e:
                logger.warning("Could not open lock file %s: %s", self.lock_file, e)
                return False

        if sys.platform == "win32":
            import msvcrt
            try:
                # Lock 1 byte from the beginning of the file (non-blocking)
                msvcrt.locking(self._fd, msvcrt.LK_NBLCK, 1)
                return True
            except OSError:
                return False
        else:
            import fcntl
            try:
                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return True
            except (OSError, BlockingIOError):
                return False

    def release(self) -> None:
        """
        Releases the file lock and closes the file descriptor.
        """
        if self._fd is not None:
            try:
                if sys.platform == "win32":
                    import msvcrt
                    msvcrt.locking(self._fd, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self._fd, fcntl.LOCK_UN)
            except Exception:
                pass

            try:
                os.close(self._fd)
            except Exception:
                pass
            self._fd = None

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()
