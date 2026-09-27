"""
Asyncio Daemon Server for Jev Gateway.
Supports primary AF_UNIX domain sockets with automatic loopback TCP fallback,
bearer token authentication, and robust lifecycle/shutdown management.
"""

from typing import Optional, Set
from pathlib import Path
import asyncio
import socket
import secrets
import logging
import time
import sys
import os

from agent_airlock.config import GatewayConfig, load_config
from agent_airlock.policy.engine import HardPolicyEngine
from agent_airlock.daemon.router import IPCRouter
from agent_airlock.daemon.pid import PIDManager
from agent_airlock.backends.jev import JevClient
from agent_airlock.backends.evaluator import JevEvaluator

logger = logging.getLogger(__name__)


def _can_load_local_laya(provider: str, checkpoint_path: str) -> bool:
    """Checks whether local Laya model (disk checkpoint or HF Hub model ID) should be attempted."""
    if provider in ("local", "laya"):
        return True
    if provider == "auto":
        if checkpoint_path and os.path.exists(checkpoint_path):
            return True
        if checkpoint_path and not checkpoint_path.startswith((".", "/", "\\")) and "\\" not in checkpoint_path:
            parts = checkpoint_path.split("/")
            if len(parts) in (1, 2) and not os.path.isabs(checkpoint_path):
                return True
    return False


class DaemonServer:
    """
    Long-running background daemon for IPC tool gating.
    """

    def __init__(
        self,
        config: Optional[GatewayConfig] = None,
        router: Optional[IPCRouter] = None,
        pid_manager: Optional[PIDManager] = None,
    ):
        self.config = config or load_config()
        self.socket_path = Path(self.config.daemon.socket_path).expanduser().resolve()
        self.host = self.config.daemon.host
        self.tcp_port = self.config.daemon.tcp_port
        self.token_file = Path(self.config.daemon.token_file).expanduser().resolve()
        self.pid_file = Path(self.config.daemon.pid_file).expanduser().resolve()
        self.transport_mode = self.config.daemon.transport.lower()
        self.timeout = self.config.daemon.request_timeout_seconds

        self.pid_manager = pid_manager or PIDManager(
            pid_file=self.pid_file,
            socket_path=self.socket_path,
            token_file=self.token_file,
        )

        self.policy_engine = HardPolicyEngine(self.config.build_effective_rules())
        self._should_load_model = False
        self._model_load_task: Optional[asyncio.Task] = None

        if router is not None:
            self.router = router
        else:
            provider = getattr(self.config.jev, "provider", "auto").lower()
            checkpoint_path = getattr(self.config.jev, "checkpoint_path", "ruddh/agent-airlock-laya")

            # Check if local fine-tuned Laya model or remote Jev can/should be loaded in background
            should_try_local = _can_load_local_laya(provider, checkpoint_path)
            api_key = os.getenv(self.config.jev.api_key_env, "")
            should_try_remote = bool(api_key or provider == "remote")
            self._should_load_model = should_try_local or should_try_remote

            audit_logger = None
            try:
                from agent_airlock.audit.logger import AuditLogger
                audit_logger = AuditLogger(
                    log_path=self.config.audit.log_file,
                    flush_immediate=self.config.audit.flush_immediate,
                    retention_days=self.config.audit.retention_days,
                )
            except Exception as e:
                logger.warning("Failed to initialize AuditLogger in DaemonServer: %s", e)

            jev_evaluator = JevEvaluator(thresholds=self.config.jev.thresholds)
            self.router = IPCRouter(
                policy_engine=self.policy_engine,
                jev_client=None,
                jev_evaluator=jev_evaluator,
                circuit_breaker_config=self.config.circuit_breaker,
                audit_logger=audit_logger,
            )
            if self._should_load_model:
                self.router.model_loading = True

        self.server: Optional[asyncio.Server] = None
        self.active_transport: Optional[str] = None  # "unix" or "tcp"
        self.auth_token: Optional[str] = None
        self._active_tasks: Set[asyncio.Task] = set()
        self._is_running = False

    async def start(self) -> None:
        """
        Starts the daemon server listener according to configuration and platform support.
        """
        if self._is_running:
            logger.warning("Daemon server is already started.")
            return

        if self.pid_manager.is_running():
            existing_pid = self.pid_manager.read_pid()
            raise RuntimeError(f"Another daemon instance is already active (PID {existing_pid}).")

        # Determine transport: "unix", "tcp", or "auto"
        selected_transport = self._resolve_transport()

        if selected_transport == "unix":
            await self._start_unix_server()
        else:
            await self._start_tcp_server()

        self.active_transport = selected_transport
        self._is_running = True

        # Write PID and transport metadata
        self.pid_manager.write_pid(
            metadata={
                "started_at": time.time(),
                "transport": self.active_transport,
                "port": self.tcp_port if self.active_transport == "tcp" else None,
            }
        )
        logger.info(
            "Daemon started successfully using %s transport (PID %s).",
            self.active_transport,
            self.pid_manager.read_pid(),
        )

        # Stage 2: Load model asynchronously in background task after socket is listening
        if self._should_load_model and self.router.jev_client is None:
            self._model_load_task = asyncio.create_task(self._load_model_background())

    async def _load_model_background(self) -> None:
        """
        Loads Laya or remote JevClient in a worker thread after socket is accepting connections.
        Hard policy engine answers requests immediately while this runs.
        """
        provider = getattr(self.config.jev, "provider", "auto").lower()
        checkpoint_path = getattr(self.config.jev, "checkpoint_path", "ruddh/agent-airlock-laya")

        should_try_local = _can_load_local_laya(provider, checkpoint_path)

        if should_try_local:
            try:
                device = getattr(self.config.jev, "device", None)
                def _load_local():
                    from agent_airlock.backends.laya import LocalLayaClient
                    return LocalLayaClient(checkpoint_path=checkpoint_path, device=device)

                client = await asyncio.to_thread(_load_local)
                self.router.set_jev_client(client)
                logger.info("Daemon background LocalLayaClient loaded and ready.")
                return
            except Exception as e:
                logger.warning("Could not initialize LocalLayaClient in background: %s", e)

        api_key = os.getenv(self.config.jev.api_key_env, "")
        if api_key or provider == "remote":
            try:
                client = JevClient(
                    api_key=api_key,
                    model=self.config.jev.model,
                    base_url=self.config.jev.base_url,
                    timeout=self.config.jev.timeout_seconds,
                )
                self.router.set_jev_client(client)
                logger.info("Daemon remote JevClient initialized and ready.")
                return
            except Exception as e:
                logger.warning("Failed to initialize JevClient in background: %s", e)

        self.router.model_loading = False
        self.router.model_ready = False

    def _resolve_transport(self) -> str:
        has_unix = hasattr(socket, "AF_UNIX")

        if self.transport_mode == "unix":
            if not has_unix:
                raise RuntimeError(
                    "Unix domain socket transport requested, but AF_UNIX is not supported on this platform."
                )
            return "unix"

        if self.transport_mode == "tcp":
            return "tcp"

        # "auto" transport selection
        return "unix" if has_unix else "tcp"

    async def _start_unix_server(self) -> None:
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        if self.socket_path.exists():
            try:
                self.socket_path.unlink()
            except Exception as e:
                logger.warning("Could not unlink existing socket file %s: %s", self.socket_path, e)

        self.server = await asyncio.start_unix_server(
            self._handle_client_connection,
            path=str(self.socket_path),
        )
        logger.info("Listening on Unix domain socket: %s", self.socket_path)

    async def _start_tcp_server(self) -> None:
        # Generate and store bearer token
        self.auth_token = secrets.token_hex(32)
        self.token_file.parent.mkdir(parents=True, exist_ok=True)
        self.token_file.write_text(self.auth_token, encoding="utf-8")

        # Restrict permissions with platform-specific checks (icacls on Windows, chmod 0600 on POSIX)
        self._restrict_token_file_permissions(self.token_file)

        # Configure router with auth token
        self.router.auth_token = self.auth_token

        self.server = await asyncio.start_server(
            self._handle_client_connection,
            host=self.host,
            port=self.tcp_port,
        )
        # Update tcp_port if port 0 was passed
        if self.server.sockets:
            for s in self.server.sockets:
                sockname = s.getsockname()
                if isinstance(sockname, tuple) and len(sockname) >= 2:
                    self.tcp_port = sockname[1]
                    break

        logger.info("Listening on TCP loopback %s:%d with bearer token", self.host, self.tcp_port)

    async def _handle_client_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        task = asyncio.current_task()
        if task:
            self._active_tasks.add(task)

        try:
            while not reader.at_eof():
                try:
                    raw_line = await asyncio.wait_for(
                        reader.readline(),
                        timeout=self.timeout,
                    )
                except asyncio.TimeoutError:
                    timeout_resp = self.router.handle_raw_message("")
                    writer.write(timeout_resp.encode("utf-8"))
                    await writer.drain()
                    break

                if not raw_line:
                    # Client disconnected / EOF
                    break

                line_str = raw_line.decode("utf-8", errors="replace")
                response_str = self.router.handle_raw_message(line_str)
                writer.write(response_str.encode("utf-8"))
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            logger.error("Error handling client connection: %s", e)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            if task and task in self._active_tasks:
                self._active_tasks.remove(task)

    async def stop(self) -> None:
        """
        Gracefully stops the server and cleans up active resources.
        """
        if not self._is_running:
            return

        self._is_running = False
        if self.server:
            self.server.close()
            try:
                await self.server.wait_closed()
            except Exception as e:
                logger.warning("Error waiting for server closure: %s", e)

        # Cancel background model loading task if still running
        if self._model_load_task and not self._model_load_task.done():
            self._model_load_task.cancel()
            try:
                await self._model_load_task
            except (asyncio.CancelledError, Exception):
                pass

        # Cancel any active client tasks
        if self._active_tasks:
            for task in list(self._active_tasks):
                task.cancel()
            await asyncio.gather(*self._active_tasks, return_exceptions=True)
            self._active_tasks.clear()

        # Teardown PID and ephemeral files
        self.pid_manager.cleanup()
        logger.info("Daemon stopped and cleaned up.")

    @staticmethod
    def _restrict_token_file_permissions(token_file: Path) -> None:
        """
        Restricts token file permissions so only the current user can access it.
        On Windows: Uses icacls to strip inheritance and grant (R,W) exclusively to the current user (%USERNAME%).
        On POSIX: Uses chmod 0600 (owner read/write only).
        """
        if sys.platform == "win32":
            try:
                import os
                import subprocess
                username = os.environ.get("USERNAME") or os.getlogin()
                subprocess.run(
                    [
                        "icacls",
                        str(token_file),
                        "/inheritance:r",
                        "/grant:r",
                        f"{username}:(R,W)",
                    ],
                    check=True,
                    capture_output=True,
                )
            except Exception as e:
                logger.warning("Could not set Windows ACL on token file %s: %s", token_file, e)
        else:
            try:
                token_file.chmod(0o600)
            except Exception as e:
                logger.warning("Could not set 0600 permissions on token file %s: %s", token_file, e)

    def get_workspace_state(self, workspace_root: str):
        """
        Retrieves the isolated in-memory state for the specified workspace.
        """
        return self.router.get_workspace_state(workspace_root)

    async def run_forever(self) -> None:
        """
        Starts the daemon and runs indefinitely until interrupted or cancelled.
        """
        await self.start()
        try:
            if self.server:
                await self.server.serve_forever()
        except (asyncio.CancelledError, KeyboardInterrupt):
            pass
        finally:
            await self.stop()

def main():
    """CLI entrypoint to run daemon server."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    server = DaemonServer()
    try:
        asyncio.run(server.run_forever())
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
