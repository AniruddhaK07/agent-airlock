"""
L0 Grounding Engine (Section 9.4).
Coordinates execution of grounding checks C1-C4.
Emits actionable hints on definite hallucination defects and operates in SHADOW mode by default.
"""

import time
from typing import Any, Dict, Optional

from agent_airlock.config import GroundingConfig
from agent_airlock.grounding.c1_binary import PathIndexCache, check_binary
from agent_airlock.grounding.c2_files import check_files
from agent_airlock.grounding.c3_scripts import check_scripts
from agent_airlock.grounding.c4_installs import check_installs
from agent_airlock.grounding.models import GroundingCheckType, GroundingResult
from agent_airlock.policy.normalizer import parse_command_segments


class GroundingEngine:
    """
    Evaluates tool calls against L0 Grounding rules (binary, files, scripts, manifests).
    Supports per-check toggling and SHADOW mode operation.
    """

    def __init__(self, config: Optional[GroundingConfig] = None):
        self.config = config or GroundingConfig()
        self.path_cache = PathIndexCache(ttl_seconds=self.config.path_cache_ttl_seconds)

    def evaluate(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        cwd: str,
        workspace_root: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> GroundingResult:
        t0 = time.perf_counter()

        if not self.config.enabled:
            return GroundingResult(status="pass", mode=self.config.mode, latency_ms=0.0)

        # 1. File tools (C2 Files Grounding)
        if tool_name in ("view_file", "write_to_file", "replace_file_content"):
            if self.config.checks.files:
                ok, hint, target = check_files(
                    tool_name=tool_name,
                    tool_args=tool_args,
                    cwd=cwd,
                    workspace_root=workspace_root,
                )
                if not ok:
                    lat = (time.perf_counter() - t0) * 1000.0
                    return GroundingResult(
                        status="fail",
                        check_id=GroundingCheckType.C2_FILES.value,
                        hint=hint,
                        target=target,
                        mode=self.config.mode,
                        latency_ms=round(lat, 3),
                    )

        # 2. Command execution (C1 Binary, C3 Scripts, C4 Installs Grounding)
        elif tool_name == "run_command":
            cmd = tool_args.get("CommandLine", "")
            if cmd and cmd.strip():
                segments = parse_command_segments(cmd)
                for seg in segments:
                    # Check C1: Binary Grounding
                    if self.config.checks.binary:
                        ok, hint, target = check_binary(
                            segment=seg,
                            cwd=cwd,
                            env=env,
                            path_cache=self.path_cache,
                        )
                        if not ok:
                            lat = (time.perf_counter() - t0) * 1000.0
                            return GroundingResult(
                                status="fail",
                                check_id=GroundingCheckType.C1_BINARY.value,
                                hint=hint,
                                target=target,
                                mode=self.config.mode,
                                latency_ms=round(lat, 3),
                            )

                    # Check C3: Scripts Grounding
                    if self.config.checks.scripts:
                        ok, hint, target = check_scripts(
                            segment=seg,
                            cwd=cwd,
                            workspace_root=workspace_root,
                        )
                        if not ok:
                            lat = (time.perf_counter() - t0) * 1000.0
                            return GroundingResult(
                                status="fail",
                                check_id=GroundingCheckType.C3_SCRIPTS.value,
                                hint=hint,
                                target=target,
                                mode=self.config.mode,
                                latency_ms=round(lat, 3),
                            )

                    # Check C4: Install Manifest Grounding
                    if self.config.checks.installs:
                        ok, hint, target = check_installs(
                            segment=seg,
                            cwd=cwd,
                            workspace_root=workspace_root,
                        )
                        if not ok:
                            lat = (time.perf_counter() - t0) * 1000.0
                            return GroundingResult(
                                status="fail",
                                check_id=GroundingCheckType.C4_INSTALLS.value,
                                hint=hint,
                                target=target,
                                mode=self.config.mode,
                                latency_ms=round(lat, 3),
                            )

        lat = (time.perf_counter() - t0) * 1000.0
        return GroundingResult(
            status="pass",
            mode=self.config.mode,
            latency_ms=round(lat, 3),
        )
