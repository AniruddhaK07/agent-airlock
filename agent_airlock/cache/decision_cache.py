"""
Exact-Key Decision Cache for Agent Airlock (Phase 1.4 / Section 9.3).
Caches deterministic/ML ALLOW/DENY decisions and human-approved decisions.
Positioned strictly after L2 Circuit Breaker (R1).
"""

from collections import OrderedDict
from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Tuple

from agent_airlock.circuit_breaker.hasher import normalize_command


DEFAULT_TRUST_ROOT_FILES = [
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "Makefile",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "tox.ini",
    "conftest.py",
    "build.rs",
    "Cargo.toml",
    "Cargo.lock",
    "justfile",
    "Taskfile.yml",
    "Taskfile.yaml",
]


@dataclass
class CachedDecision:
    key: str
    decision: str
    source: str
    reason: str
    rule_id: Optional[str]
    created_at: float
    ttl_seconds: int
    tool_name: str
    normalized_command: str
    cwd: str
    workspace_root: str
    extra: Dict[str, Any] = field(default_factory=dict)

    def is_expired(self, now: Optional[float] = None) -> bool:
        t = now if now is not None else time.time()
        return (t - self.created_at) > self.ttl_seconds


class DecisionCache:
    """
    In-memory LRU Decision Cache with exact-key hashing, trust-epoch invalidation,
    and strict security guardrails.
    """

    def __init__(
        self,
        enabled: bool = True,
        ttl_seconds: int = 3600,
        max_entries: int = 2048,
        trust_root_files: Optional[List[str]] = None,
    ):
        self.enabled = enabled
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self.trust_root_files = list(trust_root_files) if trust_root_files else list(DEFAULT_TRUST_ROOT_FILES)
        self._cache: OrderedDict[str, CachedDecision] = OrderedDict()
        self._epoch_bumps: Dict[str, int] = {}

    def normalize_target(self, tool_name: str, tool_args: Dict[str, Any]) -> str:
        """Normalizes the target command or file argument for exact key calculation."""
        if tool_name == "run_command":
            cmd = tool_args.get("CommandLine", "") or tool_args.get("command", "") or ""
            return normalize_command(str(cmd))
        elif tool_name in ("write_to_file", "replace_file_content", "view_file"):
            tgt = tool_args.get("TargetFile") or tool_args.get("target_file") or tool_args.get("path") or ""
            return str(tgt).strip().replace("\\", "/").lower()
        else:
            return str(tool_args).strip()

    def get_trust_epoch(self, workspace_root: Optional[str]) -> str:
        """
        Computes trust-epoch hash based on mtimes and sizes of trust-root files
        plus manual bump counter for the workspace.
        """
        if not workspace_root:
            return "no_workspace_epoch"

        ws_path = Path(workspace_root)
        records: List[Tuple[str, int, int]] = []

        for tf in sorted(self.trust_root_files):
            try:
                target_path = ws_path / tf
                if target_path.exists() and target_path.is_file():
                    st = target_path.stat()
                    records.append((tf, int(st.st_mtime_ns), int(st.st_size)))
                else:
                    records.append((tf, -1, -1))
            except Exception:
                records.append((tf, -1, -1))

        bump = self._epoch_bumps.get(str(ws_path), 0)
        epoch_str = f"bump:{bump}|" + "|".join(f"{name}:{mtime}:{size}" for name, mtime, size in records)
        return hashlib.sha256(epoch_str.encode("utf-8")).hexdigest()

    def invalidate_trust_epoch(self, workspace_root: Optional[str]) -> None:
        """Bumps the trust epoch for a workspace, immediately invalidating cached entries."""
        if workspace_root:
            ws_key = str(Path(workspace_root))
            self._epoch_bumps[ws_key] = self._epoch_bumps.get(ws_key, 0) + 1

    def compute_cache_key(
        self,
        tool_name: str,
        normalized_target: str,
        cwd: str,
        workspace_root: str,
        policy_hash: str,
        trust_epoch: str,
    ) -> str:
        """Generates exact SHA-256 cache key per Section 9.3."""
        norm_cwd = str(cwd or "").strip().replace("\\", "/").lower()
        norm_ws = str(workspace_root or "").strip().replace("\\", "/").lower()
        raw = f"{tool_name}|{normalized_target}|{norm_cwd}|{norm_ws}|{policy_hash}|{trust_epoch}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def get(
        self,
        tool_name: str,
        normalized_target: str,
        cwd: str,
        workspace_root: str,
        policy_hash: str,
        trust_epoch: Optional[str] = None,
    ) -> Optional[CachedDecision]:
        """
        Retrieves a cached decision. Returns None on cache miss, expiration, or disabled cache.
        """
        if not self.enabled:
            return None

        if trust_epoch is None:
            trust_epoch = self.get_trust_epoch(workspace_root)

        key = self.compute_cache_key(
            tool_name=tool_name,
            normalized_target=normalized_target,
            cwd=cwd,
            workspace_root=workspace_root,
            policy_hash=policy_hash,
            trust_epoch=trust_epoch,
        )

        entry = self._cache.get(key)
        if entry is None:
            return None

        if entry.is_expired():
            del self._cache[key]
            return None

        # Move to end for LRU order
        self._cache.move_to_end(key)
        return entry

    def put(
        self,
        tool_name: str,
        normalized_target: str,
        cwd: str,
        workspace_root: str,
        policy_hash: str,
        decision: str,
        source: str,
        reason: str,
        rule_id: Optional[str] = None,
        trust_epoch: Optional[str] = None,
        raw_length: Optional[int] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """
        Caches a decision. Enforces strict security invariants:
        - NEVER caches ASK as ALLOW.
        - NEVER caches unapproved or error/fallback decisions.
        - NEVER caches oversized payloads (>4096 chars).
        """
        if not self.enabled:
            return None

        # Invariant: Oversized payloads (>4096 chars) must never be cached
        if raw_length is not None and raw_length > 4096:
            return None
        if len(normalized_target) > 4096:
            return None

        # Invariant: Only ALLOW and DENY decisions may be cached
        # ASK is NEVER cached as ALLOW
        if decision not in ("allow", "deny"):
            return None

        # Invariant: Never cache fallback or error decisions
        if source in ("fallback", "error", "unknown"):
            return None

        if trust_epoch is None:
            trust_epoch = self.get_trust_epoch(workspace_root)

        key = self.compute_cache_key(
            tool_name=tool_name,
            normalized_target=normalized_target,
            cwd=cwd,
            workspace_root=workspace_root,
            policy_hash=policy_hash,
            trust_epoch=trust_epoch,
        )

        now = time.time()
        entry = CachedDecision(
            key=key,
            decision=decision,
            source=source,
            reason=reason,
            rule_id=rule_id,
            created_at=now,
            ttl_seconds=self.ttl_seconds,
            tool_name=tool_name,
            normalized_command=normalized_target,
            cwd=cwd,
            workspace_root=workspace_root,
            extra=extra or {},
        )

        if key in self._cache:
            del self._cache[key]
        elif len(self._cache) >= self.max_entries:
            # LRU eviction: remove oldest
            self._cache.popitem(last=False)

        self._cache[key] = entry
        return key

    def clear(self) -> None:
        """Clears all cached entries."""
        self._cache.clear()
        self._epoch_bumps.clear()

    def __len__(self) -> int:
        return len(self._cache)
