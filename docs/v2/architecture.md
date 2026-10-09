# Current Implemented Architecture — Agent Airlock (v1 Baseline)

> **Note:** This document describes the **actual currently implemented** architecture of the codebase as verified during Phase 0A orientation, **not** the planned target design for v2.

---

## 1. System Overview

Agent Airlock is a local safety gateway that intercepts AI coding assistant tool calls (`PreToolUse` and `PostToolUse` lifecycle hooks) to gate terminal commands and filesystem modifications. It combines deterministic pattern matching with a local, fine-tuned ModernBERT transformer classifier, backed by strict fail-closed guarantees.

```
Agent Lifecycle Hook (PreToolUse / PostToolUse)
         │  (ndjson over socket / loopback TCP)
         ▼
 StubHookClient (agent_airlock/hooks/stub_client.py)
   - Auto-spawns daemon via FileLock if offline
   - Fail-closed fallback to 'force_ask' / 'ask' on timeout or error
         │
         ▼
 DaemonServer (agent_airlock/daemon/server.py)
   - Transport: Unix domain socket (AF_UNIX) or localhost TCP
   - Auth: 32-byte hex bearer token (.jev-daemon.token secured with icacls/chmod)
   - Multi-tenant state isolation keyed by workspace_root
         │
         ▼
 IPCRouter (agent_airlock/daemon/router.py)
         │
 ┌───────┴────────────────────────────────────────────────────────┐
 │ Layer 1: HardPolicyEngine (agent_airlock/policy/engine.py)     │
 │   - Command Normalizer (anti-evasion: quotes, carets, chaining)│
 │   - Built-in rules (agent_airlock/policy/default_rules.py)     │
 │   - Workspace policy (.airlock-policy.yaml)                    │
 │   ALLOW ──> Return ALLOW                                       │
 │   DENY  ──> Return DENY                                        │
 │   AMBIGUOUS ──> Fall through                                   │
 └───────┬────────────────────────────────────────────────────────┘
         │
 ┌───────┴────────────────────────────────────────────────────────┐
 │ Layer 2: CircuitBreaker (agent_airlock/circuit_breaker/)       │
 │   - Rolling hash window of recent command/error signatures     │
 │   - Tripped ──> Return FORCE_ASK                               │
 └───────┬────────────────────────────────────────────────────────┘
         │
 ┌───────┴────────────────────────────────────────────────────────┐
 │ Layer 3: ML Safety Airlock (agent_airlock/backends/)           │
 │   - LocalLayaClient (fine-tuned ModernBERT, 3 task heads)      │
 │   - Evaluator thresholds: conf >= 0.90, blast <= 2.0 -> ALLOW  │
 │                           conf >= 0.85, blast >= 4.0 -> DENY   │
 │   - JevClient HTTP fallback (if TYPESAFE_API_KEY set)          │
 └───────┬────────────────────────────────────────────────────────┘
         │
 ┌───────┴────────────────────────────────────────────────────────┐
 │ Layer 4: Fail-Closed Fallback                                  │
 │   - Default: ASK operator                                      │
 └────────────────────────────────────────────────────────────────┘
```

---

## 2. Component Details

### 2.1 Deterministic Policy Engine (`agent_airlock/policy/`)
- **`normalizer.py`**: Normalizes shell syntax, strips cosmetic quotes (`r"m"` -> `rm`), removes shell escapes (`^` on Windows, `\` on POSIX), resolves subshell substitutions (`$()`, `` ` ``), and splits compound command chains (`&&`, `;`, `||`, `|`, `&`, `\n`). Any compound chained command or subshell substitution is disqualified from `hard_allow`.
- **`default_rules.py`**: Immutable baseline rules. Hard-denies dangerous operations (`rm -rf /`, fork bombs, reverse shells, raw disk writes, credential reads). Hard-allows safe read-only queries (`git status`, `git diff`, `ls`, `pwd`, etc.).
- **`engine.py`**: Evaluates normalized commands against rules. Supports workspace overrides via `.airlock-policy.yaml`.

### 2.2 Runaway Circuit Breaker (`agent_airlock/circuit_breaker/`)
- Tracks consecutive execution errors per `workspace_root`.
- Hashes command + error signature into a rolling window (`hash_window: 3`).
- When repetitions reach threshold, halts autoregressive loops with `force_ask`.

### 2.3 Local Machine Learning Classifier (`agent_airlock/backends/`)
- **`laya.py` (`LocalLayaClient`)**: Directly loads a fine-tuned ModernBERT checkpoint via `laya.load(target)` from local path `checkpoints/laya-finetuned` (falls back to Hugging Face Hub `ruddh/agent-airlock-laya`).
- **Three Task Heads**:
  1. `blast_radius`: Continuous score from 0 to 4 (read-only to catastrophic).
  2. `reversible`: Noul probability [0.0, 1.0] indicating whether command effects can be cleanly undone.
  3. `route`: Categorical choice (`deterministic-safe`, `needs-human`, `needs-reasoning-model`).
- **`evaluator.py` (`JevEvaluator`)**: Implements threshold gating:
  - `ALLOW` if `route == "deterministic-safe"`, `conf >= 0.90`, `blast <= 2.0`, and `reversible >= 0.70`.
  - `DENY` if `blast >= 4.0` and `conf >= 0.85`.
  - `ASK` for all other cases.

### 2.4 Daemon & IPC (`agent_airlock/daemon/`)
- **`server.py` (`DaemonServer`)**: Asyncio server managing lifecycle, two-stage startup (socket binds immediately in ~360ms, model loads in background worker thread), and signal shutdown.
- **`lock.py` (`FileLock`)**: Inter-process file locking using `msvcrt` on Windows and `fcntl` on POSIX to prevent thundering-herd auto-spawns.
- **`pid.py` (`PIDManager`)**: Manages PID tracking and stale file cleanup.
- **`router.py` (`IPCRouter`)**: Dispatches `PreToolUse`, `PostToolUse`, `Ping` events, enforces bearer-token authentication, and isolates state per workspace.

### 2.5 Hook Client & Installer (`agent_airlock/hooks/`)
- **`stub_client.py` (`StubHookClient`)**: Invoked by hook scripts. Connects over socket/TCP, auto-spawns daemon if needed, and strictly fails closed to `ask` / `force_ask`.
- **`installer.py`**: Configures `.agents/hooks.json` (workspace) or `~/.gemini/antigravity-cli/` (global).

### 2.6 Audit Logging (`agent_airlock/audit/`)
- **`logger.py` (`AuditLogger`)**: Appends structured JSON records to `~/.gemini/antigravity-cli/audit.jsonl`.
- **`models.py` (`AuditRecord`)**: Schema containing timestamp, tool call, policy verdict, ML evaluations, and final decision.
- **`reader.py` (`AuditReader`)**: CLI utility for inspecting audit logs (`--recent`, `--stats`).

---

## 3. Deviations & Known Issues in Baseline
1. **Daemon CLI Flags Unhandled**: `server.py:main()` does not parse `--status`, `--stop`, or `--foreground`. Any invocation attempts to launch a new daemon instance.
2. **Test Audit Log Isolation**: `tests/test_daemon_ipc.py` initializes `AuditLogger` with the default path `~/.gemini/antigravity-cli/audit.jsonl` rather than an isolated temp directory.
3. **Model Loading in Tests**: `TestDaemonIPC` starts a background model load in `asyncSetUp`, causing `asyncTearDown` to block for ~11.9s while waiting for the model load worker thread to finish.
