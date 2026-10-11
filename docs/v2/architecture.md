# System Architecture — Agent Airlock 1.1

> **Product Name:** Agent Airlock 1.1 (Measure, then Optimize)
> **Branch:** `v2-semantic` (retained until final release prep)

---

## 1. System Overview & Target Pipeline

Agent Airlock 1.1 is a local safety gateway that intercepts AI coding assistant tool calls (`PreToolUse` and `PostToolUse` lifecycle hooks) to gate terminal commands and filesystem modifications.

### Target Pipeline (Evaluation Order)

```
Agent tool call (run_command / view_file / write_to_file)
        │
        ▼
 L0  Grounding checks (nonexistent binaries/paths/scripts; SHADOW ONLY)
        │   SHADOW ONLY: logs would-deny / hint to audit metadata; passes through ↓
        ▼
 L1  Deterministic policy (rules + AST + anti-evasion + user rules)
        │   Hard-Allow ──> ALLOW
        │   Hard-Deny  ──> DENY
        │   Ambiguous  ──> pass ↓
        ▼
 L2  Circuit breaker (hash window; halts failing repetition loops)
        │   Loop ──> FORCE_ASK
        │   Normal ──> pass ↓
        ▼
 EXACT CACHE  Exact-key decision cache (placed AFTER L2 per R1)
        │   Key: tool | normalized cmd | cwd | workspace | policy_hash | trust_epoch
        │   HIT ──> cached decision (never caches ASK as ALLOW)
        │   MISS ──> pass ↓
        ▼
 L3  Calibrated ML classifier (empirically calibrated ModernBERT / compact encoder)
        │   Confident Safe ──> ALLOW
        │   High blast     ──> DENY
        │   Uncertain      ──> pass ↓
        ▼
 L4  Fail-Closed Fallback ──> ASK operator
```

---

## 2. Component Details

### 2.0 L0 Grounding Layer (`agent_airlock/grounding/`)
- **Status:** **SHADOW ONLY** (enforce mode is strictly disabled).
- Evaluates prerequisites (C1 binary, C2 files, C3 scripts, C4 packages) in zero-network shadow mode.
- Records would-deny diagnostic hints in `AuditEvent.metadata["shadow_grounding"]` without altering pipeline flow.
- **Empirical Scope:** The production census measured only ~12 grounding failures across 2,626 executed commands (<0.5%). L0 makes no claim of reducing hallucinations; it serves purely as an observational diagnostic layer.

### 2.1 Deterministic Policy Engine (`agent_airlock/policy/`)
- **`normalizer.py`**: Normalizes shell syntax, strips cosmetic quotes (`r"m"` -> `rm`), removes shell escapes (`^` on Windows, `\` on POSIX), resolves subshell substitutions (`$()`, `` ` ``), and splits compound command chains. Chaining operators are limited strictly to `;`, `&&`, and newline (`\n`). Compound evaluation rule: a compound command is ALLOW only if every segment is independently ALLOW; any DENY segment immediately yields DENY; any AMBIGUOUS segment yields AMBIGUOUS. Disallowed chaining operators (`||`, single `&`), pipes into native exes, backticks, `$()`, `@()`, and scriptblocks disqualify the command from hard allow (yielding AMBIGUOUS).
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
