# Technical Specification: Jev-Gated Safety Layer for Antigravity CLI

## 1. System Overview & Core Invariants

The Jev-Gated Safety Layer is a local, deterministic-first, fail-closed runtime extension designed to intercept and gate tool executions emitted by the Antigravity CLI. It operates via the Antigravity lifecycle hooks (`PreToolUse` and `PostToolUse`), routing decisions through a multi-tiered architecture:
1. **Deterministic Hard Policy Engine**: Zero-latency static rule matching for obvious safe and obvious dangerous operations.
2. **Circuit Breaker**: Hash-based failure signature buffer with optional semantic confirmation to prevent autoregressive repair loops.
3. **Probabilistic Evaluation Layer (Laya / Jev)**: Typed, calibrated System-1 probabilistic evaluation (`Score`, `Noul`, `Choice`) for ambiguous actions. Transitioned to local, open-source Laya (`convaiinnovations/laya`, Apache 2.0) to eliminate payment access friction.
4. **Append-Only Audit Log**: Complete event provenance for every tool call and gating decision.

### Non-Negotiable Invariants
1. **Strict Fail-Closed**: Any failure (daemon down, IPC timeout, network partition, model inference error, or low confidence score) MUST evaluate to `ask` (human confirmation), NEVER `allow`.
2. **Hard Rules Precede Probabilistic Inference**: Dangerous actions (e.g., `rm -rf /`, credential exfiltration) MUST be blocked deterministically by the policy engine; they must NEVER depend on model evaluation.
3. **Explicit Model Identity & Local Direct Loading**: All probabilistic model calls must target explicit pinned checkpoints. For local Laya inference, integration code MUST directly invoke `laya.load("convaiinnovations/laya")` (or the validated fine-tuned local checkpoint path), NOT `Router()`. `Router()` lazy-loads a separate multilingual checkpoint neither needed nor wanted for English shell commands. Silent model upgrades or unpinned aliases are strictly forbidden.
4. **Thin Hooks, Fat Daemon**: Hook scripts must remain thin (<50 lines of code) with minimal startup overhead, delegating all state, network IO, and evaluation to the background daemon via local IPC.
5. **Full Auditability**: Every single evaluation path, whether deterministic or probabilistic, must emit an immutable structured audit log entry before returning a decision.

---

## 2. Architecture & Control Flow

### Execution Pipeline

```
  Antigravity CLI Agent
           │
           │ 1. Emits PreToolUse payload on stdin
           ▼
┌─────────────────────────────────────────────────────────┐
│ Hook Script: pre_tool_use.py (<50 lines)                │
│ - Reads stdin JSON                                      │
│ - Connects to local daemon IPC socket                   │
│ - Forwards payload with timeout (e.g. 5000ms)           │
│ - If socket unreachable/fails -> returns "ask"          │
└──────────────────────────┬──────────────────────────────┘
                           │ 2. IPC Request (JSON over Socket)
                           ▼
┌─────────────────────────────────────────────────────────┐
│ Daemon: Localhost Runtime Server                        │
│                                                         │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ Step 1: Circuit Breaker Pre-Check                   │ │
│ │ - Checks if previous command failed repeatedly      │ │
│ │ - If loop tripped -> Force Ask                      │ │
│ └─────────────────────────┬───────────────────────────┘ │
│                           │ Next                        │
│ ┌─────────────────────────▼───────────────────────────┐ │
│ │ Step 2: Hard Policy Engine                          │ │
│ │ - Matches tool name and args against static regex   │ │
│ │ - Match in hard_deny  -> DENY                       │ │
│ │ - Match in hard_allow -> ALLOW                      │ │
│ │ - No match            -> AMBIGUOUS                  │ │
│ └─────────────────────────┬───────────────────────────┘ │
│                           │ If AMBIGUOUS                │
│ ┌─────────────────────────▼───────────────────────────┐ │
│ │ Step 3: Jev Integration Layer (Pinned jev-1.13.0)   │ │
│ │ - Fires Score (blast radius), Noul (reversible?),   │ │
│ │   Choice (routing) concurrently                     │ │
│ │ - Evaluates response against confidence thresholds  │ │
│ │ - Confident safe -> ALLOW                           │ │
│ │ - Confident danger -> DENY                          │ │
│ │ - Low confidence / Error / Timeout -> ASK           │ │
│ └─────────────────────────┬───────────────────────────┘ │
│                           │ Next                        │
│ ┌─────────────────────────▼───────────────────────────┐ │
│ │ Step 4: Audit Logger                                │ │
│ │ - Writes full trace to audit.jsonl                  │ │
│ └─────────────────────────────────────────────────────┘ │
└──────────────────────────┬──────────────────────────────┘
                           │ 3. IPC Response (JSON over Socket)
                           ▼
┌─────────────────────────────────────────────────────────┐
│ Hook Script: pre_tool_use.py                            │
│ - Writes decision JSON to stdout                        │
│ - Exits with code 0                                     │
└──────────────────────────┬──────────────────────────────┘
                           │ 4. Receives decision
                           ▼
  Antigravity CLI Agent (Executes, Blocks, or Prompts User)
```

---

## 3. Project Directory & Module Layout

```
sva-harness/
├── docs/
│   ├── architecture.md           # Reviewed architecture (immutable reference)
│   ├── spec.md                   # This living technical specification
│   ├── decisions.md              # Append-only architectural decision log
│   └── progress.md               # Phase tracking and status
├── agent_airlock/
│   ├── __init__.py               # Package root
│   ├── config.py                 # Pydantic/dataclass config loader & validator
│   ├── constants.py              # System constants, defaults, version strings
│   ├── policy/
│   │   ├── __init__.py
│   │   ├── models.py             # PolicyRule, PolicyVerdict, PolicyResult dataclasses
│   │   ├── engine.py             # HardPolicyEngine matching logic
│   │   └── default_rules.py      # Built-in hard-deny and hard-allow definitions
│   ├── jev/
│   │   ├── __init__.py
│   │   ├── client.py             # Pinned TypeSafe/Jev client wrapper
│   │   ├── prompts.py            # Calibrated question templates (Score/Noul/Choice)
│   │   └── evaluator.py          # Threshold evaluator & fail-closed logic
│   ├── circuit_breaker/
│   │   ├── __init__.py
│   │   ├── hasher.py             # Error signature hashing (tool, error, command)
│   │   └── breaker.py            # Sliding history window & repeat detector
│   ├── audit/
│   │   ├── __init__.py
│   │   ├── models.py             # AuditEvent dataclass
│   │   └── logger.py             # Append-only JSONL thread-safe writer
│   ├── daemon/
│   │   ├── __init__.py
│   │   ├── server.py             # Asyncio socket server (AF_UNIX / loopback TCP)
│   │   ├── router.py             # Request coordinator (Policy -> Jev -> Audit)
│   │   └── pid.py                # PID file, socket cleanup, lifecycle management
│   └── hooks/
│       ├── __init__.py
│       ├── pre_tool_use.py       # Hook script executed by Antigravity CLI (<50 lines)
│       └── post_tool_use.py      # Hook script for PostToolUse (<50 lines)
├── tests/
│   ├── __init__.py
│   ├── conftest.py               # Shared pytest fixtures
│   ├── test_policy_engine.py     # Hard policy unit tests (safe, deny, ambiguous)
│   ├── test_daemon_ipc.py        # IPC socket round-trip & timeout tests
│   ├── test_jev_integration.py   # Jev mocked & calibrated scoring tests
│   ├── test_circuit_breaker.py   # Failure loop detection tests
│   ├── test_audit_log.py         # Audit logging verification tests
│   ├── test_hooks.py             # Standalone hook script execution tests
│   └── test_scenarios.py         # End-to-end multi-step scenario evaluations
├── pyproject.toml                # Project packaging & dependencies
└── README.md                     # User documentation
```

---

## 4. Configuration Schema (`.jev-policy.yaml`)

Configurations are loaded with the following precedence:
1. Workspace root `.jev-policy.yaml` (or `.jev-policy.json`)
2. User global config `~/.gemini/antigravity-cli/jev-policy.yaml`
3. Bundled built-in defaults

```yaml
version: "1.0"

daemon:
  # Primary Unix domain socket path; falls back to TCP loopback on unsupported platforms
  socket_path: "~/.gemini/antigravity-cli/jev-daemon.sock"
  tcp_port: 48921
  host: "127.0.0.1"
  token_file: "~/.gemini/antigravity-cli/.jev-daemon.token"
  request_timeout_seconds: 5.0
  log_level: "INFO"

policy:
  allow_override_denies: false # When false, workspace rules cannot remove built-in hard_denies
  hard_deny:
    - id: "deny-destructive-fs"
      description: "Destructive recursive delete outside local boundary"
      tools: ["run_command"]
      field: "CommandLine"
      pattern: 'rm\s+(-[a-zA-Z]*r[a-zA-Z]*f|--recursive\s+--force)\s+([/~]|(\.\./)+)'
    - id: "deny-curl-sh"
      description: "Piping remote network payload into shell interpreter"
      tools: ["run_command"]
      field: "CommandLine"
      pattern: '(curl|wget)\s+.*\|\s*(ba|z)?sh'
    - id: "deny-secrets-read"
      description: "Accessing sensitive credential or secret files"
      tools: ["run_command", "view_file"]
      field: "ANY"
      pattern: '(\.env|id_rsa|id_ed25519|\.aws/credentials|\.npmrc|\.docker/config\.json)'
    - id: "deny-network-exfil"
      description: "Suspicious network socket exfiltration"
      tools: ["run_command"]
      field: "CommandLine"
      pattern: '(nc\s+-e|bash\s+-i\s+>&|socat\s+exec)'
    - id: "deny-fork-bomb"
      description: "Process table exhaustion or fork bomb patterns"
      tools: ["run_command"]
      field: "CommandLine"
      pattern: '([a-zA-Z0-9_.:]+)\s*\(\s*\)\s*\{\s*\1\s*\|\s*\1\s*&\s*\}\s*;\s*\1|while\s*(\$true|true)\s*\{.*?\}'

  hard_allow:
    - id: "allow-safe-git"
      description: "Read-only git queries"
      tools: ["run_command"]
      field: "CommandLine"
      pattern: '^git\s+(status|diff|log|branch|show|remote|rev-parse)(\s+.*)?$'
    - id: "allow-read-only-fs"
      description: "Read-only filesystem queries"
      tools: ["run_command"]
      field: "CommandLine"
      pattern: '^(ls|dir|pwd|find\s+\.\s+-name|tree|cat|head|tail|grep)(\s+.*)?$'
    - id: "allow-linters"
      description: "Non-destructive linters and checks"
      tools: ["run_command"]
      field: "CommandLine"
      pattern: '^(pytest|npm\s+test|ruff\s+check|black\s+--check|flake8|eslint|cargo\s+check)(\s+.*)?$'

jev:
  model: "jev-1.13.0" # Strictly pinned
  api_key_env: "TYPESAFE_API_KEY"
  base_url: "https://api.typesafe.ai/v1" # or gateway endpoint
  timeout_seconds: 0.400 # Strict 400ms wall-clock total fail-closed budget across retries
  thresholds:
    allow_confidence: 0.90
    deny_confidence: 0.85
    max_safe_blast_radius: 2.0    # 1=None, 2=Minor, 3=Moderate, 4=Major, 5=Catastrophic
    min_safe_reversible_prob: 0.70 # Noul probability that action is reversible
    default: "ask"

circuit_breaker:
  enabled: true
  hash_window: 3                 # Track the last N tool failures
  similarity_threshold: 0.80     # Trigger Noul if text differs but pattern is similar
  break_action: "force_ask"      # "force_ask" or "deny"

audit:
  log_file: "~/.gemini/antigravity-cli/audit.jsonl"
  flush_immediate: true
  retention_days: 30
```

---

## 5. IPC Protocol & Message Schemas

### Transport Layer
- **Unix Domain Socket (UDS)**: Used by default on Linux, macOS, and Windows 10/11 (`socket.AF_UNIX`).
- **Loopback TCP Fallback**: Bound to `127.0.0.1:48921` protected by a 32-byte cryptographically secure random bearer token stored in `.jev-daemon.token` (permissions `0600`).
- **Framing**: UTF-8 encoded newline-delimited JSON (`ndjson`). Each message is exactly one JSON line terminated with `\n`.

### IPC Request (Hook -> Daemon)
Sent by `pre_tool_use.py` or `post_tool_use.py`:
```json
{
  "version": "1.0",
  "auth_token": "optional-bearer-token-if-tcp",
  "event": "PreToolUse",
  "timestamp": 1774393260.123,
  "payload": {
    "toolCall": {
      "name": "run_command",
      "args": {
        "CommandLine": "rm -rf /tmp/build",
        "Cwd": "/workspace"
      }
    },
    "stepIdx": 4,
    "conversationId": "8fd02a46-8904-4500-b832-0a206f389ecf",
    "workspacePaths": ["/workspace"],
    "transcriptPath": "/workspace/.gemini/antigravity-cli/transcript.jsonl",
    "artifactDirectoryPath": "/workspace/.gemini/antigravity-cli/artifacts",
    "modelName": "gemini-3.8-flash"
  }
}
```

For `PostToolUse`:
```json
{
  "version": "1.0",
  "auth_token": "optional-bearer-token-if-tcp",
  "event": "PostToolUse",
  "timestamp": 1774393261.456,
  "payload": {
    "toolCall": {
      "name": "run_command",
      "args": {
        "CommandLine": "python failing_test.py"
      }
    },
    "stepIdx": 5,
    "error": "AssertionError: Expected 200 OK got 500",
    "conversationId": "8fd02a46-8904-4500-b832-0a206f389ecf",
    "workspacePaths": ["/workspace"]
  }
}
```

### IPC Response (Daemon -> Hook)
For `PreToolUse`:
```json
{
  "version": "1.0",
  "status": "success",
  "decision": "deny",
  "reason": "Hard policy engine: Matches deny rule 'deny-destructive-fs'",
  "permissionOverrides": [],
  "overwrite": null,
  "auditId": "evt_01J8ABCXYZ12345"
}
```

Permitted values for `decision`:
- `"allow"`: Automatically allow execution.
- `"deny"`: Block tool execution and inform agent.
- `"ask"`: Ask user for permission (respects cached permissions).
- `"force_ask"`: Always prompt user, bypassing cached permissions.

For `PostToolUse`:
```json
{
  "version": "1.0",
  "status": "success",
  "auditId": "evt_01J8ABCXYZ12346"
}
```

### Hook Script Error / Timeout Fallback & Daemon Auto-Spawn
1. **Race-Safe Auto-Spawn on Socket Absence**:
   If the hook script encounters `ENOENT` (socket or token file missing) or `ECONNREFUSED` (daemon not yet listening):
   - It synchronizes via a cross-platform inter-process file lock (`FileLock` on `<pid_file>.lock` using `msvcrt` on Windows and `fcntl` on POSIX).
   - Exactly one client acquires the lock, double-checks daemon connectivity, and spawns a detached background daemon process (`python -m agent_airlock.daemon.server`).
   - Concurrent hook processes wait on the file lock (bounded by the **200ms** deadline) rather than spawning competing daemons. Once the daemon is listening, waiting processes connect to the single instance.
   - Polls socket connectivity with a strict deadline of **200ms**.
   - If connection succeeds within 200ms, the request proceeds normally.
   - If startup exceeds 200ms or fails, it immediately outputs the following JSON and exits:
     ```json
     {
       "version": "1.0",
       "decision": "force_ask",
       "status": "fail_closed",
       "reason": "Safety daemon auto-spawn exceeded 200ms; failing closed to human confirmation."
     }
     ```
2. **General Error / Timeout Fallback (Strict Fail-Closed)**:
   If the hook script encounters an unrecoverable connection error or times out during execution after `request_timeout_seconds`, it outputs the following valid JSON to stdout and exits with code 0:
   ```json
   {
     "version": "1.0",
     "decision": "ask",
     "status": "fail_closed",
     "reason": "Safety daemon unreachable or timed out; failing closed to human confirmation."
   }
   ```

### Daemon In-Memory State Isolation & Workspace Context Enforcement
All runtime in-memory state in the daemon server and router is strictly partitioned by `workspace_root` (normalized absolute path string as the dictionary key):
- **Multi-project isolation**: Circuit breaker failure history, sliding hash windows, and audit buffers for Project A do not leak into or block commands in Project B.
- **Strict Fail-Closed on Unresolved Workspace**: If `workspace_root` cannot be resolved from `payload.workspace_root` or `payload.workspacePaths`, the daemon **strictly fails closed** with `{"decision": "force_ask", "status": "fail_closed", "reason": "workspace context unresolved"}`. Payloads are NEVER bucketed into a shared default key, preventing cross-workspace state leakage or unauthorized execution in unknown contexts.

### Platform-Specific Token File Security
When loopback TCP fallback is active, bearer token files require strict user-level access restriction:
- **POSIX**: Enforces `0600` via `chmod`.
- **Windows**: `chmod 0600` is a no-op for access control on NTFS. The daemon explicitly invokes `icacls` to strip inheritance (`/inheritance:r`) and grant read/write access exclusively to the current user (`/grant:r %USERNAME%:(R,W)`), preventing unauthorized local process access on multi-user systems.

---

## 6. Core Modules & Function Signatures

### 6.1. Hard Policy Engine (`agent_airlock.policy`)

#### Data Models (`agent_airlock/policy/models.py`)
```python
from enum import Enum
from typing import List, Optional, Dict, Any
from dataclasses import dataclass

class PolicyVerdict(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    AMBIGUOUS = "ambiguous"

@dataclass(frozen=True)
class PolicyRule:
    id: str
    description: str
    verdict: PolicyVerdict # ALLOW or DENY
    tools: List[str]       # ["run_command", "view_file"] or ["*"]
    field: str             # "CommandLine", "TargetFile", or "ANY"
    pattern: str           # Regular expression pattern

@dataclass(frozen=True)
class PolicyResult:
    verdict: PolicyVerdict
    rule_id: Optional[str] = None
    reason: Optional[str] = None
    matched_pattern: Optional[str] = None
```

#### Engine Interface (`agent_airlock/policy/engine.py`)
```python
class HardPolicyEngine:
    def __init__(self, rules: List[PolicyRule]):
        self._deny_rules: List[PolicyRule] = [r for r in rules if r.verdict == PolicyVerdict.DENY]
        self._allow_rules: List[PolicyRule] = [r for r in rules if r.verdict == PolicyVerdict.ALLOW]
        self._compile_patterns()

    def evaluate(self, tool_name: str, tool_args: Dict[str, Any]) -> PolicyResult:
        """
        Evaluates a tool call deterministically.
        1. Tokenizes via shlex wrapped in try/except; unparseable syntax fails closed to AMBIGUOUS ('ask').
        2. Evaluates hard_deny rules across unified candidate set {raw_cmd, norm_cmd, strip_cmd, shlex_tokens}. If any matches -> returns DENY.
        3. If no deny rules match and parse_error occurred -> returns AMBIGUOUS (fails closed to ask, never allowed).
        4. Checks hard_allow rules for side-effect-free operations. If any matches -> returns ALLOW.
        5. If no rules match -> returns AMBIGUOUS (falls through to Jev/Laya evaluation).
        """
        ...
```

### 6.2. Jev Integration Layer (`agent_airlock.backends`)

#### Data Models (`agent_airlock/backends/models.py`)
```python
from dataclasses import dataclass
from typing import Dict, Any, Optional

@dataclass(frozen=True)
class JevEvaluation:
    score_blast_radius: float       # Value from Score rubric (1.0 to 5.0)
    score_confidence: float         # Confidence for Score (0.0 to 1.0)
    noul_reversible_prob: float     # Probability action is reversible (0.0 to 1.0)
    choice_route: str               # "deterministic-safe", "needs-human", "needs-reasoning-model"
    choice_confidence: float        # Confidence for Choice (0.0 to 1.0)
    raw_payload: Dict[str, Any]     # Raw API response for audit logging
```

#### Client Interface (`agent_airlock/backends/jev.py`)
```python
class JevClient:
    def __init__(self, api_key: Optional[str] = None, model: str = "jev-1.13.0", base_url: str = "https://api.typesafe.ai/v1", timeout: float = 0.400):
        self.model = model # Strictly pinned (wall-clock total budget 400ms across retries)
        ...

    def evaluate_ambiguous_tool(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        context: Dict[str, Any]
    ) -> JevEvaluation:
        """
        Dispatches Score, Noul, and Choice questions in a single request to Jev.
        Raises JevClientError on network/timeout/API failure (handled by fail-closed evaluator).
        """
        ...
```

#### Local In-Process Laya Client (`agent_airlock/backends/laya.py`)
```python
class LocalLayaClient:
    def __init__(self, checkpoint_path: Optional[str] = None):
        """
        In-process local classifier using the fine-tuned Laya checkpoint.
        Directly loads via laya.load(checkpoint_path), NEVER Router().
        Maintains resident cached agent in GPU VRAM across invocations.
        """
        ...

    def evaluate_ambiguous_tool(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> JevEvaluation:
        """
        Dispatches tool call to local Laya model across blast_radius, reversible, and route questions.
        Fast in-process GPU execution (~38 ms median / 47 ms p95 with CUDA sync) without network overhead or API credentials.
        """
        ...
```

#### Decision Logic (`agent_airlock/backends/evaluator.py`)
```python
class JevEvaluator:
    def __init__(self, thresholds: JevThresholds):
        self.thresholds = thresholds

    def decide(self, evaluation: Optional[JevEvaluation], error: Optional[Exception] = None) -> GateDecision:
        """
        Applies gating thresholds to Jev response:
        - If error is present -> returns 'ask' (Fail-Closed)
        - If choice_confidence < thresholds.allow_confidence -> returns 'ask'
        - If choice_route == 'deterministic-safe'
          AND score_blast_radius <= max_safe_blast_radius
          AND noul_reversible_prob >= min_safe_reversible_prob
          -> returns 'allow'
        - If choice_route == 'needs-human' -> returns 'ask'
        - If score_blast_radius >= 4.0 -> returns 'deny'
        - Default -> returns 'ask'
        """
        ...
```

#### 6.2.1. Local Engine: Laya Integration (`convaiinnovations/laya`)
Due to payment and access friction with upstream cloud APIs, the probabilistic gating engine transitions from remote Jev to local Laya (Convai Innovations, Apache 2.0).

- **Target Workstation Hardware**: AMD Ryzen 7 4050HS-class CPU, NVIDIA GeForce RTX 4050 Laptop GPU (6GB VRAM), 16GB DDR5, 1TB NVMe.
- **Runtime Environment**: Python 3.11/3.13 (`torch_env`), `laya>=0.3.3` (installed `laya==0.3.20`), PyTorch CUDA active.
- **Loading Protocol**: Direct invocation `laya.load("checkpoints/laya-finetuned")` (or base `"convaiinnovations/laya"`). `Router()` is strictly prohibited as it triggers lazy-loading of secondary multilingual checkpoints unnecessary for English developer commands.
- **Evaluation Contract**: Implements the identical evaluation triad:
  - `score`: Blast radius (1.0–5.0)
  - `noul`: Reversibility probability (0.0–1.0)
  - `choice`: Routing decision (`deterministic-safe`, `needs-human`, `needs-reasoning-model`)
- **Adaptation & Fine-Tuning Status (Phase 3b Complete)**:
  - Fine-tuned on 160 curated developer tool commands with joint cross-entropy loss across all three heads.
  - Held-out validation split (N=40, stratified across all 5 archetypes) demonstrated **85.0% choice accuracy**, **87.5% noul accuracy**, and **0.748 blast radius MAE**.
  - Calibration warning resolved via post-hoc temperature scaling on validation logits: `choice:3-5` = 1.3400, `score:3-5` = 2.0800, `noul:2` = 1.8600, `choice:11+` = 1.0 (valid in `[0.5, 5.0]`).
  - Saved to `checkpoints/laya-finetuned`. Verified zero runtime warnings on load.
  - Original 15-command benchmark re-run reduced mismatches from 11/15 to 4/15, with 100% detection on known-dangerous and 100% preservation on known-safe operations.
- **Empirical Latency Profile (RTX 4050 GPU, CUDA synchronized via `torch.cuda.synchronize()`)**:
  - `p50 (Median)`: **38.14 ms**
  - `p90`: **44.10 ms**
  - `p95`: **47.16 ms**
  - `p99`: **61.21 ms**
  - `Mean`: **39.78 ms** (+/- 5.65 ms)
  - `Cold start (1st inference)`: 322.00 ms
  - Model initialization: resident singleton (~1GB VRAM).

### 6.3. Circuit Breaker (`agent_airlock.circuit_breaker`)

#### Interface (`agent_airlock/circuit_breaker/breaker.py`)
```python
@dataclass(frozen=True)
class ErrorSignature:
    tool_name: str
    command_or_target: str
    error_message: str
    normalized_command: str
    normalized_error: str
    command_hash: str
    error_hash: str
    step_idx: int
    timestamp: float

@dataclass(frozen=True)
class CircuitBreakerResult:
    is_tripped: bool
    action: str  # "force_ask", "deny", or "none"
    reason: Optional[str] = None
    repeat_count: int = 0
    noul_confidence: Optional[float] = None
    history_summary: List[Dict[str, Any]] = field(default_factory=list)

class CircuitBreaker:
    def __init__(
        self,
        workspace_root: str,
        config: Optional[CircuitBreakerConfig] = None,
        local_laya_client: Optional[Any] = None,
    ):
        ...

    def record_failure(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        error: str,
        step_idx: int = 0,
        timestamp: Optional[float] = None
    ) -> ErrorSignature:
        """Records an execution error into the workspace rolling history window."""
        ...

    def check_pre_tool(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        step_idx: int = 0
    ) -> CircuitBreakerResult:
        """
        Two-tier loop detection:
          Tier 1: Hash pre-filter checks exact and near command patterns (0ms).
          Tier 2: When surface text differs but similarity >= threshold, escalates to
                  local Laya Noul question for semantic confirmation (~38ms).
        Returns CircuitBreakerResult tripping to 'force_ask' on confirmed loops.
        """
        ...
```


### 6.4. Audit Logging (`agent_airlock.audit`)

#### Schema & Interface (`agent_airlock/audit/logger.py`)
```python
@dataclass
class AuditEvent:
    event_id: str
    timestamp: str
    conversation_id: str
    step_idx: int
    event_type: str # "PreToolUse" | "PostToolUse"
    tool_name: str
    tool_args: Dict[str, Any]
    policy_verdict: str # "allow" | "deny" | "ambiguous"
    matched_rule_id: Optional[str]
    circuit_breaker_tripped: bool
    jev_evaluation: Optional[Dict[str, Any]]
    final_decision: str # "allow" | "deny" | "ask" | "force_ask"
    reason: str
    latency_ms: float

class AuditLogger:
    def __init__(self, log_path: Path, flush_immediate: bool = True):
        ...

    def log(self, event: AuditEvent) -> None:
        """Thread-safe append of JSON line to audit.jsonl"""
        ...
```

#### Operational Characteristics & Latency Budget
- **Execution Path**: Synchronous and blocking within the `PreToolUse` and `PostToolUse` request-response path in `IPCRouter`, executing immediately before response dispatch.
- **Empirical Hot-Path Latency (`flush_immediate=True`, NVMe SSD, N=1,000)**:
  - `p50 (Median)`: **0.29 ms**
  - `p95`: **0.46 ms**
  - `p99`: **0.61 ms**
  - `Mean`: **0.31 ms**
  - Represents ~0.07% of the 400ms fail-closed budget, guaranteeing on-disk durability before client execution.
- **Retention & Disk Footprint**:
  - Default retention: `retention_days: 30` (`max_days=30` in `cleanup_old_events`).
  - Disk footprint: ~400 bytes/event, generating ~15 MB over 30 days under active agent workloads (500–2,000 tool calls/day). Pruned atomically via `.tmp` file replacement (`os.replace`).

---

## 7. Antigravity Lifecycle Hook Implementation

### `hooks.json` Mounting
Placed in `.agents/hooks.json` or discovered customization directory:
```json
{
  "jev-safety-gate": {
    "enabled": true,
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "python -m agent_airlock.hooks.pre_tool_use",
            "timeout": 10
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "python -m agent_airlock.hooks.post_tool_use",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

### Hook Script Design (<50 lines)
`agent_airlock/hooks/pre_tool_use.py`:
```python
import sys, json, socket

def main():
    try:
        raw_in = sys.stdin.read()
        if not raw_in.strip():
            sys.stdout.write(json.dumps({"decision": "ask", "reason": "Empty hook input"}))
            return
        payload = json.loads(raw_in)
        # Connect to daemon socket (UDS or loopback TCP)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(4.0)
        sock.connect(get_socket_path())
        sock.sendall((json.dumps({"event": "PreToolUse", "payload": payload}) + "\n").encode("utf-8"))
        res = sock.recv(65536).decode("utf-8").strip()
        sock.close()
        sys.stdout.write(res)
    except Exception as e:
        # Strict fail-closed
        sys.stdout.write(json.dumps({
            "decision": "ask",
            "reason": f"Safety daemon unreachable ({e}); failing closed to human confirmation."
        }))

if __name__ == "__main__":
    main()
```

---

## 8. Test & Verification Plan

| Phase | Test Suite | Target Invariant Verified |
|---|---|---|
| Phase 1 | `test_policy_engine.py` | 100% detection of hard-deny rules; zero false negatives; safe commands allowed; ambiguous fall through |
| Phase 2 | `test_daemon_ipc.py` | Socket communication round-trip, timeouts, dead client handling, concurrency |
| Phase 3 | `test_jev_integration.py` | Pinned model invocation, threshold mapping, fail-closed on mocked API error |
| Phase 4 | `test_circuit_breaker.py` | Detection of repeated failure signatures, Noul escalation, prevention of infinite retry loops |
| Phase 5 | `test_audit_log.py` | Immutable append-only log format, jsonl validity, event completeness |
| Phase 6 | `test_hooks.py` | Hook stdin/stdout compliance, sub-50ms execution on safe paths |
| Phase 7 | `test_scenarios.py` | End-to-end multi-turn evaluation across benign, dangerous, ambiguous, and crashing scenarios |
| Phase 8 | Full suite (`pytest -v`) | Cross-platform compatibility (POSIX PID), forced CPU fallback benchmark, live Laya inference, release docs & examples |

