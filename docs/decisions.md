# Decision Log

This is an append-only log of non-obvious architecture and implementation decisions.
Format:
```
## [Phase N] <short title> — <date>
Context: <why this came up>
Decision: <what was chosen>
Rejected: <alternatives considered, if any>
Model: <Flash/Opus — which one made this call>
```

---

## [Phase 0] Implementation runtime selection — 2026-09-23
Context: The extension requires a local long-running daemon, deterministic regex policy engine, IPC server, Jev SDK/REST client, and thin hook scripts executable by Antigravity CLI lifecycle hooks.
Decision: Python 3.11+ using the standard library (`asyncio`, `socket`, `re`, `json`, `dataclasses`, `logging`) with optional `typesafe-sdk` (or direct httpx/urllib client). Python hook scripts are fast, cross-platform, and align with `typesafe-sdk`.
Rejected: Node.js (adds node_modules footprint and additional runtime dependencies for safety hooks), pure Bash/PowerShell (non-portable across Windows/Linux/macOS, unable to handle complex IPC and typed Jev structures robustly).
Model: Flash

## [Phase 0] Cross-platform IPC socket transport — 2026-09-23
Context: Architecture specifies a local Unix socket (`.jev-daemon.sock`), but Antigravity CLI runs on Windows as well as macOS and Linux.
Decision: Primary transport is standard `AF_UNIX` domain socket where supported (standard on Linux/macOS and supported on modern Windows 10/11 build 17063+ in Python 3 via `socket.AF_UNIX`). A localhost TCP socket (`127.0.0.1:<port>`) with a generated loopback authentication token stored in `~/.gemini/antigravity-cli/.jev-daemon.token` is provided as an automatic fallback if `AF_UNIX` is not available.
Rejected: Windows Named Pipes only (OS-specific and requires external pywin32 library); Unauthenticated loopback TCP (insecure on multi-user systems).
Model: Flash

## [Phase 0] Hierarchical policy rules and defaults — 2026-09-23
Context: Architecture doc open question: "Where does the hard-deny/allow list live — bundled defaults, per-project override, or both?"
Decision: Tiered hierarchy: bundled defaults in package (`jev_gateway/policy/default_rules.py`) provide baseline safety (destructive shell commands, credential leaks, pipe-to-shell; safe queries like `ls`, `git status`). Projects can define `.jev-policy.yaml` (or `.json`) in workspace root to add project-specific allows and denies. Built-in hard-deny rules cannot be overridden by project rules unless an explicit `allow_override_denies: true` flag is set by the user.
Rejected: Project-only configuration (forces every project to invent baseline security rules from scratch); bundled-only configuration (prevents teams from tailoring rules to their custom tooling).
Model: Flash

## [Phase 0] Fail-closed hook behavior on daemon absence — 2026-09-23
Context: If the daemon crashes, is not running, or times out during IPC, how should the PreToolUse hook respond?
Decision: Fail-closed to `"ask"`. The hook script catches connection errors, socket timeouts, and invalid payloads, returning `{"decision": "ask", "reason": "Jev safety daemon is unreachable; failing closed to human confirmation."}`. It never returns `"allow"`.
Rejected: Fail-closed to `"deny"` (would completely block developers from working if daemon restarts, whereas `"ask"` delegates execution authority to the human operator while maintaining safety); Fail-open to `"allow"` (strictly forbidden by security invariants).
Model: Flash

## [Phase 1] Hard policy engine rule set design and evasion hardening — 2026-09-23
Context: Designing the deterministic rule engine rule set requires comprehensive protection against false negatives (the highest-severity failure mode in the system), covering regex evasion, obfuscation (quoting, escapes, line continuations), command chaining, and Windows/POSIX divergence.
Decision: Implemented multi-layered evaluation in the Hard Policy Engine:
  1. Input normalization: strip cosmetic quotes (`r"m"` -> `rm`), remove shell caret/backslash escapes, normalize path separators, and split compound chained commands (`&&`, `;`, `||`, `|`, `&`, `\n`).
  2. Command chaining disqualification: any chained command or subshell substitution (`$()`, backticks) is immediately disqualified from `hard_allow`.
  3. Every sub-command in a chain is checked against `hard_deny` rules (catching payloads like `git status; rm -rf /`).
  4. Cross-tool inspection: rules inspect `run_command` (CommandLine), `view_file` (AbsolutePath), and filesystem tools.
  5. Tested against 35+ explicit scenarios across known-dangerous, known-safe, and ambiguous categories.
Rejected: Pure raw regex matching without normalization (easily bypassed by simple quoting like `r"m" -rf /` or caret escapes); single-token allowlisting (too restrictive for developer workflows).
Model: Pro

## [Phase 2] Dual-transport daemon architecture and authenticated IPC — 2026-09-24
Context: The Antigravity safety gateway daemon must operate seamlessly across Linux, macOS, and Windows. While AF_UNIX domain sockets are standard on POSIX platforms, Windows Python environments (including standard Conda and CPython Windows distributions) frequently omit `socket.AF_UNIX` (`hasattr(socket, "AF_UNIX") == False` confirmed on the active Windows test host).
Decision: Implemented dual-transport architecture in `DaemonServer` and `StubHookClient`:
  1. Auto-negotiation: When configured with `transport: "auto"`, checks runtime availability of `socket.AF_UNIX`. If supported, binds the Unix domain socket (`jev-daemon.sock`); if unavailable or failed, transparently falls back to localhost TCP (`127.0.0.1:<port>`).
  2. Confirmed Rationale for TCP Fallback: Confirmed strictly required for Windows compatibility since `socket.AF_UNIX` is absent on the Windows host. Bearer token authentication (32-byte hex) is mandatory for TCP transport to prevent unauthorized local cross-process requests.
  3. Strict Fail-Closed Invariant: In `StubHookClient`, any connection error, timeout, or missing daemon instance immediately returns a fail-closed verdict (`{"decision": "ask", "status": "fail_closed", "reason": "... failing closed to human confirmation ..."}`).
  4. Process & Socket Lifecycle: Implemented cross-platform PID manager (`PIDManager`) with process liveness detection and automated stale PID/socket/token cleanup on exit.
Rejected: Windows Named Pipes (adds external pywin32 dependencies); unauthenticated TCP (insecure on multi-user machines); failing open to "allow" on socket error (violates Non-Negotiable Invariant 1).
Model: Flash

## [Phase 2 Amendment] In-memory state isolation by workspace root — 2026-09-24
Context: A developer may work across multiple workspaces/repositories concurrently. Shared circuit-breaker history or audit buffers between distinct workspaces could cause false-positive loop halting or cross-project data pollution.
Decision: All in-memory state in the daemon (router and future circuit-breaker hash windows, audit buffers) is explicitly partitioned by `workspace_root` (plain normalized absolute path string key).
Rejected: Global unpartitioned state; hashing workspace path (unnecessary overhead when plain strings are unique and readable).
Model: Flash

## [Phase 2 Amendment] Daemon auto-spawn with 200ms deadline & escalation rules — 2026-09-24
Context: Hook invocations from the CLI should not require the user to manually manage a background daemon in everyday use. If the daemon is not running on hook invocation, manual intervention introduces developer friction.
Decision:
  1. Auto-Spawn: On `ENOENT` (missing socket) or `ECONNREFUSED`, `StubHookClient` spawns a detached daemon process in the background.
  2. Deadline: Polling loop waits up to 200ms for daemon availability.
  3. Strict Fail-Closed: If startup exceeds 200ms or fails, the client immediately falls back to `{"decision": "force_ask", "status": "fail_closed", "reason": "Safety daemon auto-spawn exceeded 200ms; failing closed to human confirmation."}`.
  4. Operational Escalation Rules: Restored full escalation criteria: Escalate to Opus for concurrency/race-condition review OR after 2 failed Flash attempts on any single bug.
Rejected: Synchronous blocking wait without timeout (blocks CLI execution); failing open to "allow" on spawn timeout.
## [Phase 2 Hardening] Fail closed on unresolved workspace context — 2026-09-24
Context: A hook request without explicit workspace context (`workspacePaths` or `workspace_root`) must not be assumed to belong to any default workspace, nor should multiple disparate calls be allowed to share in-memory state or circuit-breaker counters under a fallback "default" bucket.
Decision: Any `PreToolUse` or `PostToolUse` request where `workspace_root` cannot be resolved immediately fails closed with `{"decision": "force_ask", "status": "fail_closed", "reason": "workspace context unresolved"}`. No state is recorded or shared under any default key.
Rejected: Falling back to a global or `"default"` workspace bucket (risks cross-project state pollution).
Model: Flash

## [Phase 2 Hardening] Race-safe daemon auto-spawn via inter-process file locking — 2026-09-24
Context: When multiple hook scripts fire concurrently during cold-start (e.g. parallel tool calls or concurrent sessions), all see `ENOENT` or `ECONNREFUSED` simultaneously. Uncoordinated auto-spawn causes a thundering herd where multiple background daemon processes attempt to start, resulting in port contention and duplicate-instance errors.
Decision: Implemented cross-platform `FileLock` (`<pid_file>.lock` using `msvcrt.locking` on Windows and `fcntl.flock` on POSIX):
  1. The first client process acquires the lock, double-checks if the daemon is running, and spawns the background daemon process if not.
  2. Concurrent client processes wait on the lock (up to the 200ms deadline).
  3. Once the daemon starts and the lock is released, waiting clients immediately connect to the single existing daemon without spawning duplicates.
  4. Tested with 8 concurrent cold-start clients, asserting exactly 1 process spawn.
Rejected: Sleep-and-retry without mutual exclusion (susceptible to race conditions under heavy concurrency).
Model: Flash

## [Phase 2 Hardening] Explicit Windows bearer token ACLs via icacls — 2026-09-24
Context: On Windows filesystems (NTFS), `os.chmod(0o600)` only modifies the DOS read-only attribute; it does not configure Discretionary Access Control Lists (DACLs). Other unprivileged processes or local users on the same machine could still read the bearer token file.
Decision: Implemented platform-specific token file securing:
  - On Windows: Daemon invokes `icacls <token_file> /inheritance:r /grant:r %USERNAME%:(R,W)` to strip inherited ACLs and grant exclusive read/write access to the active user.
  - On POSIX: Daemon applies `os.chmod(0o600)`.
Rejected: Relying on `os.chmod` on Windows (insecure no-op for ACLs); external `win32security` dependency (adds bulky third-party native dependency when `icacls` is built into all modern Windows versions).
Model: Flash

## [Phase 3] Strictly pinned model identity (jev-1.13.0) — 2026-09-24
Context: Silent upgrades to upstream LLMs or classifier models frequently introduce drift, altering confidence calibration, rubric interpretation, and gating thresholds mid-flight.
Decision: `JevClient` strictly enforces `self.model == "jev-1.13.0"`. Initialization with unpinned aliases (e.g. `jev-latest`, `gemini-2.0`) or unvalidated minor bumps immediately raises `ValueError`. Additionally, responses bearing mismatched model headers are rejected with `JevParseError`.
Rejected: Floating version aliases (`jev-latest`) which introduce non-deterministic gating behavior.
Model: Flash

## [Phase 3] Unified single-request evaluation bundling — 2026-09-24
Context: For ambiguous tool calls, querying Score (blast radius), Noul (reversibility), and Choice (routing) as independent round-trips adds 3x network latency overhead.
Decision: Bundled all three System-1 questions into a single structured evaluation prompt (`format_jev_evaluation_prompt`) dispatched in a single POST request to the Jev API, with support for both nested and flat response schemas.
Rejected: Sequential separate HTTP calls (adds 150-500ms cumulative latency); client-side parallel requests without connection reuse.
Model: Flash

## [Phase 3] Fail-closed threshold gating hierarchy — 2026-09-24
Context: Probabilistic classifiers can err or suffer network/API failures. An evaluation must translate into safe, deterministic execution verdicts (`allow`, `deny`, `ask`, `force_ask`) without risking false-negative auto-execution.
Decision: Implemented multi-stage threshold gating in `JevEvaluator`:
  1. Any network/timeout/parse error or missing evaluation strictly fails closed to `ask`.
  2. Severe blast radius (`score_blast_radius >= 4.0`) with high confidence (`score_confidence >= deny_confidence`) blocks with `deny`.
  3. Severe blast radius with low confidence fails closed to `ask` (never `allow`).
  4. Routes `needs-human` and `needs-reasoning-model` route to `ask`.
  5. Route `deterministic-safe` only grants `allow` if:
     - `choice_confidence >= allow_confidence` (default 0.90)
     - `score_blast_radius <= max_safe_blast_radius` (default 2.0)
     - `noul_reversible_prob >= min_safe_reversible_prob` (default 0.70)
  6. Any metric violating thresholds fails closed to `ask`.
Rejected: Soft-allowing on network timeout (violates Non-Negotiable Invariant 1); single-metric gating based on Choice route alone without blast-radius and reversibility verification.
Model: Flash

## [Phase 3 Verification] Rubric validation status & classification matrix — 2026-09-24
Context: Rubrics for Score (blast radius), Noul (reversibility), and Choice (routing) must be verified. Local environment lacks active `TYPESAFE_API_KEY` (unauthenticated calls to api.typesafe.ai return 401/404).
Decision: Validated the rubrics against a benchmark matrix of representative command archetypes using calibrated synthetic response matrices and unit tests. If a live API key is provisioned, the client is ready for direct live inference.
Classification Matrix:
| Archetype | Sample Command | Expected Rubric Outputs | Gating Decision | Rationale |
| :--- | :--- | :--- | :--- | :--- |
| **Known-Safe** | `python generate_docs.py` | Blast: 1.5, Rev: 0.85, Route: `deterministic-safe` (Conf: 0.94) | `ALLOW` | Minor blast radius <=2.0, high reversibility >=0.70, confidence >=0.90 |
| **Known-Dangerous** | `custom_db_drop_tool --all` | Blast: 4.8, Rev: 0.05, Route: `needs-human` (Conf: 0.95) | `DENY` | High blast radius >=4.0 with confidence >=0.85; severe destructive impact |
| **Ambiguous / High Risk**| `git push --force` | Blast: 3.5, Rev: 0.40, Route: `needs-human` (Conf: 0.95) | `ASK` | Explicit human review required; irreversible remote mutation |
| **Ambiguous / Bounded** | `docker build . -t app` | Blast: 2.8, Rev: 0.70, Route: `deterministic-safe` (Conf: 0.92) | `ASK` | Blast radius 2.8 exceeds safe threshold 2.0; requires human confirmation |
| **Low Confidence** | Ambiguous script execution | Blast: 1.8, Rev: 0.80, Route: `deterministic-safe` (Conf: 0.84) | `ASK` | Choice confidence 0.84 < 0.90 threshold; fails closed to human |
| **Offline / Timeout** | Any command during drop | None / Exception | `ASK` | Strict fail-closed invariant on any network failure |
Model: Flash

## [Phase 3 Verification] Wall-clock total deadline budget (400ms) — 2026-09-24
Context: Per-attempt timeouts with retries can stack latency beyond the system's fail-closed latency budget (e.g. 2 x 250ms = 500ms > 400ms).
Decision: Replaced per-attempt timeouts with a strict wall-clock total deadline budget (`deadline = time.time() + timeout`). Dynamic remaining time (`deadline - time.time()`) is passed into each attempt's socket timeout. If the remaining budget expires at any point before or during retries, `JevTimeoutError` is immediately raised, ensuring the hook request fails closed to `ask` within <= 400ms.
Rejected: Per-attempt static timeouts that accumulate linearly with retry counts.
Model: Flash



