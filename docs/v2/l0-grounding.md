# L0 Grounding Layer Documentation (Phase 1.5)

## Overview & Purpose

The **L0 Grounding Layer** is a deterministic, zero-network pre-filter positioned at the very front of the Agent Airlock evaluation pipeline:
```
L0 Grounding (SHADOW ONLY) -> L1 Deterministic Policy -> L2 Hash Breaker -> Exact Cache -> L3 Calibrated Classifier -> L4 Fail-Closed ASK
```

### Scope & Constraints
- **SHADOW ONLY:** L0 is accepted strictly as a shadow diagnostic monitor. Enforce mode is **not** enabled.
- **No Hallucination Reduction Claims:** In the measured census across 41 production traces, only ~12 grounding failures were detected out of 2,626 executed commands (<0.5%). L0 makes no claims of reducing hallucinations or reducing human approval fatigue.
- **Diagnostic Role:** L0 logs observational hints to audit metadata (`AuditEvent.metadata["shadow_grounding"]`) without altering decisions or blocking commands.

---

## Core Checks & Capabilities

| Check ID | Name | Tool Surface | Verification Target | Missing Action & Guidance (Shadow Logged) |
| :--- | :--- | :--- | :--- | :--- |
| **C1** | Binary / Toolchain Grounding | `run_command` | First command token / executable in PATH, cwd, shell builtins, or PowerShell cmdlets | Logs actionable hint with detected platform and executable name (e.g. `Binary 'foo' not found in PATH or cwd`). |
| **C2** | Files & Paths Grounding | `view_file`, `replace_file_content`, `write_to_file` | Target file exists (for inspect/replace) or target parent directory exists (for write) | Logs targeted hint distinguishing missing target file vs missing parent directory. |
| **C3** | Package Scripts Grounding | `run_command` (`npm run`, `pnpm run`, `yarn run`, `make <target>`) | `package.json` `"scripts"` object or `Makefile` targets | Logs closest valid target suggestions ranked by Levenshtein edit distance. |
| **C4** | Dependency Installs Grounding | `run_command` (`pip install`, `npm install`, `cargo add`) | Local project manifests (`requirements.txt`, `package.json`, `Cargo.toml`) | Detects package typosquats within edit distance $\le 2$ without external network calls (Invariant I9). |

---

## Design Invariants & Strict Rules

1. **Deny Only When Certain (Conservative Pass-Through):**
   - Commands with unparseable shell syntax, dynamic variable expansions (`$VAR`, `%VAR%`), or shell builtins pass through unconditionally.
   - Any command segment that is preceded by a build, create, or install step in the same chain (e.g. `touch out.txt && cat out.txt`, `npm install && npm test`) passes through because it creates what it references.
   - Scrubbed path placeholders (`<USER>`, `<WS>`, `<HOME>`, `<REPO>`, `<TMP>`) and offline trace environments pass through conservatively.

2. **Zero-Network Hermeticity (Invariant I9):**
   - L0 never issues HTTP requests, socket connects, or remote package registry queries.
   - All manifest lookups and PATH scans are entirely local and cached via TTL (`path_cache_ttl_seconds`).

3. **L1 Security Hard-Deny Precedence (Zero False Negatives):**
   - Security hard-deny rules (tampering with `.agents/`, fork bombs, unauthorized egress) always take precedence over grounding hints.

---

## Configuration & Operation Modes

Configured in `GroundingConfig` (`agent_airlock.config`):
```yaml
grounding:
  enabled: true
  mode: "shadow"  # Strictly "shadow"
  path_cache_ttl_seconds: 30.0
  checks:
    binary: true
    files: true
    scripts: true
    installs: true
```

### Shadow Mode (Accepted Mode)
In `mode: "shadow"`, L0 executes all checks and records would-deny events and diagnostic hints in `AuditEvent.metadata["shadow_grounding"]` and tracks execution latency in `layer_latencies_ms["l0"]`. It **never** blocks a command or alters the pipeline decision. Enforce mode is strictly disabled.


---

## Empirical Verification & Census Results

### 1. Production Trace Census (41 Traces, 7,051 Steps)
- Total Human-Prompt Approvals: 1,205
- Total Post-Approval Failures: 279 (23.15% failure rate)
  - `C1_binary_not_found`: 10 (3.6% of failures, triggering 15 subsequent retries)
  - `C2_path_not_found`: 2 overall (triggering 2 subsequent retries)
  - `other_failure` (runtime bugs/logic errors): 269 (96.4% of failures)

### 2. Mandatory Replay Zero False Positives Gate
Evaluated in full `enforce` mode against all 6,945 historically successful commands across all 41 clean production traces:
- **Historically Successful Commands Evaluated:** 6,945
- **False Positives (Grounding failures on successful commands):** **0** (0.00%)
- **Status:** **PASSED GATE** (Zero false positives on replay verified).
