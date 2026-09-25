# Context Reentry Prompt — Next Session Hand-off

*Copy and paste the prompt below into the chat when starting the next session.*

---

```markdown
# Session Bootstrap & Reentry — Jev-Gated Antigravity Safety Gateway

You are resuming work on the **Jev-Gated Antigravity CLI Extension** (`sva-harness`).
We have completed **Phase 0 (Bootstrap)**, **Phase 1 (Hard Policy Engine)**, **Phase 2 (Daemon & IPC)**, and **Phase 3 (Jev Integration Layer)** with 100% test coverage (64 test methods, 130 subtests, 0 false negatives, authenticated dual-transport IPC, race-safe auto-spawn, workspace isolation, strictly pinned model `jev-1.13.0`, 400ms wall-clock fail-closed budget, and calibrated gating).
The GitHub remote is live at `https://github.com/AniruddhaK07/jev-airlock` on branch `main` with tag `phase3-complete`.
Today we are implementing **Phase 4 — Circuit Breaker**.

---

## Step 1: Session Bootstrap Protocol (Run First)

Before taking any coding actions, read the following core project documentation in order:
1. `docs/architecture.md` (Ground truth reviewed architecture)
2. `docs/spec.md` (Detailed living technical spec & IPC schema)
3. `docs/decisions.md` (Append-only log of architectural decisions)
4. `docs/progress.md` (Phase tracker & current status)

Load the following existing Phase 1, 2, and 3 implementation files into your working context:
- `jev_gateway/policy/models.py`
- `jev_gateway/policy/engine.py`
- `jev_gateway/daemon/server.py`
- `jev_gateway/daemon/router.py`
- `jev_gateway/jev/models.py`
- `jev_gateway/jev/client.py`
- `jev_gateway/jev/evaluator.py`
- `jev_gateway/config.py`
- `tests/test_policy_engine.py`
- `tests/test_daemon_ipc.py`
- `tests/test_jev_integration.py`

State back in 3–5 lines:
- Current phase (Phase 4 — Circuit Breaker)
- What's done (Phases 0, 1, 2, and 3 complete and passing all 64 tests)
- What's next (Phase 4 objectives)

---

## Step 2: Phase 4 Objectives & Exit Criteria

**Target: Phase 4 — Circuit Breaker**
Build the loop-detection layer to halt runaway agent autoregressive repair loops:
1. **Error Signature Hasher (`jev_gateway/circuit_breaker/hasher.py`)**:
   - Normalize error messages (strip memory addresses `0x[0-9a-fA-F]+`, timestamps, transient file paths, line numbers).
   - Compute deterministic hashes for tool name, command, and normalized error.
2. **Sliding History Window & Breaker (`jev_gateway/circuit_breaker/breaker.py`)**:
   - Maintain rolling window of the last N failures (default 3) strictly partitioned per workspace (`workspace_root`).
   - Fast deterministic repeat detection: detect if the same command/error pattern repeats >= threshold.
   - Optional Jev Noul semantic confirmation when error text differs but underlying failure is identical.
   - Halts loop with `force_ask` to require human operator intervention.
3. **Pipeline Dispatch Integration (`jev_gateway/daemon/router.py`)**:
   - Record errors in `PostToolUse` into workspace circuit breaker.
   - Check `PreToolUse` against circuit breaker before running policy engine or Jev (Step 1 in pipeline).
4. **Unit & Integration Test Suite (`tests/test_circuit_breaker.py`)**:
   - Repeated error detection tripping the breaker.
   - Distinct errors not tripping the breaker.
   - Workspace isolation (failure loop in workspace A does not trip breaker in workspace B).
   - PreToolUse returning `force_ask` when tripped.

**Phase 4 Exit Criteria:**
Repeated execution failures trip the circuit breaker, halt runaway agent loops by forcing human confirmation (`force_ask`), state is partitioned by workspace, and all tests pass with 100% coverage.

---

## Operational Rules & Guardrails
- **Default Executor:** Flash for scaffolding, hashing, window buffers, and unit tests.
- **Escalate to Pro/Opus only if:** Error normalization regexes or Noul semantic similarity triggers require deep reasoning. State escalation reason in one line and log in `docs/decisions.md`.
- **Anti-Hallucination:** Do not mark tasks done without running tests. Verify commands with `python -m pytest tests/`.
- **Git Workflow Protocol (Apply at end of Phase 4):**
  1. Commit with message: `phase 4: circuit breaker — <one-line summary>`.
  2. Tag commit: `git tag phase4-complete`.
  3. Push to GitHub: `git push origin main` and `git push --tags`.
  4. Confirm the push succeeded on GitHub before updating `docs/progress.md` to mark Phase 4 done.
- **Session End:** Update `docs/progress.md` and `docs/decisions.md` before concluding.
```
