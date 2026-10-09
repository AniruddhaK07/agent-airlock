# Progress — Agent Airlock v2

## Current State (overwrite every session)
- Date/session: 2026-10-09 session 1
- Branch / last commit SHA: `v2-semantic` / `8673211`
- Active phase / task: Phase 0.0 (Test Isolation)
- Gate status: G0 [ ] G1 [ ] G2 [ ] G3 [ ]
- Test status (command + last result line): `conda run -n airlock-v2 pytest -rs` → `132 passed, 1 skipped in 19.47s`
- Environment: Windows 11 Home Single Language (10.0.26300), Python 3.11.16 (conda env `airlock-v2`), AMD Ryzen 7 7445HS (6C/12T), NVIDIA GeForce RTX 4050 Laptop GPU (6GB VRAM, CUDA available), 16GB RAM (~15.26 GiB visible)

## Phase Checklist
- [x] Phase 0A: Orientation & Documentation Setup
- [ ] Phase 0.0: Test isolation & hermetic harness (autouse audit fixture, fake client for non-ML, `ml` mark)
- [ ] Phase 0.1: Eval set (`data/eval_set.jsonl`, canonical train.json/val.json, leakage checker)
- [ ] Phase 0.2: Trace replay (`data/traces/`, scrubber, simulated approver)
- [ ] Phase 0.3: Metrics & eval harness
- [ ] Phase 0.4: Baseline against v1 (Gate G0)
- [ ] Phase 1.1: Audit schema extension
- [ ] Phase 1.2: Audit-log rule suggester
- [ ] Phase 1.3: Exact-key decision cache
- [ ] Phase 1.4: L0 grounding checks (SHADOW)
- [ ] Phase 1.5: ONNX / INT8 quantization
- [ ] Phase 1.6: Data pipeline & expansion
- [ ] Phase 2.0: Verify embedder
- [ ] Phase 2.1: Embedder daemon integration
- [ ] Phase 2.2: L2.5 semantic similarity engine
- [ ] Phase 2.3: Semantic circuit breaker
- [ ] Phase 2.4: Experiment (b) (shadow)
- [ ] Phase 2.5: Sequence analysis (shadow)
- [ ] Phase 3.1: Measure residual ASK rate
- [ ] Phase 3.2: Learned permits (L3.5, if justified)
- [ ] Phase 3.3: Experiment (b) adoption decision
- [ ] Phase 3.4: Sequence analysis activation decision
- [ ] Phase 3.5: Release preparation & PR

## Next Actions (ordered, max 5; each executable by a fresh agent without extra context)
1. Complete Phase 0.0: Implement hermetic test isolation (autouse fixture enforcing temp audit log, `ml` mark skipping on missing checkpoints, fake Laya client for non-ML daemon tests to eliminate 12s teardown delay) and commit separately.
2. Perform audit corpus hygiene: Filter test-generated records from `private/audit.jsonl`, log heuristics in `docs/v2/verified-facts.md`, and present before/after counts to Ani.
3. Verify audit schema (Verification step 1): inspect whether human approvals can be distinguished from ML auto-allows in existing records.
4. Draft safe test design for verification step 2 (deny-reason visibility) and await Ani's approval before running it.
5. Execute verification step 3: ONNX export of fine-tuned ModernBERT with all 3 output heads.

## Blockers & Questions for Ani
- [ ] Test suite isolation issue: `tests/test_daemon_ipc.py` does not configure `audit.log_file`, so test runs write to the real `~/.gemini/antigravity-cli/audit.jsonl`. When we start Phase 0, we propose isolating `GatewayConfig(audit=AuditConfig(log_file=...))` in test fixtures.
- [ ] Note on `private/` trace log: confirmed `private/audit.jsonl` is present (24.8 MB, 24,768,804 bytes). We will use this read-only copy for trace generation and replay mining.

## Handoff Notes (half-done work, gotchas, commands that need special flags)
- Active conda environment for v2 development is `airlock-v2`. Never create or modify other environments.
- Always run tests via `conda run -n airlock-v2 pytest ...` or with `airlock-v2` activated.
- Never touch live `~/.gemini/antigravity-cli/audit.jsonl`.
- `checkpoints/` is gitignored and contains local weights copied from sva-harness.
- `agent-airlock-daemon --status/--stop/--foreground` are unparsed by daemon `main()`; do not rely on them.

## Session Log (append-only, newest first)
### 2026-10-09 session 1
- Did: Completed Phase 0A Orientation. Inspected repository structure, pyproject.toml, hooks, daemon, policy engine, audit schema, and tests. Reconciled reality against Section 6 and logged discrepancies. Ran baseline test suite (`pytest -rs`), finding skip reason. Diagnosed root cause of `test_autospawn_failure_falls_back_to_force_ask` runtime (~11-13s) and network hang behavior without local checkpoints. Identified test isolation leak where test suite touches live `audit.jsonl`. Created `docs/v2/` documentation suite.
- Verified: Windows 11 Home Single Language, AMD Ryzen 7 7445HS, NVIDIA RTX 4050 Laptop GPU (CUDA enabled), 16GB RAM. Test baseline: 132 passed, 1 skipped (POSIX socket permissions). Model load time ~11.93s. Conda environment `airlock-v2`.
- Decisions made: ADR-001 (Adopt master prompt as plan of record).
- Metrics recorded: M-001 (baseline test suite execution), M-002 (LocalLayaClient cold load time).
- Left undone and why: Phase 0 feature code and harness creation awaiting Ani's review and Phase 0A sign-off per Section 14.
