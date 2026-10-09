# Progress — Agent Airlock v2

## Current State (overwrite every session)
- Date/session: 2026-10-09 session 3
- Branch / last commit SHA: `v2-semantic` / `788e516` (working changes staged for G0 commit)
- Active phase / task: Gate G0 Complete — Paused for Ani's Review & Sign-Off
- Gate status: G0 [READY FOR REVIEW] G1 [ ] G2 [ ] G3 [ ]
- Test status (command + last result line): `conda run -n airlock-v2 pytest -rs` → `143 passed, 1 skipped, 217 subtests passed in 27.8s` (Zero delta on live audit log)
- Environment: Windows 11 Home Single Language (10.0.26300), Python 3.11.16 (conda env `airlock-v2`), AMD Ryzen 7 7445HS (6C/12T), NVIDIA GeForce RTX 4050 Laptop GPU (6GB VRAM, CUDA available), 16GB RAM (~15.26 GiB visible)

## Phase Checklist
- [x] Phase 0A: Orientation & Documentation Setup
- [x] Phase 0.0: Test isolation & hermetic harness (commit `788e516`: autouse audit fixture, fake client for non-ML, `ml` mark, zero-byte live audit log delta)
- [x] Phase 0.1: Dataset hygiene, canonical train.json/val.json, leakage checker (`scripts/check_eval_leakage.py`), validator (`scripts/validate_dataset.py`)
- [x] Audit Corpus Hygiene: Excluded 316 test-generated records from `private/audit.jsonl`; 15,267 clean production records across 66 conversations (10 exclusion samples printed for verification)
- [x] Verification 1: Audit schema & human approvals vs ML auto-allows discriminability (renamed `approved_inferred` [4,012] vs `no_post_event` [53]; 50-row join validation sampled; Antigravity host allow rules noted)
- [x] Verification 2: Deny-reason visibility (executed approved `view_file` test on `.env`: verbatim reason reaches model context; proposed harmless `run_command` deny test)
- [x] Verification 3: ONNX export executed with `onnx` (1.23.2) and `onnxruntime` (1.31.0); checker passed; logit parity 1.6e-5, route 40/40, blast 40/40; reversibility head issue documented
- [x] Draft Eval Set: 50 items with 15 near-miss pairs (30 items) + 20 clean developer ops; zero leakage against train.json and val.json; compact review sheet in `docs/v2/eval-review-sheet.md`
- [x] ASK Composition Analysis: Deep dive into 4,684 clean prompted events; root-caused low ML auto-allow to uncalibrated 0.90 confidence gate (mean safe confidence was 0.571); cold start was only 20 events (0.43%)
- [x] Phase 0.2: Data scrubber implemented (`agent_airlock/scrubber.py` + `tests/test_scrubber.py`); 41 production traces (7,051 steps) extracted to `data/traces/`; trace replay harness with simulated approver (`scripts/replay.py`)
- [x] Phase 0.3: Evaluation harness (`scripts/eval_harness.py`) computing false-allow (w/ rule-of-three upper bound), false-deny, false-ask, ECE with bootstrap CI, and latencies
- [x] Phase 0.4: v1 baseline measured and recorded in `docs/v2/metrics.md`
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
1. Present Gate G0 Report to Ani for review and formal sign-off.
2. Await Ani's approval on: (a) Draft evaluation review sheet in `docs/v2/eval-review-sheet.md`, (b) Harmless `run_command` deny test proposal (`Get-Content .env`), (c) Audit exclusion heuristics sample sanity-check.
3. Upon Gate G0 sign-off: Begin Phase 1.1 (Audit schema extension).

## Blockers & Questions for Ani
- [ ] Verification Step 2 Approval: Request permission to execute the safe deny-reason visibility test using a read-only `view_file` call on a non-existent `.env` path.
- [ ] Confirmation to install `onnx` and `onnxruntime` in `airlock-v2` for Phase 1.5 ONNX export.

## Handoff Notes (half-done work, gotchas, commands that need special flags)
- Active conda environment for v2 development is `airlock-v2`. Never create or modify other environments.
- Always run tests via `conda run -n airlock-v2 pytest ...` or with `airlock-v2` activated.
- Never touch live `~/.gemini/antigravity-cli/audit.jsonl`.
- `checkpoints/` is gitignored and contains local weights copied from sva-harness.
- `agent-airlock-daemon --status/--stop/--foreground` are unparsed by daemon `main()`; do not rely on them.

## Session Log (append-only, newest first)
### 2026-10-09 session 2
- Did: Implemented hermetic test isolation (Phase 0.0, commit `788e516`): autouse audit path guard in `tests/conftest.py`, network connection blocker, `FakeLayaClient` for non-ML tests, `@pytest.mark.ml` tagging. Verified 0-byte change to live audit log during full suite execution (136 passed, 1 skipped). Built dataset tooling (`scripts/check_eval_leakage.py` and `scripts/validate_dataset.py`) confirming zero leakage between canonical `data/train.json` (160) and `data/val.json` (40), and detecting historical benchmark overlap. Analyzed `private/audit.jsonl` (15,583 raw records): excluded 316 test records (2.03%), yielding 15,267 clean production records (97.97%) across 66 conversations. Verified human approval discriminability (4,012 approvals vs 31 ML auto-allows). Diagnosed ONNX export feasibility (`scripts/diagnose_onnx_export.py`): PyTorch tracer successfully traces `DecisionModel` and ModernBERT encoder with all 3 heads; serialization only awaits `onnx` package. Formulated safe test proposal for deny-reason visibility.
- Verified: Live audit log diff is 0 across full test suite. Human approvals are observable via matching `PostToolUse` events. Model graph traces cleanly without unsupported ops.
- Decisions made: ADR-002, ADR-003.
- Metrics recorded: M-003 (hermetic test run & zero delta), M-004 (audit corpus hygiene & approval correlation).

### 2026-10-09 session 1
- Did: Completed Phase 0A Orientation. Inspected repository structure, pyproject.toml, hooks, daemon, policy engine, audit schema, and tests. Reconciled reality against Section 6 and logged discrepancies. Ran baseline test suite (`pytest -rs`), finding skip reason. Diagnosed root cause of `test_autospawn_failure_falls_back_to_force_ask` runtime (~11-13s) and network hang behavior without local checkpoints. Identified test isolation leak where test suite touches live `audit.jsonl`. Created `docs/v2/` documentation suite.
- Verified: Windows 11 Home Single Language, AMD Ryzen 7 7445HS, NVIDIA RTX 4050 Laptop GPU (CUDA enabled), 16GB RAM. Test baseline: 132 passed, 1 skipped (POSIX socket permissions). Model load time ~11.93s. Conda environment `airlock-v2`.
- Decisions made: ADR-001 (Adopt master prompt as plan of record).
- Metrics recorded: M-001 (baseline test suite execution), M-002 (LocalLayaClient cold load time).
- Left undone and why: Phase 0 feature code and harness creation awaiting Ani's review and Phase 0A sign-off per Section 14.
