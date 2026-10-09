# Progress — Agent Airlock v2

## Current State (overwrite every session)
- Date/session: 2026-10-09 session 3
- Branch / last commit SHA: `v2-semantic` / `788e516` (Phase 0 fixes ready for commit)
- Active phase / task: Gate G0 Complete — Fixes Delivered, Ready for Ani Sign-Off & Phase 1.0
- Gate status: G0 [PASS] G1 [ ] G2 [ ] G3 [ ]
- Test status (command + last result line): `conda run -n airlock-v2 pytest` → `145 passed, 1 skipped in 23.64s` (Hermetic isolation verified; zero delta on live audit log; repo hygiene test passing)
- Environment: Windows 11 Home Single Language (10.0.26300), Python 3.11.16 (conda env `airlock-v2`), AMD Ryzen 7 7445HS (6C/12T), NVIDIA GeForce RTX 4050 Laptop GPU (6GB VRAM, CUDA available), 16GB RAM (~15.26 GiB visible)

## Phase Checklist
- [x] Phase 0A: Orientation & Documentation Setup
- [x] Phase 0.0: Test isolation & hermetic harness (commit `788e516`: autouse audit fixture, fake client for non-ML, `ml` mark, zero-byte live audit log delta)
- [x] Phase 0.1: Dataset hygiene, canonical train.json/val.json, leakage checker (`scripts/check_eval_leakage.py`), validator (`scripts/validate_dataset.py`)
- [x] Audit Corpus Hygiene: Excluded 316 test-generated records from `private/audit.jsonl`; 15,267 clean production records across 66 conversations (10 exclusion samples documented in verified-facts.md)
- [x] Verification 1: Audit schema & human approvals vs ML auto-allows discriminability (renamed `approved_inferred` vs `no_post_event`; 50-row join validation sampled; Antigravity host allow rules noted)
- [x] Verification 2: Deny-reason visibility (executed approved `view_file` test on `.env` and `run_command` test on `Get-Content .env`: verbatim reasons reach model context)
- [x] Verification 3: ONNX export executed with `onnx` (1.23.2) and `onnxruntime` (1.31.0); checker passed; logit parity 1.6e-5, route 40/40, blast 40/40; reversibility head NaN documented as Phase 1 item
- [x] Canonical Eval Set: 50 human-reviewed items (20 safe, 20 dangerous, 10 ambiguous) incorporating Ani's flips; zero leakage against train/val
- [x] Eval Harness & v1 Baseline: Updated schema with `ambiguous` category; v1 baseline: 0% false allow (13.91% upper bound), 0% false deny, 90% false ask, 100% precision, ECE 0.2730
- [x] Pre->Post Join Latency Histogram: Bimodal distribution revealed exact 1.5s cutoff separating `host_auto` (<1.5s, 1,126 events) from `human_prompt` (1.5s-600s, 3,186 events)
- [x] Hard-Allow Flag Variant Investigation: Diagnosed root causes for `git status -s` and PowerShell read-only cmdlets prompting (missing L1 rules and strict regex anchoring)
- [x] Repo Hygiene: Gitignored `*.onnx` and `*.pt`; verified zero `data/traces` tracked; added `tests/test_repo_hygiene.py`
- [x] Draft Eval Growth Set: 16 near-miss pairs created in `data/eval_growth_draft.jsonl` for Ani's review
- [ ] Phase 1.0: Daemon CLI parity (`--status`, `--stop`, `--foreground`) after auditing hook auto-spawn args
- [ ] Phase 1.1: Audit schema extension (`decisionSource`, `cwd`, `policyHash`, `layerLatenciesMs`, `humanApproved: inferred`, `latency_class`)
- [ ] Phase 1.2: L1 coverage expansion via Policy Change Protocol (PowerShell read-only, `git status` flags, `manage_task status`)
- [ ] Phase 1.3: Audit-log rule suggester
- [ ] Phase 1.4: Exact-key decision cache
- [ ] Phase 1.5: L0 grounding checks (SHADOW)
- [ ] Phase 1.6: ONNX / INT8 quantization & padding mask fix
- [ ] Phase 1.7: Data pipeline & expansion
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
1. Present Gate G0 fixes report to Ani and obtain sign-off.
2. Commit Phase 0 fixes to `origin/v2-semantic` using explicit git staging paths.
3. Begin Phase 1.0: Audit hook auto-spawn arguments in `agent_airlock/hooks/` and implement `--status`, `--stop`, and `--foreground` in `agent_airlock/daemon/server.py`.
4. Begin Phase 1.1: Extend audit log schema per Section 8 and verified requirements.
5. Begin Phase 1.2: Execute Policy Change Protocol for candidate L1 rules with Ani's per-rule approval.

## Blockers & Questions for Ani
- [ ] Confirm 1.5s cutoff for `latency_class` (`host_auto` vs `human_prompt`) based on empirical histogram.
- [ ] Review draft eval growth pairs (16 items in `docs/v2/eval-growth-draft.md`).
- [ ] Sign off on Gate G0 to proceed with Phase 1.0.

## Handoff Notes (half-done work, gotchas, commands that need special flags)
- Active conda environment for v2 development is `airlock-v2`. Never create or modify other environments.
- Always run tests via `conda run -n airlock-v2 pytest ...` to ensure CUDA GPU acceleration and Python 3.11 environment.
- Never touch live `~/.gemini/antigravity-cli/audit.jsonl`.
- `checkpoints/` is gitignored and contains local weights copied from sva-harness.
- Never use `git add -A` or `git add .`; stage explicit files only. Forbidden: `data/traces/`, `private/`, `checkpoints/`, `*.onnx`, `*.pt`, `*.bin`, `*.safetensors`.

## Session Log (append-only, newest first)
### 2026-10-09 session 3
- Did: Delivered all Gate G0 amendments and fixes requested by Ani.
  1. Enforced repo hygiene: verified `git ls-files data/traces` is empty, gitignored `*.onnx` and `*.pt`, added `tests/test_repo_hygiene.py` (passes).
  2. Executed approved live deny test (`Get-Content .env`): verbatim reason reaches model context.
  3. Canonicalized eval set: applied Ani's 50-row review decisions (10 flipped to `ambiguous`, 1 to `deterministic-safe`); updated `scripts/eval_harness.py` to handle `ambiguous` category; re-measured v1 baseline (0% false allow, 13.91% bound, 90% false ask, ECE 0.2730).
  4. Built `scripts/analyze_join_latency.py`: discovered sharp bimodal distribution in Pre->Post delays, establishing exact 1.5s cutoff separating `host_auto` (1,126 events, 15.89/100 cmds) from `human_prompt` (3,186 events, 44.97/100 cmds).
  5. Reconciled audit counts in `docs/v2/verified-facts.md` (31 -> 8 ML auto-allows; 8,259 -> 8,159 clean PreToolUse).
  6. Withdrew inaccurate documentation phrases; documented true model miscalibration (ECE 0.27-0.38).
  7. Investigated hard-allow flag variant prompting (`scripts/investigate_flag_prompts.py`): identified strict regex anchoring on `git status` and complete absence of Windows PowerShell read-only cmdlets in L1 (551 prompts).
  8. Created draft evaluation growth set (`data/eval_growth_draft.jsonl`, 16 items) covering PowerShell near-miss and workspace-write / trust-root pairs.
- Verified: Full test suite passes hermetically (`conda run -n airlock-v2 pytest`: 145 passed, 1 skipped in 23.64s).
- Metrics recorded: M-005 (canonical eval set v1 baseline), M-006 (deny-reason visibility run_command), M-007 (Pre->Post delay histogram & latency class distribution).

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
