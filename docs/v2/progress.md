# Progress — Agent Airlock v2

### Current State (overwrite every session)
- Date/session: 2026-10-10 session 6
- Branch / last commit SHA: `v2-semantic` / `372b081`
- Active phase / task: Phase 1.2 Remediation Complete (L1 ReDoS/latency resolved, Family A reconciled & hardened, human_prompt headline reporting instituted, held-out set protocol confirmed) -> Starting Phase 1.3 Audit-Log Rule Suggester
- Gate status: G0 [PASS] G1 [IN PROGRESS] G2 [ ] G3 [ ]
- Test status (command + last result line): `conda run -n airlock-v2 pytest` → `161 passed, 1 skipped in 21.72s` (Full hermetic isolation; zero delta on live audit log; repo hygiene clean)
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
- [x] Gate G0: Formal baseline harness validated and committed (commit `ab95a47`).
- [x] Phase 1.0: Daemon CLI parity (`--status`, `--stop`, `--foreground`) implemented and tested in `agent_airlock/daemon/server.py` and `tests/test_daemon_cli.py` after auditing hook auto-spawn args.
- [x] Phase 1.1: Audit schema extension (`decisionSource`, `cwd`, `policyHash`, `layerLatenciesMs`, `humanApproved: inferred`, `latency_class`, `cacheKeyHash`) implemented in `agent_airlock/audit/models.py`, `router.py`, and `reader.py` with backward compatibility and verified in `tests/test_audit_log.py`.
- [x] Phase 1.2: L1 coverage expansion (Accepted Conditionally by Ani): Families A (Git), B (PowerShell), and C (Workspace Writes & Edits) implemented.
- [x] Phase 1.2 Condition Remediation:
  - [x] 1. Latency fix: Profiled per-rule, eliminated ReDoS in `deny-fork-bomb` (2326ms -> 0.34ms) and `allow-powershell-readonly` (594ms -> 0.33ms), added length cap (>4096 chars) before regex scanning head/tail 2048 chars, possessive/atomic groups, fast pre-filters. Added perf test `tests/test_policy_perf.py` (3 passed; 9 adversarial 10k-50k char inputs all <4.4ms p99, below 5ms threshold). Pure L1 replay latency restored to p50=0.631 ms, p95=3.415 ms, p99=7.575 ms.
  - [x] 2. Family A count reconciliation: Documented in verified-facts.md and decisions.md: 140 bare `git status` commands were already allowed by v1 baseline rules; 59 prompted human git commands occurred in clean corpus. 231 total read-only git commands matched Family A, of which 227 were in `human_prompt` delay class; net human prompts saved is 51-59 prompts.
  - [x] 3. Metric reporting discipline: Headline reported strictly as `human_prompt` only (~45 -> ~33.6 per 100 commands, saving 11.36 prompts/100 cmds). Legacy 61.8 -> 44.5 deprecated. `scripts/build_traces.py` and `scripts/replay.py` updated with explicit `latency_class` split.
  - [x] 4. Family A hardening: Rejected `--no-index`, required paths inside `workspace_root`, dropped `git remote -v` to prevent token leakage. 29 unit tests pass in `tests/test_policy_engine.py`.
  - [x] 5. Held-out set protocol: Confirmed `private/heldout-redteam.jsonl` will be provided by Ani for a single run at G1 and is kept strictly untouched for development.
- [x] Phase 1.3: Audit-log rule suggester (Implemented in `agent_airlock/policy/suggester.py`, `agent_airlock/suggest_rules.py`, and `scripts/suggest_rules.py`; 6 unit tests pass in `tests/test_rule_suggester.py`).
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

## Security Review: Git Inspection Rule Hardening
Confidential security analysis recorded in gitignored `private/security-notes.md` per Policy Change Protocol.

## Next Actions (ordered, max 5; each executable by a fresh agent without extra context)
1. Phase 1.4: Design and implement the Exact-Key Decision Cache (`agent_airlock/cache/decision_cache.py`). Position cache strictly AFTER L2 circuit breaker (R1) so repeated commands cannot bypass loop detection.
2. Implement cache key hashing (SHA-256 over tool_name, normalized args, cwd, and policy_hash), LRU eviction, TTL, and cache invalidation on policy/trust-root mutations. Invariant: Never cache an ASK as an ALLOW.
3. Add unit/integration tests for exact-key cache (`tests/test_decision_cache.py`) verifying breaker firing before cache hit, TTL expiration, invalidation on policy modification, and concurrent access safety.
4. Measure cache hit rate and latency impact on trace replay (`scripts/replay.py`).
5. Proceed to Phase 1.5: L0 Grounding Checks (shadow mode).

## Blockers & Questions for Ani
- None currently (Phase 1.2 accepted conditionally and fully remediated; Phase 1.3 complete; proceed to Phase 1.4).

## Handoff Notes (half-done work, gotchas, commands that need special flags)
- Active conda environment for v2 development is `airlock-v2`. Never create or modify other environments.
- Always run tests via `conda run -n airlock-v2 pytest ...` to ensure CUDA GPU acceleration and Python 3.11 environment.
- Never touch live `~/.gemini/antigravity-cli/audit.jsonl`.
- `checkpoints/` is gitignored and contains local weights copied from sva-harness.
- Never use `git add -A` or `git add .`; stage explicit files only. Forbidden: `data/traces/`, `private/`, `checkpoints/`, `*.onnx`, `*.pt`, `*.bin`, `*.safetensors`.

## Session Log (append-only, newest first)
### 2026-10-10 session 6
- Did: Addressed all 5 review items from Ani's conditional review of Phase 1.2 and completed Phase 1.3 (Audit-Log Rule Suggester):
  1. Latency & ReDoS profiling/remediation: pinpointed catastrophic backtracking in `deny-fork-bomb` (2326ms -> 0.34ms) and `allow-powershell-readonly` (594ms -> 0.33ms); added length cap before regex scanning (disqualifies >4096 chars from hard-allow; scans head/tail 2048 chars for deny); eliminated unbounded `.*?` and nested quantifiers across destructive FS, pipe, and network regexes. Built `tests/test_policy_perf.py` verifying 9 adversarial long inputs (10k-50k chars) stay strictly below 5.0 ms p99 (all < 4.4 ms p99). Replay pure L1 latency restored to p50=0.631 ms, p95=3.415 ms, p99=7.575 ms (down from 2.5/300/718 ms).
  2. Family A count reconciliation: fully documented reconciliation in decisions.md (ADR-010) and verified-facts.md (F-054): 140 bare `git status` commands were already allowed in v1; 59 prompted read-only git commands occurred in clean corpus. 231 was total read-only git commands matching Family A (227 in human_prompt class, of which 168 were already allowed). True human prompts saved by Family A is 51–59 prompts (~0.8 per 100 commands).
  3. Metric reporting discipline: headline fatigue metric reported strictly as `human_prompt` only (~45 -> ~33.6 per 100 commands, saving 11.36 prompts/100 cmds). Legacy 61.8 -> 44.5 conflated host auto-approvals and is deprecated. Updated `scripts/build_traces.py` and `scripts/replay.py` to calculate and report `latency_class` split (`human_prompt`, `host_auto`, `unapproved`, `v1_allow`, `v1_deny`).
  4. Family A hardening: rejected `--no-index`, required paths inside `workspace_root`, and dropped `git remote -v` from hard-allow to force ASK, preventing URL token exposure. Verified in `tests/test_policy_engine.py` (29 passed).
  5. Held-out set protocol confirmed: `private/heldout-redteam.jsonl` will be provided by Ani for a single run at G1; kept strictly untouched.
  6. Phase 1.3 Audit-Log Rule Suggester implemented (`agent_airlock/policy/suggester.py`, `agent_airlock/suggest_rules.py`, `scripts/suggest_rules.py`): mines human-approved commands (threshold >= N), strictly anchors patterns (`^...$`), parameterizes known clusters (`npm run <script>`, `pytest`), applies strict safety gate evaluating against all dangerous eval examples and hard-deny rules, attaches repo-controlled code execution warnings (`⚠ executes repo-controlled code`), and exports human-reviewable `.airlock-policy.yaml` snippets without ever auto-writing to policy files (Invariant I4). Tested in `tests/test_rule_suggester.py` (6 passed in 0.07s). Full test suite: 167 passed, 1 skipped in 22.41s.
- Verified: Full hermetic pytest suite passes (167 passed, 1 skipped). Live audit log zero delta. Repo hygiene clean (2/2).
- Decisions made: ADR-009, ADR-010, ADR-011, ADR-012.
- Metrics recorded: M-017, M-018, M-019, M-020, M-021.

### 2026-10-10 session 5
- Did: Implemented and validated Rule Families A, B, and C in `agent_airlock/policy/default_rules.py`, `agent_airlock/policy/engine.py`, and `agent_airlock/daemon/router.py` with all Ani amendments.
  1. Denominator discipline: recomputed clean production corpus figures with canonical denominator = 7,084 clean PreToolUse commands (`human_prompt` class): Family A saved 227 prompts (3.20/100 cmds); Family B saved 280 prompts (3.95/100 cmds); Family C saved 582 prompts (8.22/100 cmds); Combined saved 1,089 prompts (15.37 per 100 commands across 7,084 commands). Total matches: 1,578 (22.28 per 100 commands).
  2. Rule Family A (Git Read-Only): implemented negative lookahead permitting `--oneline`, `--pretty=oneline`, `--online` while blocking `--ou*` and `-o*`; enforced `-C <path>` containment inside `workspace_root`.
  3. Rule Family B (PowerShell Read-Only): implemented non-posix tokenization to preserve Windows backslash path semantics; permitted pipelines strictly to `Select-Object`, `Sort-Object`, `Measure-Object`, `Out-String`, `Format-*`; rejected `-Wait`, external paths, banned metacharacters, drives (`Env:`, `HKLM:`, `HKCU:`), UNC, and URLs. Hardened `deny-credentials-and-secrets` and `deny-credentials-in-command` to protect `.npmrc`, `.pypirc`, `.netrc`, `.git-credentials`, `.docker/config.json`, `.kube/`, `.gemini/` tokens, browser profiles, and `~/AppData` while excluding `AppData\Local\Temp` used by test workspaces.
  4. Rule Family C (Workspace Writes & Edits): implemented realpath containment refusing drive roots, user home, or home ancestors; comprehensive trust-root exclusion ledger (package manifests, build files, scripts directly under `scripts/`, `.airlock-policy.yaml`, `agent_airlock/**`, sensitive configs/extensions). Verified invariant that no L1 allow rule executes workspace code.
  5. Evaluated canonical eval set (`data/eval_set.jsonl`, N=50): False-Allow rate strictly 0.00% (0/20); False-Deny 0.00% (0/20); False-Ask dropped to 75.00% (15/20); Auto-Allow Precision 100.00% (5/5).
  6. Evaluated growth draft set (`data/eval_growth_draft.jsonl`, N=16): False-Allow 0.00% (0/6); False-Deny 0.00% (0/8); False-Ask 62.50% (5/8); Auto-Allow Precision 100.00% (3/3).
  7. Replayed 41 clean production traces (7,051 steps): ALLOW increased to 3,879 (55.01%, up from 37.68%); ASK decreased to 3,134 (44.45%, down from 61.79%); Approval Fatigue Rate dropped to 44.45 ASKs per 100 commands (saving 17.34 ASKs per 100 commands overall). Zero circuit breaker trips.
  8. Full test suite: 158 passed, 1 skipped in 23.05s hermetically. Added ADR-006, ADR-007, and ADR-008.
- Verified: Full hermetic pytest suite passes (158 passed, 1 skipped). Live audit log zero delta. Repo hygiene clean.
- Decisions made: ADR-006, ADR-007, ADR-008.
- Metrics recorded: M-010, M-011, M-012, M-013, M-014, M-015, M-016.

### 2026-10-09 session 4
- Did: Implemented Phase 1.0 daemon CLI parity, Phase 1.1 audit schema extension, Rule Family A, and verified revised proposals for Families B and C per Policy Change Protocol.
  1. Confidentiality & Git hygiene: verified Git `--output` overwrite finding was NEVER committed and NEVER pushed; scrubbed all vulnerability details from tracked files into gitignored `private/security-notes.md`.
  2. CLI `--stop` identity verification: hardened `--stop` in `agent_airlock/daemon/server.py` with `get_process_cmdline(pid)` check for `agent_airlock.daemon`. Stale or recycled PIDs (unrelated process) are NOT terminated, PID file is cleaned, exits 0. Added hermetic tests in `tests/test_daemon_cli.py` (6 passed).
  3. Rule Family A (Git Read-Only): implemented approved rule in `agent_airlock/policy/default_rules.py` with flags on status (`-s`, `-sb`, `--short`, `--porcelain`, `--branch`), strict global prefixes (`-C <path>` with `(?-i:c)` case guard, `--no-pager`; forbidding `-c` and `--exec-path`), and strict `--output` guards rejecting any token starting with `--o` or `-o` (`--outp=x`, `-ofile`, `git show --output=main.py`, etc., preserving `--oneline`). Added 26 unit tests in `tests/test_policy_engine.py`.
  4. Rule Family B (PowerShell Read-Only): revised per Ani's constraints (banning `$ ( ) { } @ ` ` ; & > <`, no script blocks, no `Env:`, `$env:`, `HKLM:`, `HKCU:`, UNC, or URLs; pipes only to `Select-Object`, `Sort-Object`, `Measure-Object`, `Out-String`, `Format-*`). Passed all 41 near-miss tests. Clean corpus match: 442 prompted commands saved (all in `human_prompt` class, saving 16.21 prompts per 100 commands).
  5. Rule Family C (Workspace Writes & Edits): added invariant test `test_invariant_no_l1_allow_executes_workspace_code` verifying 0/21 execution commands match L1 allow rules. Revised specification with canonical realpath containment, refusing drive roots, user home, or home ancestors, and excluding `.vscode/`, `.github/`, `.husky/`, `.agents/`, `.git/`, `.pre-commit-config.yaml`, `.gitattributes`, `.gitmodules`, `.npmrc`, `.envrc`, `sitecustomize.py`, `*.pth`, `.env*`. Passed 25 safety/near-miss tests. Clean corpus match: 466 writes + 622 replaces = 1,088 events (saving 620 human prompts, 22.74 per 100 commands). 169 excluded.
- Verified: Full test suite passes hermetically (`conda run -n airlock-v2 pytest`: 155 passed, 1 skipped in 29.51s). Repo hygiene passes (2/2).
- Decisions made: ADR-004.
- Metrics recorded: M-008 (daemon CLI unit tests), M-009 (Family A git tests & guards), M-010 (Family B near-miss & corpus matches), M-011 (Family C invariant & corpus matches).

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
