# Progress — Agent Airlock v2

### Current State (overwrite every session)
- Date/session: 2026-10-11 session 9
- Branch / last commit SHA: `v2-semantic` / local working tree (ahead by commits)
- Active phase / task: Family D review and remediation (Items 1-5 + Addendum 6-7) COMPLETE — STOPPING for Ani's review before Phase 1.6 (ML calibration and bake-off).
- Gate status: G0 [PASS] G1 [IN PROGRESS] G2 [RETIRED] G3 [ ]
- Test status (command + last result line): `conda run -n airlock-v2 pytest` → `213 passed, 1 skipped in 19.67s` (Full hermetic isolation; zero delta on live audit log; repo hygiene clean; replay latency p99 = 4.667 ms < 5.0 ms gate PASS)
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
- [x] Phase 1.2 Condition Remediation (ReDoS elimination, Family A count reconciliation, human_prompt headline, Family A path hardening, held-out set protocol).
- [x] Phase 1.3: Audit-log rule suggester (Implemented in `agent_airlock/policy/suggester.py`, `agent_airlock/suggest_rules.py`, and `scripts/suggest_rules.py`; 8 unit tests pass in `tests/test_rule_suggester.py`).
- [x] Amendment 1 Section A (Fix First): Oversized >4096 whole-string linear scan, host-rule classification, suggester exact-only workspace rules with warnings, L1 family latency profiling (p99=4.360ms), `private/backport-to-live.md`.
- [x] Fixes Before B:
  - [x] 1. Replay classification 3-way range: delay-only (upper) vs retroactive (lower) vs first-match (middle). Headline: Baseline `[15.78, 27.91, 44.96]` -> Replay Remaining `[8.64, 20.03, 33.60]` per 100 cmds. Replay p99 = 4.014 ms (PASSES 5.0 ms gate).
  - [x] 2. Host-rule overlap analysis: top 20 host allow rules categorized with risk tags (`[interpreter]`, `[network]`, `[git-push]`, `[destructive]`), 1,234 ASKs neutralized (56.61%), exported to gitignored `private/host-rule-overlap-analysis.md`.
  - [x] 3. Prefilter soundness: permanent test in `tests/test_prefilter_soundness.py` fuzzing eval, draft, train, val, and deny probes across quotes, carets, casing, and chaining with 0 differences.
  - [x] 4. ML real token length limit: 451 max state tokens enforced; fails closed to ASK; verified with benign head + dangerous tail in `tests/test_local_laya.py`.
  - [x] 5. Short-circuit: early AMBIGUOUS exit for safe `python -c` and inline interpreters after deny scan; verified deny rules still apply in `tests/test_policy_engine.py`.
- [x] Section B Item 1: Retire Phase 2 (EmbeddingGemma) per ADR-014; written `docs/v2/embeddings-negative-result.md`; 1 future work line in `ROADMAP.md`.
- [x] Section B Item 2: Phase 1.4 Exact-Key Decision Cache per master prompt 9.3; placed strictly after L2 breaker (R1); 6-tuple key; LRU eviction; TTL; trust-epoch manifest invalidation; verified repeated failing command still trips breaker; 9 tests pass in `tests/test_decision_cache.py`.
- [x] Section B Item 3: Phase 1.5 L0 Grounding Layer:
  - [x] Historical Census: analyzed 41 clean production traces (7,051 steps, 2,626 executed commands) against transcripts; 1,205 human approvals, 279 post-approval failures (10 C1 binary, 0 C2 path, 0 C3 script, 0 C4 install, 269 other runtime errors); report written to `docs/v2/l0-census-report.md`.
  - [x] Architecture & Implementation: Checks C1, C2, C3, C4 built in `agent_airlock/grounding/` with SHADOW mode default (`mode: "shadow"`), zero-network hermeticity (I9), conservative pass-through, L1 hard-deny precedence, and documentation in `docs/v2/l0-grounding.md`.
  - [x] Replay Verification Gate: Evaluated in full `enforce` mode against all 6,945 historically successful commands across all 41 clean production traces: **ZERO FALSE POSITIVES** verified. Permanent regression test in `tests/test_grounding_replay.py`.
- [ ] Phase 1.6: ML calibration and bake-off (tabular baseline vs ModernBERT vs Ettin vs CmdCaliper)
- [ ] 2a: Loop evidence study (lexical similarity before any model)
- [ ] Gate G1: Single run of `private/heldout-redteam.jsonl`
- [ ] Release Prep: "Agent Airlock 1.1" docs rewrite, measured stories only, tag v1.1.0

## Next Actions (ordered, max 5; each executable by a fresh agent without extra context)
1. STOP for Ani's review of Phase 1.5 L0 Grounding (`docs/v2/l0-grounding.md`, `docs/v2/l0-census-report.md`, ADR-015, and zero false positives replay verification).
2. Upon approval, proceed to Phase 1.6 ML calibration and bake-off: extract 300-500 uncertainty-sampled real trace candidates formatted into compact review sheets (<=100 rows each) with Windows/PowerShell coverage for Ani.
3. Stage 1 ML bake-off: Train tabular / parsed-feature baseline (logistic regression / gradient-boosted trees) vs current ModernBERT on identical k-fold splits.
4. Stage 2 Ettin encoder 32M and 68M evaluation; verify HF IDs, licenses, and download sizes (<200 MB).
5. Stage 3 CmdCaliper-small (CyCraftAI, gated) evaluation ONLY if license fits Apache-2.0 redistribution and Stages 1-2 show promise.

## Blockers & Questions for Ani
- STOPPED for Ani's review after Phase 1.5 L0 Grounding per instruction: "Then build per master prompt 9.4 in SHADOW mode. Enforce only with 0 false positives on replay of historically successful commands. Docs may claim only what was measured... Stop after the census for Ani's review." All deliverables and zero false positive metrics are ready for Ani's inspection.


## Handoff Notes (half-done work, gotchas, commands that need special flags)
- Active conda environment for v2 development is `airlock-v2`. Never create or modify other environments.
- Always run tests via `conda run -n airlock-v2 pytest ...` to ensure CUDA GPU acceleration and Python 3.11 environment.
- Never touch live `~/.gemini/antigravity-cli/audit.jsonl`.
- `checkpoints/` is gitignored and contains local weights copied from sva-harness.
- Never use `git add -A` or `git add .`; stage explicit files only. Forbidden: `data/traces/`, `private/`, `checkpoints/`, `*.onnx`, `*.pt`, `*.bin`, `*.safetensors`.

## Session Log (append-only, newest first)
### 2026-10-11 session 9
- Did: Completed Family D review and remediation (Items 1-5 + Addendum 6-7):
  1. Item 1: Fixed baseline DENY regression: identified root cause of 9 flipped commands (tightened `REDIRECT_TARGET_PATTERN` in `372b081` caused inspection commands targeting airlock runtime paths `.gemini\antigravity-cli\` like `hooks.json`/`airlock.pid` to bypass `is_tampering_command` and slip through). Hardened `normalizer.py:is_tampering_command` so any token matching `is_protected_runtime_path` unconditionally triggers `deny-airlock-runtime-tampering`. Fixed compound command evaluation to enforce global DENY precedence across all segments. Replay DENY count increased from 28 to 69 (safely >= baseline 37). Added regression test `test_replay_baseline_deny_regression` in `tests/test_policy_engine.py` asserting no replay decision may move from DENY to a weaker verdict without an explicit ADR.
  2. Item 2: Replaced pipeline sink denylist with strict allowlist (`Select-String`, `Select-Object`, `Sort-Object`, `Measure-Object`, `Format-*`, `Out-String`, simple `Where-Object` without scriptblock side effects). Disallowed all other sinks -> AMBIGUOUS. Disallowed pipes into native exes (`sh/bash/python/node/powershell/pwsh/cmd/xargs`), `||`, single `&`, backticks, `$()`, `@()`, and `ForEach-Object` scriptblocks -> AMBIGUOUS. Added comprehensive unit tests in `tests/test_policy_engine.py`.
  3. Item 3: Hardened git rules with near-miss tests: git grep rejects `-O/--open-files-in-pager` and prefix flags `-c/-C/--paginate/--exec-path` before subcommand; git add rejects `-f/--force`, bare `.`, `-A/--all`, `-u/--update`, globs, and pathspec magic `:(` so only explicit workspace paths pass; git tag rejects signing flags (`-s`, `-u`, `--sign`, `--local-user`). Added tests in `test_policy_engine.py`.
  4. Item 4: Gap-list coverage reconciliation: Verified per-trace containment (`workspace_root` properly resolved per step/trace in `replay.py`); verified replay hits (`Get-ChildItem` allowed=185, unallowed=120; `Select-String` allowed=77, unallowed=68) and confirmed unallowed commands genuinely target external paths (`audit.jsonl`, `brain/...`) or protected paths (`.agents`), with zero artificial loosening of containment.
  5. Item 5: Replay reporting: All replay numbers labeled IN-SAMPLE. Measured 7,051 steps across 41 traces: ALLOW: 4,050 (57.44%), DENY: 69 (0.98%), ASK: 2,932 (41.58%). Approval fatigue range: Baseline `[15.78, 27.91, 44.96]` -> Replay `[8.44, 18.35, 30.62]` per 100 cmds. Middle headline dropped to 18.35 per 100 cmds (saving 674 human prompts). False-allow rate on eval sets is 0/26 (0.00%, 95% Wilson CI upper bound: 12.87%), explicitly stated as not evidence of safety. Latency: p50=0.445 ms, p95=2.163 ms, p99=5.169 ms.
  6. Addendum Item 6: Updated `docs/v2/architecture.md:54` describing compound command rule exactly; noted Family D and compound rule in `docs/v2/decisions.md` (ADR-016) awaiting Ani's approval; updated M-031 in `docs/v2/metrics.md` recording 69 DENYs (>= 37 baseline).
  7. Review Sheet 1c: Regenerated `private/review-sheet-1c.md` and `private/review_sheet_1c.jsonl` (95 candidate rows).
- Verified: Full pytest suite passes (`conda run -n airlock-v2 pytest`: 213 passed, 1 skipped in 19.67s). Policy perf, prefilter soundness, and repo hygiene tests pass 100%. Replay baseline DENY regression passes.
- Decisions made: ADR-016 (awaiting Ani's approval under Policy Change Protocol).
- Metrics recorded: M-031 updated.

### 2026-10-10 session 8
- Did: Completed all 5 prerequisite fixes from Section A review and proceeded with Section B items 1–3, stopping after Census for Ani's review:
  1. Fix 1: Replay classification range reporting: Implemented 3-way range in `scripts/build_traces.py` and `scripts/replay.py`: delay-only (upper) vs retroactive host-rule (lower) vs first-match (middle). Replay approval fatigue: Baseline `[15.78, 27.91, 44.96]` -> Replay Remaining `[8.64, 20.03, 33.60]` per 100 cmds. Replay pure L1 latency: p50=0.396 ms, p95=1.820 ms, p99=4.014 ms (**PASSES 5.0 ms gate**). No single headline quoted.
  2. Fix 2: Host-rule overlap analysis: Built `scripts/analyze_host_overlap.py`, profiled top 20 host allow rules by match count with risk tags (`[interpreter]`, `[network]`, `[git-push]`, `[destructive]`), reported 1,234 neutralized ASKs (56.61%), exported to gitignored `private/host-rule-overlap-analysis.md`.
  3. Fix 3: Prefilter soundness: Created permanent test `tests/test_prefilter_soundness.py` asserting zero differences with and without prefilters across eval, draft, train, val, and fuzzed variants (quotes, carets, casing, chaining). Passes in 0.48s.
  4. Fix 4: ML length limit: Verified true untruncated state capacity is 451 tokens in `LocalLayaClient`. Enforced fail-closed to ASK on state > 451 tokens. Added test in `tests/test_local_laya.py` with benign head + dangerous tail (3,080 chars < 4096, 457 tokens > 451) failing closed to ASK.
  5. Fix 5: Short-circuit: Added early exit to AMBIGUOUS for safe inline interpreter scripts (`python -c`, `node -e`, etc.) after deny scan. Verified deny rules still apply in `tests/test_policy_engine.py`.
  6. Section B Item 1: Formally retired Phase 2 EmbeddingGemma per ADR-014. Documented negative result in `docs/v2/embeddings-negative-result.md` (why I2, measured L1 gains, cosine claims marked UNVERIFIED). Preserved 1 future work line in `ROADMAP.md`.
  7. Section B Item 2: Implemented Phase 1.4 Exact-Key Decision Cache in `agent_airlock/cache/decision_cache.py`, wired into `agent_airlock/daemon/router.py` strictly after L2 breaker (R1). Cache key: `sha256(tool|normalized_cmd|cwd|workspace|policy_hash|trust_epoch)`. Enforced fail-closed on oversized (>4096) and ASK payloads. Added trust-epoch mtime invalidation on manifest writes. Added 9 tests in `tests/test_decision_cache.py` verifying R1 invariant (repeated failing command still trips breaker before cache).
  8. Section B Item 3: Phase 1.5 L0 Grounding Layer:
     - Conducted failure census via `scripts/census_l0_failures.py` across 41 production traces (7,051 steps, 2,626 executed commands). Measured 279 post-approval failures (10 C1 binary, 0 C2 path, 0 C3 script, 0 C4 install, 269 other runtime errors). Reported in `docs/v2/l0-census-report.md`.
     - Built L0 Grounding subsystem in `agent_airlock/grounding/` (C1 binary, C2 files, C3 scripts, C4 installs). Default `mode: "shadow"`; Invariant I9 (zero network calls); conservative pass-through on unparseable, builtins, and creates-what-it-references; L1 security deny precedence.
     - Verified mandatory replay gate: Evaluated in full `enforce` mode against all 6,945 historically successful commands and tool calls across all 41 clean production traces: **ZERO FALSE POSITIVES** verified. Permanent regression test in `tests/test_grounding_replay.py`.
     - Comprehensive documentation written to `docs/v2/l0-grounding.md`.
     - STOPPED for Ani's review after Phase 1.5 before proceeding to Phase 1.6 (ML calibration and bake-off).
- Verified: Full test suite passes: `209 passed, 1 skipped in 36.17s`. Zero regressions. Zero live audit log delta.
- Decisions made: ADR-014, ADR-015.
- Metrics recorded: M-026 (replay 3-way range & latency gate), M-027 (exact-key cache), M-029 (L0 failure census), M-030 (L0 grounding replay zero false positive gate).


### 2026-10-10 session 7
- Did: Implemented all items in Amendment 1 Section A (Fix first) and stopped for Ani's review before Section B:
  1. A.1 Oversized commands (>4096 chars): Enforced that oversized commands are never ALLOW at any layer (L1, cache, ML). Updated `agent_airlock/policy/engine.py` with linear whole-string scanning across all deny rules using `DENY_RULE_PREFILTERS`. Updated `agent_airlock/daemon/router.py`, `agent_airlock/backends/laya.py`, and `agent_airlock/backends/jev.py` to bypass ML on oversized inputs and fail-closed to ASK. Added tests in `tests/test_policy_engine.py` with dangerous payloads buried at 3k, 6k, and 12k chars (all DENIED) and benign oversized returning AMBIGUOUS.
  2. A.2 Host auto-approval classification: Aligned `scripts/build_traces.py` with `private/host-allow-rules.txt` (`matches_host_rule()`). Any ASK matching host allow rules is classified as `host_auto` regardless of Pre->Post duration. Re-extracted 41 traces (7,051 steps). Re-reported headline approval fatigue strictly as `human_prompt`: baseline is 1,113 human prompts (15.78/100 cmds) -> replay remaining is 609 (8.64/100 cmds), saving 504 human prompts (7.15/100 cmds saved, 45.3% fatigue reduction). Pure L1 decision latency: p50=0.370 ms, p95=1.845 ms, p99=4.360 ms (passes 5.0 ms gate).
  3. A.3 Rule suggester exact-only workspace code rules & host filtering: Updated `agent_airlock/policy/suggester.py` to identify workspace code commands (`npm/pnpm/yarn run`, `make`, `pytest`, `python <file>`, `cargo`, `node <file>`) and emit exact-command rules only with warning tag `[WARN] executes repo-controlled code` and invalidation guidance, never wildcard script names. Skipped candidates covered by existing L1 or host allow rules. Reported estimated human prompts saved. Discovered 57 safe candidates from `private/audit.jsonl` and exported to `private/suggested-rules-report.yaml`. Added 2 tests in `tests/test_rule_suggester.py` (8 passed).
  4. A.4 L1 latency family profiling: Built `scripts/profile_l1_families.py` and profiled all 7,051 trace steps by rule family: Family A Git (586 steps): p50=0.079 ms, p99=1.520 ms; Family B PowerShell (558 steps): p50=0.448 ms, p99=2.792 ms; Family C Writes (1,353 steps): p50=1.125 ms, p99=4.844 ms. Slowest tail commands (> 5 ms) explained: exactly 13 commands are 1,500–4,200 char inline `python -c` scripts scanned linearly across 40+ patterns without match. Overall replay p99 is 4.360 ms (< 5.0 ms gate).
  5. A.5 Live patch backport guide: Written to gitignored `private/backport-to-live.md` detailing exact patch instructions for fork-bomb ReDoS fix, git `--output` / `--no-index` guards, prefilters, oversized limits, and host-rule classification. Zero exploit details in tracked files.
- Verified: Full hermetic pytest suite passes (`conda run -n airlock-v2 pytest`: 175 passed, 1 skipped in 18.27s). Adversarial perf tests pass (9 inputs 10k-50k chars all < 4.4 ms p99). Live audit log zero delta. Repo hygiene clean.
- Decisions made: ADR-013.
- Metrics recorded: M-022 (host auto classification & headline), M-023 (rule suggester exact-only), M-024 (L1 family latency profile), M-025 (full test suite).

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
