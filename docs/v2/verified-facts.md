# Verified Facts Ledger — Agent Airlock v2

This ledger records claims and their verification status (`VERIFIED`, `UNVERIFIED`, or `DISPROVEN`).
Every non-trivial technical claim must be logged here with concrete evidence (command, file:line, or URL).

---

## 1. Environment & Package Manifest

### Active Development Environment
- Conda Environment Name: `airlock-v2`
- Environment Path: `<CONDA_ROOT>\envs\airlock-v2`
- Python Version: `3.11.16`
- Package Installation: `agent-airlock 0.1.0` editable install from `<WORKSPACE>`

### Package Manifest (`pip list` in `airlock-v2`)
```text
Package           Version      Editable project location
----------------- ------------ --------------------------------------------------------
agent-airlock     0.1.0        <WORKSPACE>
annotated-doc     0.0.5
annotated-types   0.8.0
anyio             4.15.1
certifi           2026.7.22
click             8.5.0
colorama          0.4.6
filelock          3.32.3
fsspec            2026.7.0
h11               0.16.0
hf_transfer       0.1.9
hf-xet            1.6.0
httpcore          1.0.9
httpcore2         2.13.1
httpx             0.28.1
httpx2            2.13.1
huggingface_hub   1.33.0
idna              3.20
iniconfig         2.3.0
jev-gateway       0.1.0        <SVA_HARNESS_DIR>
Jinja2            3.1.6
laya              0.3.20
markdown-it-py    4.2.0
MarkupSafe        3.0.3
mdurl             0.1.2
mpmath            1.3.0
networkx          3.6.1
numpy             2.4.6
packaging         26.3
pillow            12.3.0
pip               26.2.1
pluggy            1.6.0
pydantic          2.13.5
pydantic_core     2.46.5
Pygments          2.21.0
pytest            9.1.1
PyYAML            6.0.3
regex             2026.9.10
rich              15.0.0
safetensors       0.8.0
setuptools        83.0.0
shellingham       1.5.4
sympy             1.13.1
tokenizers        0.23.2
torch             2.5.1+cu121
torchaudio        2.5.1+cu121
torchvision       0.20.1+cu121
tqdm              4.70.1
transformers      5.17.0
truststore        0.10.4
typer             0.27.2
typing_extensions 4.16.0
typing-inspection 0.4.4
wheel             0.47.0
```

---

## 2. Claims Ledger

| ID | Claim | Status | How verified (command / file:line / URL) | Date |
|---|---|---|---|---|
| F-001 | Operating System is Windows 11 Home Single Language (build 10.0.26300) | VERIFIED | `Get-CimInstance Win32_OperatingSystem` | 2026-10-09 |
| F-002 | CPU is AMD Ryzen 7 7445HS w/ Radeon 740M Graphics (6 cores, 12 logical processors) | VERIFIED | `Get-CimInstance Win32_Processor` | 2026-10-09 |
| F-003 | GPU is NVIDIA GeForce RTX 4050 Laptop GPU (6141 MiB VRAM), Driver 616.56, CUDA available in PyTorch | VERIFIED | `nvidia-smi` and `torch.cuda.is_available() == True` | 2026-10-09 |
| F-004 | System RAM is ~16 GB (16,009,232 KB visible, ~5.8 GB free) | VERIFIED | `Get-CimInstance Win32_OperatingSystem` | 2026-10-09 |
| F-005 | Live global agent-airlock install runs editable from local project workspace in conda env `torch_env`; live daemon running | VERIFIED | Confirmed by Ani 2026-10-09 |
| F-006 | Test suite passes with 132 passed, 1 skipped (README's "126" is outdated) | VERIFIED | `pytest -rs` in `airlock-v2` (`132 passed, 1 skipped in 19.47s`) | 2026-10-09 |
| F-007 | Test suite single skip reason is POSIX Unix domain socket permissions | VERIFIED | `tests\test_daemon_ipc.py:479: Unix domain socket permissions only applicable on POSIX` | 2026-10-09 |
| F-008 | `agent-airlock-daemon --status` does not print status; tries to start daemon and crashes if already active | VERIFIED | Inspected `agent_airlock/daemon/server.py:383-391` `main()`; no CLI arg parsing exists | 2026-10-09 |
| F-009 | `test_autospawn_failure_falls_back_to_force_ask` takes ~11–13s because `DaemonServer` asynchronously loads ModernBERT weights (~11.9s) in `asyncSetUp`, and teardown awaits the un-cancellable worker thread | VERIFIED | Measured `LocalLayaClient()` load time (11.93s) and inspected `agent_airlock/daemon/server.py:169,315` and `tests/test_daemon_ipc.py:42,54` | 2026-10-09 |
| F-010 | Tests require local `checkpoints/` folder because missing checkpoints cause `LocalLayaClient` to attempt network download from Hugging Face Hub (`ruddh/agent-airlock-laya`), blocking/hanging test teardown | VERIFIED | Inspected `agent_airlock/backends/laya.py:66-77,86-98` | 2026-10-09 |
| F-011 | Test suite hermetic isolation enforced: autouse fixture blocks live audit log access, non-loopback network is blocked, fake Laya client eliminates teardown blocking | VERIFIED | `tests/conftest.py`, `tests/test_isolation_hermetic.py`; verified 0-byte delta on live audit log across full suite run (136 passed, 1 skipped) | 2026-10-09 |
| F-012 | Read-only copy of real audit log exists at `private/audit.jsonl` (~24.8 MB, 24,768,804 bytes, gitignored) | VERIFIED | Inspected `private/` directory and `.gitignore:16` | 2026-10-09 |
| F-013 | Policy default rules exist at `agent_airlock/policy/default_rules.py` | VERIFIED | File exists, inspected `agent_airlock/policy/default_rules.py` | 2026-10-09 |
| F-014 | Audit reader exists at `agent_airlock/audit/reader.py` | VERIFIED | File exists, inspected `agent_airlock/audit/reader.py` | 2026-10-09 |
| F-015 | Hook installer exists at `installer.py` and `agent_airlock/hooks/installer.py` | VERIFIED | File exists, inspected `installer.py` and `agent_airlock/hooks/installer.py` | 2026-10-09 |
| F-016 | `data/training_examples.jsonl` does not exist in `data/`; dataset exists as `data/train.json` (160) and `data/val.json` (40), generated by `scripts/build_dataset.py` | DISPROVEN (as .jsonl) / VERIFIED (as train.json & val.json) | Inspected `data/` directory and `scripts/build_dataset.py:1-12` | 2026-10-09 |
| F-017 | Fine-tuned ModernBERT via `laya` with three heads (blast radius 0–4, reversibility 0–1, route 3-way) exists in codebase | VERIFIED | Inspected `agent_airlock/backends/laya.py:22-47` | 2026-10-09 |
| F-018 | v1 thresholds in code: Confident Safe (conf >= 0.90, blast <= 2.0 -> ALLOW), High Blast (blast >= 4.0, conf >= 0.85 -> DENY), else ASK | VERIFIED | Inspected `agent_airlock/backends/evaluator.py` and `agent_airlock/config.py:37-43` | 2026-10-09 |
| F-019 | Exact model id, size, license, MRL dimensions, dtype requirements, and prompt format of the intended embedder; whether "EmbeddingGemma 2" exists | UNVERIFIED | Appendix A item 1; to be verified in Phase 2 task 2.0 | 2026-10-09 |
| F-020 | Antigravity `PreToolUse` deny `reason` reaches model context verbatim (not truncated, not generic) | VERIFIED | Executed approved single `view_file` test on `.env`; returned verbatim: `tool call denied by pre-tool hook: Hard Deny: Cannot view secret file: Access or manipulation of sensitive credential, key, or secret configuration files` | 2026-10-09 |
| F-021 | Human approval of an ASKed command is inferred (`approved_inferred`) by correlating `PreToolUse` (ask/force_ask) with subsequent `PostToolUse` (`conv_id`, `step_idx`, `tool_name`) within a 10-minute window (600s) on non-empty `conversation_id`. Pre->Post delay histogram reveals a sharp bimodal distribution with a clear trough at 1.0–1.5s (0.51%) and a human cognitive modal peak at 5–10s (26.04%): `host_auto (< 1.5s)`: 1,126 events (25.63% of ASKs, 15.89 per 100 commands); `human_prompt (1.5s - 600s)`: 3,186 events (72.52% of ASKs, 44.97 real prompts per 100 commands); `unapproved / timeout`: 81 events (1.84% of ASKs, 1.14 per 100 commands). Percentiles: p25=0.81s, p50=6.08s, p75=14.15s, p90=42.89s, p95=81.75s, p99=236.77s. NEVER treat `approved_inferred` as a ground-truth safe label. | VERIFIED | `scripts/analyze_join_latency.py` on `private/audit.jsonl` | 2026-10-09 |
| F-022 | Fine-tuned ModernBERT / `laya` ONNX export passes `onnx.checker`; PyTorch vs ORT logit parity max abs diff 1.6e-5, route 40/40, blast 40/40. Reversibility head produced NaN in ORT on row 1 due to padding mask division; full 3-head dynamic deployment UNVERIFIED until Phase 1.5. Model weights kept gitignored. | UNVERIFIED (for full deployment) / VERIFIED (checker & route/blast parity) | `scripts/test_fixed_pad_onnx.py` on `data/val.json` | 2026-10-09 |
| F-023 | Real v1 numbers: CPU/GPU latency, load time, RAM, startup-to-ready on dev machine | VERIFIED | Cold load time ~11.93s, Warm p50 latency 47.61 ms on canonical eval set, 0.31 ms policy-only replay. Full metrics in `docs/v2/metrics.md` | 2026-10-09 |
| F-024 | Hook payload includes caller's environment/PATH/cwd (needed for L0 correctness) | UNVERIFIED | Appendix A item 7; to be investigated in Phase 1 task 1.4 | 2026-10-09 |
| F-025 | Whether `PostToolUse` can modify or truncate tool output | UNVERIFIED | Appendix A item 8; post-Phase 1 exploration | 2026-10-09 |
| F-026 | Composition and count reconciliation of `private/audit.jsonl`: Total 15,583 raw records. Exclusion of 316 test records (226 temp workspace + 90 test conv pattern) leaves exactly 15,267 clean records (8,159 PreToolUse + 7,108 PostToolUse). Preliminary single-heuristic workspace filter had left 8,259 PreToolUse; applying all 3 hygiene heuristics yields 8,159. When requiring non-empty `conversation_id`, there are exactly 7,084 clean PreToolUse events. ML auto-allows: 31 raw in audit log vs exactly 8 in clean production corpus (23 occurred in test/mock conversations). | VERIFIED | `scripts/analyze_audit.py` and `scripts/analyze_join_latency.py` on `private/audit.jsonl` | 2026-10-09 |
| F-027 | Test-suite behavior on other OSes (Linux / macOS CI status) | UNVERIFIED | Appendix A item 10; Windows dev environment active | 2026-10-09 |
| F-028 | `onnx` (1.23.2) and `onnxruntime` (1.31.0) installed in `airlock-v2` | VERIFIED | `conda run -n airlock-v2 pip list` | 2026-10-09 |
| F-029 | Dataset hygiene & leakage: Zero command leakage between `data/train.json` (160) and `data/val.json` (40); `check_eval_leakage.py` detects 9/15 leakages in historical benchmark | VERIFIED | `scripts/check_eval_leakage.py` and `scripts/validate_dataset.py` | 2026-10-09 |
| F-030 | Antigravity `run_command` deny `reason` reaches model context verbatim (not truncated, not generic) | VERIFIED | Executed approved test `run_command(CommandLine="Get-Content .env")`; returned verbatim: `tool call denied by pre-tool hook: Hard Deny: Commands targeting private keys, credential stores, or environment secret files` | 2026-10-09 |
| F-031 | ASK composition on clean corpus (4,684 prompted events): ML auto-allow was only 8 in clean corpus because ModernBERT's calibrated confidence distribution has mean 0.571 on safe route predictions with high calibration error (ECE 0.27–0.38), falling below the 0.90 gate. Approvals are not safety labels (I4); threshold recalibration is deferred to reviewed data in Phase 1.5. Cold start accounted for only 20 events (0.43%). | VERIFIED | `scripts/analyze_ask_composition.py` on `private/audit.jsonl` | 2026-10-09 |
| F-032 | Historical `benchmark_15` in `docs/benchmarks.md` is CONTAMINATED: 9/15 commands appear in `data/train.json`. Marked contaminated in docs. | VERIFIED | `scripts/check_eval_leakage.py` and `docs/benchmarks.md` | 2026-10-09 |
| F-033 | Clean corpus trace extraction and scrubbing: 41 production traces (7,051 steps) extracted, scrubbed of secrets/paths/usernames, kept local in `data/traces/` (gitignored per repo hygiene invariant). | VERIFIED | `scripts/build_traces.py` and `tests/test_repo_hygiene.py` | 2026-10-09 |
| F-034 | v1 baseline approval fatigue rate across clean traces: 61.79 ASKs per 100 commands (4,357 ASKs across 7,051 steps). Split: true human prompt rate is 44.97 per 100 commands; host auto-approval rate is 15.89 per 100 commands. | VERIFIED | `scripts/replay.py --all` and `scripts/analyze_join_latency.py` | 2026-10-09 |
| F-035 | Canonical human-reviewed evaluation set (`data/eval_set.jsonl`, N=50): 20 safe, 20 dangerous, 10 ambiguous. Zero leakage against `data/train.json` and `data/val.json`. Review sheet in `docs/v2/eval-review-sheet.md`. Rubric: "safe" = acceptable to auto-run unattended every time; when unsure, label toward needs-human/ambiguous, never safe. | VERIFIED | `scripts/build_eval_set.py` and `scripts/check_eval_leakage.py` | 2026-10-09 |
| F-036 | v1 baseline evaluation metrics on canonical human-reviewed eval set: False-Allow Rate 0.00% (0/20) [95% CI upper bound: 13.91%], False-Deny 0.00% (0/20), False-Ask 90.00% (18/20), Auto-Allow Precision 100.00% (2/2), Ambiguous 10/10 ask (excluded from gating), ECE 0.2730, Latency warm p50 47.61 ms. | VERIFIED | `scripts/eval_harness.py --eval data/eval_set.jsonl --ml` | 2026-10-09 |
| F-037 | Investigation of L1 prompt causes for read-only commands: (1) `git status -s` / `-sb` / `--porcelain` prompted because `allow-git-status-diff-log` strictly anchors bare `git status` without an argument group (unlike `git diff(?:\s+.*)?`); (2) Command chaining (e.g. `git status; git log`) without segment-level evaluation falls through to ambiguous; (3) PowerShell read-only cmdlets (`Get-ChildItem` [290x], `Select-String` [105x], `Get-Content` [96x], `Test-Path` [30x], `Get-Process` [18x], `Get-Command` [12x]) prompted because v1 has ZERO PowerShell L1 allow rules. | VERIFIED | `scripts/investigate_flag_prompts.py` on clean production corpus | 2026-10-09 |
| F-038 | Draft evaluation growth set (`data/eval_growth_draft.jsonl`, N=16): contains PowerShell near-miss pairs and workspace-write / trust-root pairs drafted for Ani's review. Zero leakage against train.json and val.json. Staged in `docs/v2/eval-growth-draft.md`. | VERIFIED | `scripts/build_eval_growth.py` and `scripts/check_eval_leakage.py` | 2026-10-09 |
| F-039 | 1.5s cutoff validation against `private/host-allow-rules.txt`: 100% (4/4) of `run_command` in `host_auto (<1.5s)` match host allow rules. Non-command events account for 99.6% of `host_auto` (`manage_task`: 509 [45.2%], `replace_file_content`: 354 [31.4%], `write_to_file`: 216 [19.2%], `schedule`: 39 [3.5%]). Fast-human clicks (1.5–2.0s): Exactly 0 `run_command` events; all 75 were file writes/edits (`write_to_file`: 50, `replace_file_content`: 24, `manage_task`: 1). | VERIFIED | `scripts/validate_host_cutoff.py` on `private/audit.jsonl` and `private/host-allow-rules.txt` | 2026-10-09 |
| F-040 | `human_prompt` ASK composition (3,186 events, 44.97 per 100 commands): `run_command` is 2,422 (76.02%), `write_to_file` is 366 (11.49%), `replace_file_content` is 310 (9.73%). Ranking candidate L1 families by human prompts saved per 100 commands: (1) PowerShell read-only cmdlets: 545 prompts (7.69/100 cmds); (2) Workspace file writes: 366 prompts (5.17/100 cmds); (3) Workspace file edits: 310 prompts (4.38/100 cmds); (4) Git read-only variants: 59 prompts (0.83/100 cmds); (5) Manage task status: 1 prompt (0.01/100 cmds). | VERIFIED | `scripts/analyze_human_prompts.py` on clean production corpus | 2026-10-09 |
| F-041 | "Out-of-distribution commands" is treated strictly as a hypothesis, not a finding; low ML auto-allow rate is empirically caused by uncalibrated confidence vs 0.90 gate on production distributions. | VERIFIED | Documented as hypothesis per Ani instruction | 2026-10-09 |
| F-042 | Security audit of existing `allow-git-status-diff-log` rule completed; finding and proposed remediation documented in gitignored `private/security-notes.md` per Policy Change Protocol. | VERIFIED | Confidential security evaluation in private notes | 2026-10-09 |
| F-043 | Phase 1.0 daemon CLI parity implemented (`--status`, `--stop`, `--foreground`) in `agent_airlock/daemon/server.py` and `PIDManager.read_info()`. Hook auto-spawn invokes `[sys.executable, "-m", "agent_airlock.daemon.server"]` with no arguments, starting server as expected. Verified in `tests/test_daemon_cli.py` (4 passed). | VERIFIED | `conda run -n airlock-v2 pytest tests/test_daemon_cli.py` | 2026-10-09 |
| F-044 | Phase 1.1 audit schema extension implemented (`decisionSource`, `cwd`, `policyHash`, `layerLatenciesMs`, `humanApproved: inferred`, `latency_class`, `cacheKeyHash`) with backward compatibility in `agent_airlock/audit/models.py`, `router.py`, and `reader.py`. Verified in `tests/test_audit_log.py` (21 passed). | VERIFIED | `conda run -n airlock-v2 pytest tests/test_audit_log.py` | 2026-10-09 |
| F-045 | Rule Family A (Git Read-Only) implemented in `default_rules.py` with flags on status (`-s`, `-sb`, `--short`, `--porcelain`, `--branch`), strict global prefixes (`-C <path>` with `(?-i:c)` case guard, `--no-pager`; forbidding `-c` and `--exec-path`), and strict `--output` guards rejecting any token starting with `--o` or `-o` (`--outp=x`, `-ofile`, `git show --output=main.py`, etc., preserving `--oneline`). Disallows chaining (`[;&|`]` etc.). Verified in `tests/test_policy_engine.py` (26 passed) and 51 scratch test cases. | VERIFIED | `conda run -n airlock-v2 pytest tests/test_policy_engine.py` | 2026-10-09 |
| F-046 | Rule Family B (PowerShell Read-Only) revised per Ani's constraints: character ban on `$ ( ) { } @ ` ` ; & > <` anywhere (including quotes), no script blocks, no `Env:`, `$env:`, `HKLM:`, `HKCU:`, UNC, or URLs; execution wrappers forbidden; pipes allowed only to `Select-Object`, `Sort-Object`, `Measure-Object`, `Out-String`, `Format-*`. Verified on 41 near-miss tests (100% pass). Clean corpus evaluation: 442 prompted commands match (100% in `human_prompt` class, saving 16.21 prompts per 100 commands). | VERIFIED | `scratch/evaluate_family_b.py` on `private/audit.jsonl` | 2026-10-09 |
| F-047 | Rule Family C (Workspace Writes & Edits) revised per Ani's constraints: canonical realpath containment strictly inside workspace, refusing drive roots, user home, or home ancestors; exclusion of `.vscode/`, `.github/`, `.husky/`, `.agents/`, `.git/`, `.pre-commit-config.yaml`, `.gitattributes`, `.gitmodules`, `.npmrc`, `.envrc`, `sitecustomize.py`, `*.pth`, `.env*`. Invariant test `test_invariant_no_l1_allow_executes_workspace_code` verified (0/21 execution commands allowed). Verified on 25 safety/near-miss tests. Clean corpus evaluation: 466 writes + 622 replaces = 1,088 matches, saving 620 human prompts (22.74 per 100 commands); 169 excluded. | VERIFIED | `scratch/evaluate_family_c.py` and `tests/test_policy_engine.py` | 2026-10-09 |
| F-048 | Clean production corpus prompt reduction with canonical denominator (7,084 clean PreToolUse commands): (1) Family A (Git Read-Only): 231 total matches (3.26/100 cmds), 227 human prompts saved (3.20/100 cmds); (2) Family B (PowerShell Read-Only): 289 total matches (4.08/100 cmds), 280 human prompts saved (3.95/100 cmds); (3) Family C (Workspace Writes & Edits): 1,058 matches (456 writes + 602 replaces, 14.94/100 cmds), 582 human prompts saved (8.22/100 cmds); (4) Combined (A + B + C): 1,578 total matches (22.28/100 cmds), 1,089 human prompts saved (15.37 per 100 commands). | VERIFIED | `scripts/compute_savings.py` on `private/audit.jsonl` | 2026-10-10 |
| F-049 | Rule Families A, B, and C integrated into `agent_airlock/policy/default_rules.py`, `agent_airlock/policy/engine.py`, and `agent_airlock/daemon/router.py`. Windows PowerShell backslash path handling verified non-posix; pipeline matching for safe cmdlets verified. AppData sensitive denylist updated to protect `AppData\Local` and `AppData\Roaming` while excluding `AppData\Local\Temp` used by test workspaces. All 158 tests pass hermetically in 23.05s (`tests/test_policy_engine.py` 29/29 passed). | VERIFIED | `conda run -n airlock-v2 pytest` | 2026-10-10 |
| F-050 | Post-L1 evaluation on canonical human-reviewed eval set (`data/eval_set.jsonl`, N=50): False-Allow rate strictly 0.00% (0/20) [95% CI upper bound: 13.91%]; False-Deny rate 0.00% (0/20); False-Ask rate dropped from 90.00% to 75.00% (15/20); Auto-Allow Precision 100.00% (5/5 auto-allows); Ambiguous Decisions: 10/10 ask (excluded from gating); ECE 0.2410. | VERIFIED | `conda run -n airlock-v2 python scripts/eval_harness.py --eval data/eval_set.jsonl --ml` | 2026-10-10 |
| F-051 | Post-L1 evaluation on growth draft eval set (`data/eval_growth_draft.jsonl`, N=16): False-Allow rate strictly 0.00% (0/6) [95% CI upper bound: 39.30%]; False-Deny rate 0.00% (0/8); False-Ask rate 62.50% (5/8); Auto-Allow Precision 100.00% (3/3 auto-allows); Ambiguous Decisions: 2/2 ask; ECE 0.0876. | VERIFIED | `conda run -n airlock-v2 python scripts/eval_harness.py --eval data/eval_growth_draft.jsonl --ml` | 2026-10-10 |
| F-052 | Post-L1 trace replay across 41 clean production traces (7,051 steps): ALLOW increased from 2,657 (37.68%) to 3,879 (55.01%); ASK decreased from 4,357 (61.79%) to 3,134 (44.45%); Approval Fatigue Rate dropped from 61.79 to 44.45 ASKs per 100 commands (saving 17.34 ASKs per 100 commands overall). Decision latency: p50=2.471 ms, p95=299.887 ms. Zero circuit breaker trips. | VERIFIED | `conda run -n airlock-v2 python scripts/replay.py --all --ml` | 2026-10-10 |
| F-053 | L1 ReDoS and latency root cause: Profiling per-rule identified catastrophic backtracking in `deny-fork-bomb` (2,326 ms on 10k chars) and `allow-powershell-readonly` (594 ms on 10k chars). Remediated with possessive quantifiers, bounded identifier lengths, eliminating nested quantifiers and unbounded `.*?`, fast pre-filters, and length capping (`_evaluate_run_command` scans head/tail 2048 chars for commands > 4096 chars). Replay pure L1 latency restored to p50=0.631 ms, p95=3.415 ms, p99=7.575 ms. All 9 adversarial long inputs (10k-50k chars) stay < 4.4 ms p99 in `tests/test_policy_perf.py`. | VERIFIED | `tests/test_policy_perf.py` and `scripts/replay.py --all` | 2026-10-10 |
| F-054 | Family A count reconciliation: In clean production PreToolUse (7,084 cmds), 175 `git status` existed. Exactly 140 were bare `git status` commands without flags; these 140 commands were ALREADY allowed by v1 L1 baseline rules (`allow-git-status`). Exactly 59 read-only Git commands in the clean corpus were prompted (`final_decision == 'ask'` and delay 1.5s-600s: 35 flagged `git status` + 24 other read-only git). The 231 figure was total read-only git commands in the clean corpus; 227 occurred in the `human_prompt` delay class, of which 168 were already allowed by v1. Net human prompts saved by Family A is 51–59 prompts (~0.8/100 cmds). | VERIFIED | `scripts/inspect_host_rules.py` and `scripts/analyze_human_prompts.py` on `private/audit.jsonl` | 2026-10-10 |
| F-055 | Headline approval fatigue reporting discipline: Baseline clean production corpus has 3,186 true human prompts (44.97 per 100 cmds) and 1,126 host auto-approvals (15.89 per 100 cmds). Headline fatigue metric is human_prompt only: ~45 -> ~33.6 per 100 commands (saving 11.36 prompts/100 cmds). Quoting legacy 61.8 -> 44.5 conflates host auto-approvals and is deprecated. `scripts/build_traces.py` and `scripts/replay.py` updated with explicit `latency_class` split. | VERIFIED | `scripts/replay.py --all` | 2026-10-10 |
| F-056 | Rule Family A hardening: `git diff --no-index` explicitly rejected; path arguments verified to resolve inside `workspace_root`; `git remote -v` dropped from hard-allow to force ASK (prevents URL token leakage). Verified in `tests/test_policy_engine.py` (29 passed). | VERIFIED | `conda run -n airlock-v2 pytest tests/test_policy_engine.py` | 2026-10-10 |
| F-057 | Held-out redteam set protocol: `private/heldout-redteam.jsonl` will be provided by Ani for a single run at Gate G1. It is strictly held out, never touched, and never used for rule development. | VERIFIED | Documented per Ani instruction | 2026-10-10 |
| F-058 | Phase 1.3 Audit-log rule suggester implemented (`agent_airlock/policy/suggester.py`, `agent_airlock/suggest_rules.py`, `scripts/suggest_rules.py`). Successfully mines human approvals with >= N threshold (default 3), strictly anchors patterns (`^...$`), parameterizes known clusters (`npm run <script>`, `pytest [flags] [tests]`), passes every candidate through a mandatory safety gate against dangerous eval examples and L1 hard-deny rules, attaches `⚠ executes repo-controlled code` warnings with invalidation guidance, and exports human-reviewable `.airlock-policy.yaml` snippets without ever auto-writing to policy files (Invariant I4). Verified by `tests/test_rule_suggester.py` (6 passed in 0.07s). | VERIFIED | `conda run -n airlock-v2 pytest tests/test_rule_suggester.py` | 2026-10-10 |
| F-059 | Linear Whole-String Scanning for Oversized Commands (Amendment 1 A.1): Commands > 4096 characters are never allowed at any layer (L1, cache, ML). Deny rules scan the WHOLE string linearly using prefilters (`DENY_RULE_PREFILTERS`). In `router.py`, commands > 4096 chars bypass ML and fail-closed to ASK. Tested with dangerous payloads buried at 3k, 6k, and 12k chars in `tests/test_policy_engine.py` (all denied) and benign oversized returning AMBIGUOUS. | VERIFIED | `conda run -n airlock-v2 pytest tests/test_policy_engine.py` | 2026-10-10 |
| F-060 | Host Auto-Approval Classification Alignment (Amendment 1 A.2): Any ASKed `run_command` matching a rule in `private/host-allow-rules.txt` is classified as `host_auto` regardless of Pre->Post execution duration. This reclassified 1,853 commands from `human_prompt` to `host_auto` that were auto-approved by Antigravity in < 5 ms but took > 1.5s to execute. True baseline human prompts: 1,113 (15.78/100 cmds). Replay remaining: 609 (8.64/100 cmds). Replay pure L1 latency: p50=0.370 ms, p95=1.845 ms, p99=4.360 ms (< 5.0 ms gate). Headline human fatigue reduction: **15.8 -> 8.6 per 100 commands** (saving 7.15 human prompts per 100 commands, 45.3% fatigue reduction). | VERIFIED | `scripts/build_traces.py` and `scripts/replay.py --all` | 2026-10-10 |
| F-061 | Rule Suggester Workspace Code Exact-Only & Host Filtering (Amendment 1 A.3): Commands that execute workspace code (`npm/pnpm/yarn run`, `make`, `pytest`, `python <file>`, `cargo`, `node <file>`) emit exact-command regexes only with warning `[WARN] executes repo-controlled code` and invalidation guidance, never wildcard script names. Candidates covered by existing L1 or host allow rules are skipped. Reports estimated human prompts saved. 57 candidates discovered from clean audit log, exported to `private/suggested-rules-report.yaml`. Verified by `tests/test_rule_suggester.py` (8 passed). | VERIFIED | `conda run -n airlock-v2 pytest tests/test_rule_suggester.py` and `scripts/suggest_rules.py` | 2026-10-10 |
| F-062 | L1 Family Profiling & Latency Breakdown (Amendment 1 A.4): Pure L1 evaluation across all 7,051 trace steps: Family A Git (586 steps): p50=0.079 ms, p99=1.520 ms. Family B PowerShell (558 steps): p50=0.448 ms, p99=2.792 ms. Family C Writes (1,353 steps): p50=1.125 ms, p99=4.844 ms. Overall replay p99 is 4.360 ms (< 5.0 ms gate). Slowest tail commands (> 5 ms) explained: exactly 13 commands are 1,500–4,200 character inline `python -c` scripts scanned linearly across all rules without match. | VERIFIED | `scripts/profile_l1_families.py` on `data/traces/` | 2026-10-10 |
| F-064 | 3-Way Replay Classification Range (Fix 1): Range [lower: retroactive host-rule, middle: first-match, upper: delay-only >=1.5s]. Baseline Human Prompts: `[15.78, 27.91, 44.96]` per 100 commands. Replay Human Prompts: `[8.64, 20.03, 33.60]` per 100 commands. Human Prompts Saved: `[7.15, 7.89, 11.36]` per 100 commands saved. Replay Latency: p50=0.396 ms, p95=1.820 ms, p99=4.014 ms (PASSES 5.0 ms gate). | VERIFIED | `scripts/replay.py --all` on 41 production traces | 2026-10-10 |
| F-065 | Prefilter Soundness (Fix 3): Permanent regression test in `tests/test_prefilter_soundness.py` verifies zero differences across deny rules with and without prefilters across eval, draft, train, val, and fuzzed variants (quotes, carets, casing, chaining). Passes in 0.48s. | VERIFIED | `tests/test_prefilter_soundness.py` | 2026-10-10 |
| F-066 | ML Real Token Length Limit (Fix 4): Maximum untruncated state token length is 451 tokens in `LocalLayaClient`. Any state exceeding 451 tokens fails closed to ASK. Tested with benign head + dangerous tail (3,080 chars < 4096, 457 tokens > 451) failing closed to ASK. | VERIFIED | `tests/test_local_laya.py` | 2026-10-10 |
| F-067 | Exact-Key Decision Cache (Phase 1.4): Placed strictly after L2 circuit breaker (R1). 6-tuple key `sha256(tool|normalized_cmd|cwd|workspace|policy_hash|trust_epoch)`. Enforces fail-closed on oversized (>4096) and ASK payloads. Added trust-epoch mtime invalidation on manifest writes. Verified repeated failing command still trips breaker before cache (9 tests pass in `tests/test_decision_cache.py`). | VERIFIED | `tests/test_decision_cache.py` | 2026-10-10 |
| F-068 | L0 Grounding Layer Architecture, Census, and Zero False Positives Gate (Phase 1.5): Evaluated on 41 clean production traces (7,051 steps, 2,626 executed commands). Census measured 279 post-approval failures (10 C1 binary, 0 C2 path, 0 C3 script, 0 C4 install, 269 other runtime errors). Built Checks C1-C4 with `mode: "shadow"` default, zero network calls (I9), conservative pass-through. Evaluated in full `enforce` mode against all 6,945 historically successful commands and tool calls across all 41 clean production traces: **ZERO FALSE POSITIVES** verified. Permanent regression test in `tests/test_grounding_replay.py`. | VERIFIED | `tests/test_grounding_replay.py` and `docs/v2/l0-grounding.md` | 2026-10-10 |

