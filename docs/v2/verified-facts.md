# Verified Facts Ledger — Agent Airlock v2

This ledger records claims and their verification status (`VERIFIED`, `UNVERIFIED`, or `DISPROVEN`).
Every non-trivial technical claim must be logged here with concrete evidence (command, file:line, or URL).

---

## 1. Environment & Package Manifest

### Active Development Environment
- Conda Environment Name: `airlock-v2`
- Environment Path: `C:\Users\ASUS\miniconda3\envs\airlock-v2`
- Python Version: `3.11.16`
- Package Installation: `agent-airlock 0.1.0` editable install from `C:\Users\ASUS\Desktop\A\projects\kaizen\agent-airlock-v2`

### Package Manifest (`pip list` in `airlock-v2`)
```text
Package           Version      Editable project location
----------------- ------------ --------------------------------------------------------
agent-airlock     0.1.0        C:\Users\ASUS\Desktop\A\projects\kaizen\agent-airlock-v2
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
jev-gateway       0.1.0        C:\Users\ASUS\Desktop\A\projects\sva-harness
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
| F-005 | Live global agent-airlock install runs editable from `...\projects\sva-harness` in conda env `torch_env`; live daemon running | VERIFIED | Confirmed by Ani 2026-10-09 |
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
