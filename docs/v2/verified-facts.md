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
| F-011 | Test suite is NOT hermetically isolated from live audit log: `tests/test_daemon_ipc.py` defaults `audit.log_file` to `~/.gemini/antigravity-cli/audit.jsonl` | VERIFIED | Inspected `tests/test_daemon_ipc.py:31-41` (no audit config override) and `agent_airlock/config.py:63` | 2026-10-09 |
| F-012 | Read-only copy of real audit log exists at `private/audit.jsonl` (~24.8 MB, 24,768,804 bytes, gitignored) | VERIFIED | Inspected `private/` directory and `.gitignore:16` | 2026-10-09 |
| F-013 | Policy default rules exist at `agent_airlock/policy/default_rules.py` | VERIFIED | File exists, inspected `agent_airlock/policy/default_rules.py` | 2026-10-09 |
| F-014 | Audit reader exists at `agent_airlock/audit/reader.py` | VERIFIED | File exists, inspected `agent_airlock/audit/reader.py` | 2026-10-09 |
| F-015 | Hook installer exists at `installer.py` and `agent_airlock/hooks/installer.py` | VERIFIED | File exists, inspected `installer.py` and `agent_airlock/hooks/installer.py` | 2026-10-09 |
| F-016 | `data/training_examples.jsonl` does not exist in `data/`; dataset exists as `data/train.json` (160) and `data/val.json` (40), generated by `scripts/build_dataset.py` | DISPROVEN (as .jsonl) / VERIFIED (as train.json & val.json) | Inspected `data/` directory and `scripts/build_dataset.py:1-12` | 2026-10-09 |
| F-017 | Fine-tuned ModernBERT via `laya` with three heads (blast radius 0–4, reversibility 0–1, route 3-way) exists in codebase | VERIFIED | Inspected `agent_airlock/backends/laya.py:22-47` | 2026-10-09 |
| F-018 | v1 thresholds in code: Confident Safe (conf >= 0.90, blast <= 2.0 -> ALLOW), High Blast (blast >= 4.0, conf >= 0.85 -> DENY), else ASK | VERIFIED | Inspected `agent_airlock/backends/evaluator.py` and `agent_airlock/config.py:37-43` | 2026-10-09 |
| F-019 | Exact model id, size, license, MRL dimensions, dtype requirements, and prompt format of the intended embedder; whether "EmbeddingGemma 2" exists | UNVERIFIED | Appendix A item 1; to be verified in Phase 2 task 2.0 | 2026-10-09 |
| F-020 | Whether the Antigravity `PreToolUse` deny `reason` reaches the model's context | UNVERIFIED | Appendix A item 2; to be tested in Phase 1 task 1.4 | 2026-10-09 |
| F-021 | How (or whether) human approval of an ASKed command is observable to the hooks | UNVERIFIED | Appendix A item 3; to be investigated in Phase 1 task 1.1 | 2026-10-09 |
| F-022 | Whether the fine-tuned ModernBERT/`laya` model exports to ONNX with all three heads; INT8 speedup on CPU; whether GPU speedup exists | UNVERIFIED | Appendix A item 4; to be tested in Phase 1 task 1.5 | 2026-10-09 |
| F-023 | Real v1 numbers: CPU/GPU latency, load time, RAM, startup-to-ready on dev machine | UNVERIFIED | Appendix A item 5; partial verification (load time ~11.93s); full benchmark in Phase 0.4 | 2026-10-09 |
| F-024 | Hook payload includes caller's environment/PATH/cwd (needed for L0 correctness) | UNVERIFIED | Appendix A item 7; to be investigated in Phase 1 task 1.4 | 2026-10-09 |
| F-025 | Whether `PostToolUse` can modify or truncate tool output | UNVERIFIED | Appendix A item 8; post-Phase 1 exploration | 2026-10-09 |
| F-026 | Composition and trace yield of user's `private/audit.jsonl` | UNVERIFIED | Appendix A item 9; to be analyzed in Phase 0 task 0.2 | 2026-10-09 |
| F-027 | Test-suite behavior on other OSes (Linux / macOS CI status) | UNVERIFIED | Appendix A item 10; Windows dev environment active | 2026-10-09 |
| F-028 | `onnxruntime` is not currently installed in `airlock-v2` | VERIFIED | `pip list` in `airlock-v2` shows no `onnxruntime` | 2026-10-09 |
