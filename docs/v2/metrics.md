# Metrics Ledger — Agent Airlock v2

Every measured latency, throughput, RAM footprint, calibration score, or accuracy number must be recorded here.
Figures marked *(hypothesis)* in prompts or design docs are targets, never recorded as facts without measurement.

---

| Run ID | Date | Git SHA | Hardware | Command | Dataset (path + sha256) | Results |
|---|---|---|---|---|---|---|
| M-001 | 2026-10-09 | 8673211 | Windows 11, Ryzen 7 7445HS, RTX 4050 Laptop (6GB), 16GB RAM | `conda run -n airlock-v2 pytest -rs` | N/A (Test suite) | 132 passed, 1 skipped in 19.47s. Skip reason: `tests\test_daemon_ipc.py:479: Unix domain socket permissions only applicable on POSIX`. |
| M-002 | 2026-10-09 | 8673211 | Windows 11, Ryzen 7 7445HS, RTX 4050 Laptop (6GB), 16GB RAM | `conda run -n airlock-v2 python -c "import time; t0 = time.perf_counter(); from agent_airlock.backends.laya import LocalLayaClient; c = LocalLayaClient(); print(time.perf_counter() - t0)"` | Local checkpoint: `checkpoints/laya-finetuned` | Cold model load time: 11.93s on dev workstation. Explains ~11–13s duration in `test_daemon_ipc.py` teardown when background model loading task joins. |
