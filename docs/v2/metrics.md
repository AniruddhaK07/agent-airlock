# Metrics Ledger — Agent Airlock v2

Every measured latency, throughput, RAM footprint, calibration score, or accuracy number must be recorded here.
Figures marked *(hypothesis)* in prompts or design docs are targets, never recorded as facts without measurement.

---

| Run ID | Date | Git SHA | Hardware | Command | Dataset (path + sha256) | Results |
|---|---|---|---|---|---|---|
| M-001 | 2026-10-09 | 8673211 | Windows 11, Ryzen 7 7445HS, RTX 4050 Laptop (6GB), 16GB RAM | `conda run -n airlock-v2 pytest -rs` | N/A (Test suite) | 132 passed, 1 skipped in 19.47s. Skip reason: `tests\test_daemon_ipc.py:479: Unix domain socket permissions only applicable on POSIX`. |
| M-002 | 2026-10-09 | 8673211 | Windows 11, Ryzen 7 7445HS, RTX 4050 Laptop (6GB), 16GB RAM | `conda run -n airlock-v2 python -c "..."` | Local checkpoint: `checkpoints/laya-finetuned` | Cold model load time: 11.93s on dev workstation. Explains ~11–13s duration in `test_daemon_ipc.py` teardown when background model loading task joins. |
| M-003 | 2026-10-09 | 788e516 | Windows 11, Ryzen 7 7445HS, RTX 4050 Laptop (6GB), 16GB RAM | `conda run -n airlock-v2 python -c "..."` (pytest full suite + audit size delta) | Full test suite (137 items) | 136 passed, 1 skipped, 217 subtests passed in 32.15s. Exact zero-byte delta on live audit log: size before 25492988, size after 25492988 (diff: 0). |
| M-004 | 2026-10-09 | 788e516 | Windows 11, Ryzen 7 7445HS, RTX 4050 Laptop (6GB), 16GB RAM | `conda run -n airlock-v2 python scripts/analyze_audit.py` | `private/audit.jsonl` (24,768,804 bytes) | Total 15,583 records. Test exclusions: 316 (2.03%). Clean production records: 15,267 (97.97%) across 66 conversations. PreToolUse asks: 4,065 -> Correlated PostToolUse human approvals: 4,012 (98.7%), human denials/aborts: 53 (1.3%). ML auto-allows: 31. Policy hard-allows: 3,138. |
