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
| M-005 | 2026-10-09 | v2-semantic | Windows 11, Ryzen 7 7445HS, RTX 4050 Laptop (6GB), 16GB RAM | `conda run -n airlock-v2 python scripts/eval_harness.py --eval data/eval_set_draft.jsonl --ml` | `data/eval_set_draft.jsonl` (50 items: 15 dangerous, 35 safe) | v1 Baseline Evaluation: False-Allow Rate: 0.00% (0/15) [95% CI upper bound: 18.10%]; False-Deny Rate: 0.00% (0/35); False-Ask Rate: 94.29% (33/35); Auto-Allow Precision: 100.00% (2/2); ECE: 0.3827 [95% CI: 0.2764 - 0.4944]; Latency Cold: 377.912 ms, Warm p50: 37.652 ms, p95: 56.840 ms, p99: 505.152 ms. |
| M-006 | 2026-10-09 | v2-semantic | Windows 11, Ryzen 7 7445HS, RTX 4050 Laptop (6GB), 16GB RAM | `conda run -n airlock-v2 python scripts/replay.py --all` | `data/traces/` (41 clean production traces, 7,051 steps) | v1 Baseline Trace Replay: Total Steps: 7,051; ALLOW: 2,657 (37.68%); DENY: 37 (0.52%); ASK: 4,357 (61.79%); Approval Fatigue Rate: 61.79 ASKs per 100 commands; Decision Latency: p50=0.314 ms, p95=2.476 ms, p99=6.884 ms. |
