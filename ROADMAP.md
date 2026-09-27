# Agent Airlock Roadmap 🗺️

This document tracks prioritized future enhancements and backlog items for Agent Airlock, ranked by operational impact, security value, and execution priority.

---

## 🔴 High Priority (Immediate Value & Latency Optimization)

1. **CPU Quantization (INT8 / ONNX / AWQ)**
   - *Description*: Quantize the fine-tuned ModernBERT Laya checkpoint to INT8 or ONNX Runtime to bring CPU inference latency from ~1.2s down to < 100ms on CPU-only machines.
   - *Target Area*: `agent_airlock/backends/laya.py`, export scripts.

2. **In-Memory LRU Inference Cache**
   - *Description*: Cache tool input hashes and model classification results with an LRU eviction policy to bypass ML inference entirely on repeated identical agent queries across turns.
   - *Target Area*: `agent_airlock/daemon/router.py`, `agent_airlock/backends/evaluator.py`.

---

## 🟡 Medium Priority (Detection Breadth & Operator Ergonomics)

3. **$k$-Cycle Loop Detection ($k \ge 2$)**
   - *Description*: Expand the circuit breaker beyond consecutive 1-step identical failures to identify oscillating multi-tool failure loops (e.g., alternating between `write_to_file` and `pytest`).
   - *Target Area*: `agent_airlock/circuit_breaker/`.

4. **CLI Policy Dry-Run Tool (`agent-airlock test-policy`)**
   - *Description*: Dedicated CLI subcommand to dry-run workspace policy rules against test command vectors offline without requiring a running daemon or live agent session.
   - *Target Area*: `agent_airlock/cli.py`, `agent_airlock/policy/engine.py`.

5. **Symlink & Canonical Realpath Normalization**
   - *Description*: Resolve symbolic links and junction points to their canonical physical disk paths before running regex and anti-tamper path matching.
   - *Target Area*: `agent_airlock/policy/normalizer.py`.

6. **Calibration & Drift Watchdog**
   - *Description*: Monitor divergence between operator prompt decisions and model confidence scores in the audit log to alert when retraining or threshold calibration is needed.
   - *Target Area*: `agent_airlock/audit/`, background monitoring.

---

## 🟢 Low Priority (Long-Term Hardening & Compliance)

7. **Multi-Tool Compound Policy Schema**
   - *Description*: Define expressive declarative policies with compound temporal prerequisites (e.g., requiring an inspection via `view_file` before permitting `write_to_file`).
   - *Target Area*: `agent_airlock/config.py`, policy schema.

8. **Audit Log Compression & Cryptographic HMAC Signing**
   - *Description*: Background gzip compression for rotated `.jsonl` audit files with optional HMAC chain verification for tamper-evident compliance logs.
   - *Target Area*: `agent_airlock/audit/logger.py`.
