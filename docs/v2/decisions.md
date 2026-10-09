# Decision Log — Agent Airlock v2

This is an append-only Architectural Decision Record (ADR) log for Agent Airlock v2.
Historical v1 label boundaries and architecture decisions are preserved in [docs/decisions.md](../decisions.md) and must never be overwritten.

---

## ADR-001 — Adopt this master prompt as plan of record
- Date / session: 2026-10-09 / session 1
- Status: accepted
- Decided by: user
- Context:
  Agent Airlock v1 successfully implemented a 4-tier safety cascade (deterministic rules, circuit breaker, ModernBERT classifier, fail-closed fallback). To address approval fatigue, token consumption, hallucinations, and throughput for agentic developers (using tools like Antigravity), v2 introduces a structured multi-phase evolution: evaluation harness (Phase 0), ONNX quantization, exact-key cache, audit-log rule suggester, L0 grounding (Phase 1), semantic similarity & breaker (Phase 2), and optional structural learned permits (Phase 3).
- Options considered:
  - Ad-hoc iterative enhancements without formal evaluation gating.
  - Separate standalone repository or complete ground-up rewrite.
  - Phased, gated development on branch `v2-semantic` governed by strict safety invariants, anti-hallucination protocols, and a living documentation system (`AIRLOCK_V2_MASTER_PROMPT.md`).
- Decision:
  Adopt `AIRLOCK_V2_MASTER_PROMPT.md` as the authoritative plan of record. Work proceeds strictly through the defined phases (Phase 0A through Phase 3), governed by the 10 core invariants (I1–I10) and locked architectural decisions (D1–D5).
- Consequences / what would make us revisit this:
  - Explicit instruction or architectural change requested by the repository owner (Ani).
  - Empirical invalidation of fundamental assumptions (e.g. inability to export classifier to ONNX, lack of measurable utility for downstream layers, or Antigravity hook protocol behavioral limitations).
- Evidence:
  - Repository branch `v2-semantic` created from main.
  - Phase 0A Orientation inspection and baseline test suite verification (`132 passed, 1 skipped`).

---

## ADR-002 — Canonical training and validation datasets (train.json and val.json)
- Date / session: 2026-10-09 / session 1
- Status: accepted
- Decided by: user
- Context:
  The master prompt and README reference `data/training_examples.jsonl` (200 examples across 21 tool families). Repo reality reveals that `data/` contains `train.json` (160 examples) and `val.json` (40 examples), generated from `scripts/build_dataset.py`.
- Options considered:
  - Generate a single `data/training_examples.jsonl` file and abandon existing train/val files.
  - Adopt `data/train.json` and `data/val.json` as the canonical v1 dataset baseline.
- Decision:
  Use `data/train.json` and `data/val.json` as the real training and validation sets for v2 evaluation harness and data pipeline tooling. Leakage checking (`scripts/check_eval_leakage.py`) and dataset validation scripts will validate against both files. Explicitly note that 40 validation examples is statistically insufficient for reliable threshold tuning (conf >= 0.90 / blast bounds); threshold calibration will require larger reviewed validation sets in Phase 1/2.
- Consequences / what would make us revisit this:
  - Continuous data expansion in Phase 1 task 1.6 targeting ~2,000 examples will supersede or expand these splits.
- Evidence:
  - Fact F-016 in `docs/v2/verified-facts.md`: `data/train.json` (160) and `data/val.json` (40) contain the 200 archetype examples.

---

## ADR-003 — Daemon CLI flags (--status, --stop, --foreground) implementation in Phase 1
- Date / session: 2026-10-09 / session 1
- Status: proposed
- Decided by: user
- Context:
  `README.md` documents `agent-airlock-daemon --status`, `agent-airlock-daemon --stop`, and `agent-airlock-daemon --foreground`. However, `agent_airlock.daemon.server:main` contains zero CLI argument parsing, crashing with `"Another daemon instance is already active"` when invoked while a daemon is running.
- Options considered:
  - Modify `README.md` to remove the documented CLI flags.
  - Implement the flags immediately in Phase 0.
  - Schedule implementation of `--status`, `--stop`, `--foreground` as a Phase 1 task to achieve README parity without disturbing Phase 0 evaluation baseline work.
- Decision:
  Adopt option 3: Implement `--status`, `--stop`, and `--foreground` in `agent_airlock.daemon.server` during Phase 1. In Phase 0, treat these flags as unreliable and do not modify daemon CLI code.
- Consequences / what would make us revisit this:
  - In Phase 1, `server.py:main` will add CLI argument parsing (checking `PIDManager.is_running()`, reading PID/port for `--status`, issuing termination signals for `--stop`, and running directly without daemonizing for `--foreground`).
- Evidence:
  - Fact F-008 in `docs/v2/verified-facts.md`: inspection of `agent_airlock/daemon/server.py:383-391`.

