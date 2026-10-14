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
- Status: accepted
- Decided by: user
- Context:
  `README.md` documents `agent-airlock-daemon --status`, `agent-airlock-daemon --stop`, and `agent-airlock-daemon --foreground`. However, `agent_airlock.daemon.server:main` originally contained zero CLI argument parsing, crashing with `"Another daemon instance is already active"` when invoked while a daemon is running.
- Options considered:
  - Modify `README.md` to remove the documented CLI flags.
  - Implement the flags immediately in Phase 0.
  - Schedule implementation of `--status`, `--stop`, `--foreground` as a Phase 1 task to achieve README parity.
- Decision:
  Implement `--status`, `--stop`, and `--foreground` in `agent_airlock.daemon.server:main` in Phase 1.0 using `argparse`. Hook auto-spawn continues to invoke `[sys.executable, "-m", "agent_airlock.daemon.server"]` with no arguments, running the background server as expected.
- Consequences / what would make us revisit this:
  - Any change to hook spawn arguments would require updating both client and server entrypoints.
- Evidence:
  - Claim F-043 in `docs/v2/verified-facts.md`; `tests/test_daemon_cli.py` (4 passed).

---

## ADR-004 — Audit Schema Extension & Dual Serialization Format (Phase 1.1)
- Date / session: 2026-10-09 / session 4
- Status: accepted
- Decided by: user
- Context:
  Section 8 requires backward-compatible audit logging with extended provenance: `decisionSource` (`l0|l1|l2|cache|l2_5|l3|l3_5|human|fallback`), `cwd`, `policyHash`, `layerLatenciesMs`, `humanApproved` (`"inferred"`), `latency_class`, and `cacheKeyHash`. Existing v1 audit records lack these fields.
- Options considered:
  - Introduce breaking schema changes or separate log files for v2.
  - Extend `AuditEvent` with optional fields, support both camelCase and snake_case in `to_dict()` and `from_dict()`, and preserve full compatibility with legacy log files.
- Decision:
  Adopt dual camelCase and snake_case compatibility in `agent_airlock.audit.models.AuditEvent`. All new fields default to `None`. Router populates `decision_source`, `cwd`, `policy_hash`, and `layer_latencies_ms`. `AuditReader` gracefully reads legacy rows and exposes query filters for `decision_source` and `human_approved`.
- Consequences / what would make us revisit this:
  - Additional pipeline layers (L0 grounding, L2.5 similarity, L3.5 templates) will populate their respective `decisionSource` values without schema changes.
- Evidence:
  - Claim F-044 in `docs/v2/verified-facts.md`; `tests/test_audit_log.py` (21 passed).

---

## ADR-005 — L1 Policy Hardening & Expansion Protocol (Phase 1.2)
- Date / session: 2026-10-09 / session 4
- Status: accepted (Family A implemented; Families B & C evaluated and submitted)
- Decided by: user
- Context:
  L1 expansion is required to reduce human approval fatigue without compromising deterministic safety. Existing L1 rules permitted file overwrite via `git diff/log/show --output` due to unanchored argument matching, and lacked coverage for PowerShell and workspace edits.
- Options considered:
  - Ad-hoc regex widening without negative lookaheads or process identity verification.
  - Strict Policy Change Protocol: each rule family requires explicit pattern definitions, negative lookaheads/guards, empirical near-miss suites, clean corpus prompt reduction measurements, and user sign-off before modifying `default_rules.py`.
- Decision:
  1. Implement approved Family A with strict negative lookahead `(?!.*?(?:[;&|`]|(?:\s|^)-(?:o\S*|-o(?!neline\b)\S*)))`, allowing only `-C <path>` (case-guarded with `(?-i:c)`) and `--no-pager`, and status flags (`-s`, `-sb`, `--short`, `--porcelain`, `--branch`).
  2. Implement CLI `--stop` identity verification checking `get_process_cmdline(pid)` for `agent_airlock.daemon` before terminating.
  3. Enforce policy invariant: "no L1 allow rule executes workspace-controlled code" via automated unit test.
  4. Submit revised Families B and C with near-miss test results and clean corpus measurements for user review prior to `default_rules.py` modification.
- Consequences / what would make us revisit this:
  - Discovery of novel option parsing bypasses in tool CLIs.
  - Development of trust-epoch cache in later phases allowing safe execution of tested code.
- Evidence:
  - Claims F-045, F-046, F-047 in `docs/v2/verified-facts.md`; `tests/test_policy_engine.py` (26 passed).

---

## ADR-006 — Rule Family A: Git Read-Only Hardening & Workspace Containment
- Date / session: 2026-10-10 / session 5
- Status: accepted
- Decided by: user
- Context:
  Git read-only queries (`status`, `diff`, `log`, `show`, `rev-parse`, `describe`, `remote`, `tag`, `branch`) are common developer operations. However, git options can trigger side effects: `--output=<file>` on `diff`, `log`, and `show` can overwrite arbitrary files; `-c key=value` can override arbitrary git config (including `core.pager` execution); `--exec-path` can redirect binary execution; and `-C <path>` could target repositories outside the workspace.
- Options considered:
  - Broad allow regex allowing any arguments after `git log` or `git diff`.
  - Disallowing all flags and requiring exact bare commands.
  - Hardened pattern permitting safe formatting flags (`--oneline`, `--pretty=oneline`, `--short`, etc.) while strictly forbidding file redirection, config overrides, and external path targets.
- Decision:
  1. Permit flags on `git status`: `-s`, `-sb`, `--short`, `--porcelain`, `--branch`.
  2. Permit only global prefixes `--no-pager` and `-C <path>` (with `(?-i:c)` case guard). Forbid `-c` and `--exec-path`.
  3. Require `-C <path>` to resolve strictly inside `workspace_root`.
  4. Guard `diff`, `log`, and `show` with negative lookahead rejecting any option starting with `--ou` or `-o` (`--ou*`, `-o*`), preventing `--output`, `--outp=x`, `-ofile`, `-o`, while safely allowing `--oneline`, `--online`, and `--pretty=oneline`.
  5. Forbid command chaining (`[;&|`]` etc.).
- Consequences / what would make us revisit this:
  - Legitimate developer use cases requiring other git subcommands (e.g. `stash list`, `blame`) will be evaluated as separate proposals.
- Evidence:
  - `tests/test_policy_engine.py`: `test_safe_git_commands` and `test_git_output_redirection_and_dangerous_flags_disallowed` (all pass). Clean corpus savings: 227 human prompts saved (3.20 per 100 commands across 7,084 commands).

---

## ADR-007 — Rule Family B: Safe PowerShell Read-Only Inspection
- Date / session: 2026-10-10 / session 5
- Status: accepted
- Decided by: user
- Context:
  Windows developers using PowerShell encounter high approval fatigue on safe inspection cmdlets (`Get-ChildItem`, `Select-String`, `Get-Content`, `Test-Path`, `Get-Process`, `Get-Command`). However, PowerShell features powerful scripting mechanisms (subshells `$()`, backticks, scriptblocks `{}`, parameter splatting `@`, pipeline side effects, and PSDrive providers like `Env:`, `HKLM:`, `HKCU:`) that can leak credentials or execute code.
- Options considered:
  - Disallow all PowerShell commands, forcing developers to use cmd.exe or bash.
  - Allow unconstrained PowerShell read-only cmdlets.
  - Implement a strictly guarded L1 regex permitting only safe cmdlets, banning scripting metacharacters and sensitive paths, allowing pipelines only to safe formatting/aggregation cmdlets, and requiring all path targets to resolve inside `workspace_root`.
- Decision:
  1. Root cmdlets limited to: `Get-ChildItem`, `Select-String`, `Get-Content`, `Test-Path`, `Get-Process`, `Get-Command`.
  2. Strict character and syntax ban: reject `$` (variables/subshells), `` ` `` (backticks/escape), `(`, `)`, `{`, `}` (closures/scriptblocks), `@` (splatting), `;`, `&`, `>`, `<` anywhere in the command line (including inside quotes).
  3. Disallow execution wrappers (`iex`, `Invoke-Expression`, `powershell -Command`, `pwsh`).
  4. Disallow dangerous flags (`-Wait`).
  5. Disallow sensitive PSDrives and remote protocols: `Env:`, `$env:`, `HKLM:`, `HKCU:`, UNC (`\\\\`, `//`), and URLs (`http://`, `https://`, `ftp://`).
  6. Pipelines permitted strictly to safe, side-effect-free projection/formatting cmdlets: `Select-Object`, `Sort-Object`, `Measure-Object`, `Out-String`, `Format-Table`, `Format-List`, `Format-Wide`, `Format-Custom`.
  7. All path arguments (`-Path`, `-LiteralPath`, positional) must resolve strictly inside `workspace_root`. External paths fall through to AMBIGUOUS / human prompt.
  8. Expand sensitive-path denylist to protect `.npmrc`, `.pypirc`, `.netrc`, `.git-credentials`, `.docker/config.json`, `.kube/`, `.gemini/` auth/oauth files, browser profile directories, and `~/AppData` (excluding `AppData\Local\Temp`).
- Consequences / what would make us revisit this:
  - Complex multi-stage pipelines or custom formatting scripts remain AMBIGUOUS / fall through to human/ML evaluation.
- Evidence:
  - `tests/test_policy_engine.py`: `test_powershell_readonly_allowed` and `test_powershell_dangerous_and_sensitive_disallowed` (all pass). Clean corpus savings: 280 human prompts saved (3.95 per 100 commands across 7,084 commands).

---

## ADR-008 — Rule Family C: Safe Workspace File Modifications & Trust-Root Containment
- Date / session: 2026-10-10 / session 5
- Status: accepted
- Decided by: user
- Context:
  Tools `write_to_file` and `replace_file_content` represent 21.2% of human prompts (676 prompts in clean corpus). Auto-allowing routine source code edits within a project drastically reduces developer fatigue, but must never allow autonomous tampering with project trust roots (e.g. build scripts, CI, package manifests, or Airlock configuration), path traversal outside the project, or dangerous workspaces (e.g. user home or root directories).
- Options considered:
  - Require human approval for all file mutations without exception.
  - Auto-allow all file writes within any directory passed as workspace.
  - Implement strict workspace containment with hard trust-root exclusions and invariant tests ensuring no L1 allow rule executes workspace code.
- Decision:
  1. Refuse auto-allow if `workspace_root` is a filesystem root (`/`, `C:\`), the user home directory (`~`), or an ancestor of home.
  2. Require `TargetFile` to resolve strictly inside `workspace_root` (canonical `Path.resolve().is_relative_to()`), strictly excluding the workspace root itself.
  3. Tier-0 anti-tamper strictly denies mutations to `.agents/hooks.json`, `*policy.yaml`, and daemon runtime socket/PID/token files before any allow rule.
  4. Exclude all project trust roots and sensitive configuration paths from auto-allow (routing them to AMBIGUOUS / human confirmation):
     - Package manifests & lockfiles: `package.json`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `Cargo.toml`, `Cargo.lock`, `build.rs`, `requirements*.txt`, `Pipfile`, `Pipfile.lock`, `pyproject.toml`, `setup.py`, `setup.cfg`, `tox.ini`, `conftest.py`.
     - Build & automation tools: `Makefile`, `justfile`, `Taskfile*`, `Dockerfile*`, `docker-compose*.yml`.
     - Executable scripts directly under `scripts/`: `*.sh`, `*.bat`, `*.ps1`, `*.cmd`.
     - Airlock policy and source files: `.airlock-policy.yaml`, `agent_airlock/**`, `*policy.yaml`, `*policy.json`.
     - VCS and IDE metadata: `.git/`, `.github/`, `.vscode/`, `.husky/`, `.agents/`, `.pre-commit-config.yaml`, `.gitattributes`, `.gitmodules`, `.envrc`, `sitecustomize.py`, `*.pth`.
     - Sensitive credentials & keys: `.env*`, `*.pem`, `*.key`, `id_rsa*`, `credentials*`.
  5. Invariant test: verify that no L1 allow rule allows executing workspace-controlled code (`python <file>`, `npm test`, `pytest`, `make`, etc.).
- Consequences / what would make us revisit this:
  - Editing package manifests or build scripts requires human confirmation until a trust-epoch model or interactive elevation is implemented.
- Evidence:
  - `tests/test_policy_engine.py`: `test_workspace_file_writes_allowed_and_trust_root_exclusions` and `test_invariant_no_l1_allow_executes_workspace_code` (all pass). Clean corpus savings: 582 human prompts saved (8.22 per 100 commands across 7,084 commands). Excluded 169 sensitive/external operations.

---

## ADR-009 — ReDoS Elimination, Length Capping, and L1 Latency Resilience
- Date / session: 2026-10-10 / session 5
- Status: accepted
- Decided by: user
- Context:
  Following Rule Families A, B, and C integration, L1 replay latency rose from 0.3/2.5/6.9 ms to 2.5/300/718 ms. Profiling identified severe catastrophic backtracking (ReDoS) in `deny-fork-bomb` (taking 2,326 ms on 10k chars) and `allow-powershell-readonly` (taking 594 ms on 10k chars). Unbounded `.*?` lookaheads and nested quantifiers represent both latency and security vulnerabilities (algorithmic complexity denial-of-service).
- Options considered:
  - Rely on Python regex timeout if supported.
  - Eliminate nested quantifiers, convert unbounded lookaheads to atomic/possessive character classes, enforce strict length caps before regex evaluation, and treat ReDoS as a security bug.
- Decision:
  1. Fix `deny-fork-bomb`: bounded lookbehind prefix `(?:^|(?<=[;&|\s]))([a-zA-Z0-9_.:]{1,32}+)`, possessive `[^}]*+`, removed second unbounded clause. Runs in 0.34 ms on 10k chars.
  2. Fix `allow-powershell-readonly`: replaced nested quantifier repetition `(?:\s+(?:\'[^\']*\'|\"[^\"]*\"|[^\s|]+))*` with bounded character class `[^|$(){}\@;&><\`\r\n]*+`. Runs in 0.33 ms on 10k chars.
  3. Harden destructive FS, pipe, and network regexes: possessive `\brm\s++`, atomic `(?>\s+-[a-zA-Z0-9_\-]+)*\s+`, bounded character classes `[^\n\r;]{0,256}?`.
  4. Enforce length cap in `_evaluate_run_command`: commands > 4096 chars are immediately disqualified from hard-allow; deny rules scan head and tail 2048 chars only (`[raw_cmd[:2048], raw_cmd[-2048:]]`).
  5. Fast pre-filter in `is_tampering_command`: exits in 0.01 ms if no tamper signatures present. Subcommand split capped at 32; subshell extraction capped at 16.
  6. Add performance regression test `tests/test_policy_perf.py`: 9 adversarial long inputs (10k-50k chars) must stay strictly < 5.0 ms p99 in L1.
- Consequences / what would make us revisit this:
  - Any future regex added to `default_rules.py` must be verified against adversarial inputs for absence of catastrophic backtracking.
- Evidence:
  - `tests/test_policy_perf.py`: 3 passed in 0.59s. All adversarial inputs stay < 4.4 ms p99. Replay pure L1 latency restored to p50=0.631 ms, p95=3.415 ms, p99=7.575 ms.

---

## ADR-010 — Family A Git Read-Only Hardening (Path Containment, No-Index, Remote Egress)
- Date / session: 2026-10-10 / session 5
- Status: accepted
- Decided by: user
- Context:
  Ani's review of Family A identified security edge cases: `git diff --no-index` permits comparing arbitrary files outside git; path arguments could reference files outside the workspace; and `git remote -v` prints repository URLs which often contain plaintext credentials or OAuth tokens (e.g., `https://<token>@github.com/...`).
- Options considered:
  - Allow `git remote -v` and rely on output scrubbing.
  - Reject `--no-index`, require all path arguments to resolve inside `workspace_root`, and drop or ASK `git remote -v`.
- Decision:
  1. Reject `--no-index` explicitly in `_evaluate_run_command`.
  2. Require `-C <path>` to resolve canonically inside `workspace_root`.
  3. Validate any path argument in git inspection commands (arguments after `--`, containing slashes, starting with `.`, or positional path arguments) to resolve inside `workspace_root`.
  4. Drop `git remote -v` from `allow-git-status-diff-log` so it falls through to AMBIGUOUS / ASK, preventing automated exposure of URL authentication tokens.
- Consequences / what would make us revisit this:
  - Developers checking git remotes will receive an interactive prompt (ASK) rather than an automated ALLOW.
- Evidence:
  - `tests/test_policy_engine.py`: Unit tests asserting `--no-index`, path escape, and `git remote -v` are NOT allowed. (29 passed in 0.15s).

---

## ADR-011 — Metric Reporting Discipline: Human-Prompt Fatigue Separation from Host Auto-Approvals
- Date / session: 2026-10-10 / session 5
- Status: accepted
- Decided by: user
- Context:
  In v1 baseline, the total ASK rate of 61.79% (4,357 / 7,051) conflated 1,126 host auto-approvals (< 1.5s delay, auto-handled by Antigravity IDE without prompting the human) with 3,186 true human prompts (1.5s-600s delay). Quoting 61.8 -> 44.5 conflated these two distinct behaviors.
- Options considered:
  - Continue reporting overall raw ASK rate.
  - Report headline fatigue strictly as `human_prompt` only (~45 -> ~30 per 100 commands), with replay and audit logs split by `latency_class` (`human_prompt` vs `host_auto`).
- Decision:
  1. The headline approval fatigue metric must strictly report `human_prompt` rate: ~45 -> ~33.6 per 100 commands.
  2. Cease quoting legacy 61.8 -> 44.5 as headline fatigue; mark it as legacy/conflated.
  3. Update `scripts/build_traces.py` and `scripts/replay.py` to record and report `latency_class` split (`human_prompt`, `host_auto`, `unapproved`, `v1_allow`, `v1_deny`).
- Consequences / what would make us revisit this:
  - All future eval harness and replay reporting must preserve the `latency_class` split.
- Evidence:
  - `scripts/replay.py --all`: Baseline Human Prompts: 3,170 (44.96/100 cmds) -> Replay Remaining: 2,369 (33.60/100 cmds), saving 801 human prompts (11.36/100 cmds). Headline: 45.0 -> 33.6 per 100 commands.

---

## ADR-012 — Audit-Log Rule Suggester Architecture and Conservative Generalization
- Date / session: 2026-10-10 / session 6
- Status: accepted
- Decided by: user
- Context:
  To reduce approval fatigue sustainably, recurring human-approved developer commands must be surfaced as candidate policy rules for developer review. The suggester must adhere strictly to Invariant I4 (humans decide on rules; airlock never auto-writes rules to policy files) and must never suggest rules that allow dangerous commands or cause catastrophic backtracking.
- Options considered:
  - Generate arbitrary regexes with open wildcards `.*`.
  - Propose exact-match anchored patterns and strictly parameterized clusters (e.g. `npm run <script>`, `pytest [flags] [tests]`), enforced by a hard safety gate testing every candidate against dangerous eval examples and L1 hard-deny rules.
- Decision:
  1. Module layout: Core logic in `agent_airlock/policy/suggester.py`, CLI in `agent_airlock/suggest_rules.py`, script wrapper in `scripts/suggest_rules.py`. Supports both `python -m agent_airlock.suggest_rules` and `python scripts/suggest_rules.py`.
  2. Mining filter: Mines commands approved by a human >= N times (default: 3). Excludes test records, ML auto-allows, host auto-approvals (<1.5s), and commands already allowed by default L1 rules.
  3. Conservative parameterization: Strict `^...$` anchoring; prohibits unanchored `.*` or open flag classes. Prioritizes cluster parameterization over redundant exact literals.
  4. Mandatory safety gate on every rule: Evaluates pattern against all dangerous eval examples (`data/eval_set.jsonl`, `data/eval_growth_draft.jsonl`) and L1 hard-deny probes (e.g., `rm -rf /`, `cat .env`, `curl | sh`, `:(){ :|:& };:`). Drops any candidate that matches a dangerous pattern.
  5. Trust-root execution warning: Attaches `⚠ executes repo-controlled code` warning and invalidation guidance for any command executing repo-controlled executables (`npm`, `python`, `node`, `pytest`, `cargo`, `make`).
  6. Output: Exports a human-reviewable `.airlock-policy.yaml` snippet to stdout or `--output`. Never auto-writes to workspace or global policy files (I4).
- Consequences / what would make us revisit this:
  - Adding new parameterized clusters (e.g., for Docker or specialized build tools) should follow the same conservative parameterization and safety gate.
- Evidence:
  - `tests/test_rule_suggester.py`: 6 passed in 0.07s. Successfully mined clean production audit log (`private/audit.jsonl`).

---

## ADR-013 — Amendment 1: "Agent Airlock 1.1" Scope, Pipeline Alignment, and Embedding Retirement
- Date / session: 2026-10-10 / session 7
- Status: accepted
- Decided by: user
- Context:
  Ani issued Amendment 1 to AIRLOCK_V2_MASTER_PROMPT.md ("Agent Airlock 1.1: measure, then optimize"). The amendment resets scope based on verified empirical findings: Phase 1 L1 coverage expansion and suggester already delivered large reductions in approval fatigue without needing dense embedding models on the hot path. Dense embedding similarity cannot safely emit ALLOW (I2) and adds unnecessary RAM and cold-start latency.
- Options considered:
  - Proceed with planned Phase 2 EmbeddingGemma 2 loading and dual-model daemon.
  - Adopt Amendment 1: Retire Phase 2 dense embedding architecture; align target pipeline as `L0 grounding -> L1 -> L2 breaker -> exact cache -> L3 calibrated classifier -> L4 ASK`; brand as "Agent Airlock 1.1" in user-facing docs (branch `v2-semantic` retained until release); fix oversized command linear scanning and host auto-approval classification; and conduct an empirical ML bake-off between calibrated ModernBERT, parsed features, Ettin, and CmdCaliper.
- Decision:
  1. Product name is "Agent Airlock 1.1" in user-facing documentation. Branch `v2-semantic` and directory structures are retained without renaming until release preparation.
  2. Target pipeline is strictly:
     `L0 grounding -> L1 deterministic policy -> L2 breaker -> exact cache -> L3 calibrated classifier -> L4 fail-closed ASK`.
  3. Retire Phase 2 (EmbeddingGemma 2 / dense similarity / L2.5) as designed; document negative result in `docs/v2/embeddings-negative-result.md` and keep one line in ROADMAP.md under future work.
  4. Fix Section A priority items before proceeding to Section B:
     - Oversized commands (>4096 chars) must never be ALLOW at any layer (L1, cache, ML). Deny checks scan the whole string in linear time. Truncated inputs are never classified by ML (oversized = ASK).
     - Host auto-approval classification: any ASKed run_command matching `private/host-allow-rules.txt` is host_auto regardless of delay.
     - Suggester: emit exact-command rules only (no wildcard script names) for commands executing workspace code (`npm/pnpm/yarn run`, `make`, `pytest`, `python <file>`, `cargo`, `node <file>`). Skip candidates covered by L1 or host rules. Report estimated human prompts saved.
     - L1 latency: profile slowest 20 real commands per rule family on trace replay and optimize to bring p99 <= 5.0 ms.
     - Backport patches to live sva-harness install documented in gitignored `private/backport-to-live.md` (fork-bomb ReDoS, git `--output` / `--no-index`).
- Consequences / what would make us revisit this:
  - Any future embedding similarity investigation is deferred to post-1.1 research.
- Evidence:
  - User directive Amendment 1 (2026-10-10).

---

## ADR-014 — Formal Retirement of Phase 2 EmbeddingGemma and Semantic Cache Tier
- Date / session: 2026-10-10 / session 7
- Status: accepted
- Decided by: user
- Context:
  Phase 2 initially designed a dense embedding model (EmbeddingGemma 2, ~300M parameters) at layer L2.5 for semantic similarity caching and dense approval matching. Analysis showed that dense similarity cannot guarantee zero false-allows (Invariant I2), as small edits (e.g. `rm -rf tmp` vs `rm -rf /`) retain high cosine similarity. Meanwhile, deterministic L1 coverage delivered large measured reductions in approval fatigue (`[15.78, 27.91, 44.96]` down to `[8.64, 20.03, 33.60]` prompts per 100 commands), making dense embeddings redundant.
- Options considered:
  - Proceed with Phase 2 dual-model architecture despite resource costs.
  - Formally retire Phase 2, replace semantic caching with exact-key decision caching (Phase 1.4), document negative result in `docs/v2/embeddings-negative-result.md`, and record offline clustering as a future work backlog line.
- Decision:
  1. Formally retire Phase 2 EmbeddingGemma and the semantic cache tier.
  2. Mark all early cosine threshold claims ($\ge 0.88$ for ALLOW) as UNVERIFIED.
  3. Replace with exact-key cache (Phase 1.4) post-L2 circuit breaker.
  4. Preserve one future work line in `ROADMAP.md` for offline sentence embedding clustering only.
- Consequences / what would make us revisit this:
  - No dense embedding model will run on the live evaluation hot path in Agent Airlock 1.1.
- Evidence:
  - `docs/v2/embeddings-negative-result.md`
  - Replay latency restored to p99 = 4.014 ms.

---

## ADR-015 — L0 Grounding Layer Architecture, Shadow Mode, and Zero False Positive Gate
- Date / session: 2026-10-10 / session 8
- Status: accepted
- Decided by: user
- Context:
  Master prompt Section 9.4 and Amendment 1 define L0 Grounding as a pre-L1 subsystem to eliminate human approval fatigue on tool calls referencing missing binaries (C1), nonexistent files/directories (C2), missing package scripts (C3), or invalid package dependencies (C4). In historical production traces, 23.15% of human-approved commands failed post-approval, generating retry loops. However, premature enforcement risks false positives where valid agent commands are erroneously blocked.
- Options considered:
  - Immediate enforcement without replay verification or shadow mode.
  - Implement L0 Grounding with individually configurable checks, default `mode: "shadow"`, strict conservative pass-through (unparseable, builtins, creates-what-it-references, and placeholders pass), and a mandatory verification gate requiring zero false positives on replay of historically successful commands before enforcement mode.
- Decision:
  1. Module layout: Core logic in `agent_airlock/grounding/` (`engine.py`, `c1_binary.py`, `c2_files.py`, `c3_scripts.py`, `c4_installs.py`, `models.py`).
  2. Integration: Evaluated at daemon entrypoint prior to L1 deterministic policy. In shadow mode (default), records results in `AuditEvent.metadata["shadow_grounding"]` and latencies in `layer_latencies_ms["l0"]`. In enforce mode, intercepts would-ASK commands that fail grounding and returns a structured denial with an actionable hint (`decision_source="l0"`).
  3. L1 hard-deny precedence: Hard security rules in L1 (tampering, fork-bombs, destructive mutations) strictly take precedence over L0 hints.
  4. Design rule adherence: Only denies when certain. Commands with unparseable syntax, dynamic variables, builtins, chained build steps, or placeholders pass through unconditionally.
  5. Invariant I9 (Zero Network Calls): Completely local checks; no network requests, socket connections, or remote registry lookups.
  6. Replay verification gate: Successfully verified 0 false positives across 6,945 historically successful commands and tool calls across all 41 clean production traces.
- Consequences / what would make us revisit this:
  - Any false positive discovered on live development workloads requires immediate pass-through widening.
- Evidence:
  - `docs/v2/l0-census-report.md` (Census: 279 post-approval failures, 12 C1 binary missing).
  - `docs/v2/l0-grounding.md` (Full architecture documentation).
  - `tests/test_grounding_checks.py` (20 unit tests passed).
  - `tests/test_grounding_replay.py` (0 false positives on replay across 6,945 commands).

---

## ADR-016 — Implementation of L1 Rule Family D (Policy Change Protocol, I8)
- Date / session: 2026-10-11 / session 9
- Status: approved (commit ed51beb)
- Decided by: user
- Context:
  Analysis of commands falling through L1 deterministic policy to ML/human review (`private/l1-gap-list.md`) revealed frequent benign inspection and workflow operations: `Get-ChildItem` with `Select-String`, `git grep`, `where.exe`, `dir`, `git branch` (list / `--show-current`), `git tag` (list / local create), and `git add` (workspace containment).
- Options considered:
  - Keep commands in ML/human review.
  - Implement L1 Family D adhering strictly to the Policy Change Protocol (I8), with ReDoS-safe patterns, prefilter soundness, and near-miss suites.
- Decision:
  1. Add Family D rules and hardening to `agent_airlock/policy/default_rules.py` and `agent_airlock/policy/engine.py` (submitted for approval):
     - `allow-git-grep`: Read-only git grep searches within workspace repository. Guards: reject `--no-index`, `-O`/`--open-files-in-pager`, reject global prefix flags `-c`/`-C`/`--paginate`/`--exec-path` before subcommand, validate all path arguments resolve inside workspace, reject sensitive targets.
     - `allow-where-binary-lookup`: Windows binary lookup using `where` or `where.exe`. Guards: reject `/r` recursive root traversal, reject searches for credential files.
     - `allow-dir-windows`: Windows directory listing. Guards: reject `/s` drive root scans, require workspace containment, reject secret files.
     - `allow-git-branch-list`: Read-only branch listing and `--show-current`. Guards: reject branch deletion (`-d`, `-D`, `--delete`) and branch renaming (`-m`, `-M`, `--move`).
     - `allow-git-tag-list`: Read-only tag listing (`-l`, `--list`). Guards: reject deletion (`-d`, `--delete`), reject signing flags (`-s`, `-u`, `--sign`, `--local-user`).
     - `allow-git-tag-local` (conditional): Local tag creation (`git tag <name>`, `git tag -a <name> -m <msg>`). Guards: reject deletion, reject signing flags (`-s`, `-u`, `--sign`), and chained/remote `push`.
     - `allow-git-add-workspace` (conditional): Staging explicit workspace files strictly contained within workspace root. Guards: reject patch/interactive modes (`-p`, `-i`), reject force (`-f`, `--force`), bare `.`, `-A`/`--all`, `-u`/`--update`, globs (`*`, `?`), pathspec magic (`:(`), and secret dotfiles (`.env*`, `.ssh`, `.aws`, `.git`, `id_rsa`). Only explicit workspace paths pass.
     - Pipeline sink allowlist: Enforce strict sink allowlist (`Select-String`, `Select-Object`, `Sort-Object`, `Measure-Object`, `Format-*`, `Out-String`, simple `Where-Object` without scriptblock side effects). Any other sink -> AMBIGUOUS. Pipes into native exes (`sh`, `bash`, `python`, `node`, `powershell`, `pwsh`, `cmd`, `xargs`), `||`, single `&`, backticks, `$()`, `@()`, and `ForEach-Object` scriptblocks -> AMBIGUOUS.
     - Anti-tampering precedence: All tokens matching `is_protected_runtime_path` unconditionally trigger `deny-airlock-runtime-tampering`, preventing runtime inspection commands from slipping to AMBIGUOUS or ALLOW.
     - Compound command evaluation: Compound commands (limited strictly to `;`, `&&`, newline) evaluated recursively: allowed ONLY if every segment is independently ALLOW. Any DENY segment -> DENY. Any AMBIGUOUS segment -> AMBIGUOUS. Disallowed chaining operators (`||`, `&`) yield AMBIGUOUS.
     - NO rules (stay ask): `npm run`, `pytest`, `python`/`node` scripts, `git fetch` strictly remain ASK.
     - Inline interpreter invariant: `python -c` and `node -e` remain strictly ASK-only regardless of model confidence.
  2. Prefilter soundness: Verified zero differences with and without `DENY_RULE_PREFILTERS` across all datasets.
  3. Latency gate: p99 stays at 5.169 ms (replay end-to-end; pure rule matching < 1.0 ms).
  4. False-allow verification: 0.00% false-allow rate on eval sets (0/20 in `eval_set.jsonl`, 0/6 in `eval_growth_draft.jsonl`). 95% Wilson score CI upper bound: 12.87% (explicitly stated: not evidence of safety).
  5. Baseline DENY regression invariant: Added `test_replay_baseline_deny_regression` testing all 37 baseline DENY decisions against `tests/fixtures/baseline_37_denies.json`. Replay DENY count reconciled to 38 (37 baseline + 1 justified daemon pid; remediated 31 false-denies per M-032).
- Consequences / what would make us revisit this:
  - Any pattern allowing external path egress or mutation without human confirmation would require immediate tightening.
  - No replay decision may move from DENY to a weaker verdict without an explicit ADR.
- Evidence:
  - `tests/test_policy_engine.py`: 37 unit tests passed, including `test_family_d_rules_and_near_misses` and `test_replay_baseline_deny_regression`.
  - `tests/test_policy_perf.py`: 3 passed in 0.82s.
  - `tests/test_prefilter_soundness.py`: 1 passed (0 differences).
  - Metric M-032 (`scripts/replay.py --all`): 4,064 ALLOWs (57.64%), 38 DENYs (0.54%, baseline 37 + 1 justified daemon pid), 2,949 ASKs (41.82%). Remediation of 31 False-Denies, Containment Symlink Guard & Savings Reconciliation: 653 prompts saved (reconciled; Hard Deny 22 removed). 3-way fatigue range: First-Match [18.65/100, saving 653 prompts], Retroactive [8.65/100, saving 503 prompts], Delay-Only [31.07/100, saving 979 prompts]. Latency p50=0.151 ms, p95=1.765 ms, p99=4.940 ms (< 5.0 ms gate PASS). (All numbers IN-SAMPLE).








