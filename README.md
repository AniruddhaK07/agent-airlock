# Agent Airlock 🛡️

**Layered Safety Airlock & Deterministic Policy Gateway for Autonomous AI Coding Assistants**

[![Tests](https://img.shields.io/badge/tests-126%20passed%20%7C%20100%25-brightgreen)](#testing)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](#hardware-requirements--performance)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml)

Autonomous AI coding assistants (such as Google Antigravity) are powerful because they can inspect code, run terminal commands, and edit files independently. However, giving an autonomous agent direct shell access introduces serious operational risks: accidental root wipes, runaway failure fix-loops, credential exfiltration, and destructive git commands.

**Agent Airlock** is a local, high-performance security airlock that intercepts tool execution calls before they reach your system. It combines deterministic pattern matching with a calibrated, fine-tuned transformer classifier to provide **zero-friction speed for safe commands** and **uncompromising protection against dangerous or ambiguous operations**.

---

## 🏗️ Layered Architecture

Agent Airlock intercepts agent tool calls via the standard `PreToolUse` and `PostToolUse` lifecycle hooks using a 4-tier decision cascade:

```
[Agent Tool Call: run_command / view_file / write_to_file]
                           │
                           ▼
  ┌───────────────────────────────────────────────────┐
  │  Layer 1: Deterministic Hard Policy Engine        │ ➔  < 1 ms
  │  - Normalized regex & AST parsing                 │
  │  - Anti-evasion (quotes, carets, chaining)        │
  │  - Hard-Allow (git status, ls)  ───────────────┐  │ ➔ ALLOW (Zero prompts)
  │  - Hard-Deny (rm -rf /, curl|sh) ──────────────┼──┼─➔ DENY  (Blocked)
  └────────────────────────┬──────────────────────────┘
                           │ (Ambiguous command)
                           ▼
  ┌───────────────────────────────────────────────────┐
  │  Layer 2: Runaway Fix-Loop Circuit Breaker        │ ➔  < 1 ms
  │  - Rolling failure hash window                    │
  │  - Semantic error similarity detection            │
  │  - Tripped on repeated cycles ────────────────────┼─➔ FORCE_ASK (Halts loop)
  └────────────────────────┬──────────────────────────┘
                           │ (Normal workflow)
                           ▼
  ┌───────────────────────────────────────────────────┐
  │  Layer 3: Calibrated ML Safety Airlock            │ ➔  ~38 ms (GPU) / ~1.2s (CPU)
  │  - Fine-tuned ModernBERT via Laya                 │
  │  - Predicts: Blast Radius, Reversibility, Route   │
  │  - Confident Safe (conf >= 0.90, blast <= 2.0) ───┼─➔ ALLOW
  │  - High Blast Radius (blast >= 4.0, conf >= 0.85) ┼─➔ DENY
  └────────────────────────┬──────────────────────────┘
                           │ (Uncertain or below threshold)
                           ▼
  ┌───────────────────────────────────────────────────┐
  │  Layer 4: Non-Negotiable Fail-Closed Fallback     │
  │  - Daemon offline / socket timeout / low confidence│
  │  - Invariant: NEVER fail open to blind execution  │ ➔ ASK (Prompt operator)
  └───────────────────────────────────────────────────┘
```

---

## ⚡ Key Highlights

- **Blazing Fast Hot-Path**: Safe developer commands (`git status`, `ls -la`, read-only queries) resolve via Layer 1 in **< 1 ms** with zero human confirmation prompts.
- **Evasion-Hardened**: Handles quote insertion (`r"m" -rf /`), line continuations, command chaining (`git status; rm -rf /`), backtick/subshell substitution, and Windows/POSIX syntax divergence.
- **Runaway Loop Breaker**: Detects when an agent gets trapped in a repetitive error-retry cycle and automatically trips into `force_ask` to stop token and compute burn.
- **Two-Stage Daemon Startup**: Background daemon binds socket and activates deterministic rules in **~360 ms**; asynchronous model loading occurs in the background without blocking terminal workflows.
- **Tamper-Evident Audit Trail**: Every decision, latency measurement, rule match, and ML score is written append-only to an ISO 8601 `audit.jsonl` log.

---

## 💻 Hardware Requirements & Performance

All benchmarks below were empirically measured on identical fine-tuned weights:

| Specification | NVIDIA GPU (Recommended) | CPU Fallback (Supported) |
|---|---|---|
| **Hardware** | NVIDIA RTX 40-series / 4GB+ VRAM | Intel Core / AMD Ryzen / Apple Silicon |
| **Model Load Time** | ~9.8s (background, non-blocking) | ~10.5s (background, non-blocking) |
| **Warm Inference Latency** | **~38 ms – 50 ms** (mean: 39.8ms) | **~1,150 ms – 1,450 ms** (mean: 1,250ms) |
| **Daemon RAM Footprint** | ~650 MB (CUDA resident) | ~450 MB (Host RAM) |
| **Recommended Timeout** | `request_timeout_seconds: 5.0` | `request_timeout_seconds: 5.0+` |

> [!WARNING]
> **CPU Fallback Latency & User Experience**: Agent Airlock does **not** hardcode CUDA dependencies and runs gracefully on CPU-only hardware. However, please be aware of the real-world operational profile:
> - **Hard-Allow and Hard-Deny commands are completely unaffected (< 1 ms)** regardless of hardware. Safe routine commands (`git status`, file reads, directory inspection) resolve instantly with zero delay.
> - **Ambiguous operations requiring ML airlock evaluation will pause for roughly 1.0 – 1.5 seconds** (empirically measured: **1,250 ms mean**, up to **1,462 ms peak**) while the ModernBERT transformer runs on CPU. This introduces a noticeable operational delay during interactive agent sessions before the decision resolves.
> - Keep the default timeout (`request_timeout_seconds: 5.0` or higher) in your configuration so CPU inference does not trigger premature fail-closed timeouts.

---

## 📦 Checkpoint Distribution & Transparency

The local ML safety airlock is powered by a fine-tuned **ModernBERT** architecture via [`laya`](https://github.com/convaiinnovations/laya), trained across three simultaneous task heads:
1. **Blast Radius** (Score 0 to 4): Potential blast radius of an operational failure.
2. **Reversibility** (Noul probability [0.0, 1.0]): Whether the command's effects can be cleanly undone.
3. **Route** (3-way choice): `deterministic-safe`, `needs-human`, or `needs-reasoning-model`.

### Out-of-the-Box Distribution
- **Pre-Trained Weights**: Pre-trained weights are hosted on Hugging Face Hub under [`ruddh/agent-airlock-laya`](https://huggingface.co/ruddh/agent-airlock-laya) and will download automatically if no local checkpoint is found.
- **Deterministic Pure Mode**: If no model weights are downloaded and no network is available, Agent Airlock operates in **Pure Deterministic Mode** (Stage 1), safely evaluating hard rules and failing closed to `ask` for any ambiguous commands.
- **Full Training Pipeline Shipped**: The complete fine-tuning pipeline and starter dataset live in this repository:
  - Dataset: `data/training_examples.jsonl` (200 diverse developer operations across 21 tool families).
  - Training script: `scripts/train_laya.py`.

> [!IMPORTANT]
> **Safety Disclaimer**: The shipped pre-trained weights reflect the author's labeling heuristics and threat model. **They are not an ISO or SOC2 certified safety authority.** Before trusting this system in a production or sensitive infrastructure environment, you should review `data/training_examples.jsonl`, inspect the label boundaries in [`docs/decisions.md`](docs/decisions.md), and re-fine-tune a checkpoint tailored to your organization's security posture.

---

## 🚀 Installation & Quickstart

### 1. Prerequisites
- Python 3.11+
- Windows 10/11, Linux, or macOS

### 2. Install Package
```bash
# Clone repository
git clone https://github.com/AniruddhaK07/agent-airlock.git
cd agent-airlock

# Install in editable mode
pip install -e .
```

For GPU acceleration (recommended):
```bash
pip install torch --index-url https://download.pytorch.org/whl/cu121
pip install laya
```

### 3. Register Antigravity Hooks
Run the automated installer to link the lifecycle hooks into your active project or global agent configuration:

```bash
# Register hooks in the current workspace (.agents/hooks.json)
python installer.py

# Or install globally across all Antigravity workspaces
python installer.py --global
```

The installer configures:
- `PreToolUse`: Intercepts `run_command`, `view_file`, and `write_to_file`.
- `PostToolUse`: Intercepts execution results to track circuit breaker failure loops.

### 4. Background Daemon Lifecycle
The background daemon automatically starts on the first hook invocation. You can also control it manually:

```bash
# Start daemon in foreground for debugging
agent-airlock-daemon --foreground

# Check daemon status
agent-airlock-daemon --status

# Stop daemon cleanly
agent-airlock-daemon --stop
```

---

## ⚙️ Configuration Hierarchy

Agent Airlock uses a 3-tier hierarchical configuration:

1. **Bundled Defaults** (`agent_airlock/policy/default_rules.py`): Immutable baseline safety rules. Destructive shell commands (`rm -rf /`, fork bombs, reverse shells, raw disk writes) are hard-denied.
2. **Global Config** (`~/.gemini/antigravity-cli/config.yaml`): Daemon timeouts, socket paths, audit retention, and ML thresholds. (See [`examples/global-config.yaml`](examples/global-config.yaml)).
3. **Workspace Policy** (`.airlock-policy.yaml` in project root): Workspace-specific allow and deny rules. (See [`examples/workspace-policy.yaml`](examples/workspace-policy.yaml)).

### Sample `.airlock-policy.yaml`
```yaml
version: "1.0"
allow_override_denies: false

rules:
  # Hard-allow workspace test runner
  - rule_id: "allow-pytest"
    tool_name: "run_command"
    pattern: '^pytest(\s+[a-zA-Z0-9_\-\./]+)*$'
    action: "allow"
    description: "Allow running pytest without confirmation prompts"

  # Hard-deny reading sensitive database files
  - rule_id: "deny-read-local-secrets"
    tool_name: "view_file"
    pattern: '.*(\.env\.local|secrets\.json)$'
    action: "deny"
    description: "Prevent agent from viewing local secret files"
```

---

## 🔍 Audit Log Inspection

Every event is recorded with microsecond timestamps in `~/.gemini/antigravity-cli/audit.jsonl`:

```bash
# Query recent tool decisions
python -m agent_airlock.audit.reader --recent 10

# View summary statistics
python -m agent_airlock.audit.reader --stats
```

Example audit record:
```json
{
  "eventId": "audit-8f7a2b9c1d3e",
  "timestamp": "2026-09-27T12:30:15.123456+00:00",
  "eventType": "PreToolUse",
  "toolName": "run_command",
  "toolArgs": {"CommandLine": "git status"},
  "policyVerdict": "allow",
  "matchedRuleId": "allow-git-safe",
  "finalDecision": "allow",
  "latencyMs": 0.231,
  "workspaceRoot": "C:/repos/my-project"
}
```

---

## 🧪 Testing

The repository includes a comprehensive test harness covering every layer of the airlock:

```bash
# Run full test suite (126 passed tests)
pytest -v
```

Test coverage includes:
- **Policy Engine**: Tier-0 anti-tamper protection, 40+ evasion patterns, PowerShell base64 decoding, subshell unwrapping, compound command splitting, regex normalization.
- **Daemon & IPC**: Dual-transport auto-negotiation, bearer token auth, stale PID recycling recovery, POSIX 0600 socket lockdown, concurrent cold-start auto-spawns.
- **Circuit Breaker**: Repeating failure loops, ephemeral token normalization, Noul semantic confirmation.
- **Antigravity Hooks**: Strict protojson schema compliance, < 50 lines constraint, fail-closed stdin parsing.
- **End-to-End Scenarios**: 5 realistic operational scenarios covering safe, dangerous, ambiguous, and runaway workflows.

---

## 🗺️ Roadmap

See [`ROADMAP.md`](ROADMAP.md) for prioritized upcoming milestones, including CPU quantization, LRU inference caching, higher-order loop detection, and policy dry-run tooling.

---

## 🤝 Contributing

Contributions are welcome! Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) for details on code structure, adding training examples, and the strict **Policy Change Protocol** required for modifying deterministic rules.

---

## 📄 License

This project is licensed under the [Apache License 2.0](LICENSE).
