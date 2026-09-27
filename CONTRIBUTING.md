# Contributing to Agent Airlock

Thank you for contributing to Agent Airlock! We welcome contributions to deterministic safety policies, ML fine-tuning datasets, circuit breaker heuristics, and platform integrations.

Because Agent Airlock sits directly on the execution boundary of autonomous AI coding assistants, **all security-critical logic—especially deterministic policy rules—must adhere to strict verification standards**.

---

## 1. Development Environment Setup

Agent Airlock requires **Python 3.11+**.

```bash
# Clone repository
git clone https://github.com/AniruddhaK07/agent-airlock.git
cd agent-airlock

# Create virtual or conda environment
conda create -n airlock_env python=3.11 -y
conda activate airlock_env

# Install package in editable development mode
pip install -e .
pip install pytest pytest-asyncio
```

Optional for local GPU inference:
```bash
# PyTorch with CUDA support (adjust for your CUDA version)
pip install torch torchvision --index-url https://download.pytorch.org/whl/cu121
pip install laya
```

---

## 2. Running Tests

Before submitting any Pull Request, ensure that the full test suite passes with **100% pass rate**:

```bash
# Run all unit, integration, and scenario tests
pytest -v

# Run specific functional suites
pytest tests/test_policy_engine.py -v   # Deterministic Hard Policy Engine
pytest tests/test_daemon_ipc.py -v      # Daemon lifecycle, socket & IPC
pytest tests/test_circuit_breaker.py -v # Runaway fix-loop breaker
pytest tests/test_audit_log.py -v       # Audit logging & integrity reader
pytest tests/test_hooks.py -v           # Antigravity CLI lifecycle hooks
pytest tests/test_local_laya.py -v      # Local Laya model inference
pytest tests/test_scenarios.py -v       # Multi-turn E2E operational scenarios
```

---

## 3. Policy Change Protocol (Security-Critical Rule Review)

Changes to the deterministic rule set in [`agent_airlock/policy/default_rules.py`](file:///C:/Users/ASUS/Desktop/A/projects/sva-harness/agent_airlock/policy/default_rules.py) and input normalizer in [`agent_airlock/policy/normalizer.py`](file:///C:/Users/ASUS/Desktop/A/projects/sva-harness/agent_airlock/policy/normalizer.py) are **security-critical**.

> [!CAUTION]
> A false negative (allowing a dangerous command to execute without human review) is the highest-severity failure mode in Agent Airlock. PRs proposing changes to built-in rules face heightened scrutiny compared to general code changes.

### Requirements for Modifying Default Rules:
1. **Zero False-Negative Guarantee**: Any new rule or pattern modification must not relax existing hard-deny invariants.
2. **Evasion Hardening**: Every new deny rule must be accompanied by unit tests covering common evasion strategies:
   - Quoting obfuscation (e.g. `r"m" -rf /`, `'rm' -rf /`).
   - Line continuations and caret/backslash escapes.
   - Command chaining (`&&`, `;`, `||`, `|`, `&`, `\n`).
   - Shell subshells and command substitution (`$()`, backticks).
   - Relative vs. absolute paths (`/etc/passwd`, `../../../../etc/passwd`).
3. **Cross-Platform Parity**: Rules must account for both POSIX (bash/sh) and Windows (PowerShell/cmd.exe) syntax divergence.
4. **Subtest Coverage**: Add test cases to `tests/test_policy_engine.py` using `with self.subTest(...)` so each attack variant is evaluated and reported individually.
5. **Review Bar**: All PRs modifying `default_rules.py` require explicit review and approval from at least two core maintainers.

---

## 4. Expanding the Laya Training Dataset

Agent Airlock uses a fine-tuned ModernBERT model (via `laya`) to evaluate ambiguous commands that cannot be resolved deterministically.

### Dataset Structure
The dataset lives in `data/training_examples.jsonl`. Each record represents a realistic command invocation evaluated across three heads:

```json
{
  "state": {
    "tool": "run_command",
    "command": "git reset --hard HEAD~1"
  },
  "answers": {
    "blast_radius": {
      "type": "score",
      "score": 3,
      "confidence": 0.90
    },
    "reversible": {
      "type": "noul",
      "noul": 0.20,
      "confidence": 0.85
    },
    "route": {
      "type": "choice",
      "choice": "needs-human",
      "confidence": 0.90
    }
  }
}
```

### Labeling Rubric:
- **Blast Radius (Score 0 to 4)**:
  - `0`: Read-only, zero side-effects (`ls`, `git status`).
  - `1`: Minor local change, isolated to build cache or scratch files.
  - `2`: Moderate change, easily recovered from git or package manager.
  - `3`: Major system change, modifies git history, dependencies, or config.
  - `4`: Catastrophic wipe, irreversible deletion, or credential exfiltration.
- **Reversibility (`noul` probability [0.0, 1.0])**:
  - `1.0`: Perfectly undoable (clean revert, no state lost).
  - `0.0`: Completely irreversible (permanent deletion, external push).
- **Route (`choice`)**:
  - `deterministic-safe`: Confidently safe, zero risk.
  - `needs-human`: Ambiguous or risky; requires operator confirmation.
  - `needs-reasoning-model`: Borderline nuance requiring deep chain-of-thought.

### Training & Retraining
To fine-tune a new checkpoint:
```bash
python scripts/train_laya.py \
  --data data/training_examples.jsonl \
  --output checkpoints/laya-finetuned \
  --epochs 5 \
  --batch-size 8
```

---

## 5. Submitting Changes

1. Fork the repository and create a branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. Commit your changes with clear, descriptive commit messages.
3. Verify all tests pass: `pytest`.
4. Open a Pull Request on GitHub against `main`. Provide:
   - A summary of the changes.
   - The security rationale (especially if modifying rules).
   - Test results demonstrating zero regressions.
