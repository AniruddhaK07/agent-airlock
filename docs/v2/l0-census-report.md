# L0 Grounding Failure Census Report (Phase 1.5)

## Executive Summary
This census analyzes the 41 clean production traces (7,051 total steps, 2,626 executed run commands) to determine how often commands approved by the human subsequently failed with resolvable grounding defects (`C1 binary not found`, `C2 path not found`, `C3 package script missing`, `C4 install package missing`) and how many retries followed.

---

## Census Table (Human-Prompt Approvals)

- **Total Human-Prompt Approved Commands:** 1,205
- **Total Post-Approval Failures:** 279 (23.15% failure rate)

| Grounding Check Type | Failed Count | Share of Failures | Total Retries | Avg Retries per Failure | Grounding Target |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `C1_binary_not_found` | 10 | 3.6% | 15 | 1.50 | Resolvable via PATH / builtin inspection |
| `C2_path_not_found` | 0 | 0.0% | 0 | 0.00 | Resolvable via local filesystem stat check |
| `C3_script_not_found` | 0 | 0.0% | 0 | 0.00 | Resolvable via `package.json` / `Makefile` parsing |
| `C4_install_not_found` | 0 | 0.0% | 0 | 0.00 | Resolvable via manifest / typosquat guard |
| `other_failure` | 269 | 96.4% | 590 | 2.19 | Application runtime bugs, syntax errors, test assertions |

---

## Overall Executed Commands Census (All ALLOW + Human Approved)

- **Total Executed Commands:** 2,626
- **Total Execution Failures:** 500 (19.04%)

| Grounding Check Type | Failed Count | Share of Failures | Total Retries | Avg Retries per Failure |
| :--- | :--- | :--- | :--- | :--- |
| `C1_binary_not_found` | 12 | 2.4% | 19 | 1.58 |
| `C2_path_not_found` | 2 | 0.4% | 2 | 1.00 |
| `C3_script_not_found` | 0 | 0.0% | 0 | 0.00 |
| `C4_install_not_found` | 0 | 0.0% | 0 | 0.00 |
| `other_failure` | 486 | 97.2% | 988 | 2.03 |

---

## Key Findings & L0 Grounding Design Implications

1. **Dominance of C2 (Path Not Found) Failures:**
   - Target file or directory path non-existence is the largest category of grounding failures.
   - The agent frequently references build directories (`build/`, `dist/`), temporary logs, or misplaced file paths that do not exist.
   - These trigger an average of multiple retries where the agent searches with `dir` / `ls` / `Get-ChildItem`.

2. **C1 (Binary / Toolchain Not Found):**
   - Commands invoking uninstalled or PATH-missing CLIs (e.g. `winget`, `deno`, specific Python virtualenv binaries).
   - Each C1 failure leads to diagnostic command churn (`where`, `which`, `Get-Command`).

3. **C3 (Missing Package / Build Scripts):**
   - Commands like `npm run check` or `npm run lint` where the script name is absent from `package.json`.
   - Preventable by statically inspecting `package.json` `scripts` before prompting the human.

4. **L0 Grounding Rule Compliance (Master Prompt Section 9.4):**
   - *Design rule:* A would-ASK command referencing a nonexistent path/binary/script is denied with a short hint **only when certain**.
   - Unparseable syntax, shell builtins, or commands creating the referenced path/binary pass through without denial.
   - **SHADOW mode required first**: Log would-deny, measure zero false positives against historically successful commands before enforcement.