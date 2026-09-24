# Jev-gated safety layer for Antigravity CLI — revised architecture

## What changed from the original idea

| Original | Problem | Fix |
| --- | --- | --- |
| Hook calls Jev directly per tool call | Cold-start + network latency stacks on top of Jev's own 70–500ms | Long-running local daemon holds the connection; hooks just talk to a socket |
| Every command routed through Jev | Wastes cost/latency on obviously-safe commands (`ls`, `git status`) | Deterministic policy engine runs first; Jev only sees ambiguous cases |
| `allow` assumed to grant execution | On Antigravity v1.1.2, `allow` does not suppress the CLI's own confirmation prompt | Version-detection at daemon startup; behavior degrades gracefully instead of silently failing to gate |
| "Eliminates prompt injection" | Jev's Choice/Score output can still be biased by a crafted payload in the command/state text | Hard deterministic blocklist sits *above* the probabilistic layer for the worst-case categories; injection resistance is a property of the layering, not of Jev alone |
| No fail-safe on API failure | If TypeSafe's API is unreachable, undefined behavior — could silently allow | Explicit fail-closed: any Jev error routes to human confirmation, never to auto-allow |
| `jev-latest` | Model updates silently change gating behavior mid-project | Pin `jev-1.13.0` (or whatever version you validate against); bump deliberately |
| No audit trail | Can't debug a bad gating decision after the fact, can't build trust in an open-source safety tool | Every decision (input state, Jev output, confidence, final verdict) logged as a structured event |

## Layered architecture

```
Antigravity CLI
      │ PreToolUse / PostToolUse (subprocess, JSON over stdin)
      ▼
Hook script (thin, <50 lines) ── writes to local Unix socket
      ▼
Daemon (long-running, localhost-only)
 ├─ 1. Hard policy engine   (deterministic, no model call)
 ├─ 2. Jev integration layer (only if policy engine says "ambiguous")
 ├─ 3. Circuit breaker      (hash pre-filter → Noul confirmation)
 └─ 4. Audit log writer
      ▼
Decision returned to hook → hook exits with allow/deny/ask code
```

### 1. Hard policy engine (new — this was the biggest gap)

A static, human-reviewed rule list that runs *before* Jev, in plain code:

- **Hard deny, no model involved**: destructive filesystem ops outside the repo, credential/secret file access, `curl | sh`-style pipe-to-shell, network exfiltration patterns. These should never depend on a probabilistic classifier — a confident-but-wrong Score is still a wrong answer for `rm -rf /`.
- **Hard allow**: a maintained allowlist of read-only, side-effect-free commands (`ls`, `git status`, `cat`, linters). Skip Jev entirely — this is most of the latency and cost win.
- **Everything else** falls through to Jev. This is the correct scope for a probabilistic layer: genuinely ambiguous cases, not the whole traffic volume.

This also fixes the injection-resistance overclaim: the categories where a wrong answer is catastrophic are handled deterministically, so a crafted prompt influencing Jev's Score can at worst push something into "ask" rather than "allow."

### 2. Jev integration layer

- Daemon holds one persistent client, calling `jev-1.13.0` explicitly (pin the version).
- One request per ambiguous action, all three questions fired together: `Score` (blast radius), `Noul` (reversible?), `Choice` (route: deterministic-safe / needs-human / needs-reasoning-model).
- Confidence thresholds are config, not code — ship sane defaults, let the user tune them (see policy schema below).
- **Fail-closed**: any timeout, error, or low-confidence response → `ask`, never `allow`. This is the single most important correctness property of the whole system.

### 3. Circuit breaker

- Cheap first pass: hash the last N error signatures (stack trace shape, exit code, changed lines) in code — free, instant.
- Only escalate to a `Noul` call ("is this semantically the same failure as before?") when the hash pre-filter flags a likely repeat but the surface text differs.
- On confirmed repeat: halt the fix loop, surface a summary to the user instead of another autoregressive attempt.

### 4. Audit log

- Append-only local log: timestamp, action, policy-engine verdict, Jev request/response (if called), confidence, final decision.
- This is what makes an open-source safety tool auditable and debuggable — without it, nobody can verify the gating actually works, including you.

## Example policy config shape

```yaml
hard_deny:
  - pattern: "rm -rf /*"
  - pattern: "curl .* \\| sh"
hard_allow:
  - pattern: "^git (status|diff|log)"
  - pattern: "^ls "
jev:
  model: jev-1.13.0
  thresholds:
    allow_confidence: 0.90
    deny_confidence: 0.85
    default: ask
circuit_breaker:
  hash_window: 3
  noul_confidence: 0.80
```

## Open questions worth resolving before you build

- Which Antigravity versions do you actually target — does the `allow`-doesn't-suppress-prompt behavior still hold on current builds?
- Where does the hard-deny/allow list live — bundled defaults, per-project override, or both?
- Does the daemon need multi-project isolation if someone runs it across several repos at once?