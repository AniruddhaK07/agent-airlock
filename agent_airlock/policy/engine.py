"""
Hard Policy Engine: Deterministic rule engine for Antigravity CLI tool gating.
"""

import os
import re
import shlex
import shutil
import time
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Set
from agent_airlock.policy.models import PolicyVerdict, PolicyRule, PolicyResult
from agent_airlock.policy.default_rules import get_default_rules
from agent_airlock.policy.normalizer import (
    tokenize_command,
    normalize_command,
    strip_all_quotes,
    has_command_chaining,
    split_command_chain,
    extract_subshell_and_encoded_payloads,
    is_protected_runtime_path,
    is_tampering_command,
)

TRUST_ROOT_FILES = {
    "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
    "pyproject.toml", "setup.py", "setup.cfg", "tox.ini", "conftest.py",
    "makefile", "justfile", "cargo.toml", "build.rs", "pipfile", "pipfile.lock",
    ".pre-commit-config.yaml", ".gitattributes", ".gitmodules",
    ".npmrc", ".pypirc", ".netrc", ".envrc", "sitecustomize.py",
    ".airlock-policy.yaml"
}

_RUNNING_PKG_DIR = Path(__file__).resolve().parent.parent.name

DISALLOWED_DIRS_WORKSPACE_WRITE = {
    ".vscode", ".github", ".husky", ".agents", ".git", ".ssh", ".aws", ".kube", ".gemini", _RUNNING_PKG_DIR
}

KNOWN_HELP_TOOLS = {
    "agy", "git", "python", "python3", "node", "npm", "npx", "yarn", "pnpm",
    "cargo", "rustc", "go", "pytest", "ruff", "black", "docker", "pip", "pip3", "tsc"
}

_REALPATH_CACHE: Dict[Tuple[str, str, bool], Tuple[bool, float]] = {}
_CACHE_TTL: float = 2.0
_GIT_HOOKS_CACHE: Dict[str, Tuple[bool, float]] = {}
_GIT_HOOKS_CACHE_TTL: float = 30.0

class HardPolicyEngine:
    """
    Deterministic rule engine running before Jev.
    Evaluates tool calls against static deny and allow lists with zero model latency.
    Guarantees zero false negatives on hard-deny rules.
    """

    def __init__(
        self,
        rules: Optional[List[PolicyRule]] = None,
        use_prefilters: bool = True,
        protected_dirs: Optional[Set[str]] = None,
    ):
        if rules is None:
            rules = get_default_rules()
        self.rules = rules
        self.use_prefilters = use_prefilters
        self._protected_dirs = set(DISALLOWED_DIRS_WORKSPACE_WRITE) | (set(protected_dirs) if protected_dirs else set())
        self._deny_rules: List[PolicyRule] = [r for r in rules if r.verdict == PolicyVerdict.DENY]
        self._allow_rules: List[PolicyRule] = [r for r in rules if r.verdict == PolicyVerdict.ALLOW]
        import hashlib
        rule_str = "|".join(f"{r.id}:{r.verdict.value}:{r.pattern}" for r in rules)
        self.policy_hash = hashlib.sha256(rule_str.encode("utf-8")).hexdigest()[:16]

    def evaluate(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        workspace_root: Optional[str] = None,
    ) -> PolicyResult:
        """
        Main entrypoint: deterministically classifies a tool call as ALLOW, DENY, or AMBIGUOUS.
        """
        if not tool_args:
            tool_args = {}

        # -------------------------------------------------------------
        # TIER 0: Anti-Tamper Protection for Airlock Runtime Surface
        # Evaluated first, before any other hard-deny or hard-allow check
        # -------------------------------------------------------------
        anti_tamper_result = self._check_tier0_anti_tamper(tool_name, tool_args)
        if anti_tamper_result is not None:
            return anti_tamper_result

        if tool_name == "run_command":
            return self._evaluate_run_command(tool_args, workspace_root=workspace_root)
        elif tool_name == "view_file":
            return self._evaluate_view_file(tool_args)
        elif tool_name in ("write_to_file", "replace_file_content"):
            return self._evaluate_file_write(tool_name, tool_args, workspace_root=workspace_root)
        elif tool_name in ("list_dir", "find_by_name", "grep_search"):
            return self._evaluate_readonly_inspection(tool_name, tool_args)
        else:
            return self._evaluate_generic_tool(tool_name, tool_args)

    def _check_tier0_anti_tamper(self, tool_name: str, tool_args: Dict[str, Any]) -> Optional[PolicyResult]:
        """
        Tier-0 Rule: Evaluated first, before any other hard-deny or hard-allow check.
        Denies any write, edit, or shell-redirect targeting:
          - .agents/hooks.json (active hook config)
          - *policy.yaml / *policy.yml / *policy.json (workspace and global policy files)
          - daemon runtime socket, PID file, and token files
        Explicit scope limit: Never protects agent_airlock/ source files or *.py files.
        """
        # 1. File write/edit tools (write_to_file, replace_file_content)
        if tool_name in ("write_to_file", "replace_file_content"):
            target_file = tool_args.get("TargetFile", "").strip()
            if target_file and is_protected_runtime_path(target_file):
                return PolicyResult(
                    verdict=PolicyVerdict.DENY,
                    rule_id="deny-airlock-runtime-tampering",
                    reason=f"Hard Deny (Anti-Tamper): Mutating airlock runtime surface ({target_file}) is prohibited.",
                )

        # 2. Shell execution (run_command)
        elif tool_name == "run_command":
            raw_cmd = tool_args.get("CommandLine", "").strip()
            if raw_cmd:
                cmd_lower = raw_cmd.lower()
                if not any(s in cmd_lower for s in ("policy", "hooks", ".sock", ".pid", ".token", ".agents", "airlock")):
                    return None
                if is_tampering_command(raw_cmd):
                    return PolicyResult(
                        verdict=PolicyVerdict.DENY,
                        rule_id="deny-airlock-runtime-tampering",
                        reason="Hard Deny (Anti-Tamper): Shell command targets airlock runtime configuration, policy, socket, or token files.",
                    )
                unwrapped = extract_subshell_and_encoded_payloads(raw_cmd)
                for p in unwrapped:
                    if is_tampering_command(p):
                        return PolicyResult(
                            verdict=PolicyVerdict.DENY,
                            rule_id="deny-airlock-runtime-tampering",
                            reason="Hard Deny (Anti-Tamper): Subshell/encoded command targets airlock runtime configuration, policy, socket, or token files.",
                        )

        # 3. Generic tools attempting to write to protected paths
        else:
            for k, val in tool_args.items():
                if isinstance(val, str) and is_protected_runtime_path(val):
                    if any(w in tool_name.lower() for w in ("write", "edit", "modify", "delete", "remove", "save")):
                        return PolicyResult(
                            verdict=PolicyVerdict.DENY,
                            rule_id="deny-airlock-runtime-tampering",
                            reason=f"Hard Deny (Anti-Tamper): Tool '{tool_name}' targeting protected runtime surface is prohibited.",
                        )

        return None

    DENY_RULE_PREFILTERS = {
        "deny-destructive-fs-posix": lambda cmd, lower: "rm" in lower,
        "deny-destructive-fs-windows": lambda cmd, lower: any(k in lower for k in ("rmdir", "rd", "remove-item", "ri", "rm", "format", "diskpart")),
        "deny-disk-wipe": lambda cmd, lower: "dd" in lower or "mkfs" in lower,
        "deny-pipe-to-shell-posix": lambda cmd, lower: "|" in cmd,
        "deny-pipe-to-shell-windows": lambda cmd, lower: "|" in cmd,
        "deny-credentials-in-command": lambda cmd, lower: any(k in lower for k in (".ssh", ".aws", ".kube", ".npmrc", ".pypirc", ".netrc", ".pgpass", ".git-credentials", ".docker", ".gemini", "chrome", "edge", "firefox", "brave", "appdata", "%appdata%", "%localappdata%", "shadow", "passwd", ".env", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa")),
        "deny-credentials-and-secrets": lambda cmd, lower: any(k in lower for k in (".ssh", ".aws", ".kube", ".npmrc", ".pypirc", ".netrc", ".pgpass", ".git-credentials", ".docker", ".gemini", "chrome", "edge", "firefox", "brave", "appdata", "%appdata%", "%localappdata%", "shadow", "passwd", ".env", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa")),
        "deny-network-exfil-reverse-shell": lambda cmd, lower: any(k in lower for k in ("nc", "socat", "/dev/tcp", "/dev/udp", "pty.spawn", "socket")),
        "deny-fork-bomb": lambda cmd, lower: any(k in cmd for k in (":()", ": (", "while", "()", "{")),
    }

    @staticmethod
    def _is_inline_script(raw_cmd: str) -> bool:
        """
        Detects inline interpreter execution (python -c, node -e, etc.).
        Since no L1 rule ever allows inline script execution, safe commands
        that pass all hard-deny checks can short-circuit directly to AMBIGUOUS.
        """
        cmd = raw_cmd.strip().lower()
        if not any(k in cmd for k in ("python", "node", "perl", "ruby")):
            return False

        patterns = [
            r"(?:^|[\r\n;&|])(?:\s*#.*[\r\n]+)*\s*(?:&?\s*[\"']?[^\"'\r\n]*?[\\/])?python(?:[23]|\.exe)?[\"']?\s+(?:-w\s+\S+\s+)?-c\b",
            r"(?:^|[\r\n;&|])(?:\s*#.*[\r\n]+)*\s*(?:&?\s*[\"']?[^\"'\r\n]*?[\\/])?node(?:\.exe)?[\"']?\s+(?:-e|--eval)\b",
            r"(?:^|[\r\n;&|])(?:\s*#.*[\r\n]+)*\s*(?:&?\s*[\"']?[^\"'\r\n]*?[\\/])?perl(?:\.exe)?[\"']?\s+-e\b",
            r"(?:^|[\r\n;&|])(?:\s*#.*[\r\n]+)*\s*(?:&?\s*[\"']?[^\"'\r\n]*?[\\/])?ruby(?:\.exe)?[\"']?\s+-e\b",
        ]
        cleaned = re.sub(r'[\'"]', '', cmd)
        return any(bool(re.search(p, cmd, re.IGNORECASE)) or bool(re.search(p, cleaned, re.IGNORECASE)) for p in patterns)

    def _evaluate_run_command(
        self, tool_args: Dict[str, Any], workspace_root: Optional[str] = None
    ) -> PolicyResult:
        raw_arg = tool_args.get("CommandLine", "")
        raw_cmd = raw_arg.strip()
        if not raw_cmd:
            return PolicyResult(
                verdict=PolicyVerdict.ALLOW,
                reason="Empty command line has no side effects."
            )

        # Length cap: legitimate hard-allow commands are <= 4096 chars.
        # An oversized command (>4096 chars) must NEVER be ALLOW at any layer.
        if len(raw_arg) > 4096 or len(raw_cmd) > 4096:
            raw_cmd_lower = raw_cmd.lower()
            norm_lower = None
            for rule in self._deny_rules:
                if self._rule_applies_to_tool(rule, "run_command"):
                    if self.use_prefilters:
                        prefilter = self.DENY_RULE_PREFILTERS.get(rule.id)
                        if prefilter and not prefilter(raw_cmd, raw_cmd_lower):
                            continue
                    if rule.compiled.search(raw_cmd):
                        return PolicyResult(
                            verdict=PolicyVerdict.DENY,
                            rule_id=rule.id,
                            reason=f"Hard Deny: {rule.description}",
                            matched_pattern=rule.pattern,
                        )
                    if norm_lower is None:
                        norm_lower = normalize_command(raw_cmd).lower()
                    if rule.compiled.search(norm_lower):
                        return PolicyResult(
                            verdict=PolicyVerdict.DENY,
                            rule_id=rule.id,
                            reason=f"Hard Deny: {rule.description}",
                            matched_pattern=rule.pattern,
                        )

            return PolicyResult(
                verdict=PolicyVerdict.AMBIGUOUS,
                reason="Command length exceeds 4096 characters; disqualified from hard-allow, falls through to fail-closed ASK.",
            )

        # Primary tokenization using shlex
        tokens, parse_error = tokenize_command(raw_cmd)
        shlex_cmd = " ".join(tokens) if tokens else ""

        norm_cmd = normalize_command(raw_cmd)
        strip_cmd = strip_all_quotes(norm_cmd)
        is_chained = has_command_chaining(raw_cmd)
        sub_cmds = split_command_chain(raw_cmd)

        # Candidates to check: {raw_cmd, norm_cmd, strip_cmd} unified regex matching
        # as an additional layer on top of shlex output
        candidates_to_check = {raw_cmd, norm_cmd, strip_cmd}
        if shlex_cmd:
            candidates_to_check.add(shlex_cmd)

        for sc in sub_cmds:
            candidates_to_check.add(sc)
            candidates_to_check.add(normalize_command(sc))
            candidates_to_check.add(strip_all_quotes(normalize_command(sc)))
            if len(sc) < 512:
                sc_tokens, _ = tokenize_command(sc)
                if sc_tokens:
                    candidates_to_check.add(" ".join(sc_tokens))

        # Extract unwrapped subshell and encoded command payloads
        unwrapped_payloads = extract_subshell_and_encoded_payloads(raw_cmd)
        for sc in sub_cmds:
            if len(sc) < 1024:
                unwrapped_payloads.extend(extract_subshell_and_encoded_payloads(sc))

        if unwrapped_payloads:
            # Subshell wrappers and encoded commands are disqualified from hard-allow
            is_chained = True

        for p in unwrapped_payloads:
            candidates_to_check.add(p)
            candidates_to_check.add(normalize_command(p))
            candidates_to_check.add(strip_all_quotes(normalize_command(p)))
            if len(p) < 512:
                p_tokens, _ = tokenize_command(p)
                if p_tokens:
                    candidates_to_check.add(" ".join(p_tokens))
            for p_sub in split_command_chain(p):
                candidates_to_check.add(p_sub)
                candidates_to_check.add(normalize_command(p_sub))
                p_sub_tokens, _ = tokenize_command(p_sub)
                if p_sub_tokens:
                    candidates_to_check.add(" ".join(p_sub_tokens))

        # -------------------------------------------------------------
        # STEP 1: Hard Deny Evaluation (Zero False Negatives)
        # -------------------------------------------------------------
        for rule in self._deny_rules:
            if not self._rule_applies_to_tool(rule, "run_command"):
                continue

            if self.use_prefilters:
                prefilter = self.DENY_RULE_PREFILTERS.get(rule.id)
                if prefilter and not any(prefilter(cand, cand.lower()) for cand in candidates_to_check if cand):
                    continue

            for candidate in candidates_to_check:
                if not candidate:
                    continue
                if rule.compiled.search(candidate):
                    return PolicyResult(
                        verdict=PolicyVerdict.DENY,
                        rule_id=rule.id,
                        reason=f"Hard Deny: {rule.description}",
                        matched_pattern=rule.pattern,
                        is_chained=is_chained,
                    )

        # -------------------------------------------------------------
        # STEP 1.5: Parse Error Fail-Closed
        # If shlex tokenization failed, do NOT fall through to weaker regex-only matching.
        # Route to AMBIGUOUS / ask rather than allowing an unparseable command.
        # -------------------------------------------------------------
        if parse_error:
            return PolicyResult(
                verdict=PolicyVerdict.AMBIGUOUS,
                rule_id="unparseable-command-syntax",
                reason=f"Unparseable command syntax or unclosed quotation ({parse_error}); failing closed to human confirmation.",
                is_chained=is_chained,
            )

        # -------------------------------------------------------------
        # STEP 1.6: Inline Script Short-Circuit
        # Inline script interpreters (python -c, node -e, ruby -e, perl -e)
        # are never permitted in L1 hard-allow (Invariant: no L1 allow executes workspace code).
        # Once all hard-deny checks have passed cleanly, early-exit to AMBIGUOUS.
        # -------------------------------------------------------------
        if self._is_inline_script(raw_cmd):
            return PolicyResult(
                verdict=PolicyVerdict.AMBIGUOUS,
                rule_id="inline-script-execution",
                reason="Inline script execution (-c/-e) cannot be statically verified as safe; falls through to ML/human approval after clean deny scan.",
                is_chained=is_chained,
            )

        # -------------------------------------------------------------
        # STEP 2: Hard Allow Evaluation (Family A, B, C, D)
        # -------------------------------------------------------------
        # Reject file redirection in allow evaluation (> or >>, unless 2>&1)
        # Strip scrubber placeholders like <USER>, <PATH> before checking redirection
        clean_for_redirect = re.sub(r'<[A-Za-z0-9_\-]+>', '', raw_cmd)
        if re.search(r'(?<!2)>|\b>\b|>>', clean_for_redirect):
            return PolicyResult(
                verdict=PolicyVerdict.AMBIGUOUS,
                rule_id="redirection-disallowed-in-allow",
                reason="File redirection (>, >>) detected; requires human confirmation.",
            )

        # Reject dangerous constructs that cannot be statically proven safe in L1:
        # ||, single &, backticks, $(...), @(...), ForEach-Object / %
        if re.search(r'\|\||(?<![&>])&(?![&>0-9])|`|\$\(|\@\(|\b(?:ForEach-Object|foreach)\b|\|\s*%', raw_cmd, re.IGNORECASE):
            return PolicyResult(
                verdict=PolicyVerdict.AMBIGUOUS,
                rule_id="dangerous-construct-requires-confirmation",
                reason="Subshell, background execution, array subexpression, conditional OR, backticks, or ForEach-Object detected; requires human confirmation.",
                is_chained=True,
            )

        # Validate pipeline stages against strict sink allowlist (Item 2)
        if self._has_unquoted_pipe(raw_cmd):
            pipe_res = self._validate_pipeline_stages(raw_cmd)
            if pipe_res is not None:
                return pipe_res

        # PowerShell if-construct evaluation ("if condition and all branch bodies are independently allowed")
        if re.match(r'^\s*if\s*\(', raw_cmd, re.IGNORECASE):
            if_res = self._evaluate_if_block(raw_cmd, workspace_root=workspace_root)
            if if_res is not None:
                return if_res

        # Family D: Compound command evaluation ("compound only if every segment is allowed")
        # Chaining operators strictly limited to ; && newline.
        # Any DENY segment -> DENY; any AMBIGUOUS segment -> AMBIGUOUS; compound is ALLOW only if all ALLOW.
        has_compound_chaining = bool(re.search(r';|&&|\n|\r', raw_cmd))
        if has_compound_chaining:
            segments = [s.strip() for s in self._split_top_level_chain(raw_cmd) if s.strip()]
            if len(segments) > 1:
                first_ambiguous = None
                for seg in segments:
                    seg_res = self._evaluate_run_command({"CommandLine": seg}, workspace_root=workspace_root)
                    if seg_res.verdict == PolicyVerdict.DENY:
                        return PolicyResult(
                            verdict=PolicyVerdict.DENY,
                            rule_id=seg_res.rule_id,
                            reason=f"Hard Deny: Chained command segment failed: {seg_res.reason}",
                            matched_pattern=seg_res.matched_pattern,
                            is_chained=True,
                        )
                    if seg_res.verdict != PolicyVerdict.ALLOW and first_ambiguous is None:
                        first_ambiguous = PolicyResult(
                            verdict=PolicyVerdict.AMBIGUOUS,
                            rule_id=seg_res.rule_id or "chained-segment-ambiguous",
                            reason=f"Compound segment '{seg}' requires human confirmation ({seg_res.reason}).",
                            is_chained=True,
                        )
                if first_ambiguous is not None:
                    return first_ambiguous
                return PolicyResult(
                    verdict=PolicyVerdict.ALLOW,
                    rule_id="allow-compound-chain",
                    reason="Hard Allow: Compound command where every segment is verified safe by L1.",
                    is_chained=True,
                )

        clean_scrubbed_cmd = re.sub(r'<[A-Za-z0-9_\-]+>', '_SCRUBBED_', raw_cmd)
        clean_norm_cmd = re.sub(r'<[A-Za-z0-9_\-]+>', '_SCRUBBED_', norm_cmd)

        for rule in self._allow_rules:
            if not self._rule_applies_to_tool(rule, "run_command"):
                continue

            # If the command contains pipes, ONLY allow-powershell-readonly and allow-powershell-get-process are permitted to evaluate it
            if self._has_unquoted_pipe(raw_cmd) and rule.id not in ("allow-powershell-readonly", "allow-powershell-get-process"):
                continue

            # For allow-powershell-readonly and allow-powershell-get-process, mask quoted pipes so regex matches argument literals without misinterpreting shell sinks
            target_to_match = self._mask_pipes_in_quotes(clean_scrubbed_cmd) if rule.id in ("allow-powershell-readonly", "allow-powershell-get-process") else (clean_scrubbed_cmd if shlex_cmd else clean_norm_cmd)
            if rule.compiled.search(target_to_match):
                # Extra check: make sure the command does not touch secret files
                if self._touches_credentials(target_to_match) or self._touches_credentials(clean_norm_cmd) or self._touches_credentials(raw_cmd):
                    return PolicyResult(
                        verdict=PolicyVerdict.DENY,
                        rule_id="deny-credentials-in-command",
                        reason="Hard Deny: Command targets credential or secret files.",
                        matched_pattern=rule.pattern,
                    )

                # Family A & D guard: Git inspection rules require workspace containment, reject --no-index, and reject sensitive URLs
                if rule.id in ("allow-git-status-diff-log", "allow-git-grep"):
                    if "--no-index" in raw_cmd.lower():
                        return PolicyResult(
                            verdict=PolicyVerdict.AMBIGUOUS,
                            rule_id="git-no-index-disallowed",
                            reason="Git --no-index accesses arbitrary filesystem paths; requires human confirmation.",
                        )

                    # Item 3: git grep reject -O/--open-files-in-pager, and git -c/-C/--paginate/--exec-path before subcommand
                    if rule.id == "allow-git-grep":
                        if re.search(r'-(?:O\b|-(?:open-files-in-pager)\b)', raw_cmd):
                            return PolicyResult(
                                verdict=PolicyVerdict.AMBIGUOUS,
                                rule_id="git-grep-pager-disallowed",
                                reason="Git grep with pager execution (-O/--open-files-in-pager) requires human confirmation.",
                            )
                        # Reject prefix flags -c, -C, --paginate, --exec-path before grep subcommand
                        prefix_match = re.search(r'^git\s+(.*?)\bgrep\b', raw_cmd, re.IGNORECASE)
                        if prefix_match:
                            prefix_str = prefix_match.group(1)
                            if re.search(r'(?:-(?:[cC]|-(?:paginate|exec-path))\b)', prefix_str):
                                return PolicyResult(
                                    verdict=PolicyVerdict.AMBIGUOUS,
                                    rule_id="git-global-prefix-disallowed",
                                    reason="Git prefix flags (-c, -C, --paginate, --exec-path) before subcommand require human confirmation.",
                                )

                    # Validate all path arguments resolve inside workspace_root
                    try:
                        tokens_to_check = shlex.split(raw_cmd, posix=False)
                    except Exception:
                        tokens_to_check = raw_cmd.split()

                    for i, tok in enumerate(tokens_to_check):
                        if tok.startswith("-C"):
                            c_p = tokens_to_check[i + 1] if tok == "-C" and i + 1 < len(tokens_to_check) else tok[2:]
                            c_p = c_p.strip("'\"")
                            if not self._is_path_contained_in_workspace(c_p, workspace_root):
                                return PolicyResult(
                                    verdict=PolicyVerdict.AMBIGUOUS,
                                    rule_id="git-external-path-requires-confirmation",
                                    reason=f"Git -C path '{c_p}' is outside workspace root; falls through to human confirmation.",
                                )

                    paths_to_check = []
                    if rule.id == "allow-git-grep":
                        grep_idx = 0
                        for idx, tok in enumerate(tokens_to_check):
                            if tok.lower() == "grep":
                                grep_idx = idx
                                break
                        args = tokens_to_check[grep_idx + 1:]
                        pattern_seen = False
                        skip_next = False
                        after_double_dash = False
                        for t in args:
                            if skip_next:
                                skip_next = False
                                continue
                            if t == "--":
                                after_double_dash = True
                                continue
                            if after_double_dash:
                                paths_to_check.append(t.strip("'\""))
                                continue
                            if t.startswith("-"):
                                t_low = t.lower()
                                if t_low == "-e":
                                    skip_next = True
                                    pattern_seen = True
                                elif t_low in ("-c", "-a", "-b", "--context"):
                                    skip_next = True
                                continue
                            if not pattern_seen:
                                pattern_seen = True
                            else:
                                paths_to_check.append(t.strip("'\""))
                    else:
                        after_double_dash = False
                        for tok in tokens_to_check:
                            if tok == "--":
                                after_double_dash = True
                                continue
                            if after_double_dash:
                                paths_to_check.append(tok.strip("'\""))
                            elif "/" in tok or "\\" in tok or tok.startswith(".."):
                                if not tok.startswith("-"):
                                    target_p = tok.strip("'\"")
                                    if ":" in target_p and not (len(target_p) >= 2 and target_p[1] == ":" and target_p[0].isalpha()):
                                        target_p = target_p.split(":", 1)[1]
                                    paths_to_check.append(target_p)

                    for p in paths_to_check:
                        if not self._is_path_contained_in_workspace(p, workspace_root):
                            return PolicyResult(
                                verdict=PolicyVerdict.AMBIGUOUS,
                                rule_id="git-external-path-requires-confirmation",
                                reason=f"Git path '{p}' is outside workspace root; falls through to human confirmation.",
                            )

                # Family D guard: git branch list must not delete or rename branches
                if rule.id == "allow-git-branch-list":
                    if re.search(r'-[dD]\b|--delete\b', raw_cmd):
                        return PolicyResult(
                            verdict=PolicyVerdict.AMBIGUOUS,
                            rule_id="git-branch-delete-requires-confirmation",
                            reason="Git branch deletion requires human confirmation.",
                        )
                    if re.search(r'-[mM]\b|--move\b', raw_cmd):
                        return PolicyResult(
                            verdict=PolicyVerdict.AMBIGUOUS,
                            rule_id="git-branch-rename-requires-confirmation",
                            reason="Git branch rename requires human confirmation.",
                        )

                # Family D guard: git tag list / local must not delete or push tags
                if rule.id in ("allow-git-tag-list", "allow-git-tag-local"):
                    if re.search(r'-d\b|--delete\b', raw_cmd):
                        return PolicyResult(
                            verdict=PolicyVerdict.AMBIGUOUS,
                            rule_id="git-tag-delete-requires-confirmation",
                            reason="Git tag deletion requires human confirmation.",
                        )
                    # Item 3: git tag reject -s/-u/--sign
                    if re.search(r'-(?:s\b|u\b|-(?:sign|local-user)\b)', raw_cmd):
                        return PolicyResult(
                            verdict=PolicyVerdict.AMBIGUOUS,
                            rule_id="git-tag-sign-requires-confirmation",
                            reason="Git signed tags require human confirmation.",
                        )
                    if rule.id == "allow-git-tag-local" and "push" in raw_cmd.lower():
                        return PolicyResult(
                            verdict=PolicyVerdict.AMBIGUOUS,
                            rule_id="git-tag-push-requires-confirmation",
                            reason="Git tag creation chained with push requires human confirmation.",
                        )

                # Family D guard: git add workspace paths
                if rule.id == "allow-git-add-workspace":
                    # Item 3: reject -f/--force, '.', -A/--all, -u, globs, pathspec magic ':(', only explicit workspace paths pass
                    if re.search(r'-(?:p|i|f|A|u)\b|--(?:patch|interactive|force|all|update)\b|\b\.(?:\s|$)|[*?\[\]]|:\(', raw_cmd):
                        return PolicyResult(
                            verdict=PolicyVerdict.AMBIGUOUS,
                            rule_id="git-add-flags-or-globs-disallowed",
                            reason="Git add with bulk flags (-A, -u, -f, .), globs, or pathspec magic requires human confirmation; only explicit workspace paths permitted.",
                        )
                    add_tokens = raw_cmd.split()[1:]
                    for tok in add_tokens:
                        if tok.startswith("-"):
                            continue
                        clean_tok = tok.strip("'\"")
                        if not clean_tok:
                            continue
                        # Reject secret files and sensitive dotfiles
                        clean_lower = clean_tok.lower().replace("\\", "/").split("/")[-1]
                        if clean_lower in (".env", ".git-credentials", "id_rsa", "credentials") or clean_lower.startswith((".env.", ".ssh", ".aws")):
                            return PolicyResult(
                                verdict=PolicyVerdict.DENY,
                                rule_id="deny-credentials-in-command",
                                reason=f"Hard Deny: Git add cannot stage secret dotfile '{clean_tok}'.",
                            )
                        if not self._is_path_contained_in_workspace(clean_tok, workspace_root):
                            return PolicyResult(
                                verdict=PolicyVerdict.AMBIGUOUS,
                                rule_id="git-add-external-path",
                                reason=f"Git add path '{clean_tok}' is outside workspace root; requires human confirmation.",
                            )

                # Family D guard: where / where.exe lookup
                if rule.id == "allow-where-binary-lookup":
                    if re.search(r'/[rR]\b', raw_cmd):
                        return PolicyResult(
                            verdict=PolicyVerdict.AMBIGUOUS,
                            rule_id="where-recursive-disallowed",
                            reason="Where /r recursive traversal requires human confirmation.",
                        )
                    if self._touches_credentials(raw_cmd):
                        return PolicyResult(
                            verdict=PolicyVerdict.DENY,
                            rule_id="deny-credentials-in-command",
                            reason="Hard Deny: Command searches for secret credential file.",
                        )

                # Family D guard: Windows dir listing
                if rule.id == "allow-dir-windows":
                    if "/s" in raw_cmd.lower() and re.search(r'\b[A-Za-z]:\\(?:\s|$)|^\s*dir\s+/s(?:\s*$|\s+[A-Za-z]:\\)', raw_cmd, re.I):
                        return PolicyResult(
                            verdict=PolicyVerdict.AMBIGUOUS,
                            rule_id="dir-root-traversal-disallowed",
                            reason="Dir /s starting from system drive root requires human confirmation.",
                        )
                    dir_tokens = raw_cmd.split()[1:]
                    for tok in dir_tokens:
                        if tok.startswith("/"):
                            continue
                        clean_tok = tok.strip("'\"")
                        if clean_tok and not self._is_path_contained_in_workspace(clean_tok, workspace_root):
                            return PolicyResult(
                                verdict=PolicyVerdict.AMBIGUOUS,
                                rule_id="dir-path-outside-workspace",
                                reason=f"Dir path '{clean_tok}' is outside workspace root; requires human confirmation.",
                            )

                # Family B & D guard: PowerShell paths must resolve inside workspace_root
                if rule.id == "allow-powershell-readonly":
                    first_seg = self._split_pipeline_quote_aware(raw_cmd)[0].strip()
                    try:
                        tokens = shlex.split(first_seg, posix=False)
                    except Exception:
                        tokens = first_seg.split()
                    skip_next = False
                    for i, tok in enumerate(tokens[1:], 1):
                        if skip_next:
                            skip_next = False
                            continue
                        if tok.startswith("-"):
                            tok_low = tok.lower()
                            if tok_low in ("-path", "-literalpath"):
                                if i + 1 < len(tokens):
                                    target_p = tokens[i + 1].strip("'\"")
                                    skip_next = True
                                    if not self._is_path_contained_in_workspace(target_p, workspace_root):
                                        return PolicyResult(
                                            verdict=PolicyVerdict.AMBIGUOUS,
                                            rule_id="powershell-path-outside-workspace",
                                            reason=f"PowerShell path '{target_p}' is outside workspace root; falls through to human confirmation.",
                                        )
                            elif tok_low in ("-filter", "-pattern", "-include", "-exclude", "-erroraction", "-ea", "-warningaction", "-wa", "-informationaction", "-infa", "-encoding"):
                                # Parameter takes an argument that is NOT a filesystem path
                                skip_next = True
                            continue
                        target_p = tok.strip("'\"")
                        if not target_p or target_p.startswith("-"):
                            continue
                        if not self._is_path_contained_in_workspace(target_p, workspace_root):
                            return PolicyResult(
                                verdict=PolicyVerdict.AMBIGUOUS,
                                rule_id="powershell-path-outside-workspace",
                                reason=f"PowerShell positional path '{target_p}' is outside workspace root; falls through to human confirmation.",
                            )

                # Approved Gap Rule 1: Test-Path binary/system discovery
                if rule.id == "allow-powershell-test-path":
                    toks = []
                    try:
                        toks = shlex.split(raw_cmd, posix=False)
                    except Exception:
                        toks = raw_cmd.split()
                    target_p = None
                    skip = False
                    for i, t in enumerate(toks[1:], 1):
                        if skip:
                            skip = False
                            continue
                        t_low = t.lower()
                        if t_low in ("-path", "-literalpath"):
                            if i + 1 < len(toks):
                                target_p = toks[i + 1]
                                skip = True
                        elif t_low.startswith("-"):
                            if t_low in ("-pathtype", "-erroraction", "-ea"):
                                skip = True
                            continue
                        elif target_p is None:
                            target_p = t

                    if not target_p:
                        return PolicyResult(
                            verdict=PolicyVerdict.AMBIGUOUS,
                            rule_id="test-path-missing-argument",
                            reason="Test-Path without path argument requires human confirmation.",
                        )
                    clean_path = target_p.strip("'\"")
                    # Rejects wildcards
                    if any(c in clean_path for c in ("*", "?", "[", "]")):
                        return PolicyResult(
                            verdict=PolicyVerdict.AMBIGUOUS,
                            rule_id="test-path-wildcards-disallowed",
                            reason="Test-Path with wildcards requires human confirmation.",
                        )
                    # Rejects UNC paths
                    if clean_path.startswith(r"\\") or clean_path.startswith("//"):
                        return PolicyResult(
                            verdict=PolicyVerdict.AMBIGUOUS,
                            rule_id="test-path-unc-disallowed",
                            reason="Test-Path targeting UNC network paths requires human confirmation.",
                        )
                    # Rejects reparse points (symlinks/junctions)
                    try:
                        p_obj = Path(clean_path)
                        if p_obj.exists() and (p_obj.is_symlink() or (hasattr(os.path, "isjunction") and os.path.isjunction(clean_path))):
                            return PolicyResult(
                                verdict=PolicyVerdict.AMBIGUOUS,
                                rule_id="test-path-reparse-point-disallowed",
                                reason="Test-Path on reparse points (symlinks/junctions) requires human confirmation.",
                            )
                    except Exception:
                        pass
                    # Permits workspace paths or standard installation prefixes (C:\Program Files*)
                    in_workspace = self._is_path_contained_in_workspace(clean_path, workspace_root)
                    norm_clean = os.path.normpath(clean_path)
                    is_install_prefix = bool(re.match(r'^[a-zA-Z]:[/\\]Program Files(?:\s*\(x86\))?[/\\]', norm_clean, re.IGNORECASE))
                    if not (in_workspace or is_install_prefix):
                        return PolicyResult(
                            verdict=PolicyVerdict.AMBIGUOUS,
                            rule_id="test-path-outside-workspace-or-install-prefix",
                            reason=f"Test-Path path '{clean_path}' is outside workspace and not a standard installation prefix; requires human confirmation.",
                        )

                # Approved Gap Rule 2: Copy-Item in workspace
                if rule.id == "allow-powershell-copy-item":
                    toks = []
                    try:
                        toks = shlex.split(raw_cmd, posix=False)
                    except Exception:
                        toks = raw_cmd.split()
                    # Rejects -Force, -Recurse, -Confirm:$false
                    for t in toks[1:]:
                        t_low = t.lower()
                        if t_low in ("-force", "-f", "-recurse", "-r", "-confirm:$false"):
                            return PolicyResult(
                                verdict=PolicyVerdict.AMBIGUOUS,
                                rule_id="copy-item-force-recurse-disallowed",
                                reason="Copy-Item with -Force or -Recurse requires human confirmation.",
                            )
                    src_p = None
                    dst_p = None
                    skip = False
                    for i, t in enumerate(toks[1:], 1):
                        if skip:
                            skip = False
                            continue
                        t_low = t.lower()
                        if t_low in ("-path", "-literalpath"):
                            if i + 1 < len(toks):
                                src_p = toks[i + 1]
                                skip = True
                        elif t_low in ("-destination", "-dest"):
                            if i + 1 < len(toks):
                                dst_p = toks[i + 1]
                                skip = True
                        elif t.startswith("-"):
                            continue
                        else:
                            if src_p is None:
                                src_p = t
                            elif dst_p is None:
                                dst_p = t

                    if not src_p or not dst_p:
                        return PolicyResult(
                            verdict=PolicyVerdict.AMBIGUOUS,
                            rule_id="copy-item-missing-paths",
                            reason="Copy-Item requires explicit source and destination paths.",
                        )
                    clean_src = src_p.strip("'\"")
                    clean_dst = dst_p.strip("'\"")
                    if any(c in clean_src or c in clean_dst for c in ("*", "?", "[", "]")):
                        return PolicyResult(
                            verdict=PolicyVerdict.AMBIGUOUS,
                            rule_id="copy-item-wildcards-disallowed",
                            reason="Copy-Item with wildcards requires human confirmation.",
                        )
                    if clean_src.startswith(r"\\") or clean_src.startswith("//") or clean_dst.startswith(r"\\") or clean_dst.startswith("//"):
                        return PolicyResult(
                            verdict=PolicyVerdict.AMBIGUOUS,
                            rule_id="copy-item-unc-disallowed",
                            reason="Copy-Item on UNC network paths requires human confirmation.",
                        )
                    if not self._is_path_contained_in_workspace(clean_src, workspace_root):
                        return PolicyResult(
                            verdict=PolicyVerdict.AMBIGUOUS,
                            rule_id="copy-item-source-outside-workspace",
                            reason=f"Copy-Item source '{clean_src}' is outside workspace root; requires human confirmation.",
                        )
                    target_dest_file = clean_dst
                    if clean_dst.endswith(("/", "\\")) or (workspace_root and os.path.isdir(os.path.join(workspace_root, clean_dst))):
                        target_dest_file = os.path.join(clean_dst, os.path.basename(clean_src))
                    if not self._check_workspace_write_allowed(target_dest_file, workspace_root):
                        return PolicyResult(
                            verdict=PolicyVerdict.AMBIGUOUS,
                            rule_id="copy-item-destination-sensitive-or-outside",
                            reason=f"Copy-Item destination '{clean_dst}' targets a sensitive, trust-root, or external path; requires human confirmation.",
                        )

                # Approved Gap Rule 3: Get-Process inspection
                if rule.id == "allow-powershell-get-process":
                    if re.search(r'\b(?:Stop-Process|Kill|Start-Process)\b|-(?:wait)\b|\{|\}', raw_cmd, re.I):
                        return PolicyResult(
                            verdict=PolicyVerdict.AMBIGUOUS,
                            rule_id="get-process-mutating-disallowed",
                            reason="Get-Process with mutating cmdlets, scriptblocks, or -Wait requires human confirmation.",
                        )

                # Approved Gap Rule 5: Tool help queries
                if rule.id == "allow-tool-help":
                    clean_help_cmd = re.sub(r'\s*2>&1\s*$', '', raw_cmd.strip())
                    if re.search(r'[;&|`$(){}>]', clean_help_cmd):
                        return PolicyResult(
                            verdict=PolicyVerdict.AMBIGUOUS,
                            rule_id="tool-help-chaining-or-pipe-disallowed",
                            reason="Tool help query with chaining, piping, or file redirection requires human confirmation.",
                        )
                    m_help = re.match(r'^(?:([a-zA-Z0-9_\-]+)\s+(?:--help|-h|help)|help\s+([a-zA-Z0-9_\-]+))(?:\s+2>&1)?$', raw_cmd.strip(), re.I)
                    if not m_help:
                        return PolicyResult(
                            verdict=PolicyVerdict.AMBIGUOUS,
                            rule_id="tool-help-malformed",
                            reason="Malformed tool help query requires human confirmation.",
                        )
                    tool_bin = (m_help.group(1) or m_help.group(2)).lower()
                    if "/" in tool_bin or "\\" in tool_bin:
                        return PolicyResult(
                            verdict=PolicyVerdict.AMBIGUOUS,
                            rule_id="tool-help-path-separator-disallowed",
                            reason=f"Tool help with path separator ('{tool_bin}') requires human confirmation; bare command name required.",
                        )
                    if tool_bin not in KNOWN_HELP_TOOLS:
                        return PolicyResult(
                            verdict=PolicyVerdict.AMBIGUOUS,
                            rule_id="tool-help-unknown-tool",
                            reason=f"Tool '{tool_bin}' is not in the known tool help allowlist; requires human confirmation.",
                        )
                    if not shutil.which(tool_bin):
                        return PolicyResult(
                            verdict=PolicyVerdict.AMBIGUOUS,
                            rule_id="tool-help-not-on-path",
                            reason=f"Tool '{tool_bin}' does not resolve to an executable on system PATH; requires human confirmation.",
                        )

                # Approved Gap Rule 7: Local git commit in workspace
                if rule.id == "allow-git-commit":
                    if re.search(r'-(?:a\b|F\b|S\b|c\b|C\b|-(?:all|amend|file|gpg-sign|reedit-message|reuse-message|author|date|no-verify|fixup|squash)\b)', raw_cmd):
                        return PolicyResult(
                            verdict=PolicyVerdict.AMBIGUOUS,
                            rule_id="git-commit-disallowed-flags",
                            reason="Git commit with modifying/signing/bypass flags (-a, --amend, -F, -S, -c, --author, --no-verify) requires human confirmation.",
                        )
                    tokens_to_check = raw_cmd.split()
                    for i, tok in enumerate(tokens_to_check):
                        if tok.startswith("-C"):
                            c_p = tokens_to_check[i + 1] if tok == "-C" and i + 1 < len(tokens_to_check) else tok[2:]
                            if not self._is_path_contained_in_workspace(c_p, workspace_root):
                                return PolicyResult(
                                    verdict=PolicyVerdict.AMBIGUOUS,
                                    rule_id="git-external-path-requires-confirmation",
                                    reason=f"Git -C path '{c_p}' is outside workspace root; falls through to human confirmation.",
                                )
                    if self._has_active_git_hooks(workspace_root):
                        return PolicyResult(
                            verdict=PolicyVerdict.AMBIGUOUS,
                            rule_id="git-active-hooks-require-confirmation",
                            reason="Git repository has active hooks or core.hooksPath configured; requires human confirmation.",
                        )

                # Approved Gap Rule: Write-Output of pure string literals
                if rule.id == "allow-powershell-write-output":
                    if re.search(r'[;&|`$(){}>]', raw_cmd):
                        return PolicyResult(
                            verdict=PolicyVerdict.AMBIGUOUS,
                            rule_id="write-output-chaining-or-redirection-disallowed",
                            reason="Write-Output with command chaining, redirection, or expansions requires human confirmation.",
                        )

                # Approved Gap Rule: New-Item Directory in workspace
                if rule.id == "allow-powershell-new-item-dir":
                    try:
                        toks = shlex.split(raw_cmd, posix=False)
                    except Exception:
                        toks = raw_cmd.split()
                    target_p = None
                    skip = False
                    for i, t in enumerate(toks[1:], 1):
                        if skip:
                            skip = False
                            continue
                        t_low = t.lower()
                        if t_low in ("-itemtype", "-type"):
                            skip = True
                            continue
                        if t_low in ("-path", "-name"):
                            if i + 1 < len(toks):
                                target_p = toks[i + 1]
                                skip = True
                            continue
                        if not t.startswith("-") and target_p is None:
                            target_p = t
                    if not target_p:
                        return PolicyResult(
                            verdict=PolicyVerdict.AMBIGUOUS,
                            rule_id="new-item-dir-missing-path",
                            reason="New-Item Directory without path argument requires human confirmation.",
                        )
                    clean_p = target_p.strip("'\"")
                    if any(c in clean_p for c in ("*", "?", "[", "]")):
                        return PolicyResult(
                            verdict=PolicyVerdict.AMBIGUOUS,
                            rule_id="new-item-dir-wildcard-disallowed",
                            reason="New-Item Directory with wildcards requires human confirmation.",
                        )
                    if clean_p.startswith(r"\\") or clean_p.startswith("//"):
                        return PolicyResult(
                            verdict=PolicyVerdict.AMBIGUOUS,
                            rule_id="new-item-dir-unc-disallowed",
                            reason="New-Item Directory targeting UNC path requires human confirmation.",
                        )
                    norm_p = os.path.normpath(clean_p)
                    parts = [part.lower() for part in norm_p.replace("\\", "/").split("/")]
                    sensitive_dir_names = {".git", ".agents", ".vscode", ".ssh", ".aws", ".azure", ".gnupg"}
                    if any(part in sensitive_dir_names for part in parts):
                        return PolicyResult(
                            verdict=PolicyVerdict.AMBIGUOUS,
                            rule_id="new-item-dir-sensitive-name-disallowed",
                            reason=f"New-Item Directory targeting sensitive folder name in '{clean_p}' requires human confirmation.",
                        )
                    try:
                        p_obj = Path(clean_p)
                        if p_obj.exists() and (p_obj.is_symlink() or (hasattr(os.path, "isjunction") and os.path.isjunction(clean_p))):
                            return PolicyResult(
                                verdict=PolicyVerdict.AMBIGUOUS,
                                rule_id="new-item-dir-reparse-point-disallowed",
                                reason="New-Item Directory on existing symlink or junction requires human confirmation.",
                            )
                    except Exception:
                        pass
                    if not self._is_path_contained_in_workspace(clean_p, workspace_root):
                        return PolicyResult(
                            verdict=PolicyVerdict.AMBIGUOUS,
                            rule_id="new-item-dir-outside-workspace",
                            reason=f"New-Item Directory path '{clean_p}' is outside workspace root; requires human confirmation.",
                        )

                # Approved Gap Rule: python -m pip inspect
                if rule.id == "allow-python-pip-inspect":
                    if re.search(r'[;&|`$(){}>]', raw_cmd):
                        return PolicyResult(
                            verdict=PolicyVerdict.AMBIGUOUS,
                            rule_id="pip-inspect-chaining-disallowed",
                            reason="Pip inspection query with chaining or redirection requires human confirmation.",
                        )

                return PolicyResult(
                    verdict=PolicyVerdict.ALLOW,
                    rule_id=rule.id,
                    reason=f"Hard Allow: {rule.description}",
                    matched_pattern=rule.pattern,
                )

        # Any pipeline command that did not match allow-powershell-readonly or allow-powershell-get-process is ambiguous
        if self._has_unquoted_pipe(raw_cmd):
            return PolicyResult(
                verdict=PolicyVerdict.AMBIGUOUS,
                reason="Command chaining or pipeline execution detected; falls through to Laya.",
                is_chained=True,
            )

        # -------------------------------------------------------------
        # STEP 3: Fall Through to Laya (Ambiguous)
        # -------------------------------------------------------------
        return PolicyResult(
            verdict=PolicyVerdict.AMBIGUOUS,
            reason="Command is not in deterministic allow/deny rules; falls through to Laya evaluation."
        )

    def _evaluate_view_file(self, tool_args: Dict[str, Any]) -> PolicyResult:
        file_path = tool_args.get("AbsolutePath", "").strip()

        # Check against credential/secret deny rules
        for rule in self._deny_rules:
            if self._rule_applies_to_tool(rule, "view_file"):
                if rule.compiled.search(file_path):
                    return PolicyResult(
                        verdict=PolicyVerdict.DENY,
                        rule_id=rule.id,
                        reason=f"Hard Deny: Cannot view secret file: {rule.description}",
                        matched_pattern=rule.pattern,
                    )

        # Safe read-only view of ordinary file
        return PolicyResult(
            verdict=PolicyVerdict.ALLOW,
            reason="Safe read-only file inspection.",
        )

    def _evaluate_file_write(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        workspace_root: Optional[str] = None,
    ) -> PolicyResult:
        target_file = tool_args.get("TargetFile", "").strip()

        # Check if write targets credential/secret files
        for rule in self._deny_rules:
            if self._rule_applies_to_tool(rule, tool_name):
                if rule.compiled.search(target_file):
                    return PolicyResult(
                        verdict=PolicyVerdict.DENY,
                        rule_id=rule.id,
                        reason=f"Hard Deny: Cannot modify secret or sensitive file: {rule.description}",
                        matched_pattern=rule.pattern,
                    )

        # Rule Family C: Safe workspace file modifications strictly inside workspace root
        if workspace_root and self._check_workspace_write_allowed(target_file, workspace_root):
            return PolicyResult(
                verdict=PolicyVerdict.ALLOW,
                rule_id="allow-workspace-file-modification",
                reason="Hard Allow: Safe workspace file modification inside workspace root.",
            )

        # Modifying trust roots or files without verified workspace root falls through to Laya
        return PolicyResult(
            verdict=PolicyVerdict.AMBIGUOUS,
            reason=f"File mutation via {tool_name} requires confirmation or blast-radius assessment; falls through to Jev.",
        )

    def _has_active_git_hooks(self, workspace_root: Optional[str]) -> bool:
        """
        Checks whether repository has active hooks in .git/hooks or core.hooksPath configured.
        Cached with short TTL (30s).
        """
        if not workspace_root:
            return True  # Fail closed to AMBIGUOUS if workspace unknown
        now = time.time()
        cached = _GIT_HOOKS_CACHE.get(workspace_root)
        if cached and (now - cached[1]) < _GIT_HOOKS_CACHE_TTL:
            return cached[0]

        has_hooks = False
        try:
            ws_path = Path(workspace_root)
            git_dir = ws_path / ".git"
            if not git_dir.is_dir():
                if git_dir.is_file():
                    content = git_dir.read_text(encoding="utf-8", errors="ignore").strip()
                    if content.startswith("gitdir:"):
                        git_dir = Path(content[7:].strip())
                        if not git_dir.is_absolute():
                            git_dir = (ws_path / git_dir).resolve()

            git_config = git_dir / "config"
            if git_config.is_file():
                config_text = git_config.read_text(encoding="utf-8", errors="ignore")
                if re.search(r'^\s*hookspath\s*=', config_text, re.MULTILINE | re.IGNORECASE):
                    has_hooks = True

            if not has_hooks:
                hooks_dir = git_dir / "hooks"
                if hooks_dir.is_dir():
                    for entry in hooks_dir.iterdir():
                        if entry.is_file() and not entry.name.endswith(".sample"):
                            has_hooks = True
                            break
        except Exception:
            has_hooks = True  # Fail closed on error

        _GIT_HOOKS_CACHE[workspace_root] = (has_hooks, now)
        return has_hooks

    def _is_dangerous_workspace_root(self, ws_str: str) -> bool:
        if not ws_str:
            return True
        try:
            ws_path = Path(ws_str).resolve()
        except Exception:
            return True

        # 1. Drive root check
        if ws_path == ws_path.parent or str(ws_path).rstrip("/\\") in ("C:", "D:", "E:", ""):
            return True

        # 2. User home and its ancestors
        home_path = Path(os.path.expanduser("~")).resolve()
        try:
            if ws_path == home_path or home_path.is_relative_to(ws_path):
                return True
        except Exception:
            pass
        return False

    def _mask_pipes_in_quotes(self, cmd: str) -> str:
        """
        Masks '|' inside single or double quotes so regex pattern matching
        does not misinterpret argument literals (e.g. Select-String regex patterns)
        as shell pipeline operators.
        """
        chars = []
        in_single = False
        in_double = False
        for c in cmd:
            if c == "'" and not in_double:
                in_single = not in_single
                chars.append(c)
            elif c == '"' and not in_single:
                in_double = not in_double
                chars.append(c)
            elif c == '|' and (in_single or in_double):
                chars.append('_PIPE_')
            else:
                chars.append(c)
        return "".join(chars)

    def _has_unquoted_pipe(self, cmd: str) -> bool:
        in_single = False
        in_double = False
        for c in cmd:
            if c == "'" and not in_double:
                in_single = not in_single
            elif c == '"' and not in_single:
                in_double = not in_double
            elif c == '|' and not in_single and not in_double:
                return True
        return False

    def _split_pipeline_quote_aware(self, cmd: str) -> List[str]:
        if not cmd or not cmd.strip():
            return []
        stages = []
        current = []
        in_single = False
        in_double = False
        i = 0
        n = len(cmd)

        while i < n:
            c = cmd[i]
            if c == "'" and not in_double:
                in_single = not in_single
                current.append(c)
                i += 1
            elif c == '"' and not in_single:
                in_double = not in_double
                current.append(c)
                i += 1
            elif not in_single and not in_double:
                if c == '|':
                    if i + 1 < n and cmd[i + 1] == '|':
                        current.append("||")
                        i += 2
                        continue
                    stage = "".join(current).strip()
                    stages.append(stage)
                    current = []
                    i += 1
                else:
                    current.append(c)
                    i += 1
            else:
                current.append(c)
                i += 1

        last = "".join(current).strip()
        if last or stages:
            stages.append(last)

        return stages if len(stages) > 1 else [cmd.strip()]

    def _split_top_level_chain(self, cmd: str) -> List[str]:
        if not cmd or not cmd.strip():
            return []
        stmts = []
        current = []
        in_single = False
        in_double = False
        brace_depth = 0
        paren_depth = 0
        i = 0
        n = len(cmd)

        while i < n:
            c = cmd[i]
            if c == "'" and not in_double:
                in_single = not in_single
                current.append(c)
                i += 1
            elif c == '"' and not in_single:
                in_double = not in_double
                current.append(c)
                i += 1
            elif not in_single and not in_double:
                if c == '{':
                    brace_depth += 1
                    current.append(c)
                    i += 1
                elif c == '}':
                    if brace_depth > 0:
                        brace_depth -= 1
                    current.append(c)
                    i += 1
                elif c == '(':
                    paren_depth += 1
                    current.append(c)
                    i += 1
                elif c == ')':
                    if paren_depth > 0:
                        paren_depth -= 1
                    current.append(c)
                    i += 1
                elif brace_depth == 0 and paren_depth == 0:
                    if c == ';':
                        s = "".join(current).strip()
                        if s:
                            stmts.append(s)
                        current = []
                        i += 1
                    elif c == '&' and i + 1 < n and cmd[i + 1] == '&':
                        s = "".join(current).strip()
                        if s:
                            stmts.append(s)
                        current = []
                        i += 2
                    elif c in ('\n', '\r'):
                        s = "".join(current).strip()
                        if s:
                            stmts.append(s)
                        current = []
                        i += 1
                    else:
                        current.append(c)
                        i += 1
                else:
                    current.append(c)
                    i += 1
            else:
                current.append(c)
                i += 1

        last = "".join(current).strip()
        if last:
            stmts.append(last)

        return stmts

    def _parse_if_block(self, cmd: str) -> Optional[Tuple[str, str, Optional[str]]]:
        s = cmd.strip()
        if not re.match(r'^if\s*\(', s, re.IGNORECASE):
            return None

        idx = s.find('(')
        depth = 0
        in_single = False
        in_double = False
        cond_end = -1
        for i in range(idx, len(s)):
            c = s[i]
            if c == "'" and not in_double:
                in_single = not in_single
            elif c == '"' and not in_single:
                in_double = not in_double
            elif not in_single and not in_double:
                if c == '(':
                    depth += 1
                elif c == ')':
                    depth -= 1
                    if depth == 0:
                        cond_end = i
                        break

        if cond_end == -1:
            return None

        condition = s[idx + 1:cond_end].strip()

        rest = s[cond_end + 1:].strip()
        if not rest.startswith('{'):
            return None

        depth = 0
        in_single = False
        in_double = False
        then_end = -1
        for i in range(len(rest)):
            c = rest[i]
            if c == "'" and not in_double:
                in_single = not in_single
            elif c == '"' and not in_single:
                in_double = not in_double
            elif not in_single and not in_double:
                if c == '{':
                    depth += 1
                elif c == '}':
                    depth -= 1
                    if depth == 0:
                        then_end = i
                        break

        if then_end == -1:
            return None

        then_block = rest[1:then_end].strip()
        after_then = rest[then_end + 1:].strip()

        else_block = None
        if after_then:
            if re.match(r'^else\s*\{', after_then, re.IGNORECASE):
                e_idx = after_then.find('{')
                depth = 0
                in_single = False
                in_double = False
                else_end = -1
                for i in range(e_idx, len(after_then)):
                    c = after_then[i]
                    if c == "'" and not in_double:
                        in_single = not in_single
                    elif c == '"' and not in_single:
                        in_double = not in_double
                    elif not in_single and not in_double:
                        if c == '{':
                            depth += 1
                        elif c == '}':
                            depth -= 1
                            if depth == 0:
                                else_end = i
                                break
                if else_end == -1:
                    return None
                else_block = after_then[e_idx + 1:else_end].strip()
                trailing = after_then[else_end + 1:].strip()
                if trailing:
                    return None
            else:
                return None

        return condition, then_block, else_block

    def _evaluate_if_block(self, raw_cmd: str, workspace_root: Optional[str] = None) -> Optional[PolicyResult]:
        """
        Evaluates PowerShell if constructs:
        if (<condition>) { <then_block> } [else { <else_block> }]
        Policy Change Protocol rule: An if-construct may ONLY be allowed if
        every statement in condition, then-block, and optional else-block is independently ALLOWED.
        Any DENY statement -> DENY.
        Any AMBIGUOUS statement -> AMBIGUOUS.
        Unparseable or nested unsupported constructs -> AMBIGUOUS (fail closed).
        """
        parsed = self._parse_if_block(raw_cmd)
        if parsed is None:
            return PolicyResult(
                verdict=PolicyVerdict.AMBIGUOUS,
                rule_id="unparseable-if-syntax",
                reason="Unparseable or unsupported if-block syntax; failing closed to human confirmation.",
            )

        condition, then_block, else_block = parsed
        clauses = [("condition", condition), ("then", then_block)]
        if else_block:
            clauses.append(("else", else_block))

        first_ambiguous = None
        for clause_name, clause_cmd in clauses:
            if not clause_cmd.strip():
                continue
            clause_res = self._evaluate_run_command({"CommandLine": clause_cmd}, workspace_root=workspace_root)
            if clause_res.verdict == PolicyVerdict.DENY:
                return PolicyResult(
                    verdict=PolicyVerdict.DENY,
                    rule_id=clause_res.rule_id,
                    reason=f"Hard Deny: If-block {clause_name} clause failed: {clause_res.reason}",
                    matched_pattern=clause_res.matched_pattern,
                    is_chained=True,
                )
            if clause_res.verdict != PolicyVerdict.ALLOW and first_ambiguous is None:
                first_ambiguous = PolicyResult(
                    verdict=PolicyVerdict.AMBIGUOUS,
                    rule_id=clause_res.rule_id or f"if-{clause_name}-clause-ambiguous",
                    reason=f"If-block {clause_name} clause '{clause_cmd}' requires human confirmation ({clause_res.reason}).",
                    is_chained=True,
                )

        if first_ambiguous is not None:
            return first_ambiguous

        return PolicyResult(
            verdict=PolicyVerdict.ALLOW,
            rule_id="allow-powershell-if-construct",
            reason="Hard Allow: If-construct where condition and all branch bodies are verified safe by L1.",
            is_chained=True,
        )

    def _validate_pipeline_stages(self, raw_cmd: str) -> Optional[PolicyResult]:
        """
        Validates pipeline stages against strict sink allowlist (Item 2).
        Allowed sinks: Select-String, Select-Object, Sort-Object, Measure-Object,
        Format-*, Out-String, simple Where-Object without scriptblock side effects.
        Pipes into native exes, dangerous chaining operators, or non-allowlisted sinks -> AMBIGUOUS.
        """
        if not self._has_unquoted_pipe(raw_cmd):
            return None

        stages = self._split_pipeline_quote_aware(raw_cmd)
        if len(stages) <= 1:
            return None

        for stage in stages[1:]:
            s_clean = stage.strip()
            if not s_clean:
                return PolicyResult(
                    verdict=PolicyVerdict.AMBIGUOUS,
                    rule_id="pipe-syntax-error",
                    reason="Empty pipeline stage detected; requires human confirmation.",
                    is_chained=True,
                )

            # Check redirection inside sink (ignoring scrubber placeholders)
            clean_no_scrub = re.sub(r'<[A-Za-z0-9_\-]+>', '', s_clean)
            if re.search(r'(?<!2)>|\b>\b|>>', clean_no_scrub):
                return PolicyResult(
                    verdict=PolicyVerdict.AMBIGUOUS,
                    rule_id="redirection-disallowed-in-allow",
                    reason="File redirection (>, >>) detected in pipeline sink; requires human confirmation.",
                    is_chained=True,
                )

            toks = s_clean.split()
            first = toks[0].lower()
            if first in ("sh", "bash", "zsh", "ksh", "csh", "dash", "powershell", "pwsh", "python", "python2", "python3", "node", "cmd", "cmd.exe", "xargs", "perl", "ruby") or (first == "sudo" and len(toks) > 1 and toks[1].lower() in ("sh", "bash", "zsh", "ksh", "csh", "dash", "powershell", "pwsh", "python", "node", "cmd", "xargs")):
                return PolicyResult(
                    verdict=PolicyVerdict.AMBIGUOUS,
                    rule_id="pipe-sink-native-interpreter",
                    reason="Pipeline into native shell, interpreter, or execution utility requires human confirmation.",
                    is_chained=True,
                )

            allowed = (
                first in (
                    "select-string", "sls",
                    "select-object", "select",
                    "sort-object", "sort",
                    "measure-object", "measure",
                    "out-string",
                    "where-object", "?", "where",
                    "format-table", "ft",
                    "format-list", "fl",
                    "format-wide", "fw",
                    "format-custom",
                )
                or first.startswith("format-")
            )
            if not allowed:
                return PolicyResult(
                    verdict=PolicyVerdict.AMBIGUOUS,
                    rule_id="pipe-sink-not-allowlisted",
                    reason=f"Pipeline sink '{toks[0]}' is not in hard-allow sink allowlist; requires human confirmation.",
                    is_chained=True,
                )

            if first in ("where-object", "?", "where"):
                # Validate simple Where-Object without scriptblock side effects
                # 1. Assignments
                if re.search(r'(?:\+\+|--|\+=|-=|\*=|/=|=(?![=~]))', s_clean):
                    return PolicyResult(
                        verdict=PolicyVerdict.AMBIGUOUS,
                        rule_id="where-object-side-effects-detected",
                        reason="Where-Object scriptblock contains variable assignment or mutating operator; requires human confirmation.",
                        is_chained=True,
                    )
                # 2. Mutating cmdlets
                if re.search(r'\b(?:Remove-[A-Za-z]+|Set-[A-Za-z]+|New-[A-Za-z]+|Out-[A-Za-z]+|Invoke-[A-Za-z]+|Start-[A-Za-z]+|Stop-[A-Za-z]+|Clear-[A-Za-z]+|Write-[A-Za-z]+|ri\b|rm\b|del\b|erase\b|iex\b|kill\b)\b', s_clean, re.IGNORECASE):
                    return PolicyResult(
                        verdict=PolicyVerdict.AMBIGUOUS,
                        rule_id="where-object-side-effects-detected",
                        reason="Where-Object scriptblock invokes mutating cmdlet; requires human confirmation.",
                        is_chained=True,
                    )
                # 3. Method invocation or type instantiation
                if re.search(r'\.[a-zA-Z0-9_]+\s*\(|\[[a-zA-Z0-9_.:]+\]::|\bnew-object\b', s_clean, re.IGNORECASE):
                    return PolicyResult(
                        verdict=PolicyVerdict.AMBIGUOUS,
                        rule_id="where-object-side-effects-detected",
                        reason="Where-Object scriptblock contains method invocation or type construction; requires human confirmation.",
                        is_chained=True,
                    )
                # 4. Semicolons or nested subshells/pipes
                if ";" in s_clean or "`" in s_clean or "$(" in s_clean:
                    return PolicyResult(
                        verdict=PolicyVerdict.AMBIGUOUS,
                        rule_id="where-object-side-effects-detected",
                        reason="Where-Object scriptblock contains subshell or chained statement syntax; requires human confirmation.",
                        is_chained=True,
                    )

        return None

    def _is_path_contained_in_workspace(self, path_str: str, workspace_root: Optional[str]) -> bool:
        if not path_str:
            return True
        if not workspace_root:
            return not (Path(path_str).is_absolute() or ".." in path_str)
        try:
            norm_ws = os.path.normcase(os.path.abspath(workspace_root))
            is_abs = os.path.isabs(path_str) or (len(path_str) >= 2 and path_str[1] == ':')
            candidate = path_str if is_abs else os.path.join(workspace_root, path_str)
            norm_p = os.path.normcase(os.path.abspath(candidate))
            if norm_p == norm_ws:
                return True
            if not norm_p.startswith(norm_ws + os.sep):
                return False
            return self._verify_realpath_containment(candidate, workspace_root, check_trust_root=False)
        except Exception:
            return False

    def _verify_realpath_containment(self, candidate_path: str, workspace_root: str, check_trust_root: bool = True) -> bool:
        """
        Verifies that candidate_path does not escape workspace_root via symlinks or junctions,
        does not target trust roots or disallowed directories, and contains no reparse points.
        Uses a short-TTL cache (2.0s) to keep latency overhead negligible (<0.005 ms warm).
        Fails closed (returns False -> AMBIGUOUS) on any error, reparse point, or escape.
        """
        if not candidate_path or not workspace_root:
            return False
        global _REALPATH_CACHE
        now = time.monotonic()
        cache_key = (os.path.normcase(candidate_path), os.path.normcase(workspace_root), check_trust_root)
        cached = _REALPATH_CACHE.get(cache_key)
        if cached and (now - cached[1] < _CACHE_TTL):
            return cached[0]

        try:
            norm_ws = os.path.normcase(os.path.abspath(workspace_root))
            norm_cand = os.path.normcase(os.path.abspath(candidate_path))

            # 1. Reparse point and symlink check along candidate path hierarchy
            curr = norm_cand
            while curr and curr != norm_ws and len(curr) >= len(norm_ws):
                if os.path.lexists(curr):
                    try:
                        if os.path.islink(curr):
                            _REALPATH_CACHE[cache_key] = (False, now)
                            return False
                        st = os.lstat(curr)
                        if getattr(st, 'st_file_attributes', 0) & 0x0400:  # FILE_ATTRIBUTE_REPARSE_POINT (junction/symlink)
                            _REALPATH_CACHE[cache_key] = (False, now)
                            return False
                    except Exception:
                        _REALPATH_CACHE[cache_key] = (False, now)
                        return False
                parent = os.path.dirname(curr)
                if parent == curr:
                    break
                curr = parent

            # 2. Realpath containment
            real_ws = os.path.normcase(os.path.realpath(workspace_root))
            real_cand = os.path.normcase(os.path.realpath(candidate_path))

            if not real_cand.startswith(real_ws + os.sep) or real_cand == real_ws:
                _REALPATH_CACHE[cache_key] = (False, now)
                return False

            # 3. Trust root and disallowed dirs verification on resolved target
            if check_trust_root:
                rel = os.path.relpath(real_cand, real_ws)
                rel_parts = [p.lower() for p in Path(rel).parts]
                filename = rel_parts[-1]

                disallowed = getattr(self, '_protected_dirs', DISALLOWED_DIRS_WORKSPACE_WRITE)
                for part in rel_parts[:-1]:
                    if part in disallowed:
                        _REALPATH_CACHE[cache_key] = (False, now)
                        return False

                if filename in TRUST_ROOT_FILES:
                    _REALPATH_CACHE[cache_key] = (False, now)
                    return False

                if filename.startswith("taskfile") or (filename.startswith("requirements") and filename.endswith(".txt")) or filename.startswith("dockerfile"):
                    _REALPATH_CACHE[cache_key] = (False, now)
                    return False
                if filename.startswith("docker-compose") and filename.endswith((".yml", ".yaml")):
                    _REALPATH_CACHE[cache_key] = (False, now)
                    return False
                if len(rel_parts) == 2 and rel_parts[0] == "scripts" and filename.endswith((".sh", ".bat", ".ps1", ".cmd")):
                    _REALPATH_CACHE[cache_key] = (False, now)
                    return False
                if "policy" in filename and filename.endswith((".yaml", ".yml", ".json")):
                    _REALPATH_CACHE[cache_key] = (False, now)
                    return False
                if filename.endswith((".pth", ".pem", ".key")):
                    _REALPATH_CACHE[cache_key] = (False, now)
                    return False
                if filename.startswith(".env") or any(k in filename for k in ("id_rsa", "id_ed25519", "credentials")):
                    _REALPATH_CACHE[cache_key] = (False, now)
                    return False

            _REALPATH_CACHE[cache_key] = (True, now)
            return True
        except Exception:
            _REALPATH_CACHE[cache_key] = (False, now)
            return False

    def _check_workspace_write_allowed(self, target_file_str: str, workspace_root: str) -> bool:
        if not target_file_str or not workspace_root:
            return False
        if self._is_dangerous_workspace_root(workspace_root):
            return False
        try:
            norm_ws = os.path.normcase(os.path.abspath(workspace_root))
            is_abs = os.path.isabs(target_file_str) or (len(target_file_str) >= 2 and target_file_str[1] == ':')
            candidate = target_file_str if is_abs else os.path.join(workspace_root, target_file_str)
            norm_target = os.path.normcase(os.path.abspath(candidate))
            if not norm_target.startswith(norm_ws + os.sep) or norm_target == norm_ws:
                return False
            rel_str = os.path.relpath(norm_target, norm_ws)
            rel_parts = [part.lower() for part in Path(rel_str).parts]
        except Exception:
            return False

        filename = rel_parts[-1]

        # 1. Disallowed directory components (including running package dir)
        disallowed = getattr(self, '_protected_dirs', DISALLOWED_DIRS_WORKSPACE_WRITE)
        for part in rel_parts[:-1]:
            if part in disallowed:
                return False

        # 2. Exact trust root files
        if filename in TRUST_ROOT_FILES:
            return False

        # 3. Dynamic trust patterns (Taskfile*, requirements*.txt, Dockerfile*, docker-compose*.yml)
        if filename.startswith("taskfile"):
            return False
        if filename.startswith("requirements") and filename.endswith(".txt"):
            return False
        if filename.startswith("dockerfile"):
            return False
        if filename.startswith("docker-compose") and filename.endswith((".yml", ".yaml")):
            return False

        # 4. Scripts directly under scripts/ (*.sh, *.bat, *.ps1, *.cmd)
        if len(rel_parts) == 2 and rel_parts[0] == "scripts":
            if filename.endswith((".sh", ".bat", ".ps1", ".cmd")):
                return False

        # 5. Policy files
        if "policy" in filename and filename.endswith((".yaml", ".yml", ".json")):
            return False

        # 6. Sensitive extensions (*.pth, *.pem, *.key)
        if filename.endswith((".pth", ".pem", ".key")):
            return False

        # 7. Secrets
        if filename.startswith(".env") or any(k in filename for k in ("id_rsa", "id_ed25519", "credentials")):
            return False

        # Fast lexical checks passed. Verify realpath containment and reparse points:
        return self._verify_realpath_containment(candidate, workspace_root, check_trust_root=True)

    def _evaluate_readonly_inspection(self, tool_name: str, tool_args: Dict[str, Any]) -> PolicyResult:
        # Check all string arguments against deny rules
        for val in tool_args.values():
            if isinstance(val, str):
                for rule in self._deny_rules:
                    if self._rule_applies_to_tool(rule, tool_name):
                        if rule.compiled.search(val):
                            return PolicyResult(
                                verdict=PolicyVerdict.DENY,
                                rule_id=rule.id,
                                reason=f"Hard Deny: {rule.description}",
                                matched_pattern=rule.pattern,
                            )

        return PolicyResult(
            verdict=PolicyVerdict.ALLOW,
            reason=f"Safe read-only inspection tool: {tool_name}."
        )

    def _evaluate_generic_tool(self, tool_name: str, tool_args: Dict[str, Any]) -> PolicyResult:
        # Check all string arguments against deny rules
        for val in tool_args.values():
            if isinstance(val, str):
                for rule in self._deny_rules:
                    if self._rule_applies_to_tool(rule, tool_name):
                        if rule.compiled.search(val):
                            return PolicyResult(
                                verdict=PolicyVerdict.DENY,
                                rule_id=rule.id,
                                reason=f"Hard Deny: {rule.description}",
                                matched_pattern=rule.pattern,
                            )

        return PolicyResult(
            verdict=PolicyVerdict.AMBIGUOUS,
            reason=f"Tool {tool_name} requires evaluation; falls through to Laya."
        )

    def _rule_applies_to_tool(self, rule: PolicyRule, tool_name: str) -> bool:
        return "*" in rule.tools or tool_name in rule.tools

    def _touches_credentials(self, text: str) -> bool:
        for rule in self._deny_rules:
            if "credentials" in rule.id or "secrets" in rule.id:
                if rule.compiled.search(text):
                    return True
        return False
