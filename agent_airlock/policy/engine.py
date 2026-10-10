"""
Hard Policy Engine: Deterministic rule engine for Antigravity CLI tool gating.
"""

import os
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
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

DISALLOWED_DIRS_WORKSPACE_WRITE = {
    ".vscode", ".github", ".husky", ".agents", ".git", ".ssh", ".aws", ".kube", ".gemini", "agent_airlock"
}

class HardPolicyEngine:
    """
    Deterministic rule engine running before Jev.
    Evaluates tool calls against static deny and allow lists with zero model latency.
    Guarantees zero false negatives on hard-deny rules.
    """

    def __init__(self, rules: Optional[List[PolicyRule]] = None):
        if rules is None:
            rules = get_default_rules()
        self.rules = rules
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

    def _evaluate_run_command(
        self, tool_args: Dict[str, Any], workspace_root: Optional[str] = None
    ) -> PolicyResult:
        raw_cmd = tool_args.get("CommandLine", "").strip()
        if not raw_cmd:
            return PolicyResult(
                verdict=PolicyVerdict.ALLOW,
                reason="Empty command line has no side effects."
            )

        # Length cap: legitimate hard-allow commands are <= 4096 chars.
        if len(raw_cmd) > 4096:
            scan_targets = [raw_cmd[:2048], raw_cmd[-2048:]]
            for rule in self._deny_rules:
                if self._rule_applies_to_tool(rule, "run_command"):
                    for target in scan_targets:
                        if rule.compiled.search(target):
                            return PolicyResult(
                                verdict=PolicyVerdict.DENY,
                                rule_id=rule.id,
                                reason=f"Hard Deny: {rule.description}",
                                matched_pattern=rule.pattern,
                            )
            return PolicyResult(
                verdict=PolicyVerdict.AMBIGUOUS,
                reason="Command length exceeds 4096 characters; disqualified from hard-allow, falls through to ML/human.",
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
            sc_tokens, _ = tokenize_command(sc)
            if sc_tokens:
                candidates_to_check.add(" ".join(sc_tokens))

        # Extract unwrapped subshell and encoded command payloads
        unwrapped_payloads = extract_subshell_and_encoded_payloads(raw_cmd)
        for sc in sub_cmds:
            unwrapped_payloads.extend(extract_subshell_and_encoded_payloads(sc))

        if unwrapped_payloads:
            # Subshell wrappers and encoded commands are disqualified from hard-allow
            is_chained = True

        for p in unwrapped_payloads:
            candidates_to_check.add(p)
            candidates_to_check.add(normalize_command(p))
            candidates_to_check.add(strip_all_quotes(normalize_command(p)))
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
        # STEP 2: Hard Allow Evaluation (Strictly side-effect free)
        # -------------------------------------------------------------
        # Chained commands or subshells are NEVER permitted in Hard Allow,
        # with the sole exception of safe PowerShell pipelines matching allow-powershell-readonly.
        has_dangerous_chaining = bool(re.search(r';|&&|\|\||&|\n|\r|\$\(.*?\)|`.*?`', raw_cmd))
        if has_dangerous_chaining:
            return PolicyResult(
                verdict=PolicyVerdict.AMBIGUOUS,
                reason="Command chaining or subshell substitution detected; falls through to Laya.",
                is_chained=True,
            )

        for rule in self._allow_rules:
            if not self._rule_applies_to_tool(rule, "run_command"):
                continue

            # If the command contains pipes, ONLY allow-powershell-readonly is permitted to evaluate it
            if "|" in raw_cmd and rule.id != "allow-powershell-readonly":
                continue

            # For allow-powershell-readonly, match against norm_cmd to preserve Windows backslashes
            target_to_match = norm_cmd if rule.id == "allow-powershell-readonly" else (shlex_cmd or norm_cmd)
            if rule.compiled.search(target_to_match):
                # Extra check: make sure the command does not touch secret files
                if self._touches_credentials(target_to_match) or self._touches_credentials(norm_cmd) or self._touches_credentials(raw_cmd):
                    return PolicyResult(
                        verdict=PolicyVerdict.DENY,
                        rule_id="deny-credentials-in-command",
                        reason="Hard Deny: Command targets credential or secret files.",
                        matched_pattern=rule.pattern,
                    )

                # Family A guard: Git rules require workspace containment, reject --no-index, and reject sensitive URLs
                if rule.id == "allow-git-status-diff-log":
                    if "--no-index" in raw_cmd.lower():
                        return PolicyResult(
                            verdict=PolicyVerdict.AMBIGUOUS,
                            rule_id="git-no-index-disallowed",
                            reason="Git --no-index accesses arbitrary filesystem paths; requires human confirmation.",
                        )

                    # Validate all path arguments resolve inside workspace_root
                    tokens_to_check = raw_cmd.split()
                    after_double_dash = False
                    for i, tok in enumerate(tokens_to_check):
                        if tok == "--":
                            after_double_dash = True
                            continue
                        if tok.startswith("-C"):
                            c_p = tokens_to_check[i + 1] if tok == "-C" and i + 1 < len(tokens_to_check) else tok[2:]
                            if not self._is_path_contained_in_workspace(c_p, workspace_root):
                                return PolicyResult(
                                    verdict=PolicyVerdict.AMBIGUOUS,
                                    rule_id="git-external-path-requires-confirmation",
                                    reason=f"Git -C path '{c_p}' is outside workspace root; falls through to human confirmation.",
                                )
                            continue
                        if after_double_dash:
                            if not self._is_path_contained_in_workspace(tok, workspace_root):
                                return PolicyResult(
                                    verdict=PolicyVerdict.AMBIGUOUS,
                                    rule_id="git-external-path-requires-confirmation",
                                    reason=f"Git path '{tok}' is outside workspace root; falls through to human confirmation.",
                                )
                        else:
                            if "/" in tok or "\\" in tok or tok.startswith(".."):
                                if tok.startswith("-"):
                                    continue
                                target_p = tok
                                if ":" in target_p and not (len(target_p) >= 2 and target_p[1] == ":" and target_p[0].isalpha()):
                                    target_p = target_p.split(":", 1)[1]
                                if not self._is_path_contained_in_workspace(target_p, workspace_root):
                                    return PolicyResult(
                                        verdict=PolicyVerdict.AMBIGUOUS,
                                        rule_id="git-external-path-requires-confirmation",
                                        reason=f"Git path '{target_p}' is outside workspace root; falls through to human confirmation.",
                                    )

                # Family B guard: PowerShell paths must resolve inside workspace_root
                if rule.id == "allow-powershell-readonly":
                    first_seg = raw_cmd.split("|")[0].strip()
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
                            if tok.lower() in ("-path", "-literalpath", "-includepath", "-excludepath"):
                                if i + 1 < len(tokens):
                                    target_p = tokens[i + 1].strip("'\"")
                                    skip_next = True
                                    if not self._is_path_contained_in_workspace(target_p, workspace_root):
                                        return PolicyResult(
                                            verdict=PolicyVerdict.AMBIGUOUS,
                                            rule_id="powershell-path-outside-workspace",
                                            reason=f"PowerShell path '{target_p}' is outside workspace root; falls through to human confirmation.",
                                        )
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

                return PolicyResult(
                    verdict=PolicyVerdict.ALLOW,
                    rule_id=rule.id,
                    reason=f"Hard Allow: {rule.description}",
                    matched_pattern=rule.pattern,
                )

        # Any pipeline command that did not match allow-powershell-readonly is ambiguous
        if "|" in raw_cmd:
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

    def _is_path_contained_in_workspace(self, path_str: str, workspace_root: Optional[str]) -> bool:
        if not path_str:
            return True
        if not workspace_root:
            return not (Path(path_str).is_absolute() or ".." in path_str)
        try:
            ws_path = Path(workspace_root).resolve()
            p = Path(path_str)
            is_abs = p.is_absolute() or (len(path_str) >= 2 and path_str[1] == ':')
            resolved_p = p.resolve() if is_abs else (ws_path / p).resolve()
            return resolved_p.is_relative_to(ws_path)
        except Exception:
            return False

    def _check_workspace_write_allowed(self, target_file_str: str, workspace_root: str) -> bool:
        if not target_file_str or not workspace_root:
            return False
        if self._is_dangerous_workspace_root(workspace_root):
            return False
        try:
            ws_path = Path(workspace_root).resolve()
            p = Path(target_file_str)
            target_path = p.resolve() if p.is_absolute() else (ws_path / p).resolve()
            if not target_path.is_relative_to(ws_path) or target_path == ws_path:
                return False
            rel_path = target_path.relative_to(ws_path)
        except Exception:
            return False

        rel_parts = [part.lower() for part in rel_path.parts]
        filename = rel_parts[-1]

        # 1. Disallowed directory components (including agent_airlock/**)
        for part in rel_parts[:-1]:
            if part in DISALLOWED_DIRS_WORKSPACE_WRITE:
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

        return True

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
