"""
Hard Policy Engine: Deterministic rule engine for Antigravity CLI tool gating.
"""

from typing import List, Dict, Any, Optional
from jev_gateway.policy.models import PolicyVerdict, PolicyRule, PolicyResult
from jev_gateway.policy.default_rules import get_default_rules
from jev_gateway.policy.normalizer import (
    tokenize_command,
    normalize_command,
    strip_all_quotes,
    has_command_chaining,
    split_command_chain,
)

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

    def evaluate(self, tool_name: str, tool_args: Dict[str, Any]) -> PolicyResult:
        """
        Main entrypoint: deterministically classifies a tool call as ALLOW, DENY, or AMBIGUOUS.
        """
        if not tool_args:
            tool_args = {}

        if tool_name == "run_command":
            return self._evaluate_run_command(tool_args)
        elif tool_name == "view_file":
            return self._evaluate_view_file(tool_args)
        elif tool_name in ("write_to_file", "replace_file_content"):
            return self._evaluate_file_write(tool_name, tool_args)
        elif tool_name in ("list_dir", "find_by_name", "grep_search"):
            return self._evaluate_readonly_inspection(tool_name, tool_args)
        else:
            return self._evaluate_generic_tool(tool_name, tool_args)

    def _evaluate_run_command(self, tool_args: Dict[str, Any]) -> PolicyResult:
        raw_cmd = tool_args.get("CommandLine", "").strip()
        if not raw_cmd:
            return PolicyResult(
                verdict=PolicyVerdict.ALLOW,
                reason="Empty command line has no side effects."
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
        # Chained commands or subshells are NEVER permitted in Hard Allow
        if is_chained:
            return PolicyResult(
                verdict=PolicyVerdict.AMBIGUOUS,
                reason="Command chaining or subshell substitution detected; falls through to Jev.",
                is_chained=True,
            )

        for rule in self._allow_rules:
            if not self._rule_applies_to_tool(rule, "run_command"):
                continue

            # Hard allow must match shlex_cmd or norm_cmd
            target_to_match = shlex_cmd or norm_cmd
            if rule.compiled.search(target_to_match):
                # Extra check: make sure the command does not touch secret files
                if self._touches_credentials(target_to_match) or self._touches_credentials(norm_cmd):
                    return PolicyResult(
                        verdict=PolicyVerdict.DENY,
                        rule_id="deny-credentials-in-command",
                        reason="Hard Deny: Command targets credential or secret files.",
                        matched_pattern=rule.pattern,
                    )

                return PolicyResult(
                    verdict=PolicyVerdict.ALLOW,
                    rule_id=rule.id,
                    reason=f"Hard Allow: {rule.description}",
                    matched_pattern=rule.pattern,
                )

        # -------------------------------------------------------------
        # STEP 3: Fall Through to Jev (Ambiguous)
        # -------------------------------------------------------------
        return PolicyResult(
            verdict=PolicyVerdict.AMBIGUOUS,
            reason="Command is not in deterministic allow/deny rules; falls through to Jev evaluation."
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

    def _evaluate_file_write(self, tool_name: str, tool_args: Dict[str, Any]) -> PolicyResult:
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

        # Modifying project files is mutating -> falls through to Jev
        return PolicyResult(
            verdict=PolicyVerdict.AMBIGUOUS,
            reason=f"File mutation via {tool_name} requires blast-radius assessment; falls through to Jev.",
        )

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
            reason=f"Tool {tool_name} requires evaluation; falls through to Jev."
        )

    def _rule_applies_to_tool(self, rule: PolicyRule, tool_name: str) -> bool:
        return "*" in rule.tools or tool_name in rule.tools

    def _touches_credentials(self, text: str) -> bool:
        for rule in self._deny_rules:
            if "credentials" in rule.id or "secrets" in rule.id:
                if rule.compiled.search(text):
                    return True
        return False
