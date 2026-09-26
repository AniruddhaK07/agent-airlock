"""
Configuration loader and schema validator for Jev Gateway.
"""

from typing import List, Optional, Dict, Any
from pathlib import Path
import json
import yaml
from pydantic import BaseModel, Field
from jev_gateway.policy.models import PolicyRule, PolicyVerdict
from jev_gateway.policy.default_rules import get_default_rules

class RuleConfig(BaseModel):
    id: str
    description: str
    verdict: str  # "allow" | "deny"
    tools: List[str] = Field(default_factory=lambda: ["run_command"])
    field: str = "CommandLine"
    pattern: str

class PolicyConfig(BaseModel):
    allow_override_denies: bool = False
    hard_deny: List[RuleConfig] = Field(default_factory=list)
    hard_allow: List[RuleConfig] = Field(default_factory=list)

class DaemonConfig(BaseModel):
    socket_path: str = "~/.gemini/antigravity-cli/jev-daemon.sock"
    tcp_port: int = 48921
    host: str = "127.0.0.1"
    token_file: str = "~/.gemini/antigravity-cli/.jev-daemon.token"
    pid_file: str = "~/.gemini/antigravity-cli/jev-daemon.pid"
    transport: str = "auto"  # "auto" | "unix" | "tcp"
    request_timeout_seconds: float = 5.0
    log_level: str = "INFO"

class JevThresholdsConfig(BaseModel):
    allow_confidence: float = 0.90
    deny_confidence: float = 0.85
    max_safe_blast_radius: float = 2.0
    min_safe_reversible_prob: float = 0.70
    default: str = "ask"

class JevConfig(BaseModel):
    provider: str = "none"  # "none" | "local" | "remote"
    checkpoint_path: str = "checkpoints/laya-finetuned"
    model: str = "jev-1.13.0"
    api_key_env: str = "TYPESAFE_API_KEY"
    base_url: str = "https://api.typesafe.ai/v1"
    timeout_seconds: float = 0.400
    thresholds: JevThresholdsConfig = Field(default_factory=JevThresholdsConfig)

class CircuitBreakerConfig(BaseModel):
    enabled: bool = True
    hash_window: int = 3
    similarity_threshold: float = 0.80
    break_action: str = "force_ask"

class AuditConfig(BaseModel):
    log_file: str = "~/.gemini/antigravity-cli/audit.jsonl"
    flush_immediate: bool = True
    retention_days: int = 30

class GatewayConfig(BaseModel):
    version: str = "1.0"
    daemon: DaemonConfig = Field(default_factory=DaemonConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    jev: JevConfig = Field(default_factory=JevConfig)
    circuit_breaker: CircuitBreakerConfig = Field(default_factory=CircuitBreakerConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)

    def build_effective_rules(self) -> List[PolicyRule]:
        """
        Combines built-in default rules with custom user rules.
        Built-in hard-deny rules cannot be removed unless allow_override_denies is explicitly True.
        """
        defaults = get_default_rules()
        custom_rules: List[PolicyRule] = []

        for r in self.policy.hard_deny:
            custom_rules.append(
                PolicyRule(
                    id=r.id,
                    description=r.description,
                    verdict=PolicyVerdict.DENY,
                    tools=r.tools,
                    field=r.field,
                    pattern=r.pattern,
                )
            )

        for r in self.policy.hard_allow:
            custom_rules.append(
                PolicyRule(
                    id=r.id,
                    description=r.description,
                    verdict=PolicyVerdict.ALLOW,
                    tools=r.tools,
                    field=r.field,
                    pattern=r.pattern,
                )
            )

        # Merge custom rules with defaults (custom rules first, then defaults)
        all_rules = custom_rules + defaults
        return all_rules

def load_config(config_path: Optional[str] = None) -> GatewayConfig:
    """
    Loads configuration from specified file path or searches default locations:
    1. config_path (if provided)
    2. .jev-policy.yaml / .jev-policy.json in cwd
    3. ~/.gemini/antigravity-cli/jev-policy.yaml
    4. Defaults
    """
    candidates = []
    if config_path:
        candidates.append(Path(config_path))
    candidates.append(Path(".jev-policy.yaml"))
    candidates.append(Path(".jev-policy.yml"))
    candidates.append(Path(".jev-policy.json"))
    candidates.append(Path("~/.gemini/antigravity-cli/jev-policy.yaml").expanduser())

    for path in candidates:
        if path.is_file():
            try:
                content = path.read_text(encoding="utf-8")
                if path.suffix in (".yaml", ".yml"):
                    data = yaml.safe_load(content) or {}
                else:
                    data = json.loads(content) or {}
                return GatewayConfig.model_validate(data)
            except Exception as e:
                # Log or warn, but don't fail insecurely
                pass

    return GatewayConfig()
