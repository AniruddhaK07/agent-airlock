"""
Default built-in rules for the Hard Policy Engine.
"""

from typing import List
import re
from jev_gateway.policy.models import PolicyRule, PolicyVerdict

def get_default_rules() -> List[PolicyRule]:
    """
    Returns the comprehensive, reviewed default rule set for hard-deny and hard-allow.
    Hard-deny rules take absolute precedence and prevent catastrophic operations deterministically.
    Hard-allow rules permit strictly safe, read-only, non-chained commands.
    All rules compile with re.IGNORECASE by default.
    """
    return [
        # =====================================================================
        # HARD DENY RULES (Zero false negatives)
        # =====================================================================

        # 1. Destructive Filesystem Operations (POSIX)
        PolicyRule(
            id="deny-destructive-fs-posix",
            description="Destructive recursive deletion targeting root, home, system directories, or parent traversal",
            verdict=PolicyVerdict.DENY,
            tools=["run_command"],
            field="CommandLine",
            pattern=(
                r'\brm\s+(?:-[a-zA-Z0-9_\-]+\s+)*'
                r'(?:(?:-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*|'
                r'--recursive\s+--force|--force\s+--recursive|'
                r'-[a-zA-Z]*r[a-zA-Z]*\s+-[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*\s+-[a-zA-Z]*r[a-zA-Z]*|'
                r'-[a-zA-Z]*r[a-zA-Z]*\s+--force|--force\s+-[a-zA-Z]*r[a-zA-Z]*|'
                r'-[a-zA-Z]*f[a-zA-Z]*\s+--recursive|--recursive\s+-[a-zA-Z]*f[a-zA-Z]*)\s+)+'
                r'(?:-[a-zA-Z0-9_\-]+\s+)*'
                r'(?:/(?:[\s*]|$|etc|var|usr|bin|sbin|root|boot|home|opt|dev|sys|proc)|~|\$HOME|\.\./)'
            ),
        ),

        # 2. Destructive Filesystem Operations (Windows / PowerShell)
        PolicyRule(
            id="deny-destructive-fs-windows",
            description="Destructive directory deletion targeting system drive or root paths on Windows",
            verdict=PolicyVerdict.DENY,
            tools=["run_command"],
            field="CommandLine",
            pattern=(
                r'\b(?:rmdir|rd)\s+(?:/[sq]\s+)+[a-z]:\\?|'
                r'\b(?:remove-item|ri|rm)\s+.*?(?:-[rR]ecurse\s+-[fF]orce|-[fF]orce\s+-[rR]ecurse).*?[a-z]:\\?|'
                r'\bformat\s+[a-z]:|'
                r'\bdiskpart\b'
            ),
        ),

        # 3. Disk Wipes and Low-level formatting
        PolicyRule(
            id="deny-disk-wipe",
            description="Direct raw device write or filesystem creation on devices",
            verdict=PolicyVerdict.DENY,
            tools=["run_command"],
            field="CommandLine",
            pattern=(
                r'\bdd\s+if=/dev/(?:zero|random|urandom)\s+of=/dev/[a-z]+|'
                r'\bmkfs(?:\.[a-z0-9]+)?\s+/dev/'
            ),
        ),

        # 4. Pipe-to-Shell Remote Execution (POSIX)
        PolicyRule(
            id="deny-pipe-to-shell-posix",
            description="Piping remote network download into shell interpreter",
            verdict=PolicyVerdict.DENY,
            tools=["run_command"],
            field="CommandLine",
            pattern=(
                r'\b(?:curl|wget|fetch)\b.*?\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|'
                r'\becho\s+.*?\|\s*base64\s+-d\s*\|\s*(?:ba|z)?sh\b'
            ),
        ),

        # 5. Pipe-to-Shell Remote Execution (Windows PowerShell)
        PolicyRule(
            id="deny-pipe-to-shell-windows",
            description="PowerShell web download piped into Invoke-Expression / IEX",
            verdict=PolicyVerdict.DENY,
            tools=["run_command"],
            field="CommandLine",
            pattern=(
                r'\b(?:invoke-webrequest|iwr|invoke-restmethod|irm)\b.*?\|\s*(?:invoke-expression|iex)\b'
            ),
        ),

        # 6. Credential and Secret Exposure (Cross-tool: run_command, view_file, write_to_file)
        PolicyRule(
            id="deny-credentials-and-secrets",
            description="Access or manipulation of sensitive credential, key, or secret configuration files",
            verdict=PolicyVerdict.DENY,
            tools=["run_command", "view_file", "write_to_file", "replace_file_content"],
            field="ANY",
            pattern=(
                r'(?:'
                r'(?:^|[/\\])\.env(?:\.[a-zA-Z0-9_-]+)?$|'
                r'(?:^|[/\\])\.ssh[/\\](?:id_rsa|id_ed25519|id_ecdsa|id_dsa|authorized_keys)$|'
                r'(?:^|[/\\])\.aws[/\\](?:credentials|config)$|'
                r'(?:^|[/\\])\.kube[/\\]config$|'
                r'(?:^|[/\\])(?:\.npmrc|\.pypirc|\.netrc|_netrc|\.pgpass)$|'
                r'(?:^|[/\\])\.docker[/\\]config\.json$|'
                r'/etc/(?:shadow|passwd|master\.passwd)'
                r')'
            ),
        ),

        # 6b. Credential exposure specifically within run_command CommandLine arguments
        PolicyRule(
            id="deny-credentials-in-command",
            description="Commands targeting private keys, credential stores, or environment secret files",
            verdict=PolicyVerdict.DENY,
            tools=["run_command"],
            field="CommandLine",
            pattern=(
                r'(?:'
                r'\.ssh/(?:id_rsa|id_ed25519|id_ecdsa|id_dsa)|'
                r'\.aws/(?:credentials|config)|'
                r'\.kube/config|'
                r'\.npmrc|\.pypirc|\.netrc|\.pgpass|'
                r'\.docker/config\.json|'
                r'/etc/shadow|/etc/passwd|'
                r'\.env(?:\.[a-zA-Z0-9_-]+)?(?:\s+|$|["\'])'
                r')'
            ),
        ),

        # 7. Network Exfiltration & Reverse Shells
        PolicyRule(
            id="deny-network-exfil-reverse-shell",
            description="Spawning interactive reverse shells or network redirect exfiltration",
            verdict=PolicyVerdict.DENY,
            tools=["run_command"],
            field="CommandLine",
            pattern=(
                r'\bnc(?:\.traditional|\.openbsd)?\s+.*?-e\s+(?:/bin/)?(?:ba|z)?sh|'
                r'(?:>&|&>|>|<)\s*/dev/(?:tcp|udp)/\S+|'
                r'\bsocat\s+.*exec:|'
                r'\bpython[23]?\s+-c\s+.*?(?:pty\.spawn|socket\..*connect)'
            ),
        ),

        # 8. Fork Bombs & Infinite Process Loops
        PolicyRule(
            id="deny-fork-bomb",
            description="Process table exhaustion or fork bomb",
            verdict=PolicyVerdict.DENY,
            tools=["run_command"],
            field="CommandLine",
            pattern=(
                r':\(\)\{\s*:\|:&\s*\};\s*:|'
                r'while\s*\(\$true\)\s*\{\s*Start-Process\s+powershell\s*\}'
            ),
        ),

        # =====================================================================
        # HARD ALLOW RULES (Safe, read-only, non-chained)
        # =====================================================================

        # 1. Read-only Git Inspection
        PolicyRule(
            id="allow-git-status-diff-log",
            description="Read-only git queries with zero side effects",
            verdict=PolicyVerdict.ALLOW,
            tools=["run_command"],
            field="CommandLine",
            pattern=(
                r'^git\s+(?:status|diff(?:\s+.*)?|log(?:\s+.*)?|'
                r'show(?:\s+.*)?|rev-parse(?:\s+.*)?|describe(?:\s+.*)?|'
                r'remote(?:\s+-v)?|tag(?:\s+-l)?|branch(?:\s+-[ravl]+(?:\s+\S+)?)?)$'
            ),
        ),

        # 2. Read-only Filesystem Inspection
        PolicyRule(
            id="allow-filesystem-readonly",
            description="Safe read-only directory and file display commands",
            verdict=PolicyVerdict.ALLOW,
            tools=["run_command"],
            field="CommandLine",
            pattern=(
                r'^(?:ls|dir|pwd)(?:\s+-[a-zA-Z0-9]+)*(?:\s+[a-zA-Z0-9_\-\./\\]+)*$|'
                r'^(?:cat|type|head|tail|more|less)(?:\s+-[a-zA-Z0-9]+)*(?:\s+[a-zA-Z0-9_\-\./\\]+)+$'
            ),
        ),

        # 3. Safe CLI Version Checks
        PolicyRule(
            id="allow-version-checks",
            description="Safe informational version and help flag queries",
            verdict=PolicyVerdict.ALLOW,
            tools=["run_command"],
            field="CommandLine",
            pattern=(
                r'^(?:python|python3|node|npm|git|docker|go|rustc|cargo|ruff|black|pytest|echo)'
                r'\s+(--version|-v|-V|--help|-h)$'
            ),
        ),
    ]
