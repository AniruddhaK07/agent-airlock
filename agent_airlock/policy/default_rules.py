"""
Default built-in rules for the Hard Policy Engine.
"""

from typing import List
import re
from agent_airlock.policy.models import PolicyRule, PolicyVerdict

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
                r'\brm\s++'
                r'(?:'
                r'-(?:[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*)\b|'
                r'--recursive\s+--force\b|--force\s+--recursive\b|'
                r'-[a-zA-Z]*r[a-zA-Z]*\b\s+-[a-zA-Z]*f[a-zA-Z]*\b|-[a-zA-Z]*f[a-zA-Z]*\b\s+-[a-zA-Z]*r[a-zA-Z]*\b|'
                r'-[a-zA-Z]*r[a-zA-Z]*\b\s+--force\b|--force\b\s+-[a-zA-Z]*r[a-zA-Z]*\b|'
                r'-[a-zA-Z]*f[a-zA-Z]*\b\s+--recursive\b|--recursive\b\s+-[a-zA-Z]*f[a-zA-Z]*\b'
                r')'
                r'(?>\s+-[a-zA-Z0-9_\-]+)*\s+'
                r'(?:/(?:[\s*;&|"`\')]|$|etc|var|usr|bin|sbin|root|boot|home|opt|dev|sys|proc)|~|\$HOME|\.\./)'
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
                r'\b(?:remove-item|ri|rm)\b[^\n\r;]{0,256}?(?:'
                r'(?:-[rR]ecurse\s+-[fF]orce|-[fF]orce\s+-[rR]ecurse)[^\n\r;]{0,256}?(?:'
                r'[a-z]:\\?(?:["\'\s;&|]|$)|'
                r'[a-z]:\\(?:Windows|System32|Program Files|ProgramData|Users\\?(?:["\'\s;&|]|$))|'
                r'[a-z]:\\[^\\/\r\n;"\'&|]+(?:["\'\s;&|]|$)|'
                r'\.gemini|'
                r'\$safeBase\b'
                r')|'
                r'(?:'
                r'[a-z]:\\?(?:["\'\s;&|]|$)|'
                r'[a-z]:\\(?:Windows|System32|Program Files|ProgramData|Users\\?(?:["\'\s;&|]|$))|'
                r'[a-z]:\\[^\\/\r\n;"\'&|]+(?:["\'\s;&|]|$)|'
                r'\.gemini'
                r')[^\n\r;]{0,256}?(?:-[rR]ecurse\s+-[fF]orce|-[fF]orce\s+-[rR]ecurse)'
                r')|'
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
                r'\b(?:curl|wget|fetch)\b[^|\r\n]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|'
                r'\becho\s+[^|\r\n]*\|\s*base64\s+-d\s*\|\s*(?:ba|z)?sh\b'
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
                r'\b(?:invoke-webrequest|iwr|invoke-restmethod|irm)\b[^|\r\n]*\|\s*(?:invoke-expression|iex)\b'
            ),
        ),

        # 6. Credential exposure specifically within run_command CommandLine arguments
        PolicyRule(
            id="deny-credentials-in-command",
            description="Commands targeting private keys, credential stores, or environment secret files",
            verdict=PolicyVerdict.DENY,
            tools=["run_command"],
            field="CommandLine",
            pattern=(
                r'(?:'
                r'(?:^|[/\\]|\b|\.ssh[/\\])(?:id_rsa|id_ed25519|id_ecdsa|id_dsa)(?:\.pub)?\b|'
                r'\.aws[/\\](?:credentials|config)|'
                r'\.kube(?:[/\\]|$)|'
                r'\.npmrc|\.pypirc|\.netrc|\.pgpass|\.git-credentials|'
                r'\.docker[/\\]config\.json|'
                r'\.gemini[/\\](?:oauth|auth|.*token.*)|'
                r'(?:Google[/\\]+Chrome|Microsoft[/\\]+Edge|Mozilla[/\\]+Firefox|Brave-Browser)[/\\]+User Data|'
                r'(?:AppData(?![/\\]*(?:Local[/\\]+Temp\b))(?:$|[/\\]+)|%APPDATA%|%LOCALAPPDATA%)|'
                r'/etc/shadow|/etc/passwd|'
                r'\.env(?:\.[a-zA-Z0-9_-]+)?(?:\s+|$|["\';])'
                r')'
            ),
        ),

        # 6b. Credential and Secret Exposure (Cross-tool: view_file, write_to_file, replace_file_content, run_command)
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
                r'(?:^|[/\\])\.kube(?:[/\\]|$)|'
                r'(?:^|[/\\])(?:\.npmrc|\.pypirc|\.netrc|_netrc|\.pgpass|\.git-credentials)$|'
                r'(?:^|[/\\])\.docker[/\\]config\.json$|'
                r'(?:^|[/\\])\.gemini[/\\](?:oauth|auth|.*token.*)|'
                r'(?:^|[/\\])(?:Google[/\\]Chrome|Microsoft[/\\]Edge|Mozilla[/\\]Firefox|Brave-Browser)[/\\]User Data|'
                r'(?:^|[/\\])(?:AppData(?![/\\]*(?:Local[/\\]+Temp\b))(?:$|[/\\]+)|%APPDATA%|%LOCALAPPDATA%)|'
                r'/etc/(?:shadow|passwd|master\.passwd)'
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
                r'\bnc(?:\.traditional|\.openbsd)?\s+[^\r\n;|&]*-e\s+(?:/bin/)?(?:ba|z)?sh|'
                r'(?:>&|&>|>|<)\s*/dev/(?:tcp|udp)/\S+|'
                r'\bsocat\s+[^\r\n;|&]*exec:|'
                r'\bpython[23]?\s+-c\s+[^\r\n]*?(?:pty\.spawn|socket\..*?connect)'
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
                r'(?:'
                r':\(\)\s*\{[^}]*+\}\s*;\s*:|'
                r'(?:^|(?<=[;&|\s]))([a-zA-Z0-9_.:]{1,32}+)\s*\(\s*\)\s*\{\s*\1\s*\|\s*\1\s*&\s*\}\s*;\s*\1|'
                r'while\s*\(\s*\$true\s*\)\s*\{[^}]*?(?:Start-Process|powershell|pwsh)[^}]*?\}|'
                r'while\s+(?:true|:\s*;?)\s*;?\s*do\s+.*?(?:ba|z|da|k)?sh.*?&?\s*done'
                r')'
            ),
        ),

        # =====================================================================
        # HARD ALLOW RULES (Safe, read-only, non-chained)
        # =====================================================================

        # 1. Read-only Git Inspection
        PolicyRule(
            id="allow-git-status-diff-log",
            description="Read-only git queries with zero side effects, guarded against --output redirection, --no-index, and sensitive URLs",
            verdict=PolicyVerdict.ALLOW,
            tools=["run_command"],
            field="CommandLine",
            pattern=(
                r'^git'
                r'(?:\s+(?:--no-pager|(?-i:-C)\s+[^\s;&|`$(){}<>]+))*\s+'
                r'(?:'
                r'status(?:\s+(?:-[sb]+|--short|--porcelain(?:=[a-zA-Z0-9]+)?|--branch|[a-zA-Z0-9_\-\./\\]+))*|'
                r'(?:diff|log|show)(?:\s+(?!--no-index\b|-(?:o(?!neline\b)\S*|-ou\S*))[^\s;&|`$(){}<>]+)*|'
                r'rev-parse(?:\s+[^\s;&|`$(){}<>]+)*|'
                r'describe(?:\s+[^\s;&|`$(){}<>]+)*|'
                r'tag(?:\s+-l)?|'
                r'branch(?:\s+-[ravl]+(?:\s+[^\s;&|`$(){}<>]+)?)?'
                r')$'
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

        # 4. Safe Read-only PowerShell Cmdlets (Rule Family B & D)
        PolicyRule(
            id="allow-powershell-readonly",
            description="Safe read-only PowerShell cmdlets with zero side effects",
            verdict=PolicyVerdict.ALLOW,
            tools=["run_command"],
            field="CommandLine",
            pattern=(
                r'^(?:Get-ChildItem|Select-String|Get-Content|Get-Command)'
                r'(?![^|\r\n]*?(?:-(?:wait)\b|Env:|HKLM:|HKCU:|\\\\|https?://|ftp://|\.\.[/\\]))'
                r'(?:\s+(?:\'[^\'\r\n]*\'|"[^"$`\r\n]*"|[^\s|$(){}\@;&><`\r\n]+))*'
                r'(?:\s*\|\s*(?:Select-String|Select-Object|Sort-Object|Measure-Object|Out-String|Format-Table|Format-List|Format-Wide|Format-Custom|Where-Object|\?|where)'
                r'(?![^|\r\n]*?(?:-(?:wait)\b|Env:|HKLM:|HKCU:|\\\\|https?://|ftp://|\.\.[/\\]))'
                r'[^|;&><\`\r\n]*)*$'
            ),
        ),

        # 5. Safe Workspace File Modifications (Rule Family C)
        PolicyRule(
            id="allow-workspace-file-modification",
            description="Safe file write or replacement strictly contained within workspace root",
            verdict=PolicyVerdict.ALLOW,
            tools=["write_to_file", "replace_file_content"],
            field="TargetFile",
            pattern=r'.*',  # Evaluated with realpath containment and trust-root exclusion ledger in HardPolicyEngine
        ),

        # =====================================================================
        # HARD ALLOW RULES: FAMILY D (Policy Change Protocol, I8)
        # =====================================================================

        # 6. Read-only Git Grep (Family D)
        PolicyRule(
            id="allow-git-grep",
            description="Safe read-only git grep searches within workspace repository",
            verdict=PolicyVerdict.ALLOW,
            tools=["run_command"],
            field="CommandLine",
            pattern=(
                r'^git(?:\s+--no-pager)*\s+'
                r'grep'
                r'(?:\s+-(?:[inEIwFvhqpzcwLl]|-[a-zA-Z0-9_\-]+|[ABC]\s*\d+))*'
                r'(?:\s+(?!--no-index\b|-O\b|--open-files-in-pager\b)(?:\'[^\'\r\n]*\'|"[^"$`\r\n]*"|[^\s;&|`$(){}<>]+))*$'
            ),
        ),

        # 7. Safe Windows Binary Lookup (Family D)
        PolicyRule(
            id="allow-where-binary-lookup",
            description="Safe Windows binary location lookup using where or where.exe",
            verdict=PolicyVerdict.ALLOW,
            tools=["run_command"],
            field="CommandLine",
            pattern=(
                r'^(?:where|where\.exe)'
                r'(?:\s+(?!/[rR]\b)[a-zA-Z0-9_\-\.]+)+$'
            ),
        ),

        # 8. Safe Windows Directory Listing (Family D)
        PolicyRule(
            id="allow-dir-windows",
            description="Safe Windows directory listing with non-destructive switches",
            verdict=PolicyVerdict.ALLOW,
            tools=["run_command"],
            field="CommandLine",
            pattern=(
                r'^dir'
                r'(?:\s+/[a-zA-Z0-9\-]+)*'
                r'(?:\s+[a-zA-Z0-9_\-\./\\]+)*$'
            ),
        ),

        # 9. Safe Read-only Git Branch Listing (Family D)
        PolicyRule(
            id="allow-git-branch-list",
            description="Safe read-only git branch listing and current branch inspection",
            verdict=PolicyVerdict.ALLOW,
            tools=["run_command"],
            field="CommandLine",
            pattern=(
                r'^git'
                r'(?:\s+(?:--no-pager|(?-i:-C)\s+[^\s;&|`$(){}<>]+))*\s+'
                r'branch'
                r'(?:\s+(?:-[ravl]+|--show-current|--list(?:\s+[a-zA-Z0-9_\-\./*]+)?))*$'
            ),
        ),

        # 10. Safe Read-only Git Tag Listing (Family D)
        PolicyRule(
            id="allow-git-tag-list",
            description="Safe read-only git tag listing",
            verdict=PolicyVerdict.ALLOW,
            tools=["run_command"],
            field="CommandLine",
            pattern=(
                r'^git'
                r'(?:\s+(?:--no-pager|(?-i:-C)\s+[^\s;&|`$(){}<>]+))*\s+'
                r'tag'
                r'(?:\s+(?:-l|--list)(?:\s+["\']?[a-zA-Z0-9_\-\./*]+["\']?)?)?$'
            ),
        ),

        # 11. Safe Git Add Workspace Paths (Family D - Conditional)
        PolicyRule(
            id="allow-git-add-workspace",
            description="Safe git staging strictly contained within workspace, excluding dotfiles and secrets",
            verdict=PolicyVerdict.ALLOW,
            tools=["run_command"],
            field="CommandLine",
            pattern=(
                r'^git'
                r'(?:\s+(?:--no-pager|(?-i:-C)\s+[^\s;&|`$(){}<>]+))*\s+'
                r'add'
                r'(?:\s+-(?:v|n|-(?:verbose|dry-run)))*'
                r'(?:\s+(?!--patch\b|-p\b|--interactive\b|-i\b|-f\b|--force\b|-A\b|--all\b|-u\b|--update\b|\.(?:\s|$)|[^\s;&|`$(){}<>]*[*?\[\]]|:\()[^\s;&|`$(){}<>]+)+$'
            ),
        ),

        # 12. Safe Local Git Tag Creation (Family D - Conditional)
        PolicyRule(
            id="allow-git-tag-local",
            description="Safe local git tag creation without remote push",
            verdict=PolicyVerdict.ALLOW,
            tools=["run_command"],
            field="CommandLine",
            pattern=(
                r'^git'
                r'(?:\s+(?:--no-pager|(?-i:-C)\s+[^\s;&|`$(){}<>]+))*\s+'
                r'tag'
                r'(?:\s+(?!--sign\b|-s\b|-u\b|--local-user\b)(?:-a|--annotate))?'
                r'(?:\s+[a-zA-Z0-9_\-\.]+)?'
                r'(?:\s+-m\s+(?:(?:"[^"\r\n]*"|\'[^\'\r\n]*\')|[a-zA-Z0-9_\-\.]+(?:\s+[a-zA-Z0-9_\-\.]+)*))?'
                r'(?:\s+[a-zA-Z0-9_\-\.]+)?$'
            ),
        ),

        # =====================================================================
        # HARD ALLOW RULES: APPROVED GAP EXTENSIONS (Rules 1, 2, 3, 5, 7)
        # =====================================================================

        # 13. Safe PowerShell Test-Path (Rule 1)
        PolicyRule(
            id="allow-powershell-test-path",
            description="Safe PowerShell Test-Path query on workspace or standard installation prefixes",
            verdict=PolicyVerdict.ALLOW,
            tools=["run_command"],
            field="CommandLine",
            pattern=(
                r'^Test-Path\s+'
                r'(?:-(?:Path|LiteralPath)\s+)?'
                r'(?:'
                r'"[^"\r\n*?<>|]+"'
                r"|'[^'\r\n*?<>|]+'"
                r'|[^\s;&|`$(){}<>*?]+'
                r')'
                r'(?:\s+-(?:PathType\s+(?:Leaf|Container|Any)|ErrorAction\s+[a-zA-Z]+|EA\s+[a-zA-Z]+))*$'
            ),
        ),

        # 14. Safe PowerShell Copy-Item in Workspace (Rule 2)
        PolicyRule(
            id="allow-powershell-copy-item",
            description="Safe PowerShell Copy-Item strictly within workspace without -Force or -Recurse",
            verdict=PolicyVerdict.ALLOW,
            tools=["run_command"],
            field="CommandLine",
            pattern=(
                r'^(?:Copy-Item|cpi)\s+'
                r'(?:'
                r'(?!-(?:[fF](?:orce)?|[rR](?:ecurse)?|[cC]onfirm:\$false)\b)'
                r'(?:-(?:Path|Destination|LiteralPath|PassThru)\b|-[a-zA-Z0-9_\-]+|"[^"\r\n*?<>|]+"|\'[^\'\r\n*?<>|]+\'|[^\s;&|`$(){}<>*?]+)'
                r'(?:\s+|$)'
                r')+$'
            ),
        ),

        # 15. Safe PowerShell Get-Process Inspection (Rule 3)
        PolicyRule(
            id="allow-powershell-get-process",
            description="Safe PowerShell Get-Process query piped to safe formatting/selection sinks or property access",
            verdict=PolicyVerdict.ALLOW,
            tools=["run_command"],
            field="CommandLine",
            pattern=(
                r'^(?:\(?\s*Get-Process\b'
                r'(?![^|\r\n]*?(?:-(?:wait)\b))'
                r'[^|$(){}\@;&><\`\r\n]*'
                r'(?:\)\.[a-zA-Z0-9_\-]+)?'
                r')'
                r'(?:\s*\|\s*(?:Select-String|Select-Object|Sort-Object|Measure-Object|Out-String|Format-Table|Format-List|Format-Wide|Format-Custom|Where-Object|\?|where)'
                r'(?![^|\r\n]*?(?:-(?:wait)\b))'
                r'[^|;&><\`\r\n]*)*$'
            ),
        ),

        # 16. Safe Tool Help Queries (Rule 5)
        PolicyRule(
            id="allow-tool-help",
            description="Safe informational help queries for bare commands on system PATH",
            verdict=PolicyVerdict.ALLOW,
            tools=["run_command"],
            field="CommandLine",
            pattern=(
                r'^(?:'
                r'([a-zA-Z0-9_\-]+)\s+(--help|-h|help)'
                r'|'
                r'help\s+([a-zA-Z0-9_\-]+)'
                r')'
                r'(?:\s+2>&1)?$'
            ),
        ),

        # 17. Safe Local Git Commit (Rule 7)
        PolicyRule(
            id="allow-git-commit",
            description="Safe local git commit strictly without hooks, amending, or signing flags",
            verdict=PolicyVerdict.ALLOW,
            tools=["run_command"],
            field="CommandLine",
            pattern=(
                r'^git'
                r'(?:\s+(?:--no-pager|(?-i:-C)\s+[^\s;&|`$(){}<>]+))*\s+'
                r'commit'
                r'(?:\s+-(?:q|-(?:quiet)))?'
                r'\s+-m\s+(?:(?:"[^"\r\n]*"|\'[^\'\r\n]*\')|[a-zA-Z0-9_\-\.]+(?:\s+[a-zA-Z0-9_\-\.]+)*)'
                r'(?:\s+-(?:q|-(?:quiet)))?$'
            ),
        ),

        # 18. Safe PowerShell Write-Output (Pure string literals)
        PolicyRule(
            id="allow-powershell-write-output",
            description="Safe PowerShell Write-Output of pure string literals without redirection, pipes, or expansions",
            verdict=PolicyVerdict.ALLOW,
            tools=["run_command"],
            field="CommandLine",
            pattern=(
                r'^Write-Output\s+'
                r'(?:'
                r'"[^"$`\r\n]*"'
                r"|'[^'\r\n]*'"
                r'|[a-zA-Z0-9_\-\.]+'
                r')'
                r'(?:\s+'
                r'(?:'
                r'"[^"$`\r\n]*"'
                r"|'[^'\r\n]*'"
                r'|[a-zA-Z0-9_\-\.]+'
                r'))*$'
            ),
        ),

        # 19. Safe PowerShell New-Item Directory in Workspace
        PolicyRule(
            id="allow-powershell-new-item-dir",
            description="Safe PowerShell New-Item directory creation strictly contained in workspace",
            verdict=PolicyVerdict.ALLOW,
            tools=["run_command"],
            field="CommandLine",
            pattern=(
                r'^New-Item\s+'
                r'(?=.*-(?:ItemType|Type)\s+Directory\b)'
                r'(?!.*-(?:Target|Value|Force)\b)'
                r'(?:'
                r'-(?:ItemType|Type)\s+Directory\b'
                r'|-(?:Path|Name)\s+(?:"[^"$`\r\n*?<>|]+"|\'[^\'\r\n*?<>|]+\'|[^\s;&|`$(){}<>*?]+)'
                r'|"[^"$`\r\n*?<>|]+"'
                r"|'[^'\r\n*?<>|]+'"
                r'|[^\s;&|`$(){}<>*?]+'
                r')'
                r'(?:\s+'
                r'(?:'
                r'-(?:ItemType|Type)\s+Directory\b'
                r'|-(?:Path|Name)\s+(?:"[^"$`\r\n*?<>|]+"|\'[^\'\r\n*?<>|]+\'|[^\s;&|`$(){}<>*?]+)'
                r'|"[^"$`\r\n*?<>|]+"'
                r"|'[^'\r\n*?<>|]+'"
                r'|[^\s;&|`$(){}<>*?]+'
                r'))*$'
            ),
        ),

        # 20. Safe Python Pip Inspection
        PolicyRule(
            id="allow-python-pip-inspect",
            description="Safe read-only python -m pip show/list/--version queries",
            verdict=PolicyVerdict.ALLOW,
            tools=["run_command"],
            field="CommandLine",
            pattern=(
                r'^(?:python|python3|py)\s+-m\s+pip\s+'
                r'(?:'
                r'show(?:\s+(?:-[a-zA-Z0-9_\-]+(?:=[a-zA-Z0-9_\-]+)?|[a-zA-Z0-9_\-\.]+))+'
                r'|list(?:\s+-[a-zA-Z0-9_\-]+(?:=[a-zA-Z0-9_\-]+)?)*'
                r'|--version|-V'
                r')$'
            ),
        ),
    ]
