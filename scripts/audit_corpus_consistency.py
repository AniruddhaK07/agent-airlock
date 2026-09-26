"""
Audit tool to evaluate internal label consistency across data/train.json and data/val.json.
Groups commands by semantic action class and checks for variance in:
  - blast_level (0-4)
  - reversible (0.0 or 1.0)
  - route (deterministic-safe, needs-human, needs-reasoning-model)
"""

import json
import re
from collections import defaultdict

def load_data():
    with open("data/train.json", "r", encoding="utf-8") as f:
        train = json.load(f)
    with open("data/val.json", "r", encoding="utf-8") as f:
        val = json.load(f)
    return train, val

def classify_command(cmd: str):
    """Assigns an action class to a command for consistency clustering."""
    c = cmd.strip()

    # Process Management
    if re.search(r'\bkill\s+(-[0-9A-Z]+\s+)?\d+\b', c):
        return "process:single_pid_kill"
    if re.search(r'\b(pkill|killall)\b', c):
        return "process:broad_kill"
    if re.search(r'\b(systemctl|service)\s+(stop|restart|reload)\b', c):
        return "process:service_control"
    if re.search(r'\bdocker\s+(stop|kill|rm|prune)\b', c):
        return "container:management"

    # Filesystem Deletes
    if re.search(r'\brm\s+-(?:[a-zA-Z]*r[a-zA-Z]*f|[a-zA-Z]*f[a-zA-Z]*r)\s+(/|/etc|/var|~|\$HOME)', c):
        return "fs:catastrophic_delete"
    if re.search(r'\brm\s+-(?:[a-zA-Z]*r[a-zA-Z]*f|[a-zA-Z]*f[a-zA-Z]*r)\s+(\./|\bnode_modules\b|\bdist\b|\bbuild\b|/tmp/)', c):
        return "fs:scoped_recursive_delete"
    if re.search(r'\brm\s+(?!-.*r)[^\n]+$', c) or re.search(r'\brm\s+-[fiv]+\s+[^\n/]+$', c):
        return "fs:single_file_delete"

    # Permissions
    if re.search(r'\bchmod\s+-R\s+777\s+(/|/etc|/var|/usr)', c):
        return "permission:broad_system_chmod"
    if re.search(r'\bchmod\s+(\+x|[0-7]{3,4})\s+[^\n/]+$', c):
        return "permission:scoped_local_chmod"

    # Git
    if re.search(r'\bgit\s+(status|log|diff|branch|show|remote)\b', c):
        return "git:read_only"
    if re.search(r'\bgit\s+push\s+.*--force\b', c):
        return "git:force_push"
    if re.search(r'\bgit\s+(reset\s+--hard|clean\s+-fdx)\b', c):
        return "git:destructive_local_reset"
    if re.search(r'\bgit\s+(add|commit|checkout|switch|merge|rebase)\b', c):
        return "git:standard_mutation"

    # Package Managers
    if re.search(r'\b(npm|pip|pnpm|yarn|cargo)\s+install\s+.*(?:untrusted|random|malicious)', c):
        return "package:untrusted_install"
    if re.search(r'\b(npm|pip|pnpm|yarn|cargo)\s+install\b', c):
        return "package:standard_install"

    # Network / Remote Execution
    if re.search(r'\b(curl|wget)\b.*\|\s*(?:ba|z)?sh\b', c):
        return "network:pipe_to_shell"
    if re.search(r'\b(curl|wget)\b\s+-(?:s|I|v)\s+https?://', c):
        return "network:read_only_fetch"

    # Secrets
    if re.search(r'(\.env|SECRET|KEY|PASSWORD|TOKEN|id_rsa)', c):
        return "secrets:access_or_echo"

    # Infrastructure / Cloud
    if re.search(r'\bterraform\s+apply\b', c):
        return "infra:terraform_apply"
    if re.search(r'\bterraform\s+(plan|validate|fmt)\b', c):
        return "infra:terraform_read"

    return "other:unclassified"

def audit():
    train, val = load_data()
    print("=" * 80)
    print("INTERNAL LABEL CONSISTENCY AUDIT (data/train.json + data/val.json)")
    print("=" * 80)

    all_data = [("train", d) for d in train] + [("val", d) for d in val]

    clusters = defaultdict(list)
    for split, ex in all_data:
        cls_key = classify_command(ex["command"])
        clusters[cls_key].append((split, ex))

    inconsistencies = []

    for cls_key, items in sorted(clusters.items()):
        routes = set(it[1]["route"] for it in items)
        blast_levels = set(it[1]["blast_level"] for it in items)
        reversibles = set(it[1]["reversible"] for it in items)

        is_inconsistent = len(routes) > 1 or (max(blast_levels) - min(blast_levels) > 1) or len(reversibles) > 1

        print(f"CLASS: {cls_key} (N={len(items)})")
        print(f"  Routes present:     {list(routes)}")
        print(f"  Blast levels:       {sorted(list(blast_levels))}")
        print(f"  Reversibles:        {sorted(list(reversibles))}")

    print("=" * 80)
    print("DETAILED INCONSISTENCY REPORT (CLASSES WITH LABEL VARIANCE)")
    print("=" * 80)

    for cls_key, items in sorted(clusters.items()):
        if cls_key == "other:unclassified":
            continue
        routes = set(it[1]["route"] for it in items)
        blast_levels = set(it[1]["blast_level"] for it in items)
        reversibles = set(it[1]["reversible"] for it in items)

        # Check if route differs or blast differs by > 1
        route_variance = len(routes) > 1
        blast_variance = (max(blast_levels) - min(blast_levels)) > 1

        if route_variance or blast_variance:
            print(f"\n[CLASS: {cls_key}] (N={len(items)})")
            print(f"  Routes: {list(routes)} | Blast: {sorted(list(blast_levels))} | Rev: {sorted(list(reversibles))}")
            for split, it in items:
                print(f"    - [{split}] '{it['command']}' => route={it['route']}, blast={it['blast_level']}, rev={it['reversible']}")


if __name__ == "__main__":
    audit()
