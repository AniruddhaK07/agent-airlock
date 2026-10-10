import json
import re

with open("private/host-allow-rules.txt", "r", encoding="utf-8") as f:
    text = "{" + f.read().strip() + "}"
data = json.loads(text)
rules = data.get("allow", [])

# Look at short rules without arguments vs regex rules
bare_commands = []
regex_like = []
exact_like = []

for r in rules:
    m = re.match(r"^command\((.*)\)$", r)
    if not m:
        continue
    cmd_pattern = m.group(1)
    if re.search(r"\\\(|\\\)|\\\[|\\\]|\\\.", cmd_pattern):
        regex_like.append(cmd_pattern)
    elif " " not in cmd_pattern:
        bare_commands.append(cmd_pattern)
    else:
        exact_like.append(cmd_pattern)

print(f"Total command rules: {len(rules)}")
print(f"Bare command rules (e.g. 'Get-Content', 'git status', etc.): {len(bare_commands)}")
print(f"Bare commands sample: {bare_commands[:30]}")
print(f"Regex-like rules: {len(regex_like)}")
print(f"Exact/other rules: {len(exact_like)}")
