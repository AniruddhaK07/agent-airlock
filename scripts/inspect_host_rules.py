import json
import re

with open("private/host-allow-rules.txt", "r", encoding="utf-8") as f:
    text = f.read().strip()

# Try parsing as JSON if wrapped in braces, or extract array
if not text.startswith("{"):
    text_wrapped = "{" + text + "}"
else:
    text_wrapped = text

try:
    data = json.loads(text_wrapped)
    rules = data.get("allow", [])
    print(f"Successfully parsed as JSON: {len(rules)} rules found.")
except Exception as e:
    print(f"JSON parse error: {e}")
    # Regex fallback
    rules = re.findall(r'"([^"]+)"', text)
    print(f"Regex extracted {len(rules)} items.")

rule_types = {}
for r in rules:
    m = re.match(r"^([a-zA-Z0-9_\-]+)(?:\((.*)\))?$", r)
    if m:
        t = m.group(1)
        rule_types[t] = rule_types.get(t, 0) + 1
    else:
        rule_types["other"] = rule_types.get("other", 0) + 1

print("Rule types count:", rule_types)
print("\nFirst 10 sample rules:")
for r in rules[:10]:
    print(" ", r[:100])
