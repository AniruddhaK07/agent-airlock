import re

pattern = re.compile(
    r'(?:'
    r'([a-zA-Z0-9_.:]+)\s*\(\s*\)\s*\{\s*\1\s*\|\s*\1\s*&\s*\}\s*;\s*\1|'
    r':\(\)\s*\{.*?\}\s*;\s*:|'
    r'while\s*\(\s*\$true\s*\)\s*\{\s*.*?(?:Start-Process|powershell|pwsh).*?\}|'
    r'while\s+(?:true|:\s*;?)\s*;?\s*do\s+.*?(?:ba|z|da|k)?sh.*?&?\s*done|'
    r'(\w+)\s*\(\s*\)\s*\{.*?\b\1\b\s*\|\s*\b\1\b.*?\}'
    r')',
    re.IGNORECASE
)

test_cases = [
    (':(){ :|:& };:', True),
    (':(){ :|:&};:', True),
    (':() { :|:& }; :', True),
    (':(){:|:&};:', True),
    ('bomb(){ bomb|bomb& };bomb', True),
    ('f(){ f|f& };f', True),
    ('f() { f | f & }; f', True),
    ('.(){ .|.& };.', True),
    ('while ($true) { Start-Process powershell }', True),
    ('while true; do bash -c x & done', True),
    ('git status', False),
    ('npm run build', False),
    ('python scripts/test.py', False),
]

all_passed = True
for tc, expected in test_cases:
    matched = bool(pattern.search(tc))
    ok = (matched == expected)
    if not ok:
        all_passed = False
    print(f"[{'PASS' if ok else 'FAIL'}] '{tc}' -> matched={matched} (expected={expected})")

if all_passed:
    print("\nAll fork bomb regex test cases passed!")
else:
    print("\nSome test cases failed.")
