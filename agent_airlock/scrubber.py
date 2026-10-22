"""
Data Scrubber for Agent Airlock v2.
Scrubs sensitive secrets, credentials, tokens, emails, usernames, and private paths
from audit logs, traces, and datasets before persistence or evaluation.
"""

import os
import re
from typing import Any, Dict, List, Optional, Set, Union


# Regex patterns for sensitive tokens and secrets
PATTERNS = [
    # Private keys
    (re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----"), "<SCRUBBED_PRIVATE_KEY>"),
    # AWS Access Key ID
    (re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "<SCRUBBED_AWS_KEY_ID>"),
    # GitHub Tokens
    (re.compile(r"\b(ghp_[0-9a-zA-Z]{36}|gho_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\b"), "<SCRUBBED_GITHUB_TOKEN>"),
    # OpenAI & generic sk- tokens
    (re.compile(r"\b(sk-[a-zA-Z0-9_-]{20,})\b"), "<SCRUBBED_API_KEY>"),
    # Hugging Face tokens
    (re.compile(r"\b(hf_[a-zA-Z0-9]{34,})\b"), "<SCRUBBED_HF_TOKEN>"),
    # Slack tokens
    (re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b"), "<SCRUBBED_SLACK_TOKEN>"),
    # JWT tokens
    (re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"), "<SCRUBBED_JWT>"),
    # Bearer tokens
    (re.compile(r"(?i)\bBearer\s+[a-zA-Z0-9_\-\.]{16,}\b"), "Bearer <SCRUBBED_TOKEN>"),
    # Generic password / secret assignments in commands / args (preserving key name, skipping already scrubbed tokens)
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|api_key|token)\s*([=:])\s*(?!<SCRUBBED)([\"']?[^\s\"',;]+[\"']?)"), r"\1\2<SCRUBBED_SECRET>"),
    # Email addresses
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "<SCRUBBED_EMAIL>"),
    # Private / local IP addresses (RFC 1918)
    (re.compile(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"), "<SCRUBBED_IP>"),
]

# Path patterns
WINDOWS_USER_PATH = re.compile(r"[C-Zc-z]:\\Users\\[^\\]+", re.IGNORECASE)
LINUX_USER_PATH = re.compile(r"/(?:home|Users)/[^/]+")


def scrub_text(text: str, extra_usernames: Optional[List[str]] = None) -> str:
    """
    Scrubs sensitive patterns from a single string.
    """
    if not text or not isinstance(text, str):
        return text

    result = text

    # 1. Apply regex token replacements
    for pattern, replacement in PATTERNS:
        result = pattern.sub(replacement, result)

    # 2. Scrub user paths
    result = WINDOWS_USER_PATH.sub(r"C:\\Users\\<USER>", result)
    result = LINUX_USER_PATH.sub(r"/home/<USER>", result)

    # 3. Scrub current OS username if detectable
    current_user = os.environ.get("USERNAME") or os.environ.get("USER")
    users_to_scrub = set()
    if current_user and len(current_user) > 2:
        users_to_scrub.add(current_user)
    if extra_usernames:
        for u in extra_usernames:
            if u and len(u) > 2:
                users_to_scrub.add(u)

    for u in users_to_scrub:
        # Case insensitive word match
        pattern = re.compile(re.escape(u), re.IGNORECASE)
        result = pattern.sub("<USER>", result)

    return result


def scrub_data(data: Any) -> Any:
    """
    Recursively scrubs dictionary, list, or primitive data structures.
    """
    if isinstance(data, str):
        return scrub_text(data)
    elif isinstance(data, dict):
        return {k: scrub_data(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [scr_item for item in data for scr_item in [scrub_data(item)]]
    elif isinstance(data, tuple):
        return tuple(scrub_data(item) for item in data)
    return data
