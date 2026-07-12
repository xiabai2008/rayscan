"""
JS / Config file sensitive information extraction.

Extracts from JavaScript and config files:
- API keys / tokens / secrets
- Internal endpoints / IPs
- Credentials in source code
- Cloud service keys (AWS, GCP, Azure)

Based on patterns from LinkFinder and common secret-detection tools.
"""

import re
from typing import List, Set

# ── Sensitive info patterns ────────────────────────────────────

SENSITIVE_PATTERNS = [
    # API keys / tokens
    (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([\w\-]{20,})["\']', "API key"),
    (r'(?:access[_-]?token|auth[_-]?token)\s*[:=]\s*["\']([\w\-\.]{16,})["\']', "Access token"),
    (r'(?:secret[_-]?key|secretkey)\s*[:=]\s*["\']([\w\-]{16,})["\']', "Secret key"),
    (r'(?:bearer|jwt)\s+["\']?([\w\-\.]{20,})["\']?', "JWT / Bearer token"),
    (r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\'\s]{3,})["\']', "Password in code"),
    # Cloud service keys
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"AIza[0-9A-Za-z\-_]{35}", "GCP API Key"),
    (r"(?:xox[pboa]-[\w\-]{10,})", "Slack Token"),
    # Internal infrastructure
    (r"(?:https?://)(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?", "Internal IP endpoint"),
    (r'(?:mongodb|mysql|postgres(?:ql)?|redis)://[^\s"\'<>]+', "Database connection string"),
    (r'jdbc:[^\s"\'<>]+', "JDBC connection string"),
    # SSH / private keys
    (r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----", "Private key in code"),
    (r"ssh-rsa\s+[A-Za-z0-9+/=]{100,}", "SSH public key"),
    # .env / config patterns
    (r"(?:DATABASE_URL|DB_URL|MONGO_URL|REDIS_URL)\s*=\s*(\S+)", "Database URL"),
    (r"(?:SENDGRID|MAILGUN|STRIPE|TWILIO)_(?:API_)?KEY\s*=\s*(\S+)", "Service API key"),
]


def extract_sensitive_info(js_text: str) -> List[dict]:
    """
    Extract sensitive information from JS/config text.
    Returns list of {pattern, type, value, line_context}.
    """
    findings: List[dict] = []
    seen: Set[str] = set()

    lines = js_text.splitlines()

    for pattern, ptype in SENSITIVE_PATTERNS:
        for match in re.finditer(pattern, js_text, re.IGNORECASE):
            value = match.group(1) if match.lastindex else match.group(0)
            if value in seen:
                continue
            seen.add(value)

            # Find line number
            start = match.start()
            line_num = 1
            pos = 0
            for i, line in enumerate(lines):
                if pos + len(line) >= start:
                    line_num = i + 1
                    break
                pos += len(line) + 1

            findings.append(
                {
                    "type": ptype,
                    "value": value[:100],
                    "line": line_num,
                    "context": lines[line_num - 1].strip()[:120] if line_num <= len(lines) else "",
                }
            )

    return findings


def extract_endpoints_from_js(js_text: str) -> List[str]:
    """
    Extract additional URL endpoints from JS files using LinkFinder patterns.
    Returns list of unique endpoint strings.
    """
    endpoints: Set[str] = set()

    # LinkFinder comprehensive regex
    patterns = [
        # Full URLs
        re.compile(r'["\'`](https?://[^\s"\'`<>]{5,})["\'`]', re.IGNORECASE),
        # Relative API paths
        re.compile(r'["\'`](/api/[^\s"\'`<>]{1,})["\'`]', re.IGNORECASE),
        # REST-style paths
        re.compile(r'["\'`](/(?:v\d+/)?[a-z][a-z0-9_\-/]{2,})["\'`]', re.IGNORECASE),
        # GraphQL endpoints
        re.compile(r'["\'`]([^\s"\'`]*graphql[^\s"\'`]*)["\'`]', re.IGNORECASE),
        # WebSocket endpoints
        re.compile(r'["\'`](wss?://[^\s"\'`<>]{5,})["\'`]', re.IGNORECASE),
    ]

    for pattern in patterns:
        for match in pattern.finditer(js_text):
            endpoint = match.group(1).strip()
            if endpoint and len(endpoint) > 2:
                endpoints.add(endpoint)

    return sorted(endpoints)
