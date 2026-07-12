"""
RayScan 1.0.2 — Encoding bypass payload generator

Generates encoding-variant payloads to evade WAF/IDS detection:
- URL encoding (single, double, triple)
- Unicode normalization bypass
- Case variation
- Comment insertion
- Whitespace substitution
- Character escaping
"""

import urllib.parse
from typing import List


def url_encode(payload: str) -> str:
    """Single URL-encode the payload."""
    return urllib.parse.quote(payload, safe="")


def double_url_encode(payload: str) -> str:
    """Double URL-encode the payload."""
    return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")


def case_shuffle(payload: str) -> List[str]:
    """Generate case-variation payloads."""
    variants = []
    # Random upper/lower mix
    chars = list(payload)
    for i in range(min(5, len(payload))):
        # Vary case at position i
        variant = chars.copy()
        for j in range(i, len(payload), 2):
            variant[j] = variant[j].upper() if variant[j].islower() else variant[j].lower()
        variants.append("".join(variant))
    return variants


def comment_obfuscate(payload: str) -> List[str]:
    """Insert inline comments to break keyword matching."""
    variants = []
    keywords = [
        "SELECT",
        "UNION",
        "OR",
        "AND",
        "FROM",
        "WHERE",
        "INSERT",
        "UPDATE",
        "DELETE",
        "DROP",
        "SLEEP",
        "BENCHMARK",
        "WAITFOR",
        "ORDER BY",
        "GROUP BY",
    ]
    for kw in keywords:
        if kw in payload.upper():
            # Insert /**/ between characters
            commented = "/**/".join(list(kw))
            variant = payload.upper().replace(kw.upper(), commented)
            variants.append(variant)
    return variants[:3]


def whitespace_bypass(payload: str) -> List[str]:
    """Replace spaces with various whitespace alternatives."""
    alternatives = ["\\t", "\\v", "\\f", "\\n", "/**/", "+", "%09", "%0a", "%0d", "%0c", "%a0"]
    variants = []
    for alt in alternatives:
        variants.append(payload.replace(" ", alt))
    return variants


def null_byte_inject(payload: str, positions: int = 3) -> List[str]:
    """Insert null bytes at various positions."""
    variants = []
    step = max(1, len(payload) // positions)
    for i in range(0, len(payload), step):
        variant = payload[:i] + "%00" + payload[i:]
        variants.append(variant)
    return variants[:5]


def generate_all_variants(payload: str, limit: int = 20) -> List[str]:
    """Generate all encoding bypass variants for a payload."""
    variants = []
    variants.append(url_encode(payload))
    variants.append(double_url_encode(payload))
    variants.extend(case_shuffle(payload))
    variants.extend(comment_obfuscate(payload))
    variants.extend(whitespace_bypass(payload))
    variants.extend(null_byte_inject(payload))
    # Deduplicate and limit
    seen = set()
    unique = []
    for v in variants:
        if v != payload and v not in seen:
            seen.add(v)
            unique.append(v)
    return unique[:limit]
