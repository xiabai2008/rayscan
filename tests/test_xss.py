"""Unit tests for the XSS detector core analysis logic (context_analyzer).

Pure-logic tests target the context-aware reflection analyzer that powers
XSS detection. The integration test mocks the detector's HTTP session seam
(_send_request) to verify end-to-end reflected-XSS detection against a
mocked session response.
"""

from unittest.mock import AsyncMock

import pytest

from wvs.models import ScanTarget, VulnerabilityType
from wvs.modules.xss.context_analyzer import (
    XSS_CHECKER,
    ReflectionContext,
    analyze_reflection,
    select_payload,
)
from wvs.modules.xss.detector import XSSDetector

# ── analyze_reflection: context determination ──────────────────────────────


def test_analyze_reflection_script_context():
    html = "<html><script>var x = 'vXSScH3ck3r';</script></html>"
    ctxs = analyze_reflection(html, XSS_CHECKER)
    assert len(ctxs) == 1
    assert ctxs[0].context == "script"


def test_analyze_reflection_attribute_context():
    html = '<html><input value="vXSScH3ck3r"></html>'
    ctxs = analyze_reflection(html, XSS_CHECKER)
    assert ctxs
    assert ctxs[0].context == "attribute"


def test_analyze_reflection_html_context():
    html = "<html><body>hello vXSScH3ck3r world</body></html>"
    ctxs = analyze_reflection(html, XSS_CHECKER)
    assert ctxs
    assert ctxs[0].context == "html"


def test_analyze_reflection_comment_not_executable():
    html = "<html><!-- vXSScH3ck3r --></html>"
    ctxs = analyze_reflection(html, XSS_CHECKER)
    assert ctxs
    assert ctxs[0].context == "comment"
    # A marker inside an HTML comment cannot be executed -> not exploitable.
    assert ctxs[0].is_executable() is False


def test_reflection_context_is_executable_matrix():
    assert ReflectionContext(context="script").is_executable() is True
    assert ReflectionContext(context="attribute").is_executable() is True
    assert ReflectionContext(context="html").is_executable() is True
    assert ReflectionContext(context="comment").is_executable() is False
    assert ReflectionContext(context="bad").is_executable() is False


# ── select_payload: context-optimized payload selection ────────────────────


def test_select_payload_script_quote():
    ctx = ReflectionContext(context="script", quote_char="'")
    payloads = select_payload(ctx)
    assert any("alert(1)" in p for p in payloads)


def test_select_payload_html():
    ctx = ReflectionContext(context="html")
    payloads = select_payload(ctx)
    assert any("<img" in p or "<svg" in p for p in payloads)


def test_select_payload_comment_escapes():
    ctx = ReflectionContext(context="comment")
    payloads = select_payload(ctx)
    assert all("img" in p or "svg" in p for p in payloads)


# ── integration: mock session -> reflected XSS detected ─────────────────────


@pytest.mark.asyncio
async def test_xss_detector_finds_reflected_xss_with_mocked_session():
    """End-to-end reflected-XSS detection with a mocked HTTP session.

    The detector's _send_request seam is replaced by a coroutine that
    reflects every parameter value back into the response body, emulating a
    vulnerable target. This proves the detector's core logic correctly turns
    a mocked session response into a vulnerability.
    """
    detector = XSSDetector(session=AsyncMock())

    async def fake_send_request(method, url, params, param_type):
        body = " ".join(str(v) for v in params.values())
        return {"status_code": 200, "text": f"<html><body>{body}</body></html>", "headers": {}}

    detector._send_request = AsyncMock(side_effect=fake_send_request)

    target = ScanTarget(url="http://example.com/search?q=hello")
    vulns = await detector._scan_impl(target)

    assert len(vulns) >= 1
    assert vulns[0].type == VulnerabilityType.XSS
