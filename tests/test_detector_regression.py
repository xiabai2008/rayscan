"""
Regression tests for SQLi/XSS detectors with mocked HTTP responses.
Exercises the full detector pipeline: endpoint extraction → payload injection → response analysis.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from wvs.config import ConfigManager
from wvs.models import ScanTarget


@pytest.fixture
def config():
    cfg = ConfigManager()
    cfg.set("modules.sqli.enabled", True)
    cfg.set("modules.xss.enabled", True)
    return cfg


def _make_mock_session():
    session = MagicMock()
    session.request = AsyncMock(return_value=_FakeResponse(200, "<html><body>Welcome</body></html>", {}))
    session._get_httpx_client = MagicMock()
    session._lab_mode = False
    session.set_cookie = MagicMock()
    session.close = AsyncMock()
    return session


class _FakeResponse:
    def __init__(self, status_code, text, headers):
        self.status_code = status_code
        self.text = text
        self.headers = headers


# -- SQLiDetector integration tests --


class TestSQLiDetectorIntegration:

    @pytest.fixture
    def mock_session(self):
        return _make_mock_session()

    @pytest.mark.asyncio
    async def test_detector_initialization(self, config, mock_session):
        from wvs.modules.sqli import SQLiDetector
        detector = SQLiDetector(config=config, session=mock_session)
        assert detector.info.name == "sqli"
        assert detector.info.category == "core"
        assert detector.enabled is True

    @pytest.mark.asyncio
    async def test_scan_normal_page(self, config, mock_session):
        from wvs.modules.sqli import SQLiDetector
        detector = SQLiDetector(config=config, session=mock_session)
        target = ScanTarget(url="http://example.com/page?id=1")
        vulns = await detector.scan(target)
        assert isinstance(vulns, list)

    @pytest.mark.asyncio
    async def test_extract_endpoints_query_params(self, config, mock_session):
        from wvs.modules.sqli import SQLiDetector
        detector = SQLiDetector(config=config, session=mock_session)
        target = ScanTarget(url="http://example.com/search?q=test&page=1")
        endpoints = detector._extract_endpoints(target)
        assert len(endpoints) >= 1
        ep = endpoints[0]
        assert ep["method"] == "GET"
        assert "q" in ep["params"]

    @pytest.mark.asyncio
    async def test_extract_endpoints_post_body(self, config, mock_session):
        from wvs.modules.sqli import SQLiDetector
        detector = SQLiDetector(config=config, session=mock_session)
        target = ScanTarget(
            url="http://example.com/login",
            data={"username": "admin", "password": "test"},
        )
        endpoints = detector._extract_endpoints(target)
        post_ep = [e for e in endpoints if e["method"] == "POST"]
        assert len(post_ep) >= 1
        assert "username" in post_ep[0]["params"]

    @pytest.mark.asyncio
    async def test_create_vuln(self, config, mock_session):
        from wvs.models import Confidence, VulnerabilityType
        from wvs.modules.sqli import SQLiDetector
        detector = SQLiDetector(config=config, session=mock_session)
        vuln = detector._create_vuln(
            url="http://example.com?id=1",
            param="id",
            param_type="query",
            method="GET",
            payload="1 OR 1=1--",
            vuln_type="error-based",
            confidence=Confidence.HIGH,
            db_type="mysql",
            evidence="SQL syntax error",
        )
        assert vuln.type == VulnerabilityType.SQL_INJECTION
        assert vuln.parameter == "id"

    @pytest.mark.asyncio
    async def test_detector_disabled(self, config, mock_session):
        from wvs.modules.sqli import SQLiDetector
        detector = SQLiDetector(config=config, session=mock_session)
        detector.disable()
        target = ScanTarget(url="http://example.com/page?id=1")
        vulns = await detector.scan(target)
        assert vulns == []


# -- XSSDetector integration tests --


class TestXSSDetectorIntegration:

    @pytest.fixture
    def mock_session(self):
        return _make_mock_session()

    @pytest.mark.asyncio
    async def test_detector_initialization(self, config, mock_session):
        from wvs.modules.xss import XSSDetector
        detector = XSSDetector(config=config, session=mock_session)
        assert detector.info.name == "xss"
        assert detector.info.category == "core"

    @pytest.mark.asyncio
    async def test_extract_endpoints(self, config, mock_session):
        from wvs.modules.xss import XSSDetector
        detector = XSSDetector(config=config, session=mock_session)
        target = ScanTarget(url="http://example.com/search?q=test")
        endpoints = detector._extract_endpoints(target)
        assert len(endpoints) >= 1

    @pytest.mark.asyncio
    async def test_disabled_detector(self, config, mock_session):
        from wvs.modules.xss import XSSDetector
        detector = XSSDetector(config=config, session=mock_session)
        detector.disable()
        target = ScanTarget(url="http://example.com/page?q=test")
        vulns = await detector.scan(target)
        assert vulns == []


# -- XSS context analyzer tests --


class TestXSSContextAnalyzer:

    def test_html_content_reflection(self):
        from wvs.modules.xss.context_analyzer import analyze_reflection
        contexts = analyze_reflection(
            '<html><body><div id="content">XSS_TEST_12345</div></body></html>',
            "XSS_TEST_12345",
        )
        assert len(contexts) >= 1

    def test_attribute_reflection(self):
        from wvs.modules.xss.context_analyzer import analyze_reflection
        contexts = analyze_reflection(
            '<input type="text" value="XSS_TEST_12345">',
            "XSS_TEST_12345",
        )
        assert len(contexts) >= 1

    def test_no_reflection(self):
        from wvs.modules.xss.context_analyzer import analyze_reflection
        contexts = analyze_reflection(
            "<html><body>No match here</body></html>",
            "XSS_TEST_12345",
        )
        assert len(contexts) == 0

    def test_script_context(self):
        from wvs.modules.xss.context_analyzer import analyze_reflection
        contexts = analyze_reflection(
            "<script>var x = 'XSS_TEST_12345';</script>",
            "XSS_TEST_12345",
        )
        assert len(contexts) >= 1
