"""
Integration tests for WAVScanner core scan path.
Uses mocked HTTP responses to verify the scan orchestration flow.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from wvs.config import ConfigManager
from wvs.core.scanner import WAVScanner
from wvs.core.session import HTTPPool
from wvs.models import ScanResult, ScanTarget, Severity, Vulnerability, VulnerabilityType


class TestScannerCore:
    """Core scanner integration tests with mocked HTTP."""

    @pytest.fixture
    def config(self):
        cfg = ConfigManager()
        cfg.set("crawl_depth", 1)
        cfg.set("crawl_max_urls", 3)
        cfg.set("enable_waf_detection", False)
        cfg.set("modules.sqli.enabled", True)
        cfg.set("modules.xss.enabled", True)
        cfg.set("integrations.enabled", False)
        cfg.set("integrations.nuclei.enabled", False)
        cfg.set("integrations.sqlmap.enabled", False)
        cfg.set("integrations.ffuf.enabled", False)
        cfg.set("integrations.wappalyzer.enabled", False)
        return cfg

    @pytest.fixture
    def mock_session(self):
        session = MagicMock(spec=HTTPPool)
        session.request = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                text="<html><body>Test</body></html>",
                headers={"Content-Type": "text/html"},
            )
        )
        session.get = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                text="<html><body>Test Page</body></html>",
                headers={},
            )
        )
        session._get_httpx_client = MagicMock()
        session._lab_mode = False
        session.set_cookie = MagicMock()
        session.close = AsyncMock()
        return session

    @pytest.mark.asyncio
    async def test_scanner_initialization(self, config, mock_session):
        scanner = WAVScanner(config=config, session=mock_session)
        assert scanner.config is config
        assert scanner.session is mock_session
        assert scanner._modules == {}

    @pytest.mark.asyncio
    async def test_load_module_sqli(self, config, mock_session):
        scanner = WAVScanner(config=config, session=mock_session)
        result = scanner.load_module("sqli")
        assert result is True
        assert "sqli" in scanner._modules

    @pytest.mark.asyncio
    async def test_load_module_xss(self, config, mock_session):
        scanner = WAVScanner(config=config, session=mock_session)
        result = scanner.load_module("xss")
        assert result is True
        assert "xss" in scanner._modules

    @pytest.mark.asyncio
    async def test_load_module_nonexistent(self, config, mock_session):
        scanner = WAVScanner(config=config, session=mock_session)
        result = scanner.load_module("nonexistent_module")
        assert result is False

    @pytest.mark.asyncio
    async def test_load_all_modules(self, config, mock_session):
        scanner = WAVScanner(config=config, session=mock_session)
        scanner.load_all_modules()
        assert "sqli" in scanner._modules
        assert "xss" in scanner._modules

    @pytest.mark.asyncio
    async def test_resolve_enabled_modules_default(self, config, mock_session):
        scanner = WAVScanner(config=config, session=mock_session)
        modules = scanner._resolve_enabled_modules()
        assert "sqli" in modules
        assert "xss" in modules
        assert "oa" not in modules

    @pytest.mark.asyncio
    async def test_resolve_enabled_modules_all(self, config, mock_session):
        scanner = WAVScanner(config=config, session=mock_session)
        scanner._load_all_modules = True
        modules = scanner._resolve_enabled_modules()
        assert "sqli" in modules
        assert "xss" in modules
        assert "oa" in modules

    @pytest.mark.asyncio
    async def test_get_stats_initial(self, config, mock_session):
        scanner = WAVScanner(config=config, session=mock_session)
        stats = scanner.get_stats()
        assert "total_requests" in stats
        assert "modules_run" in stats
        assert "errors" in stats

    @pytest.mark.asyncio
    async def test_ensure_params_preserves_existing(self, config, mock_session):
        from wvs.core.crawler import DiscoveredEndpoint

        scanner = WAVScanner(config=config, session=mock_session)
        ep = DiscoveredEndpoint(
            url="http://example.com/page?id=1",
            parameters={"id": "1"},
            param_types={"id": "query"},
        )
        params, _types = scanner._ensure_params(ep)
        assert params == {"id": "1"}

    @pytest.mark.asyncio
    async def test_ensure_params_fills_missing(self, config, mock_session):
        from wvs.core.crawler import DiscoveredEndpoint

        scanner = WAVScanner(config=config, session=mock_session)
        ep = DiscoveredEndpoint(
            url="http://example.com/page?id=1&name=test",
            parameters={},
            param_types={},
        )
        params, _types = scanner._ensure_params(ep)
        assert "id" in params
        assert "name" in params


class TestVulnerabilityDedup:
    """Vulnerability deduplication tests."""

    def test_vuln_signature_deterministic(self):
        v1 = Vulnerability(
            type=VulnerabilityType.SQL_INJECTION,
            url="http://x.com?id=1",
            parameter="id",
            payload="' OR 1=1--",
        )
        v2 = Vulnerability(
            type=VulnerabilityType.SQL_INJECTION,
            url="http://x.com?id=1",
            parameter="id",
            payload="' OR 1=1--",
        )
        sig1 = f"{v1.type.value}|{v1.url}|{v1.parameter}|{v1.payload}".lower()
        sig2 = f"{v2.type.value}|{v2.url}|{v2.parameter}|{v2.payload}".lower()
        assert sig1 == sig2

    def test_vuln_different_payloads_different_sigs(self):
        v1 = Vulnerability(
            type=VulnerabilityType.SQL_INJECTION,
            url="http://x.com?id=1",
            parameter="id",
            payload="' OR 1=1--",
        )
        v2 = Vulnerability(
            type=VulnerabilityType.SQL_INJECTION,
            url="http://x.com?id=1",
            parameter="id",
            payload="1' AND 1=2--",
        )
        sig1 = f"{v1.type.value}|{v1.url}|{v1.parameter}|{v1.payload}".lower()
        sig2 = f"{v2.type.value}|{v2.url}|{v2.parameter}|{v2.payload}".lower()
        assert sig1 != sig2

    def test_scan_result_vuln_count(self):
        target = ScanTarget(url="http://example.com")
        result = ScanResult(target=target)
        result.vulnerabilities = [
            Vulnerability(type=VulnerabilityType.SQL_INJECTION, url="http://x.com/a"),
            Vulnerability(type=VulnerabilityType.SQL_INJECTION, url="http://x.com/b"),
            Vulnerability(type=VulnerabilityType.XSS, url="http://x.com/c"),
        ]
        assert result.vulnerability_count.get("sql_injection") == 2
        assert result.vulnerability_count.get("cross_site_scripting") == 1

    def test_scan_result_severity_count(self):
        target = ScanTarget(url="http://example.com")
        result = ScanResult(target=target)
        result.vulnerabilities = [
            Vulnerability(type=VulnerabilityType.SQL_INJECTION, severity=Severity.HIGH, url="http://x.com/a"),
            Vulnerability(type=VulnerabilityType.XSS, severity=Severity.MEDIUM, url="http://x.com/b"),
            Vulnerability(type=VulnerabilityType.XSS, severity=Severity.MEDIUM, url="http://x.com/c"),
        ]
        assert result.severity_count.get("high") == 1
        assert result.severity_count.get("medium") == 2


class TestModuleFactory:
    """ModuleFactory tests."""

    def test_list_modules_includes_core(self):
        from wvs.modules import register_all_modules
        from wvs.modules.base import ModuleFactory

        register_all_modules()
        modules = ModuleFactory.list_modules()
        assert "sqli" in modules
        assert "xss" in modules

    def test_create_module_returns_instance(self):
        from wvs.modules import register_all_modules
        from wvs.modules.base import DetectionModule, ModuleFactory

        register_all_modules()
        mod = ModuleFactory.create("sqli")
        assert isinstance(mod, DetectionModule)
        assert mod.info.name == "sqli"
        assert mod.info.category == "core"

    def test_get_module_info(self):
        from wvs.modules import register_all_modules
        from wvs.modules.base import ModuleFactory

        register_all_modules()
        info = ModuleFactory.get_module_info("xss")
        assert info is not None
        assert info.name == "xss"
