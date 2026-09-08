"""T4 core 层单元测试 — 2026-08-08（TD-008）.

覆盖 scanner 去重/归一化纯逻辑、crawler URL 处理纯逻辑、HTTPPool cookie/header 管理。
原则：不发起任何真实网络请求。
"""

from wvs.core.scanner import WAVScanner
from wvs.models import Confidence, Severity, Vulnerability, VulnerabilityType

# =====================================================================
# WAVScanner 去重/归一化
# =====================================================================


def _make_scanner():
    from wvs.config import ConfigManager
    from wvs.core.scanner import WAVScanner

    return WAVScanner(ConfigManager())


class TestScannerNormalize:
    def test_normalize_url_strips_query_fragment(self):
        assert WAVScanner._normalize_url("http://t/a?x=1#frag") == "http://t/a"
        assert WAVScanner._normalize_url("http://t/a/") == "http://t/a"

    def test_normalize_vuln_url_id_segment(self):
        assert WAVScanner._normalize_vuln_url("http://t/user/123/profile") == "http://t/user/:id/profile"
        assert WAVScanner._normalize_vuln_url("http://t/item/42") == "http://t/item/:id"

    def test_normalize_vuln_url_static_collapse(self):
        assert WAVScanner._normalize_vuln_url("http://t/themes/original/css/foo.css") == "http://t/themes/*"
        assert WAVScanner._normalize_vuln_url("http://t/static/js/app.js") == "http://t/static/*"

    def test_normalize_vuln_url_long_hash(self):
        assert WAVScanner._normalize_vuln_url("http://t/page/a1b2c3d4e5f6a7b8c9d0e1f2") == "http://t/page/:hash"

    def test_vuln_signature_case_insensitive(self):
        scanner = _make_scanner()
        v1 = Vulnerability(
            type=VulnerabilityType.SQL_INJECTION, url="http://t/a?id=1", parameter="id", payload="' OR '1'='1"
        )
        v2 = Vulnerability(
            type=VulnerabilityType.SQL_INJECTION, url="http://T/A?ID=1", parameter="Id", payload="' or '1'='1"
        )
        assert scanner._vuln_signature(v1) == scanner._vuln_signature(v2)

    def test_vuln_signature_differs_by_payload(self):
        scanner = _make_scanner()
        v1 = Vulnerability(type=VulnerabilityType.SQL_INJECTION, url="http://t/a", payload="p1")
        v2 = Vulnerability(type=VulnerabilityType.SQL_INJECTION, url="http://t/a", payload="p2")
        assert scanner._vuln_signature(v1) != scanner._vuln_signature(v2)


class TestScannerDedup:
    def test_keep_highest_severity(self):
        scanner = _make_scanner()
        low = Vulnerability(
            type=VulnerabilityType.XSS,
            url="http://t/a",
            payload="<x>",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
        )
        high = Vulnerability(
            type=VulnerabilityType.XSS,
            url="http://t/a",
            payload="<x>",
            severity=Severity.HIGH,
            confidence=Confidence.LOW,
        )
        result = scanner._deduplicate([low, high])
        assert len(result) == 1
        assert result[0].severity == Severity.HIGH

    def test_same_severity_keep_higher_confidence(self):
        scanner = _make_scanner()
        med_low_conf = Vulnerability(
            type=VulnerabilityType.XSS,
            url="http://t/a",
            payload="<x>",
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
        )
        med_high_conf = Vulnerability(
            type=VulnerabilityType.XSS,
            url="http://t/a",
            payload="<x>",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
        )
        result = scanner._deduplicate([med_low_conf, med_high_conf])
        assert len(result) == 1
        assert result[0].confidence == Confidence.HIGH

    def test_different_payloads_not_merged(self):
        scanner = _make_scanner()
        v1 = Vulnerability(type=VulnerabilityType.XSS, url="http://t/a", payload="p1")
        v2 = Vulnerability(type=VulnerabilityType.XSS, url="http://t/a", payload="p2")
        assert len(scanner._deduplicate([v1, v2])) == 2

    def test_endpoint_base_key_ignores_param_values(self):
        scanner = _make_scanner()
        k1 = scanner._endpoint_base_key("http://t/i.php?page=a", {"page": "a"})
        k2 = scanner._endpoint_base_key("http://t/i.php?page=b", {"page": "b"})
        assert k1 == k2
        assert k1 == "/i.php?page"

    def test_prioritize_params_first(self):
        scanner = _make_scanner()
        from wvs.core.crawler import DiscoveredEndpoint

        no_params = DiscoveredEndpoint(url="http://t/static", method="GET", source_url="http://t/", source_depth=1)
        with_params = DiscoveredEndpoint(
            url="http://t/i.php?id=1",
            method="GET",
            source_url="http://t/",
            source_depth=1,
            parameters={"id": "1"},
            param_types={"id": "query"},
        )
        ordered = scanner._prioritize_endpoints([no_params, with_params])
        assert ordered[0] is with_params


# =====================================================================
# WebCrawler URL 处理纯逻辑
# =====================================================================


class TestCrawlerPure:
    def setup_method(self):
        from wvs.core.crawler import WebCrawler

        self.crawler = WebCrawler(max_depth=2, max_urls_per_run=10)

    def test_normalize_lowercases_host_strips_default_port(self):
        assert self.crawler._normalize_url("http://EXAMPLE.COM:80/a") == "http://example.com/a"
        assert self.crawler._normalize_url("https://Example.com:443/a") == "https://example.com/a"

    def test_normalize_sorts_query_and_strips_fragment(self):
        n = self.crawler._normalize_url("http://t/a?b=2&a=1#frag")
        assert n == "http://t/a?a=1&b=2"
        assert "#" not in n

    def test_normalize_relative_prefixed(self):
        assert self.crawler._normalize_url("example.com/a") == "http://example.com/a"

    def test_join_url_skips_non_http(self):
        assert self.crawler._join_url("http://t/", "mailto:x@y.com") == "http://t/"
        assert self.crawler._join_url("http://t/", "data:text/html;base64,AAA") == "http://t/"
        assert self.crawler._join_url("http://t/", "/path/x") == "http://t/path/x"

    def test_url_key_ignores_unimportant_params(self):
        k1 = self.crawler._url_key("http://t/a?utm_source=x")
        k2 = self.crawler._url_key("http://t/a?utm_source=y")
        assert k1 == k2

    def test_is_visited(self):
        self.crawler._visited = {"http://t/a"}
        assert self.crawler._is_visited("http://t/a?utm=1") is True
        assert self.crawler._is_visited("http://t/b") is False

    def test_is_crawlable_host_and_ext(self):
        self.crawler._allowed_host = "example.com"
        assert self.crawler._is_crawlable("http://example.com/a") is True
        assert self.crawler._is_crawlable("http://evil.com/a") is False
        assert self.crawler._is_crawlable("http://example.com/logo.png") is False
        assert self.crawler._is_crawlable("") is False

    def test_discovered_endpoint_hash_eq(self):
        from wvs.core.crawler import DiscoveredEndpoint

        a = DiscoveredEndpoint(url="http://t/x", method="GET", source_url="http://t/", source_depth=1)
        b = DiscoveredEndpoint(url="http://t/x", method="GET", source_url="http://t/", source_depth=2)
        assert a == b
        assert hash(a) == hash(b)


# =====================================================================
# HTTPPool cookie / header 管理
# =====================================================================


class TestHTTPSession:
    def setup_method(self):
        from wvs.config import ConfigManager
        from wvs.core.session import HTTPPool

        self.session = HTTPPool(ConfigManager())

    def test_get_host(self):
        assert self.session._get_host("http://example.com:8080/a?b=1") == "example.com:8080"
        assert self.session._get_host("naked-string") == "naked-string"

    def test_set_cookie_injects_httpx_jar(self):
        self.session.set_cookie("http://example.com/", "sid", "abc123")
        jar = list(self.session._ensure_client().cookies.jar)
        assert any(c.name == "sid" and c.value == "abc123" for c in jar)

    def test_get_cookie_jar_roundtrip(self):
        self.session._cookie_jar = {"example.com": {"sid": "xyz"}}
        assert self.session.get_cookie("example.com", "sid") == "xyz"
        assert self.session.get_cookie("example.com", "missing") is None
        assert self.session.get_cookie("other.com", "sid") is None

    def test_merge_headers_adds_ua(self):
        kwargs = self.session._merge_headers("http://example.com/", {})
        assert "User-Agent" in kwargs["headers"]

    def test_merge_headers_keeps_custom(self):
        kwargs = self.session._merge_headers("http://example.com/", {"headers": {"X-Test": "1"}})
        assert kwargs["headers"]["X-Test"] == "1"
        assert "User-Agent" in kwargs["headers"]

    def test_merge_headers_injects_jar_cookies(self):
        self.session.set_cookie("http://example.com/", "sid", "abc123")
        kwargs = self.session._merge_headers("http://example.com/", {})
        cookie_header = kwargs["headers"].get("Cookie", "")
        assert "sid=abc123" in cookie_header
