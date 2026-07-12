"""Tests for remaining detector modules: RCE, XXE, SSRF, Sensitive, WAF, jspathfinder, API."""

import json

import pytest

from wvs.models import Severity
from wvs.modules.base import ModuleFactory, ModuleInfo


class TestModuleInfo:
    def test_default_values(self):
        info = ModuleInfo(name="test", description="test module")
        assert info.name == "test"
        assert info.author == "WVS Team"
        assert info.version == "1.0.0"
        assert info.enabled_by_default is True
        assert info.tags == []

    def test_custom_values(self):
        info = ModuleInfo(
            name="custom",
            description="custom module",
            author="Test Author",
            version="2.0.0",
            enabled_by_default=False,
            tags=["tag1", "tag2"],
        )
        assert info.author == "Test Author"
        assert info.version == "2.0.0"
        assert info.enabled_by_default is False
        assert info.tags == ["tag1", "tag2"]


class TestModuleFactory:
    def test_list_modules_contains_common(self):
        modules = ModuleFactory.list_modules()
        for name in ("sqli", "xss", "cmdi", "lfi", "rce", "xxe", "ssrf", "waf"):
            assert name in modules

    def test_create_known_module(self):
        module = ModuleFactory.create("sqli")
        assert module is not None
        assert module.get_info().name == "sqli"

    def test_create_unknown_module(self):
        with pytest.raises(KeyError):
            ModuleFactory.create("nonexistent_module")


# =====================================================================
# RCE Detector
# =====================================================================


class TestRCEDetector:
    def test_get_info(self):
        from wvs.modules.rce.detector import RCEDetector

        info = RCEDetector.get_info()
        assert info.name == "rce"
        assert "code" in info.description.lower()

    def test_module_registration(self):
        assert "rce" in ModuleFactory.list_modules()

    def test_is_input_reflection_full_payload(self):
        """Entire payload reflected in response -> FP (input reflection)."""
        from wvs.modules.rce.detector import RCEDetector

        det = RCEDetector()
        resp_text = "some text ; echo TESTTOKEN123 more text"
        assert det._is_input_reflection(resp_text, "; echo TESTTOKEN123", "TESTTOKEN123") is True

    def test_is_input_reflection_token_independent(self):
        """Token appears separately from payload -> true positive."""
        from wvs.modules.rce.detector import RCEDetector

        det = RCEDetector()
        resp_text = "some output TESTTOKEN123 here"
        assert det._is_input_reflection(resp_text, "; echo TESTTOKEN123", "TESTTOKEN123") is False

    def test_is_input_reflection_payload_not_in_resp(self):
        """Payload not in response at all -> not input reflection."""
        from wvs.modules.rce.detector import RCEDetector

        det = RCEDetector()
        assert det._is_input_reflection("just normal text", "; echo xyz", "xyz") is False

    def test_is_input_reflection_empty_response(self):
        from wvs.modules.rce.detector import RCEDetector

        det = RCEDetector()
        assert det._is_input_reflection("", "; echo xyz", "xyz") is False

    def test_is_html_display_reflection_pre_tag(self):
        """Token wrapped in <pre> tag -> HTML display reflection (FP)."""
        from wvs.modules.rce.detector import RCEDetector

        det = RCEDetector()
        html = "<html><body><pre>Your input: TESTTOKEN42</pre></body></html>"
        assert det._is_html_display_reflection(html, "TESTTOKEN42", "; echo TESTTOKEN42") is True

    def test_is_html_display_reflection_code_tag(self):
        from wvs.modules.rce.detector import RCEDetector

        det = RCEDetector()
        html = "<html><body><code>TESTTOKEN99</code></body></html>"
        assert det._is_html_display_reflection(html, "TESTTOKEN99", "TESTTOKEN99") is True

    def test_is_html_display_reflection_no_wrapper(self):
        """Token without HTML display wrapper -> not FP."""
        from wvs.modules.rce.detector import RCEDetector

        det = RCEDetector()
        assert det._is_html_display_reflection("output TESTTOKEN42 here", "TESTTOKEN42", "x") is False

    def test_is_echo_server_json_response(self):
        """httpbin-style JSON echo -> echo server (FP)."""
        from wvs.modules.rce.detector import RCEDetector

        det = RCEDetector()
        # payload appears inside a JSON string value in the response
        resp = json.dumps({"args": {"cmd": "echo test"}, "url": "http://httpbin.org/get"})
        assert det._is_echo_server("http://httpbin.org/get", resp, "echo test") is True

    def test_is_echo_server_normal_response(self):
        """Normal HTML response -> not an echo server."""
        from wvs.modules.rce.detector import RCEDetector

        det = RCEDetector()
        assert det._is_echo_server("http://example.com", "<html>OK</html>", "test") is False

    def test_is_lfi_context_positive(self):
        """Response with passwd + PATH= markers -> LFI context (FP)."""
        from wvs.modules.rce.detector import RCEDetector

        det = RCEDetector()
        resp = "root:x:0:0:root:/root:/bin/bash\nPATH=/usr/local/bin:/usr/bin"
        assert det._is_lfi_context(resp) is True

    def test_is_lfi_context_negative(self):
        """Normal response -> not LFI context."""
        from wvs.modules.rce.detector import RCEDetector

        det = RCEDetector()
        assert det._is_lfi_context("<html>Welcome</html>") is False


# =====================================================================
# XXE Detector
# =====================================================================


class TestXXEDetector:
    def test_get_info(self):
        from wvs.modules.xxe.detector import XXEDetector

        info = XXEDetector.get_info()
        assert info.name == "xxe"
        assert "xml" in info.description.lower()

    def test_module_registration(self):
        assert "xxe" in ModuleFactory.list_modules()

    def test_xml_content_types(self):
        from wvs.modules.xxe.detector import XXEDetector

        assert "application/xml" in XXEDetector.XML_CONTENT_TYPES
        assert "text/xml" in XXEDetector.XML_CONTENT_TYPES
        assert "application/soap+xml" in XXEDetector.XML_CONTENT_TYPES

    def test_xml_extensions(self):
        from wvs.modules.xxe.detector import XXEDetector

        assert ".xml" in XXEDetector.XML_EXTENSIONS
        assert ".svg" in XXEDetector.XML_EXTENSIONS
        assert ".wsdl" in XXEDetector.XML_EXTENSIONS

    def test_check_xxe_success_file_content(self):
        """Response containing /etc/passwd content -> XXE success."""
        from wvs.modules.xxe.detector import XXEDetector

        det = XXEDetector()
        resp = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
        assert det._check_xxe_success(resp) is True

    def test_check_xxe_success_parse_error(self):
        """XML parse error in response -> XXE success."""
        from wvs.modules.xxe.detector import XXEDetector

        det = XXEDetector()
        assert det._check_xxe_success("failed to load external entity") is True

    def test_check_xxe_success_xml_parse_error(self):
        """XML parser error message -> XXE success."""
        from wvs.modules.xxe.detector import XXEDetector

        det = XXEDetector()
        assert det._check_xxe_success("Warning: DOMDocument::loadXML(): Entity") is True

    def test_check_xxe_success_negative(self):
        """Normal HTML response -> no XXE."""
        from wvs.modules.xxe.detector import XXEDetector

        det = XXEDetector()
        assert det._check_xxe_success("<html>Welcome</html>") is False

    def test_check_xxe_success_empty(self):
        from wvs.modules.xxe.detector import XXEDetector

        det = XXEDetector()
        assert det._check_xxe_success("") is False


# =====================================================================
# SSRF Detector
# =====================================================================


class TestSSRFDetector:
    def test_get_info(self):
        from wvs.modules.ssrf.detector import SSRFDetector

        info = SSRFDetector.get_info()
        assert info.name == "ssrf"
        assert "request" in info.description.lower()

    def test_module_registration(self):
        assert "ssrf" in ModuleFactory.list_modules()

    def test_param_patterns(self):
        from wvs.modules.ssrf.detector import SSRFDetector

        patterns = SSRFDetector.SSRF_PARAM_PATTERNS
        assert "url" in patterns
        assert "redirect" in patterns
        assert "proxy" in patterns
        assert "file" in patterns

    def test_check_ssrf_success_file_read(self):
        """Response with /etc/passwd content -> SSRF file read success."""
        from wvs.modules.ssrf.detector import SSRFDetector

        det = SSRFDetector.__new__(SSRFDetector)
        resp = "root:x:0:0:root:/root:/bin/bash"
        assert det._check_ssrf_success(resp, None) is True

    def test_check_ssrf_success_aws_metadata(self):
        """Response with AWS metadata -> SSRF cloud metadata success."""
        from wvs.modules.ssrf.detector import SSRFDetector

        det = SSRFDetector.__new__(SSRFDetector)
        resp = '{"AccessKeyId": "ASIA123456", "SecretAccessKey": "secret123"}'
        assert det._check_ssrf_success(resp, None) is True

    def test_check_ssrf_success_connection_error_with_payload(self):
        """Connection error text when payload provided -> SSRF attempted."""
        from wvs.modules.ssrf.detector import SSRFDetector

        det = SSRFDetector.__new__(SSRFDetector)
        assert det._check_ssrf_success("Connection refused", "http://internal:22") is True

    def test_check_ssrf_success_banner_detection(self):
        """SSH banner in response with payload -> SSRF detected."""
        from wvs.modules.ssrf.detector import SSRFDetector

        det = SSRFDetector.__new__(SSRFDetector)
        assert det._check_ssrf_success("SSH-2.0-OpenSSH_8.9p1", "http://internal:22") is True

    def test_check_ssrf_success_negative(self):
        """Normal response -> no SSRF success."""
        from wvs.modules.ssrf.detector import SSRFDetector

        det = SSRFDetector.__new__(SSRFDetector)
        assert det._check_ssrf_success("<html>OK</html>", None) is False

    def test_check_ssrf_connection_error_refused(self):
        from wvs.modules.ssrf.detector import SSRFDetector

        det = SSRFDetector.__new__(SSRFDetector)
        assert det._check_ssrf_connection_error("Error: Connection refused") is True

    def test_check_ssrf_connection_error_timeout(self):
        from wvs.modules.ssrf.detector import SSRFDetector

        det = SSRFDetector.__new__(SSRFDetector)
        assert det._check_ssrf_connection_error("Connection timed out") is True

    def test_check_ssrf_connection_error_negative(self):
        from wvs.modules.ssrf.detector import SSRFDetector

        det = SSRFDetector.__new__(SSRFDetector)
        assert det._check_ssrf_connection_error("<html>OK</html>") is False


# =====================================================================
# Sensitive Info Detector
# =====================================================================


class TestSensitiveDetector:
    def test_get_info(self):
        from wvs.modules.sensitive.detector import SensitiveDetector

        info = SensitiveDetector.get_info()
        assert info.name == "sensitive"
        assert "sensitive" in info.description.lower()

    def test_module_registration(self):
        assert "sensitive" in ModuleFactory.list_modules()

    def test_high_priority_paths(self):
        from wvs.modules.sensitive.detector import SensitiveDetector

        assert "/.git/config" in SensitiveDetector.HIGH_PRIORITY_PATHS
        assert "/.env" in SensitiveDetector.HIGH_PRIORITY_PATHS
        assert "/wp-config.php" in SensitiveDetector.HIGH_PRIORITY_PATHS

    def test_normalize_url_strips_query_and_fragment(self):
        from wvs.modules.sensitive.detector import SensitiveDetector

        normalized = SensitiveDetector._normalize_sensitive_url("http://example.com/page?q=1#frag")
        assert normalized == "http://example.com/page"

    def test_normalize_url_no_change(self):
        from wvs.modules.sensitive.detector import SensitiveDetector

        normalized = SensitiveDetector._normalize_sensitive_url("http://example.com/page")
        assert normalized == "http://example.com/page"

    def test_dedup_sensitive_vulns(self):
        from wvs.models import Confidence, Severity, Vulnerability, VulnerabilityType
        from wvs.modules.sensitive.detector import SensitiveDetector

        vulns = [
            # Identical url + severity + evidence -> dedup
            Vulnerability(
                type=VulnerabilityType.INFO_DISCLOSURE,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                url="http://example.com/.git/config",
                evidence="Sensitive file exposed: .git/config",
            ),
            Vulnerability(
                type=VulnerabilityType.INFO_DISCLOSURE,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                url="http://example.com/.git/config",
                evidence="Sensitive file exposed: .git/config",
            ),
            # Different url -> separate
            Vulnerability(
                type=VulnerabilityType.INFO_DISCLOSURE,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                url="http://other.com/.env",
                evidence="Sensitive file exposed: .env",
            ),
        ]
        deduped = SensitiveDetector._dedup_sensitive_vulns(vulns)
        assert len(deduped) == 2  # first two collapsed to 1, third stays

    def test_has_sensitive_content_git_config(self):
        from wvs.modules.sensitive.detector import SensitiveDetector

        det = SensitiveDetector.__new__(SensitiveDetector)
        assert det._has_sensitive_content("/.git/config", "[core]\n\trepositoryformatversion = 0") is True

    def test_has_sensitive_content_plain_html(self):
        from wvs.modules.sensitive.detector import SensitiveDetector

        det = SensitiveDetector.__new__(SensitiveDetector)
        assert det._has_sensitive_content("/.env", "<html>404 Not Found</html>") is False

    def test_get_path_severity_git(self):
        from wvs.modules.sensitive.detector import SensitiveDetector

        det = SensitiveDetector.__new__(SensitiveDetector)
        sev = det._get_path_severity("/.git/config")
        assert sev == Severity.CRITICAL

    def test_get_path_severity_backup(self):
        from wvs.modules.sensitive.detector import SensitiveDetector

        det = SensitiveDetector.__new__(SensitiveDetector)
        sev = det._get_path_severity("/backup.zip")
        assert sev == Severity.HIGH

    def test_get_path_severity_admin(self):
        from wvs.modules.sensitive.detector import SensitiveDetector

        det = SensitiveDetector.__new__(SensitiveDetector)
        sev = det._get_path_severity("/admin/")
        assert sev == Severity.MEDIUM


# =====================================================================
# WAF Detector
# =====================================================================


class TestWAFDetector:
    def test_get_info(self):
        from wvs.modules.waf.detector import WAFDetector

        info = WAFDetector.get_info()
        assert info.name == "waf"
        assert "waf" in info.tags or "cloudflare" in info.description.lower()

    def test_module_registration(self):
        assert "waf" in ModuleFactory.list_modules()

    def test_waf_signatures_cloudflare(self):
        from wvs.modules.waf.detector import WAF_SIGNATURES

        sig = next((s for name, s in WAF_SIGNATURES if name == "Cloudflare"), None)
        assert sig is not None
        assert "cf-ray" in sig.get("headers", {})

    def test_waf_signatures_aws(self):
        from wvs.modules.waf.detector import WAF_SIGNATURES

        sig = next((s for name, s in WAF_SIGNATURES if "AWS" in name), None)
        assert sig is not None
        assert any("x-amz" in k for k in sig.get("headers", {}))

    def test_match_all_signatures_cloudflare(self):
        from wvs.modules.waf.detector import WAFDetector

        det = WAFDetector.__new__(WAFDetector)
        baseline = {
            "status": 403,
            "headers": {"cf-ray": "abc123", "server": "cloudflare"},
            "text": "Attention Required! Cloudflare",
            "cookies": {},
        }
        matches = det._match_all_signatures(baseline)
        assert len(matches) > 0
        assert any("cloudflare" in m.lower() for m in matches)

    def test_match_all_signatures_no_waf(self):
        """Normal response -> no WAF detected."""
        from wvs.modules.waf.detector import WAFDetector

        det = WAFDetector.__new__(WAFDetector)
        baseline = {
            "status": 200,
            "headers": {"content-type": "text/html"},
            "text": "<html>Welcome</html>",
            "cookies": {},
        }
        matches = det._match_all_signatures(baseline)
        assert len(matches) == 0


# =====================================================================
# JSPathFinder Detector
# =====================================================================


class TestJSPathFinder:
    def test_get_info(self):
        from wvs.modules.jspathfinder.detector import JSPathfinderDetector

        info = JSPathfinderDetector.get_info()
        assert info.name == "jspathfinder"
        assert "js" in info.description.lower() or "path" in info.description.lower()

    def test_module_registration(self):
        assert "jspathfinder" in ModuleFactory.list_modules()

    def test_is_known_library_jquery(self):
        from wvs.modules.jspathfinder.detector import JSPathfinderDetector

        det = JSPathfinderDetector.__new__(JSPathfinderDetector)
        assert det._is_known_library("https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js") is True

    def test_is_known_library_vue(self):
        from wvs.modules.jspathfinder.detector import JSPathfinderDetector

        det = JSPathfinderDetector.__new__(JSPathfinderDetector)
        assert det._is_known_library("https://cdn.jsdelivr.net/npm/vue/dist/vue.js") is True

    def test_is_known_library_custom(self):
        from wvs.modules.jspathfinder.detector import JSPathfinderDetector

        det = JSPathfinderDetector.__new__(JSPathfinderDetector)
        assert det._is_known_library("https://app.example.com/static/js/custom.js") is False

    def test_scan_secrets_aws_key(self):
        from wvs.modules.jspathfinder.detector import JSPathfinderDetector

        det = JSPathfinderDetector.__new__(JSPathfinderDetector)
        js_content = 'const awsKey = "AKIAIOSFODNN7EXAMPLE";'
        secrets = det._scan_secrets(js_content, "test.js")
        types = [s["type"] for s in secrets]
        assert "AWS Access Key" in types

    def test_scan_secrets_private_key(self):
        from wvs.modules.jspathfinder.detector import JSPathfinderDetector

        det = JSPathfinderDetector.__new__(JSPathfinderDetector)
        js_content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."
        secrets = det._scan_secrets(js_content, "test.key")
        types = [s["type"] for s in secrets]
        assert any("Private Key" in t for t in types)

    def test_scan_secrets_empty(self):
        from wvs.modules.jspathfinder.detector import JSPathfinderDetector

        det = JSPathfinderDetector.__new__(JSPathfinderDetector)
        assert det._scan_secrets("console.log('hello');", "test.js") == []

    def test_extract_endpoints_api(self):
        from wvs.modules.jspathfinder.detector import JSPathfinderDetector

        det = JSPathfinderDetector.__new__(JSPathfinderDetector)
        det._current_target = "http://example.com"  # needed by _extract_endpoints
        det._seen_endpoints = set()  # needed by _extract_endpoints
        js = 'fetch("/api/v1/users/123"); axios.get("/api/config");'
        endpoints = det._extract_endpoints(js, "test.js")
        urls = [e["url"] for e in endpoints]
        assert any("/api/v1/users/123" in u for u in urls)
        assert any("/api/config" in u for u in urls)

    def test_extract_endpoints_skip_images(self):
        from wvs.modules.jspathfinder.detector import JSPathfinderDetector

        det = JSPathfinderDetector.__new__(JSPathfinderDetector)
        js = 'img.src = "/static/img/logo.png";'
        endpoints = det._extract_endpoints(js, "test.js")
        assert len(endpoints) == 0

    def test_scan_vuln_keywords_sqli(self):
        from wvs.modules.jspathfinder.detector import JSPathfinderDetector

        det = JSPathfinderDetector.__new__(JSPathfinderDetector)
        js = 'db.query("SELECT * FROM users WHERE id = " + userId);'
        vulns = det._scan_vuln_keywords(js, "test.js")
        assert len(vulns) > 0
        types = [v["type"] for v in vulns]
        assert any("SQL" in t or "sqli" in t.lower() for t in types)

    def test_scan_vuln_keywords_eval(self):
        from wvs.modules.jspathfinder.detector import JSPathfinderDetector

        det = JSPathfinderDetector.__new__(JSPathfinderDetector)
        js = 'eval("alert(" + userInput + ")");'
        vulns = det._scan_vuln_keywords(js, "test.js")
        assert len(vulns) > 0


# =====================================================================
# API Detector
# =====================================================================


class TestAPIDetector:
    def test_get_info(self):
        from wvs.modules.api.detector import APIDetector

        info = APIDetector.get_info()
        assert info.name == "api"

    def test_module_registration(self):
        assert "api" in ModuleFactory.list_modules()

    def test_is_public_path_login(self):
        from wvs.modules.api.detector import APIDetector

        assert APIDetector._is_public_path("http://example.com/login") is True

    def test_is_public_path_assets(self):
        from wvs.modules.api.detector import APIDetector

        assert APIDetector._is_public_path("http://example.com/assets/js/app.js") is True

    def test_is_public_path_health(self):
        from wvs.modules.api.detector import APIDetector

        assert APIDetector._is_public_path("http://example.com/health") is True

    def test_is_public_path_api_endpoint(self):
        from wvs.modules.api.detector import APIDetector

        assert APIDetector._is_public_path("http://example.com/api/users") is False

    def test_is_public_path_swagger(self):
        from wvs.modules.api.detector import APIDetector

        assert APIDetector._is_public_path("http://example.com/swagger/index.html") is True

    def test_is_public_path_case_insensitive(self):
        from wvs.modules.api.detector import APIDetector

        assert APIDetector._is_public_path("http://example.com/LOGIN") is True


# =====================================================================
# T2.1: ModuleFactory registry is the single source of truth for loading
# =====================================================================


class TestModuleRegistryT2_1:
    def test_all_expected_modules_registered(self):
        from wvs.modules import register_all_modules

        register_all_modules()
        registered = set(ModuleFactory.list_modules())

        expected = {
            "sqli",
            "xss",  # core
            "sensitive",
            "waf",
            "cmdi",
            "lfi",
            "ssrf",
            "xxe",  # lite
            "rce",
            "api",
            "js_analysis",
            "oa",
            "webshell",
            "weakpass",
            "subdomain",
            "jspathfinder",  # optional (registered, never auto-loaded)
        }
        assert expected.issubset(registered), registered - expected

    def test_core_modules(self):
        assert ModuleFactory.get_module_info("sqli").category == "core"
        assert ModuleFactory.get_module_info("xss").category == "core"

    def test_lite_modules(self):
        for name in (
            "sensitive",
            "waf",
            "cmdi",
            "lfi",
            "ssrf",
            "xxe",
            "rce",
            "api",
            "js_analysis",
            "oa",
            "webshell",
            "weakpass",
            "subdomain",
        ):
            info = ModuleFactory.get_module_info(name)
            assert info is not None, name
            assert info.category == "lite", name

    def test_optional_modules(self):
        info = ModuleFactory.get_module_info("jspathfinder")
        assert info is not None
        assert info.category == "optional"

    def test_scanner_derives_enabled_from_registry(self):
        # Default mode loads only core modules (sqli, xss).
        from wvs.config import ConfigManager
        from wvs.core import WAVScanner
        from wvs.core.session import HTTPPool

        config = ConfigManager()
        session = HTTPPool(config)
        scanner = WAVScanner(config, session)
        assert scanner._resolve_enabled_modules() == ["sqli", "xss"]

        # --all-modules mode loads core + lite and excludes optional modules.
        scanner._load_all_modules = True
        enabled = scanner._resolve_enabled_modules()
        assert "sqli" in enabled and "xss" in enabled
        assert "jspathfinder" not in enabled
        for name in (
            "sensitive",
            "waf",
            "cmdi",
            "lfi",
            "ssrf",
            "xxe",
            "rce",
            "api",
            "js_analysis",
            "oa",
            "webshell",
            "weakpass",
            "subdomain",
        ):
            assert name in enabled, name
