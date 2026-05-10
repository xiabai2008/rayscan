"""
Tests for XXE and SSRF detection modules
"""
import pytest

from wvs.modules.xxe import XXEDetector
from wvs.modules.ssrf import SSRFDetector


class TestXXEDetector:
    """XXE detector tests"""

    def test_detector_info(self):
        """Test detector has correct info"""
        info = XXEDetector.get_info()
        assert info.name == "xxe"
        assert "xml" in info.description.lower()
        assert info.enabled_by_default is True

    def test_module_imports(self):
        """Test that module imports work correctly"""
        from wvs.modules.xxe.payloads import CLASSIC_PAYLOADS
        from wvs.modules.xxe.payloads import XXE_SUCCESS_PATTERNS
        
        assert len(CLASSIC_PAYLOADS) > 0
        assert len(XXE_SUCCESS_PATTERNS) > 0


class TestXXEPayloads:
    """XXE payload tests"""

    def test_payloads_exist(self):
        """Test that XXE payloads are defined"""
        from wvs.modules.xxe.payloads import (
            CLASSIC_PAYLOADS,
            PARAM_ENTITY_PAYLOADS,
            SOAP_PAYLOADS,
            SVG_PAYLOADS,
            WAF_BYPASS_PAYLOADS,
        )
        
        assert len(CLASSIC_PAYLOADS) > 0
        assert len(PARAM_ENTITY_PAYLOADS) > 0
        assert len(SOAP_PAYLOADS) > 0
        assert len(SVG_PAYLOADS) > 0
        assert len(WAF_BYPASS_PAYLOADS) > 0

    def test_payloads_contain_dtd(self):
        """Test that payloads contain DOCTYPE"""
        from wvs.modules.xxe.payloads import CLASSIC_PAYLOADS
        
        for payload in CLASSIC_PAYLOADS:
            assert "DOCTYPE" in payload or "ENTITY" in payload


class TestSSRFDetector:
    """SSRF detector tests"""

    def test_detector_info(self):
        """Test detector has correct info"""
        info = SSRFDetector.get_info()
        assert info.name == "ssrf"
        assert "request" in info.description.lower() or "forgery" in info.description.lower()
        assert info.enabled_by_default is True

    def test_module_imports(self):
        """Test that module imports work correctly"""
        from wvs.modules.ssrf.payloads import CLOUD_METADATA_PAYLOADS
        from wvs.modules.ssrf.payloads import SSRF_SUCCESS_PATTERNS
        
        assert len(CLOUD_METADATA_PAYLOADS) > 0
        assert len(SSRF_SUCCESS_PATTERNS) > 0


class TestSSRFPayloads:
    """SSRF payload tests"""

    def test_payloads_exist(self):
        """Test that SSRF payloads are defined"""
        from wvs.modules.ssrf.payloads import (
            BASIC_PAYLOADS,
            CLOUD_METADATA_PAYLOADS,
            INTERNAL_SERVICES,
            ENCODING_BYPASS_PAYLOADS,
        )
        
        assert len(BASIC_PAYLOADS) > 0
        assert len(CLOUD_METADATA_PAYLOADS) > 0
        assert len(INTERNAL_SERVICES) > 0
        assert len(ENCODING_BYPASS_PAYLOADS) > 0

    def test_cloud_metadata_endpoints(self):
        """Test that cloud metadata endpoints are valid URLs"""
        from wvs.modules.ssrf.payloads import CLOUD_METADATA_PAYLOADS
        
        for url in CLOUD_METADATA_PAYLOADS:
            assert url.startswith("http://")
            assert "169.254" in url or "metadata" in url
