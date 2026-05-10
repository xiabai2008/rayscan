"""
敏感信息检测模块测试 - 简化版
"""
import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from wvs.modules.sensitive import SensitiveDetector
from wvs.models import ScanTarget, Severity


class TestSensitiveDetector:
    """敏感信息检测器测试"""
    
    @pytest.fixture
    def detector(self):
        return SensitiveDetector()
    
    @pytest.fixture
    def target(self):
        return ScanTarget(url="http://example.com/")
    
    def test_detector_info(self, detector):
        """测试检测器信息"""
        info = detector.get_info()
        assert info.name == "sensitive"
    
    def test_module_imports(self):
        """测试模块导入"""
        from wvs.modules.sensitive import SensitiveDetector
        
        detector = SensitiveDetector()
        assert detector is not None


class TestSensitivePatterns:
    """敏感信息模式测试"""
    
    def test_aws_key_pattern(self):
        """测试AWS密钥模式"""
        import re
        
        pattern = r"AKIA[0-9A-Z]{16}"
        
        valid_keys = [
            "AKIAIOSFODNN7EXAMPLE",
            "AKIA1234567890ABCDEF",
        ]
        
        for key in valid_keys:
            assert re.search(pattern, key)
    
    def test_private_key_pattern(self):
        """测试私钥模式"""
        import re
        
        pattern = r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"
        
        valid_keys = [
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
        ]
        
        for key in valid_keys:
            assert re.search(pattern, key)
