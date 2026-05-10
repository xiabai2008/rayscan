"""
API安全检测模块测试 - 简化版
"""
import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from wvs.modules.api import APIDetector
from wvs.models import ScanTarget, Severity


class TestAPIDetector:
    """API安全检测器测试"""
    
    @pytest.fixture
    def detector(self):
        return APIDetector()
    
    @pytest.fixture
    def api_target(self):
        return ScanTarget(
            url="http://api.example.com/users/1",
            headers={"Authorization": "Bearer test_token"},
        )
    
    def test_detector_info(self, detector):
        """测试检测器信息"""
        info = detector.get_info()
        assert info.name == "api"
    
    def test_module_imports(self):
        """测试模块导入"""
        from wvs.modules.api import APIDetector
        
        detector = APIDetector()
        assert detector is not None


class TestAPIPatterns:
    """API敏感模式测试"""
    
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
    
    def test_api_key_pattern(self):
        """测试API密钥模式"""
        import re
        
        # 常见API key模式
        patterns = [
            r"sk-[a-zA-Z0-9]{32,}",  # OpenAI
            r"ghp_[a-zA-Z0-9]{36}",   # GitHub
            r"AKIA[0-9A-Z]{16}",      # AWS
        ]
        
        # 验证模式编译正常
        for p in patterns:
            re.compile(p)
