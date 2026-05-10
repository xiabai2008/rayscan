"""
pytest 配置文件
提供测试fixtures和通用配置
"""
import asyncio
import sys
from pathlib import Path
from typing import Generator

import pytest

# 添加项目路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from wvs.config import ConfigManager
from wvs.core.session import HTTPPool
from wvs.models import ScanTarget, Vulnerability, Severity, Confidence


@pytest.fixture
def event_loop():
    """创建事件循环"""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def config():
    """配置管理器fixture"""
    return ConfigManager()


@pytest.fixture
def sample_target():
    """示例扫描目标"""
    return ScanTarget(
        url="http://testphp.vulnweb.com/artists.php?artist=1",
        method="GET",
        params={"artist": "1"},
    )


@pytest.fixture
def sample_vulnerability():
    """示例漏洞"""
    return Vulnerability(
        type="sqli",
        title="SQL Injection",
        url="http://example.com?id=1",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        evidence="' OR '1'='1",
        description="SQL injection vulnerability in id parameter",
        module="sqli",
    )


@pytest.fixture
def mock_response():
    """模拟HTTP响应"""
    class MockResponse:
        def __init__(self, text="", status_code=200, headers=None):
            self.text = text
            self.status_code = status_code
            self.headers = headers or {}
            
        def json(self):
            import json
            return json.loads(self.text)
    
    return MockResponse


# 标记所有异步测试
def pytest_collection_modifyitems(items):
    for item in items:
        if asyncio.iscoroutinefunction(item.function):
            item.add_marker(pytest.mark.asyncio)
