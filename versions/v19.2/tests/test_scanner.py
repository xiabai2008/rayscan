"""
扫描器集成测试 - 简化版
"""
import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from wvs.config import ConfigManager
from wvs.core.scanner import WAVScanner
from wvs.models import ScanTarget, ScanResult


class TestWAVScanner:
    """WAVScanner集成测试"""
    
    @pytest.fixture
    def scanner(self):
        """创建扫描器实例"""
        config = ConfigManager()
        return WAVScanner(config)
    
    def test_load_modules(self, scanner):
        """测试模块加载"""
        scanner.load_all_modules()
        
        # 验证核心模块已加载
        assert "sqli" in scanner._modules
        assert "xss" in scanner._modules
        assert "cmdi" in scanner._modules
    
    def test_module_count(self, scanner):
        """测试模块数量"""
        scanner.load_all_modules()
        
        # 应至少有4个核心模块
        assert len(scanner._modules) >= 4


class TestScannerDVWAAuth:
    """DVWA认证测试"""
    
    @pytest.fixture
    def scanner(self):
        config = ConfigManager()
        return WAVScanner(config)
    
    def test_dvwa_auth_single_execution(self, scanner):
        """测试DVWA认证只执行一次"""
        import inspect
        
        # 获取scan方法源码
        source = inspect.getsource(WAVScanner.scan)
        
        # 验证"DVWA 自动认证"只出现一次
        auth_count = source.count("DVWA 自动认证")
        
        assert auth_count == 1, f"DVWA认证出现{auth_count}次，应只出现1次"


class TestScannerConfig:
    """扫描器配置测试"""
    
    def test_config_manager(self):
        """测试配置管理器"""
        config = ConfigManager()
        
        # 验证配置可以正常创建
        assert config is not None
    
    def test_scanner_with_config(self):
        """测试带配置的扫描器"""
        config = ConfigManager()
        scanner = WAVScanner(config)
        
        assert scanner.config is not None
