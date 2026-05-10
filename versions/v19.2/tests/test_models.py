"""
数据模型测试
"""
import pytest
from datetime import datetime, timedelta

from wvs.models import (
    ScanTarget,
    ScanResult,
    Vulnerability,
    VulnerabilityType,
    Severity,
    Confidence,
)


class TestScanTarget:
    """ScanTarget模型测试"""
    
    def test_create_target(self):
        """测试创建扫描目标"""
        target = ScanTarget(url="http://example.com/test?id=1")
        
        assert target.url == "http://example.com/test?id=1"
    
    def test_target_headers(self):
        """测试目标请求头"""
        target = ScanTarget(
            url="http://api.example.com/data",
            headers={
                "Authorization": "Bearer token123",
                "Content-Type": "application/json",
            }
        )
        
        assert target.headers is not None
        assert "Authorization" in target.headers


class TestVulnerability:
    """Vulnerability模型测试"""
    
    def test_create_vulnerability(self):
        """测试创建漏洞"""
        vuln = Vulnerability(
            type=VulnerabilityType.SQL_INJECTION,
            title="SQL Injection in id parameter",
            url="http://example.com/product?id=1",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            evidence="' OR '1'='1",
            description="SQL injection vulnerability detected",
            module="sqli",
        )
        
        assert vuln.type == VulnerabilityType.SQL_INJECTION
        assert vuln.severity == Severity.HIGH
        assert vuln.confidence == Confidence.HIGH
    
    def test_vulnerability_to_dict(self):
        """测试漏洞序列化"""
        vuln = Vulnerability(
            type=VulnerabilityType.XSS,
            title="XSS vulnerability",
            url="http://example.com/search?q=test",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            evidence="<script>alert(1)</script>",
            description="Reflected XSS",
            module="xss",
        )
        
        data = vuln.to_dict()
        
        assert data["type"] == "cross_site_scripting"
        assert data["severity"] == "medium"
        assert data["title"] == "XSS vulnerability"


class TestScanResult:
    """ScanResult模型测试"""
    
    def test_create_result(self):
        """测试创建扫描结果"""
        target = ScanTarget(url="http://example.com")
        result = ScanResult(target=target)
        
        assert result.target == target
        assert result.vulnerabilities == []
        assert result.scan_time is not None
    
    def test_add_vulnerability(self):
        """测试添加漏洞"""
        target = ScanTarget(url="http://example.com")
        result = ScanResult(target=target)
        
        vuln = Vulnerability(
            type=VulnerabilityType.SQL_INJECTION,
            title="SQL Injection",
            url="http://example.com?id=1",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            evidence="test",
            description="test",
            module="sqli",
        )
        
        result.vulnerabilities.append(vuln)
        
        assert len(result.vulnerabilities) == 1
        assert result.vulnerabilities[0].type == VulnerabilityType.SQL_INJECTION
    
    def test_severity_count(self):
        """测试漏洞统计"""
        target = ScanTarget(url="http://example.com")
        result = ScanResult(target=target)
        
        # 添加不同严重程度的漏洞（使用关键字参数）
        result.vulnerabilities = [
            Vulnerability(
                type=VulnerabilityType.SQL_INJECTION,
                title="SQLi",
                url="http://example.com",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                description="test",
                module="sqli"
            ),
            Vulnerability(
                type=VulnerabilityType.XSS,
                title="XSS1",
                url="http://example.com",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                description="test",
                module="xss"
            ),
            Vulnerability(
                type=VulnerabilityType.XSS,
                title="XSS2",
                url="http://example.com",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                description="test",
                module="xss"
            ),
            Vulnerability(
                type=VulnerabilityType.INFO_DISCLOSURE,
                title="Info",
                url="http://example.com",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                description="test",
                module="sensitive"
            ),
        ]
        
        stats = result.severity_count
        
        assert stats.get("high", 0) == 1
        assert stats.get("medium", 0) == 2
        assert stats.get("low", 0) == 1
    
    def test_result_to_dict(self):
        """测试结果序列化"""
        target = ScanTarget(url="http://example.com")
        result = ScanResult(target=target)
        result.duration = timedelta(seconds=10)
        result.requests_made = 50
        result.endpoints_found = 20
        
        data = result.to_dict()
        
        assert "target" in data
        assert data["requests_made"] == 50
        assert data["endpoints_found"] == 20


class TestVulnerabilityType:
    """VulnerabilityType枚举测试"""
    
    def test_vuln_types(self):
        """测试漏洞类型枚举"""
        types = [
            VulnerabilityType.SQL_INJECTION,
            VulnerabilityType.XSS,
            VulnerabilityType.COMMAND_INJECTION,
            VulnerabilityType.LFI,
            VulnerabilityType.BROKEN_AUTH,
            VulnerabilityType.INFO_DISCLOSURE,
        ]
        
        for vtype in types:
            assert isinstance(vtype.value, str)


class TestSeverity:
    """Severity枚举测试"""
    
    def test_severity_values(self):
        """测试严重程度值"""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"
    
    def test_severity_order(self):
        """测试严重程度顺序"""
        # 验证严重程度的定义顺序
        assert list(Severity)[0] == Severity.INFO
        assert list(Severity)[4] == Severity.CRITICAL


class TestConfidence:
    """Confidence枚举测试"""
    
    def test_confidence_values(self):
        """测试置信度值"""
        assert Confidence.LOW.value == "low"
        assert Confidence.MEDIUM.value == "medium"
        assert Confidence.HIGH.value == "high"
        assert Confidence.CERTAIN.value == "certain"
