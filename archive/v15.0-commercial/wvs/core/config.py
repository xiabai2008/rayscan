"""Web Vulnerability Scanner - 核心配置模块"""
from dataclasses import dataclass, field
from typing import List, Optional
from pathlib import Path

from .auth import AuthConfig


@dataclass
class ScanConfig:
    """扫描配置类"""
    target: str
    port_range: tuple = (1, 1000)
    max_depth: int = 3
    max_urls: int = 100
    concurrency: int = 50
    timeout: float = 10.0
    threads: int = 100
    
    # 漏洞检测开关
    check_xss: bool = True
    check_sqli: bool = True
    check_csrf: bool = False
    check_info: bool = True
    check_traversal: bool = True
    
    # 认证配置
    auth: AuthConfig = field(default_factory=lambda: AuthConfig(auth_type="none"))
    
    # 输出配置
    output_dir: Path = field(default_factory=lambda: Path("reports"))
    output_format: str = "html"  # html, json, csv
    
    # 去重配置
    deduplicate: bool = True
    min_confidence: float = 0.5
    
    # POC 验证
    verify_poc: bool = False
    
    def __post_init__(self):
        self.output_dir = Path(self.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)


# 默认Payload配置
XSS_PAYLOADS = [
    {"type": "reflected", "payload": "<script>alert(1)</script>"},
    {"type": "reflected", "payload": "<img src=x onerror=alert(1)>"},
    {"type": "reflected", "payload": "<svg onload=alert(1)>"},
    {"type": "bypass", "payload": "<ScRiPt>alert(1)</sCrIpT>"},
    {"type": "bypass", "payload": "<iframe src='javascript:alert(1)'>"},
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    '" OR "1"="1" --',
    "1 UNION SELECT NULL--",
    "1 AND 1=1",
    "1 AND 1=2",
    "admin'--",
]

SQLI_ERROR_SIGNATURES = [
    "SQL syntax", "MySQL", "mysql_fetch",
    "syntax error", "SQLite", "PostgreSQL",
    "ORA-", "Microsoft SQL Server",
    "Warning: mysql_", "unterminated string",
]

SENSITIVE_PATHS = [
    ".git/config", ".env", ".env.bak",
    "config.php.bak", "phpinfo.php", "info.php",
    "admin/", "phpmyadmin/",
]
