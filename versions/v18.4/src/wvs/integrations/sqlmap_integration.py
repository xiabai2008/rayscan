"""WVS v18.0 - SQLMap 集成模块

提供 SQLMap 的 Python API 调用，而不是直接调用命令行。
SQLMap 已经作为 Python 包安装。
"""
import os
import sys
import json
import time
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

# SQLMap Python API
try:
    import sqlmap
    from sqlmap.api import start
    SQLMAP_AVAILABLE = True
except ImportError:
    SQLMAP_AVAILABLE = False


@dataclass
class SQLMapVulnerability:
    """SQLMap 发现的漏洞"""
    url: str
    parameter: str
    injection_type: str  # boolean-based, error-based, time-based, stacked, union-based
    title: str
    payload: str
    severity: str  # critical, high, medium
    confidence: float  # 0.0 - 1.0
    dbms: str  # MySQL, PostgreSQL, etc.
    os: str  # Linux, Windows, etc.
    technology: str  # PHP, ASP.NET, etc.


class SQLMapIntegration:
    """SQLMap 集成器"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.level = self.config.get("level", 1)  # 1-5
        self.risk = self.config.get("risk", 1)  # 0-3
        self.timeout = self.config.get("timeout", 600)
        self.verbose = self.config.get("verbose", 1)
        self.batch = self.config.get("batch", True)
        
        # 输出目录
        self.output_dir = Path(self.config.get("output_dir", "reports/sqlmap"))
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def scan(self, url: str, method: str = "GET", 
             data: Dict = None, cookies: Dict = None,
             headers: Dict = None) -> List[SQLMapVulnerability]:
        """
        扫描 SQL 注入
        
        Args:
            url: 目标 URL
            method: HTTP 方法
            data: POST 数据
            cookies: Cookie 字典
            headers: 请求头字典
            
        Returns:
            发现的漏洞列表
        """
        if not SQLMAP_AVAILABLE:
            return self._fallback_scan_sync(url, method, data)
        
        print(f"[*] SQLMap scanning: {url}")
        
        # 创建临时配置文件
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ini', delete=False, 
                                          dir=self.output_dir) as f:
            config_file = f.name
        
        try:
            # 构造 SQLMap 命令参数
            cmd_args = [
                "-u", url,
                "--batch",  # 非交互模式
                "--level", str(self.level),
                "--risk", str(self.risk),
                "--timeout", str(self.timeout),
                "--output-dir", str(self.output_dir),
                "--results-file", str(self.output_dir / "results.json"),
            ]
            
            if method.upper() == "POST" and data:
                cmd_args.extend(["--data", "&".join(f"{k}={v}" for k, v in data.items())])
            
            if cookies:
                cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
                cmd_args.extend(["--cookie", cookie_str])
            
            if headers:
                for k, v in headers.items():
                    cmd_args.extend(["--header", f"{k}: {v}"])
            
            # 设置代理（如果有）
            if self.config.get("proxy"):
                cmd_args.extend(["--proxy", self.config["proxy"]])
            
            # 禁用特性加速
            if not self.config.get("crawl", True):
                cmd_args.append("--no-crawl")
            
            # 使用文本模式输出
            cmd_args.append("-v")  # Verbose
            
            # 执行 SQLMap
            from sqlmap.cmdline import parsecmdline
            from sqlmap.lib.utils import api
            import sqlmap.modules
            
            # 解析命令行
            opts, _ = parsecmdline(cmd_args)
            
            # 设置输出目录
            if hasattr(opts, 'outputDir'):
                opts.outputDir = str(self.output_dir)
            
            # 运行扫描
            start(opts)
            
            # 解析结果
            return self._parse_results()
            
        except Exception as e:
            print(f"[!] SQLMap error: {e}")
            return self._fallback_scan_sync(url, method, data)
        finally:
            if os.path.exists(config_file):
                os.unlink(config_file)
    
    def _fallback_scan_sync(self, url: str, method: str = "GET",
                           data: Dict = None) -> List[SQLMapVulnerability]:
        """
        后备扫描方案（同步版本）- 当 SQLMap 不可用时使用内置检测
        """
        print(f"[*] Using fallback SQLi detection for: {url}")
        
        # 导入扫描器
        from wvs.vuln.scanner_v18 import VulnerabilityScanner
        
        scanner = VulnerabilityScanner({"timeout": 10, "delay": 0.1})
        
        # 从 URL 中提取参数
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        vulns = []
        
        for param in params.keys():
            # 创建一个简单的检测
            import aiohttp
            import asyncio
            
            async def check_sqli():
                async with aiohttp.ClientSession() as session:
                    found = await scanner.test_sqli(session, url, param, method, "")
                    return found
            
            try:
                loop = asyncio.get_running_loop()
                # 在运行中的事件循环，使用 create_task
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    result = pool.submit(asyncio.run, check_sqli())
                    sqli_results = result.result()
            except RuntimeError:
                sqli_results = asyncio.run(check_sqli())
            
            for v in sqli_results:
                vulns.append(SQLMapVulnerability(
                    url=v.url,
                    parameter=v.parameter,
                    injection_type=v.type.replace("SQL Injection (", "").replace(")", "").lower(),
                    title=v.type,
                    payload=v.payload,
                    severity="critical" if v.severity == "critical" else "high",
                    confidence=v.confidence,
                    dbms="Unknown",
                    os="Unknown",
                    technology="Unknown"
                ))
        
        return vulns
    
    def _parse_results(self) -> List[SQLMapVulnerability]:
        """解析 SQLMap 输出"""
        vulns = []
        results_file = self.output_dir / "results.json"
        
        if results_file.exists():
            try:
                with open(results_file) as f:
                    data = json.load(f)
                    
                for item in data:
                    vulns.append(SQLMapVulnerability(
                        url=item.get("url", ""),
                        parameter=item.get("parameter", ""),
                        injection_type=item.get("type", "unknown"),
                        title=item.get("title", "SQL Injection"),
                        payload=item.get("payload", ""),
                        severity="critical",
                        confidence=item.get("confidence", 0.9),
                        dbms=item.get("dbms", "Unknown"),
                        os=item.get("os", "Unknown"),
                        technology=item.get("technology", "Unknown")
                    ))
            except Exception as e:
                print(f"[!] Parse error: {e}")
        
        return vulns
    
    def scan_targeted(self, url: str, param: str, method: str = "GET") -> Optional[SQLMapVulnerability]:
        """
        针对特定参数扫描
        """
        print(f"[*] Targeted SQLMap scan: {url} ? {param}")
        
        if not SQLMAP_AVAILABLE:
            return self._fallback_targeted(url, param, method)
        
        # 针对特定参数的优化配置
        config = self.config.copy()
        config["level"] = min(config["level"] + 1, 5)  # 提高检测级别
        config["risk"] = min(config["risk"] + 1, 3)  # 提高风险级别
        
        try:
            from sqlmap.cmdline import parsecmdline
            
            cmd_args = [
                "-u", url,
                "-p", param,
                "--batch",
                "--level", str(config["level"]),
                "--risk", str(config["risk"]),
                "--output-dir", str(self.output_dir),
            ]
            
            if method.upper() == "POST":
                cmd_args.extend(["--method", "POST"])
            
            opts, _ = parsecmdline(cmd_args)
            start(opts)
            
            results = self._parse_results()
            return results[0] if results else None
            
        except Exception as e:
            print(f"[!] Targeted scan error: {e}")
            return self._fallback_targeted(url, param, method)
    
    def _fallback_targeted(self, url: str, param: str, method: str) -> Optional[SQLMapVulnerability]:
        """后备目标扫描"""
        vulns = self._fallback_scan(url, method)
        for v in vulns:
            if v.parameter == param:
                return v
        return None


def quick_sqli_test(url: str, param: str = None) -> Dict[str, Any]:
    """
    快速 SQL 注入测试
    
    Args:
        url: 目标 URL
        param: 可选，指定参数
        
    Returns:
        测试结果字典
    """
    integration = SQLMapIntegration({"level": 1, "risk": 1})
    
    results = integration.scan(url)
    
    if results:
        return {
            "vulnerable": True,
            "vulnerabilities": [
                {
                    "type": v.injection_type,
                    "parameter": v.parameter,
                    "severity": v.severity,
                    "confidence": v.confidence,
                    "payload": v.payload[:100]
                }
                for v in results
            ]
        }
    else:
        return {
            "vulnerable": False,
            "vulnerabilities": []
        }
