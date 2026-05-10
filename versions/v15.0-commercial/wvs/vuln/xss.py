"""XSS 漏洞扫描器"""
import asyncio
from typing import List, Dict
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

from .base import BaseVulnerabilityChecker, Vulnerability, Severity
from ..core.payloads_v3 import XSS_PAYLOADS_V3

try:
    import aiohttp
except ImportError:
    aiohttp = None


class XSSScanner(BaseVulnerabilityChecker):
    """反射型和存储型 XSS 扫描器"""
    
    def __init__(self, config: Dict = None):
        super().__init__(config)
        self.payloads = XSS_PAYLOADS_V3
    
    async def check(self, target: str, context: Dict) -> List[Vulnerability]:
        """执行 XSS 检测"""
        vulns = []
        forms = context.get("forms", [])
        urls = context.get("urls", [])
        session = context.get("session")
        
        if session is None:
            return vulns
        
        # 检测表单 XSS
        for form in forms:
            for payload_item in self.payloads:
                result = await self._test_form_xss(form, payload_item, session)
                if result:
                    vulns.append(result)
        
        # 检测 URL 参数反射
        for url in urls:
            parsed = urlparse(url)
            if parsed.query:
                for payload_item in self.payloads:
                    result = await self._test_reflected_xss(url, payload_item, session)
                    if result:
                        vulns.append(result)
        
        return vulns
    
    async def _test_form_xss(self, form, payload_item: Dict, session) -> Vulnerability:
        """测试表单 XSS"""
        payload = payload_item["payload"]
        inputs = form.inputs if hasattr(form, 'inputs') else form.get("inputs", [])
        data = {inp["name"]: payload for inp in inputs if inp.get("name")}
        
        try:
            method = form.method if hasattr(form, 'method') else form.get("method", "GET")
            action = form.action if hasattr(form, 'action') else form.get("action", "")
            if method == "POST":
                async with session.post(action, data=data, ssl=False) as resp:
                    text = await resp.text()
            else:
                async with session.get(action, params=data, ssl=False) as resp:
                    text = await resp.text()
            
            if payload in text and not self.is_false_positive(text):
                return Vulnerability(
                    name=f"XSS ({payload_item['type']})",
                    severity=Severity.HIGH,
                    url=action,
                    payload=payload,
                    description=f"检测到 {payload_item['type']} 型 XSS，payload 被反射到响应中",
                    remediation="对用户输入进行 HTML 转义，使用 Content-Security-Policy",
                    confidence=0.9,
                )
        except Exception:
            pass
        return None
    
    async def _test_reflected_xss(self, url: str, payload_item: Dict, session) -> Vulnerability:
        """测试 URL 参数反射 XSS"""
        payload = payload_item["payload"]
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return None
        
        for key in params:
            test_params = {k: [payload] if k == key else v for k, v in params.items()}
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
            
            try:
                async with session.get(test_url, ssl=False) as resp:
                    text = await resp.text()
                    if payload in text and not self.is_false_positive(text):
                        return Vulnerability(
                            name=f"反射型 XSS (参数: {key})",
                            severity=Severity.HIGH,
                            url=test_url,
                            payload=payload,
                            description=f"URL 参数 `{key}` 存在反射型 XSS",
                            remediation="对 URL 参数进行 HTML 实体编码",
                            confidence=0.85,
                        )
            except Exception:
                pass
        return None
