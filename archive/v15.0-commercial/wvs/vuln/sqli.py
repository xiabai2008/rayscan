"""SQL 注入漏洞扫描器"""
from typing import List, Dict
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

from .base import BaseVulnerabilityChecker, Vulnerability, Severity
from ..core.payloads_v3 import SQLI_PAYLOADS_V3, SQLI_ERROR_SIGNATURES_V3

try:
    import aiohttp
except ImportError:
    aiohttp = None


class SQLiScanner(BaseVulnerabilityChecker):
    """SQL 注入扫描器 - 基于错误检测和布尔盲注"""
    
    def __init__(self, config: Dict = None):
        super().__init__(config)
        self.payloads = SQLI_PAYLOADS_V3
        self.error_signatures = SQLI_ERROR_SIGNATURES_V3
    
    async def check(self, target: str, context: Dict) -> List[Vulnerability]:
        """执行 SQL 注入检测"""
        vulns = []
        urls = context.get("urls", [])
        forms = context.get("forms", [])
        session = context.get("session")
        
        if session is None:
            return vulns
        
        # 检测 URL 参数
        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param in params:
                for payload in self.payloads:
                    result = await self._test_sqli(url, param, payload, session)
                    if result:
                        vulns.append(result)
        
        # 检测表单
        for form in forms:
            for payload in self.payloads:
                result = await self._test_form_sqli(form, payload, session)
                if result:
                    vulns.append(result)
        
        return vulns
    
    async def _test_sqli(self, url: str, param: str, payload: str, session) -> Vulnerability:
        """测试 URL 参数 SQL 注入"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
        
        try:
            async with session.get(test_url, ssl=False) as resp:
                text = await resp.text()
                
                # 检查 SQL 错误信息
                for sig in self.error_signatures:
                    if sig.lower() in text.lower():
                        return Vulnerability(
                            name=f"SQL 注入 (参数: {param})",
                            severity=Severity.CRITICAL,
                            url=test_url,
                            payload=payload,
                            description=f"检测到 SQL 错误信息，参数 `{param}` 存在 SQL 注入",
                            remediation="使用参数化查询（Prepared Statements），禁止拼接 SQL 字符串",
                            confidence=0.95,
                        )
        except Exception:
            pass
        return None
    
    async def _test_form_sqli(self, form, payload: str, session) -> Vulnerability:
        """测试表单 SQL 注入"""
        inputs = form.inputs if hasattr(form, 'inputs') else form.get("inputs", [])
        data = {inp["name"]: payload for inp in inputs if inp.get("name")}
        
        if not data:
            return None
        
        try:
            method = form.method if hasattr(form, 'method') else form.get("method", "GET")
            action = form.action if hasattr(form, 'action') else form.get("action", "")
            if method == "POST":
                async with session.post(action, data=data, ssl=False) as resp:
                    text = await resp.text()
            else:
                async with session.get(action, params=data, ssl=False) as resp:
                    text = await resp.text()
            
            for sig in self.error_signatures:
                if sig.lower() in text.lower():
                    return Vulnerability(
                        name="SQL 注入 (表单)",
                        severity=Severity.CRITICAL,
                        url=action,
                        payload=payload,
                        description=f"表单提交检测到 SQL 错误信息",
                        remediation="使用参数化查询，对用户输入进行严格过滤",
                        confidence=0.95,
                    )
        except Exception:
            pass
        return None
