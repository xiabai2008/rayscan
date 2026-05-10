"""POC 验证框架 - 漏洞可利用性验证"""
import asyncio
from typing import Dict, Optional
from urllib.parse import urlparse, parse_qs, urlencode

try:
    import aiohttp
except ImportError:
    aiohttp = None


class POCVerifier:
    """POC 验证器 - 验证漏洞是否真实可利用"""
    
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self.verified_results: Dict[str, bool] = {}
    
    async def verify_vulnerability(self, vuln_type: str, url: str, 
                                   param: str = None, payload: str = None,
                                   session=None) -> bool:
        """
        验证漏洞是否可利用
        
        Args:
            vuln_type: 漏洞类型 (xss, sqli, etc.)
            url: 漏洞 URL
            param: 参数名
            payload: 测试 payload
            session: aiohttp session
        
        Returns:
            bool: 是否验证成功
        """
        if session is None:
            return False
        
        cache_key = f"{vuln_type}:{url}:{param}:{payload}"
        if cache_key in self.verified_results:
            return self.verified_results[cache_key]
        
        result = False
        try:
            if vuln_type == "xss":
                result = await self._verify_xss(url, param, payload, session)
            elif vuln_type == "sqli":
                result = await self._verify_sqli(url, param, payload, session)
            elif vuln_type == "traversal":
                result = await self._verify_traversal(url, param, payload, session)
        except Exception:
            pass
        
        self.verified_results[cache_key] = result
        return result
    
    async def _verify_xss(self, url: str, param: str, payload: str, session) -> bool:
        """验证 XSS 漏洞 - 检查 payload 是否完整执行"""
        # 使用唯一标识符验证
        unique_id = f"wvs_{id(asyncio.current_task())}"
        verify_payload = payload.replace("alert(1)", f"alert('{unique_id}')")
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [verify_payload]
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
        
        try:
            async with session.get(test_url, timeout=self.timeout, ssl=False) as resp:
                text = await resp.text()
                # 检查 payload 是否完整反射
                if verify_payload in text:
                    # 进一步检查是否在正确的上下文
                    if self._is_xss_executable(text, verify_payload):
                        return True
        except Exception:
            pass
        return False
    
    async def _verify_sqli(self, url: str, param: str, payload: str, session) -> bool:
        """验证 SQL 注入 - 检查是否可以影响查询结果"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # 测试真条件
        params[param] = ["1 AND 1=1"]
        true_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
        
        # 测试假条件
        params[param] = ["1 AND 1=2"]
        false_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
        
        try:
            async with session.get(true_url, timeout=self.timeout, ssl=False) as true_resp:
                true_text = await true_resp.text()
                true_len = len(true_text)
            
            async with session.get(false_url, timeout=self.timeout, ssl=False) as false_resp:
                false_text = await false_resp.text()
                false_len = len(false_text)
            
            # 如果真假条件返回不同长度，说明注入成功
            if abs(true_len - false_len) > 100:
                return True
            
            # 检查内容差异
            if true_text != false_text:
                return True
                
        except Exception:
            pass
        return False
    
    async def _verify_traversal(self, url: str, param: str, payload: str, session) -> bool:
        """验证目录遍历 - 检查是否可以读取系统文件"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
        
        try:
            async with session.get(test_url, timeout=self.timeout, ssl=False) as resp:
                text = await resp.text()
                # 检查是否包含系统文件特征
                if "root:x:0:0:" in text or "[extensions]" in text:
                    return True
        except Exception:
            pass
        return False
    
    def _is_xss_executable(self, html: str, payload: str) -> bool:
        """检查 XSS payload 是否在可执行上下文"""
        # 简单检查：不在 script 标签内，不在属性值内被转义
        import re
        
        # 查找 payload 位置
        idx = html.find(payload)
        if idx == -1:
            return False
        
        # 检查是否在 script 标签内
        before = html[:idx]
        script_open = before.rfind("<script")
        script_close = before.rfind("</script>")
        
        if script_open > script_close:
            # 在 script 标签内，可执行
            return True
        
        # 检查是否在事件处理器内
        if re.search(r'on\w+=[\'"]', before[max(0, idx-50):idx]):
            return True
        
        # 检查是否在 HTML 标签内（非属性值）
        tag_open = before.rfind("<")
        tag_close = before.rfind(">")
        if tag_open > tag_close:
            # 在标签内
            return True
        
        return False
    
    def get_verification_summary(self) -> Dict:
        """获取验证统计"""
        total = len(self.verified_results)
        verified = sum(1 for v in self.verified_results.values() if v)
        return {
            "total": total,
            "verified": verified,
            "unverified": total - verified,
            "verification_rate": verified / total if total > 0 else 0,
        }
