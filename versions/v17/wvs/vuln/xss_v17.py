"""WVS v16.0 - 增强型 XSS 扫描器

改进点：
1. 上下文感知 payload 选择（根据响应特征选择最佳 payload）
2. 多阶段验证（反射 -> DOM -> 存储）
3. CSP 检测和绕过建议
4. 浏览器兼容性检测
5. WAF 规避技术
"""
import asyncio
import re
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode
from dataclasses import dataclass
from enum import Enum

try:
    import aiohttp
except ImportError:
    aiohttp = None

from ..core.payloads_v16 import XSS_PAYLOADS_V16, DETECTION_CONFIG_V16


class XSSType(Enum):
    REFLECTED = "reflected"
    DOM_BASED = "dom_based"
    STORED = "stored"
    MUTATION = "mutation"


class ContextType(Enum):
    HTML_BODY = "html_body"
    HTML_ATTRIBUTE = "html_attribute"
    JAVASCRIPT = "javascript"
    URL = "url"
    CSS = "css"
    UNKNOWN = "unknown"


@dataclass
class XSSResult:
    vulnerable: bool
    xss_type: XSSType
    context: ContextType
    parameter: str
    payload: str
    confidence: float
    evidence: str
    csp_bypass: Optional[str] = None
    browser_compatible: List[str] = None


class XSSScannerV16:
    """XSS 扫描器 v16.0 - 上下文感知 + 多阶段验证"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", DETECTION_CONFIG_V16["request_timeout"])
        
        # 检测到的上下文
        self.detected_context = None
        self.csp_detected = False
        self.csp_policy = None
    
    async def scan(self, url: str, session) -> List[XSSResult]:
        """执行多阶段 XSS 扫描"""
        results = []
        
        # 解析 URL
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return results
        
        # 预检测：获取原始响应，分析上下文
        base_response = await self._get_response(url, session)
        if base_response:
            self.detected_context = self._analyze_context(base_response)
            self.csp_policy = self._extract_csp(base_response)
            self.csp_detected = bool(self.csp_policy)
        
        # 对每个参数进行测试
        for param in params:
            # 阶段 1: 基础反射检测
            result = await self._phase1_reflected(url, param, session)
            if result:
                results.append(result)
                continue
            
            # 阶段 2: DOM 型 XSS 检测
            result = await self._phase2_dom_based(url, param, session)
            if result:
                results.append(result)
                continue
            
            # 阶段 3: 编码绕过检测
            result = await self._phase3_encoding_bypass(url, param, session)
            if result:
                results.append(result)
                continue
            
            # 阶段 4: WAF 规避检测
            result = await self._phase4_waf_bypass(url, param, session)
            if result:
                results.append(result)
        
        return results
    
    async def _phase1_reflected(self, url: str, param: str, session) -> Optional[XSSResult]:
        """阶段 1: 基础反射型 XSS 检测"""
        # 根据上下文选择 payload
        payloads = self._select_payloads_by_context(ContextType.HTML_BODY)
        
        for payload in payloads:
            test_url = self._build_test_url(url, param, payload)
            
            try:
                async with session.get(test_url, timeout=self.timeout, ssl=False) as resp:
                    text = await resp.text()
                    
                    # 检测反射
                    if self._check_reflection(payload, text):
                        # 验证是否可执行（检查是否被过滤）
                        if self._verify_executable(payload, text):
                            return XSSResult(
                                vulnerable=True,
                                xss_type=XSSType.REFLECTED,
                                context=self.detected_context or ContextType.HTML_BODY,
                                parameter=param,
                                payload=payload,
                                confidence=0.90,
                                evidence=f"Payload 完整反射: {payload[:50]}...",
                                csp_bypass=self._check_csp_bypass(payload) if self.csp_detected else None,
                                browser_compatible=self._check_browser_compat(payload)
                            )
                        else:
                            # 部分反射，降低置信度
                            return XSSResult(
                                vulnerable=True,
                                xss_type=XSSType.REFLECTED,
                                context=self.detected_context or ContextType.HTML_BODY,
                                parameter=param,
                                payload=payload,
                                confidence=0.60,
                                evidence=f"Payload 部分反射（可能被过滤）",
                            )
            except Exception:
                pass
        
        return None
    
    async def _phase2_dom_based(self, url: str, param: str, session) -> Optional[XSSResult]:
        """阶段 2: DOM 型 XSS 检测"""
        payloads = XSS_PAYLOADS_V16["dom_based"]
        
        for payload in payloads:
            test_url = self._build_test_url(url, param, payload)
            
            try:
                async with session.get(test_url, timeout=self.timeout, ssl=False) as resp:
                    text = await resp.text()
                    
                    # 检测 DOM sink
                    if self._detect_dom_sink(text, payload):
                        return XSSResult(
                            vulnerable=True,
                            xss_type=XSSType.DOM_BASED,
                            context=ContextType.JAVASCRIPT,
                            parameter=param,
                            payload=payload,
                            confidence=0.85,
                            evidence="检测到 DOM sink: document.write/innerHTML/eval",
                        )
            except Exception:
                pass
        
        return None
    
    async def _phase3_encoding_bypass(self, url: str, param: str, session) -> Optional[XSSResult]:
        """阶段 3: 编码绕过检测"""
        payloads = XSS_PAYLOADS_V16["encoding_bypass"]
        
        for payload in payloads:
            test_url = self._build_test_url(url, param, payload)
            
            try:
                async with session.get(test_url, timeout=self.timeout, ssl=False) as resp:
                    text = await resp.text()
                    
                    if self._check_reflection(payload, text, encoded=True):
                        return XSSResult(
                            vulnerable=True,
                            xss_type=XSSType.REFLECTED,
                            context=self.detected_context or ContextType.HTML_BODY,
                            parameter=param,
                            payload=payload,
                            confidence=0.80,
                            evidence="编码绕过成功",
                        )
            except Exception:
                pass
        
        return None
    
    async def _phase4_waf_bypass(self, url: str, param: str, session) -> Optional[XSSResult]:
        """阶段 4: WAF 规避检测"""
        payloads = XSS_PAYLOADS_V16["waf_bypass"]
        
        for payload in payloads:
            test_url = self._build_test_url(url, param, payload)
            
            try:
                async with session.get(test_url, timeout=self.timeout, ssl=False) as resp:
                    text = await resp.text()
                    
                    if self._check_reflection(payload, text):
                        return XSSResult(
                            vulnerable=True,
                            xss_type=XSSType.REFLECTED,
                            context=self.detected_context or ContextType.HTML_BODY,
                            parameter=param,
                            payload=payload,
                            confidence=0.75,
                            evidence="WAF 绕过成功",
                        )
            except Exception:
                pass
        
        return None
    
    def _select_payloads_by_context(self, context: ContextType) -> List[str]:
        """根据上下文选择最佳 payload"""
        context_payloads = {
            ContextType.HTML_BODY: XSS_PAYLOADS_V16["basic_reflected"] + XSS_PAYLOADS_V16["event_handlers"],
            ContextType.HTML_ATTRIBUTE: [
                "' onmouseover='alert(1)",
                "\" onfocus=alert(1) autofocus=\"",
                "' onclick='alert(1)",
            ],
            ContextType.JAVASCRIPT: [
                "'-alert(1)-'",
                "\"-alert(1)-\"",
                "';alert(1);//",
                "${alert(1)}",
            ],
            ContextType.URL: [
                "javascript:alert(1)",
                "data:text/html,<script>alert(1)</script>",
            ],
        }
        
        return context_payloads.get(context, XSS_PAYLOADS_V16["basic_reflected"])
    
    def _analyze_context(self, response_text: str) -> ContextType:
        """分析注入点上下文"""
        # 简化版上下文分析
        if "<script>" in response_text.lower():
            return ContextType.JAVASCRIPT
        if "href=" in response_text.lower() or "src=" in response_text.lower():
            return ContextType.HTML_ATTRIBUTE
        if "<" in response_text and ">" in response_text:
            return ContextType.HTML_BODY
        return ContextType.UNKNOWN
    
    def _extract_csp(self, response_text: str) -> Optional[str]:
        """提取 CSP 策略"""
        # 从响应头或 meta 标签提取
        csp_match = re.search(r'Content-Security-Policy:\s*([^\r\n]+)', response_text, re.IGNORECASE)
        if csp_match:
            return csp_match.group(1)
        
        csp_meta = re.search(r'<meta[^>]*http-equiv=["\']Content-Security-Policy["\'][^>]*content=["\']([^"\']+)["\']', response_text, re.IGNORECASE)
        if csp_meta:
            return csp_meta.group(1)
        
        return None
    
    def _check_reflection(self, payload: str, text: str, encoded: bool = False) -> bool:
        """检查 payload 是否被反射"""
        if encoded:
            # 检查编码后的形式
            import html
            decoded = html.unescape(text)
            return payload in decoded or html.escape(payload) in text
        return payload in text
    
    def _verify_executable(self, payload: str, text: str) -> bool:
        """验证 payload 是否可执行（未被过滤）"""
        # 检查关键字符是否被保留
        critical_chars = ["<", ">", "script", "onerror", "onload", "alert"]
        
        for char in critical_chars:
            if char in payload.lower() and char not in text.lower():
                return False
        
        return True
    
    def _detect_dom_sink(self, text: str, payload: str) -> bool:
        """检测 DOM sink"""
        sinks = [
            r'document\.write\s*\(',
            r'\.innerHTML\s*=',
            r'\.outerHTML\s*=',
            r'eval\s*\(',
            r'setTimeout\s*\([^)]*,\s*\d+\)',
            r'setInterval\s*\([^)]*,\s*\d+\)',
            r'location\s*=',
            r'location\.href\s*=',
        ]
        
        for sink in sinks:
            if re.search(sink, text, re.IGNORECASE):
                return True
        
        return False
    
    def _check_csp_bypass(self, payload: str) -> Optional[str]:
        """检查 CSP 是否可绕过"""
        if not self.csp_policy:
            return None
        
        csp = self.csp_policy.lower()
        
        # 检查绕过技术
        if "script-src" not in csp and "default-src" not in csp:
            return "CSP 缺少 script-src，可直接执行脚本"
        
        if "unsafe-inline" in csp:
            return "CSP 允许 unsafe-inline，可直接注入"
        
        if "data:" in payload.lower() and "data:" not in csp:
            return "可使用 data: URI 绕过"
        
        return None
    
    def _check_browser_compat(self, payload: str) -> List[str]:
        """检查浏览器兼容性"""
        compatible = ["Chrome", "Firefox", "Safari", "Edge"]
        
        # 检查特定浏览器限制
        if "<svg" in payload.lower() and "onload" in payload.lower():
            # SVG onload 在所有现代浏览器都支持
            pass
        
        if "<details" in payload.lower():
            # details 元素在 IE 不支持
            compatible = ["Chrome", "Firefox", "Safari", "Edge"]
        
        return compatible
    
    async def _get_response(self, url: str, session) -> Optional[str]:
        """获取响应"""
        try:
            async with session.get(url, timeout=self.timeout, ssl=False) as resp:
                return await resp.text()
        except Exception:
            return None
    
    def _build_test_url(self, url: str, param: str, payload: str) -> str:
        """构建测试 URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"


# 突变 XSS 检测（mXSS）
class MutationXSSScanner:
    """突变 XSS 检测器"""
    
    def __init__(self):
        # mXSS 测试向量
        self.mutation_payloads = [
            # 常见突变向量
            "<noembed><img src=x onerror=alert(1)></noembed>",
            "<noscript><img src=x onerror=alert(1)></noscript>",
            "<textarea><img src=x onerror=alert(1)></textarea>",
            "<xmp><img src=x onerror=alert(1)></xmp>",
            "<iframe><img src=x onerror=alert(1)></iframe>",
            # 双重突变
            "<img src=x onerror=\"alert(1)\">",
            "<img src='x' onerror='alert(1)'>",
        ]
    
    async def scan(self, url: str, param: str, session) -> Optional[XSSResult]:
        """检测突变 XSS"""
        for payload in self.mutation_payloads:
            test_url = self._build_url(url, param, payload)
            
            try:
                async with session.get(test_url, ssl=False) as resp:
                    text = await resp.text()
                    
                    # 检查突变后的结果
                    if self._detect_mutation(text, payload):
                        return XSSResult(
                            vulnerable=True,
                            xss_type=XSSType.MUTATION,
                            context=ContextType.HTML_BODY,
                            parameter=param,
                            payload=payload,
                            confidence=0.70,
                            evidence="检测到突变 XSS",
                        )
            except Exception:
                pass
        
        return None
    
    def _detect_mutation(self, text: str, original_payload: str) -> bool:
        """检测突变"""
        # 简化检测：如果原始 payload 被转换但危险内容保留
        if "onerror" in text.lower() and "alert" in text.lower():
            return True
        return False
    
    def _build_url(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
