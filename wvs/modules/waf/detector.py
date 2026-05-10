"""
WAF (Web Application Firewall) 检测模块
检测常见 WAF：Cloudflare / AWS WAF / 阿里云 / ModSecurity 等
"""
import asyncio
import logging
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from ..base import DetectionModule, ModuleInfo, register_module
from ...models import ScanTarget


logger = logging.getLogger("wvs.module.waf")


class WAFType(Enum):
    """WAF 类型枚举"""
    CLOUDFLARE = "Cloudflare"
    AWS_WAF = "AWS WAF"
    ALIYUN = "Aliyun WAF"
    MODSECURITY = "ModSecurity"
    BARRACUDA = "Barracuda"
    F5_BIGIP = "F5 BIG-IP ASM"
    IMPERVA = "Imperva (Incapsula)"
    AKAMAI = "Akamai"
    FORTINET = "Fortinet"
    SONICWALL = "SonicWall"
    SUCKER_PUNCH = "Sucuri"
    GENERIC = "Generic WAF"
    UNKNOWN = "Unknown"


@dataclass
class WAFDetectionResult:
    """WAF 检测结果"""
    detected: bool
    waf_type: WAFType
    vendor: str
    confidence: float  # 0.0 - 1.0
    evidence: str
    bypass_suggestions: List[str]
    headers_detected: Dict[str, str]
    response_codes: List[int]


# WAF 特征库
WAF_SIGNATURES = {
    WAFType.CLOUDFLARE: {
        "headers": {
            "cf-ray": r".+",
            "cf-cache-status": r".+",
            "server": r"cloudflare",
            "report-to": r".*cloudflare.*",
        },
        "cookies": ["__cfduid", "__cf_bm", "cf_clearance"],
        "response": [
            r"cloudflare",
            r"cf-ray",
            r"Attention Required!.*Cloudflare",
            r"Checking your browser before accessing",
            r"Please Wait.*Cloudflare",
            r"ray ID:",
            r"cf-browser-verification",
        ],
        "block_status": [403, 503],
    },
    WAFType.AWS_WAF: {
        "headers": {
            "x-amz-cf-id": r".+",
            "x-amz-cf-pop": r".+",
            "server": r"CloudFront",
        },
        "cookies": ["AWSALB", "AWSALBAPP"],
        "response": [
            r"Request blocked",
            r"Access Denied.*AWS",
            r"aws waf",
            r"RequestId:",
        ],
        "block_status": [403],
    },
    WAFType.ALIYUN: {
        "headers": {
            "server": r"Tengine",
            "x-swift-cachetime": r".+",
            "x-swift-savetime": r".+",
        },
        "cookies": ["ALIGATOR"],
        "response": [
            r"aliyun",
            r"alibaba",
            r"error5xx\.aliyun",
            r"blocked by security",
            r"\u88ab\u62e6\u622a",  # 被拦截
        ],
        "block_status": [403, 405],
    },
    WAFType.MODSECURITY: {
        "headers": {
            "server": r"(?i)mod_security|modsecurity",
        },
        "cookies": [],
        "response": [
            r"(?i)ModSecurity",
            r"(?i)Not Acceptable.*ModSecurity",
            r"(?i)Access Denied.*ModSecurity",
            r"An error has occurred",
            r"Error code: 403",
            r"OWASP CRS",
            r"rules? triggered",
        ],
        "block_status": [403, 406, 500],
    },
    WAFType.BARRACUDA: {
        "headers": {
            "server": r"(?i)barracuda",
            "x-barracuda-waf": r".+",
        },
        "cookies": ["Barracuda"],
        "response": [
            r"(?i)barracuda",
            r"(?i)Barracuda Networks",
            r"Web Application Firewall",
        ],
        "block_status": [403],
    },
    WAFType.F5_BIGIP: {
        "headers": {
            "server": r"(?i)BigIP|F5",
            "x-wa-info": r".+",
        },
        "cookies": ["F5", "BIGipServer"],
        "response": [
            r"(?i)BigIP",
            r"(?i)F5 Networks",
            r"(?i)Application Security Module",
            r"Request Rejected",
            r"Support ID:",
        ],
        "block_status": [403],
    },
    WAFType.IMPERVA: {
        "headers": {
            "x-cdn": r"Incapsula",
            "x-iinfo": r".+",
            "server": r"Incapsula",
        },
        "cookies": ["incap_ses_", "visid_incap_", "nlbi_", "incap_"],
        "response": [
            r"(?i)Incapsula",
            r"(?i)Imperva",
            r"(?i)incident ID",
            r"You have been blocked",
            r"cdn\.incapsula\.com",
        ],
        "block_status": [403, 503],
    },
    WAFType.AKAMAI: {
        "headers": {
            "server": r"AkamaiGHost",
            "x-akamai-transformed": r".+",
        },
        "cookies": ["_abck", "ak_bmsc"],
        "response": [
            r"(?i)Akamai",
            r"Access Denied",
            r"Reference #",
        ],
        "block_status": [403],
    },
    WAFType.FORTINET: {
        "headers": {
            "server": r"(?i)FortiWeb|Fortinet",
        },
        "cookies": ["FORTIWAFSID"],
        "response": [
            r"(?i)FortiWeb",
            r"(?i)Fortinet",
            r"FortiGate",
            r"Application Blocked",
        ],
        "block_status": [403],
    },
    WAFType.SONICWALL: {
        "headers": {
            "server": r"(?i)SonicWall",
        },
        "cookies": ["SonicWAF"],
        "response": [
            r"(?i)SonicWall",
            r"(?i)Web Site Blocked",
            r"blocked by SonicWall",
        ],
        "block_status": [403],
    },
    WAFType.SUCKER_PUNCH: {
        "headers": {
            "server": r"(?i)Sucuri",
            "x-sucuri-id": r".+",
            "x-sucuri-cache": r".+",
        },
        "cookies": [],
        "response": [
            r"(?i)Sucuri",
            r"(?i)CloudProxy",
            r"Access Denied - Sucuri",
        ],
        "block_status": [403],
    },
}

# WAF 绕过建议
WAF_BYPASS_SUGGESTIONS = {
    WAFType.CLOUDFLARE: [
        "使用编码绕过：URL 编码、双重 URL 编码、Unicode 编码",
        "使用大小写混淆：SeLeCt, UnIoN",
        "使用注释填充：/**/SELECT/**/",
        "使用换行符或制表符分割关键字",
        "尝试 HTTP 方法变换：PUT、PATCH 替代 POST",
        "利用 Content-Type 变换：multipart/form-data",
    ],
    WAFType.AWS_WAF: [
        "使用分段传输编码",
        "利用 JSON 嵌套结构",
        "使用 Unicode 变体字符",
        "尝试修改 Content-Length",
        "利用 HTTP/2 特性",
    ],
    WAFType.ALIYUN: [
        "使用 GBK/GB2312 编码绕过 UTF-8 检测",
        "尝试宽字节注入：0x%bf%27",
        "使用注释符绕过关键字检测",
        "利用 URL 编码变形",
    ],
    WAFType.MODSECURITY: [
        "利用规则版本差异",
        "使用 HTTP 参数污染 (HPP)",
        "尝试分段请求绕过",
        "使用编码组合：Base64 + URL 编码",
        "利用 JSON/XML 格式变换",
    ],
    WAFType.GENERIC: [
        "使用编码技术：URL、双重URL、Unicode、Base64",
        "关键字混淆：大小写、注释、空白符",
        "协议层绕过：HTTP 方法变换、分块传输",
        "利用解析器差异：JSON、XML、序列化格式",
        "延迟请求或分片发送",
    ],
}


@register_module
class WAFDetector(DetectionModule):
    """WAF 检测模块"""

    @classmethod
    def get_info(cls) -> ModuleInfo:
        return ModuleInfo(
            name="waf",
            description="检测 Web 应用防火墙（Cloudflare/AWS/阿里云/ModSecurity 等）",
            author="WVS Team",
            version="1.0.0",
            enabled_by_default=True,
            tags=["waf", "reconnaissance", "security"],
        )

    def __init__(self, config=None, session=None):
        super().__init__(config)
        self.session = session
        self._result: Optional[WAFDetectionResult] = None

    async def _scan_impl(self, target: ScanTarget) -> list:
        """
        检测 WAF

        Returns:
            空列表（WAF 检测不是漏洞检测，结果存储在 self._result）
        """
        logger.info(f"[WAF] 开始检测: {target.url}")

        # 1. 正常请求获取基线
        baseline = await self._send_normal_request(target.url)
        if not baseline:
            logger.warning(f"[WAF] 无法获取基线响应: {target.url}")
            return []

        # 2. 分析响应头和内容
        detected_wafs = self._analyze_response(baseline)

        # 3. 发送恶意 payload 触发 WAF
        if not detected_wafs:
            detected_wafs = await self._probe_with_payloads(target.url, baseline)

        # 4. 确定最终结果
        if detected_wafs:
            best_match = max(detected_wafs, key=lambda x: x[2])  # 按 confidence 排序
            waf_type, evidence, confidence = best_match

            bypass_suggestions = WAF_BYPASS_SUGGESTIONS.get(
                waf_type, WAF_BYPASS_SUGGESTIONS[WAFType.GENERIC]
            )

            self._result = WAFDetectionResult(
                detected=True,
                waf_type=waf_type,
                vendor=waf_type.value,
                confidence=confidence,
                evidence=evidence,
                bypass_suggestions=bypass_suggestions,
                headers_detected=self._extract_detected_headers(baseline, waf_type),
                response_codes=[baseline.get("status_code", 0)],
            )
            logger.info(f"[WAF] 检测到: {waf_type.value} (置信度: {confidence:.2f})")
        else:
            self._result = WAFDetectionResult(
                detected=False,
                waf_type=WAFType.UNKNOWN,
                vendor="None",
                confidence=0.0,
                evidence="未检测到 WAF 特征",
                bypass_suggestions=[],
                headers_detected={},
                response_codes=[baseline.get("status_code", 200)],
            )
            logger.info("[WAF] 未检测到 WAF")

        return []  # WAF 检测不返回漏洞列表

    def get_result(self) -> Optional[WAFDetectionResult]:
        """获取检测结果"""
        return self._result

    async def _send_normal_request(self, url: str) -> Optional[Dict[str, Any]]:
        """发送正常请求"""
        try:
            if not self.session:
                logger.error("HTTPPool session not set")
                return None

            resp = await self.session.get(url)
            return {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "text": resp.text[:5000],
                "cookies": dict(resp.cookies),
            }
        except Exception as e:
            logger.debug(f"请求失败: {e}")
            return None

    def _analyze_response(self, response: Dict[str, Any]) -> List[Tuple[WAFType, str, float]]:
        """分析响应中的 WAF 特征"""
        detected = []
        headers = {k.lower(): v for k, v in response.get("headers", {}).items()}
        cookies = list(response.get("cookies", {}).keys())
        text = response.get("text", "").lower()
        status = response.get("status_code", 200)

        for waf_type, sigs in WAF_SIGNATURES.items():
            confidence = 0.0
            evidence_list = []

            # 检查响应头
            for header_name, pattern in sigs.get("headers", {}).items():
                header_lower = header_name.lower()
                if header_lower in headers:
                    if re.search(pattern, headers[header_lower], re.IGNORECASE):
                        confidence += 0.4
                        evidence_list.append(f"Header: {header_name}={headers[header_lower][:50]}")

            # 检查 Cookie
            for cookie_name in sigs.get("cookies", []):
                if any(cookie_name.lower() in c.lower() for c in cookies):
                    confidence += 0.3
                    evidence_list.append(f"Cookie: {cookie_name}")

            # 检查响应内容
            for pattern in sigs.get("response", []):
                if re.search(pattern, text, re.IGNORECASE):
                    confidence += 0.3
                    evidence_list.append(f"Response pattern: {pattern[:30]}")

            # 检查阻断状态码
            if status in sigs.get("block_status", []):
                confidence += 0.2
                evidence_list.append(f"Block status: {status}")

            if confidence > 0.3:
                detected.append((waf_type, "; ".join(evidence_list), min(confidence, 1.0)))

        return detected

    async def _probe_with_payloads(
        self, url: str, baseline: Dict[str, Any]
    ) -> List[Tuple[WAFType, str, float]]:
        """发送恶意 payload 尝试触发 WAF"""
        detected = []

        # 常见触发 WAF 的 payload
        test_payloads = [
            ("?id=1' OR '1'='1", "SQL injection test"),
            ("?id=1 UNION SELECT 1,2,3--", "UNION test"),
            ("?id=<script>alert(1)</script>", "XSS test"),
            ("?file=../../../etc/passwd", "LFI test"),
            ("?cmd=;cat /etc/passwd", "Command injection test"),
        ]

        for payload, desc in test_payloads[:3]:  # 只测试前 3 个
            test_url = url + payload if "?" not in url else url + "&" + payload[1:]

            try:
                if not self.session:
                    continue

                resp = await self.session.get(test_url)

                # 对比基线响应
                if self._is_waf_blocked(resp, baseline):
                    # 分析阻断页面特征
                    text = resp.text.lower()
                    for waf_type, sigs in WAF_SIGNATURES.items():
                        for pattern in sigs.get("response", []):
                            if re.search(pattern, text, re.IGNORECASE):
                                detected.append((
                                    waf_type,
                                    f"Triggered by {desc}",
                                    0.7,
                                ))
                                break

                    # 如果无法识别具体 WAF，标记为 Generic
                    if not detected:
                        detected.append((
                            WAFType.GENERIC,
                            f"Request blocked by unknown WAF (status: {resp.status_code})",
                            0.5,
                        ))
                    break  # 检测到一个就够了

            except Exception as e:
                logger.debug(f"Payload 测试失败: {e}")
                continue

        return detected

    def _is_waf_blocked(self, response: Any, baseline: Dict[str, Any]) -> bool:
        """判断是否被 WAF 阻断"""
        status = getattr(response, "status_code", 200)
        baseline_status = baseline.get("status_code", 200)

        # 状态码变化
        if status in [403, 406, 503]:
            if baseline_status not in [403, 406, 503]:
                return True

        # 响应长度大幅变化
        resp_len = len(getattr(response, "text", ""))
        baseline_len = len(baseline.get("text", ""))

        if baseline_len > 100 and resp_len > 0:
            ratio = resp_len / baseline_len
            if ratio < 0.3 or ratio > 3.0:
                return True

        return False

    def _extract_detected_headers(
        self, response: Dict[str, Any], waf_type: WAFType
    ) -> Dict[str, str]:
        """提取检测到的相关响应头"""
        headers = {k.lower(): v for k, v in response.get("headers", {}).items()}
        sigs = WAF_SIGNATURES.get(waf_type, {}).get("headers", {})

        detected_headers = {}
        for header_name in sigs.keys():
            header_lower = header_name.lower()
            if header_lower in headers:
                detected_headers[header_name] = headers[header_lower]

        return detected_headers
