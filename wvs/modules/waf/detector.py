"""
WAF (Web Application Firewall) Detection Module
Detects common WAFs: Cloudflare / AWS WAF / Alibaba Cloud / ModSecurity and others
"""

import logging
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from ..base import DetectionModule, ModuleInfo, register_module
from ...models import ScanTarget


logger = logging.getLogger("wvs.module.waf")


class WAFType(Enum):
    """WAF type enumeration"""

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
    """WAF detection result"""

    detected: bool
    waf_type: WAFType
    vendor: str
    confidence: float  # 0.0 - 1.0
    evidence: str
    bypass_suggestions: List[str]
    headers_detected: Dict[str, str]
    response_codes: List[int]


# WAF signature database
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
            r"\u88ab\u62e6\u622a",  # Intercepted
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

# WAF bypass suggestions
WAF_BYPASS_SUGGESTIONS = {
    WAFType.CLOUDFLARE: [
        "Use encoding bypass: URL encoding, double URL encoding, Unicode encoding",
        "Use case obfuscation: SeLeCt, UnIoN",
        "Use comment padding: /**/SELECT/**/",
        "Use newline or tab characters to split keywords",
        "Try HTTP method transformation: PUT, PATCH instead of POST",
        "Leverage Content-Type transformation: multipart/form-data",
    ],
    WAFType.AWS_WAF: [
        "Use chunked transfer encoding",
        "Leverage JSON nested structures",
        "Use Unicode variant characters",
        "Try modifying Content-Length",
        "Leverage HTTP/2 features",
    ],
    WAFType.ALIYUN: [
        "Use GBK/GB2312 encoding to bypass UTF-8 detection",
        "Try wide byte injection: 0x%bf%27",
        "Use comment characters to bypass keyword detection",
        "Leverage URL encoding variations",
    ],
    WAFType.MODSECURITY: [
        "Exploit rule version differences",
        "Use HTTP Parameter Pollution (HPP)",
        "Try segmented request bypass",
        "Use encoding combinations: Base64 + URL encoding",
        "Leverage JSON/XML format transformation",
    ],
    WAFType.GENERIC: [
        "Use encoding techniques: URL, double URL, Unicode, Base64",
        "Keyword obfuscation: case, comments, whitespace",
        "Protocol layer bypass: HTTP method transformation, chunked transfer",
        "Exploit parser differences: JSON, XML, serialization formats",
        "Delay requests or fragment sending",
    ],
}


@register_module
class WAFDetector(DetectionModule):
    """WAF Detection Module"""

    @classmethod
    def get_info(cls) -> ModuleInfo:
        return ModuleInfo(
            name="waf",
            description="Detect Web Application Firewalls (Cloudflare/AWS/Aliyun/ModSecurity, etc.)",
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
        Detect WAF

        Returns:
            Empty list (WAF detection is not vulnerability detection, results stored in self._result)
        """
        logger.info(f"[WAF] Starting detection: {target.url}")

        # 1. Normal request to get baseline
        baseline = await self._send_normal_request(target.url)
        if not baseline:
            logger.warning(f"[WAF] Cannot get baseline response: {target.url}")
            return []

        # 2. Analyze response headers and content
        detected_wafs = self._analyze_response(baseline)

        # 3. Send malicious payloads to trigger WAF
        if not detected_wafs:
            detected_wafs = await self._probe_with_payloads(target.url, baseline)

        # 4. Determine final result
        if detected_wafs:
            best_match = max(detected_wafs, key=lambda x: x[2])  # Sort by confidence
            waf_type, evidence, confidence = best_match

            bypass_suggestions = WAF_BYPASS_SUGGESTIONS.get(waf_type, WAF_BYPASS_SUGGESTIONS[WAFType.GENERIC])

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
            logger.info(f"[WAF] Detected: {waf_type.value} (confidence: {confidence:.2f})")
        else:
            self._result = WAFDetectionResult(
                detected=False,
                waf_type=WAFType.UNKNOWN,
                vendor="None",
                confidence=0.0,
                evidence="No WAF signatures detected",
                bypass_suggestions=[],
                headers_detected={},
                response_codes=[baseline.get("status_code", 200)],
            )
            logger.info("[WAF] No WAF detected")

        return []  # WAF detection does not return vulnerability list

    def get_result(self) -> Optional[WAFDetectionResult]:
        """Get detection result"""
        return self._result

    async def _send_normal_request(self, url: str) -> Optional[Dict[str, Any]]:
        """Send normal request"""
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
            logger.debug(f"Request failed: {e}")
            return None

    def _analyze_response(self, response: Dict[str, Any]) -> List[Tuple[WAFType, str, float]]:
        """Analyze WAF signatures in response"""
        detected = []
        headers = {k.lower(): v for k, v in response.get("headers", {}).items()}
        cookies = list(response.get("cookies", {}).keys())
        text = response.get("text", "").lower()
        status = response.get("status_code", 200)

        for waf_type, sigs in WAF_SIGNATURES.items():
            confidence = 0.0
            evidence_list = []

            # Check response headers
            for header_name, pattern in sigs.get("headers", {}).items():
                header_lower = header_name.lower()
                if header_lower in headers:
                    if re.search(pattern, headers[header_lower], re.IGNORECASE):
                        confidence += 0.4
                        evidence_list.append(f"Header: {header_name}={headers[header_lower][:50]}")

            # Check cookies
            for cookie_name in sigs.get("cookies", []):
                if any(cookie_name.lower() in c.lower() for c in cookies):
                    confidence += 0.3
                    evidence_list.append(f"Cookie: {cookie_name}")

            # Check response content
            for pattern in sigs.get("response", []):
                if re.search(pattern, text, re.IGNORECASE):
                    confidence += 0.3
                    evidence_list.append(f"Response pattern: {pattern[:30]}")

            # Check block status codes
            if status in sigs.get("block_status", []):
                confidence += 0.2
                evidence_list.append(f"Block status: {status}")

            if confidence > 0.3:
                detected.append((waf_type, "; ".join(evidence_list), min(confidence, 1.0)))

        return detected

    async def _probe_with_payloads(self, url: str, baseline: Dict[str, Any]) -> List[Tuple[WAFType, str, float]]:
        """Send malicious payloads to try to trigger WAF"""
        detected = []

        # Common WAF-triggering payloads
        test_payloads = [
            ("?id=1' OR '1'='1", "SQL injection test"),
            ("?id=1 UNION SELECT 1,2,3--", "UNION test"),
            ("?id=<script>alert(1)</script>", "XSS test"),
            ("?file=../../../etc/passwd", "LFI test"),
            ("?cmd=;cat /etc/passwd", "Command injection test"),
        ]

        for payload, desc in test_payloads[:3]:  # Only test first 3
            test_url = url + payload if "?" not in url else url + "&" + payload[1:]

            try:
                if not self.session:
                    continue

                resp = await self.session.get(test_url)

                # Compare with baseline response
                if self._is_waf_blocked(resp, baseline):
                    # Analyze block page signatures
                    text = resp.text.lower()
                    for waf_type, sigs in WAF_SIGNATURES.items():
                        for pattern in sigs.get("response", []):
                            if re.search(pattern, text, re.IGNORECASE):
                                detected.append(
                                    (
                                        waf_type,
                                        f"Triggered by {desc}",
                                        0.7,
                                    )
                                )
                                break

                    # If unable to identify specific WAF, mark as Generic
                    if not detected:
                        detected.append(
                            (
                                WAFType.GENERIC,
                                f"Request blocked by unknown WAF (status: {resp.status_code})",
                                0.5,
                            )
                        )
                    break  # One detection is enough

            except Exception as e:
                logger.debug(f"Payload test failed: {e}")
                continue

        return detected

    def _is_waf_blocked(self, response: Any, baseline: Dict[str, Any]) -> bool:
        """Determine if request was blocked by WAF"""
        status = getattr(response, "status_code", 200)
        baseline_status = baseline.get("status_code", 200)

        # Status code change
        if status in [403, 406, 503]:
            if baseline_status not in [403, 406, 503]:
                return True

        # Large change in response length
        resp_len = len(getattr(response, "text", ""))
        baseline_len = len(baseline.get("text", ""))

        if baseline_len > 100 and resp_len > 0:
            ratio = resp_len / baseline_len
            if ratio < 0.3 or ratio > 3.0:
                return True

        return False

    def _extract_detected_headers(self, response: Dict[str, Any], waf_type: WAFType) -> Dict[str, str]:
        """Extract detected relevant response headers"""
        headers = {k.lower(): v for k, v in response.get("headers", {}).items()}
        sigs = WAF_SIGNATURES.get(waf_type, {}).get("headers", {})

        detected_headers = {}
        for header_name in sigs.keys():
            header_lower = header_name.lower()
            if header_lower in headers:
                detected_headers[header_name] = headers[header_lower]

        return detected_headers
