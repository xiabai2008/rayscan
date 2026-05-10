"""
SSRF (Server-Side Request Forgery) Detector

Detects SSRF vulnerabilities by testing various URL inputs and checking
for internal service access or cloud metadata disclosure.
"""

import logging
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urljoin, urlparse

from ..base import DetectionModule, ModuleInfo
from ..base import register_module
from ...models import Vulnerability, VulnerabilityType, Severity, Confidence, ScanTarget
from ...core.session import HTTPPool
from .payloads import (
    BASIC_PAYLOADS,
    CLOUD_METADATA_PAYLOADS,
    INTERNAL_SERVICES,
    PROTOCOL_PAYLOADS,
    ENCODING_BYPASS_PAYLOADS,
    SSRF_SUCCESS_PATTERNS,
)


logger = logging.getLogger("wvs.module.ssrf")


MODULE_INFO = ModuleInfo(
    name="ssrf",
    description="Server-Side Request Forgery detection",
    author="WVS Team",
    version="1.0.0",
    enabled_by_default=True,
    tags=["ssrf", "network", "injection", "cloud"],
)


@register_module
class SSRFDetector(DetectionModule):
    """SSRF vulnerability detector"""

    SSRF_PARAM_PATTERNS = [
        "url", "uri", "path", "dest", "redirect", "return", "continue",
        "domain", "host", "server", "site", "link", "src", "source",
        "target", "fetch", "load", "proxy", "callback", "next", "goto",
        "location", "data", "file", "page", "image", "img", "resource",
        "endpoint",
    ]

    def __init__(self, config: Optional[Any] = None, session: Optional[HTTPPool] = None):
        super().__init__(config)
        self.session = session
        self._found_vulns: List[Vulnerability] = []
        self._checked_urls: set = set()

    @classmethod
    def get_info(cls) -> ModuleInfo:
        return MODULE_INFO

    # ----------------------------------------------------------
    # 核心入口
    # ----------------------------------------------------------

    async def _scan_impl(self, target: ScanTarget) -> List[Vulnerability]:
        """扫描目标，检测 SSRF"""
        self._found_vulns = []

        # 1. 直接用 target.params/data
        target_params = getattr(target, "params", None) or {}
        target_data = getattr(target, "data", None) or {}
        if target_params:
            await self._scan_endpoint(target.url, target_params.copy(), "GET", "query")
        elif target_data:
            await self._scan_endpoint(target.url, target_data.copy(), "POST", "body")

        # 2. 补充端点
        endpoints = self._extract_endpoints(target)
        logger.info(f"[SSRF] 开始检测，共 {len(endpoints)} 个端点")

        for endpoint in endpoints:
            url = endpoint["url"]
            params = endpoint.get("params", {})
            method = endpoint.get("method", "GET")
            param_type = endpoint.get("param_type", "query")

            if url in self._checked_urls:
                continue
            self._checked_urls.add(url)

            try:
                await self._scan_endpoint(url, params, method, param_type)
            except Exception as e:
                logger.debug(f"[SSRF] 检测 {url} 出错: {e}")

        logger.info(f"[SSRF] 检测完成，发现 {len(self._found_vulns)} 个漏洞")
        return self._found_vulns

    # ----------------------------------------------------------
    # 主要检测流程
    # ----------------------------------------------------------

    async def _scan_endpoint(
        self,
        url: str,
        params: Dict[str, str],
        method: str,
        param_type: str,
    ) -> None:
        """对单个端点进行 SSRF 检测"""
        if not params:
            return

        # P16: 获取 baseline 响应，用于过滤输入反射误报
        baseline_resp = await self._send_request(method, url, params.copy(), param_type)
        baseline_text = baseline_resp.get("text", "") if baseline_resp else ""

        all_payloads = (BASIC_PAYLOADS[:3] + CLOUD_METADATA_PAYLOADS[:3] +
                       INTERNAL_SERVICES[:3] + PROTOCOL_PAYLOADS[:2])

        for param_name, original_value in params.items():
            for payload in all_payloads:
                try:
                    test_params = params.copy()
                    test_params[param_name] = payload

                    response = await self._send_request(method, url, test_params, param_type)
                    if response is None:
                        continue

                    resp_text = response.get("text", "")

                    if self._check_ssrf_success(resp_text, payload):
                        # P16: 过滤输入反射误报
                        if self._is_input_reflection_ssrf(resp_text, baseline_text, payload):
                            logger.debug(f"[SSRF] 跳过反射误报: {url} [{param_name}] payload={payload[:30]}")
                            continue
                        # P18: file:// 协议读本地文件 → 这是 LFI 不是 SSRF
                        if payload.startswith("file://"):
                            logger.debug(f"[SSRF] 跳过 file:// (LFI): {url} [{param_name}]")
                            continue

                        severity = self._get_severity_for_response(resp_text)
                        evidence = self._build_ssrf_evidence(resp_text[:2000], payload, param_name)
                        conf = Confidence.HIGH if severity == Severity.CRITICAL else Confidence.MEDIUM
                        vuln = Vulnerability(
                            type=VulnerabilityType.SSRF,
                            severity=severity,
                            url=url,
                            title="Server-Side Request Forgery (SSRF)",
                            description="The application is vulnerable to SSRF. "
                            "Attackers can access internal services or cloud metadata.",
                            evidence=evidence,
                            payload=payload,
                            method=method,
                            context={"request_params": {k: v for k, v in test_params.items() if k in params}},
                            http_response=resp_text[:500],
                            confidence=conf,
                            parameter=param_name,
                        )
                        self._found_vulns.append(vuln)
                        logger.info(f"[SSRF] 发现漏洞: {url} (param: {param_name}, confidence={conf.value})")
                        return

                except Exception as e:
                    logger.debug(f"[SSRF] Error testing {url}: {e}")
                    continue

        # OOB 检测（如果配置了 OOB 管理器）
        if self._oob_manager:
            await self._test_oob_ssrf(url, params, method, param_type)

    async def _test_oob_ssrf(
        self,
        url: str,
        params: Dict[str, str],
        method: str,
        param_type: str,
    ) -> None:
        """
        OOB SSRF 检测：发送带回调 URL 的 payload，等待服务器发起外带请求
        """
        if not self._oob_manager or not params:
            return

        param_name = list(params.keys())[0]

        # SSRF OOB payload 模板
        oob_templates = [
            "{callback_url}",
            "http://{dns_url}",
            "http://{token}.{dns_url}",
        ]

        vuln = await self._test_oob_payload(
            url=url,
            params=params,
            param_name=param_name,
            method=method,
            param_type=param_type,
            payload_templates=oob_templates,
            timeout=15.0,
        )

        if vuln:
            vuln.title = "SSRF (Out-of-Band)"
            vuln.description = "SSRF vulnerability confirmed via OOB callback"
            self._found_vulns.append(vuln)
            logger.warning(f"[SSRF] OOB 回调确认: {url}")

    async def _send_request(
        self,
        method: str,
        url: str,
        params: Dict[str, str],
        param_type: str,
    ) -> Optional[Dict[str, Any]]:
        """发送 HTTP 请求"""
        try:
            if method.upper() == "GET":
                resp = await self.session.get(url, params=params, timeout=10)
            else:
                resp = await self.session.post(url, data=params, timeout=10)
            if resp is None:
                return None
            return {"status_code": resp.status_code, "text": resp.text, "headers": dict(resp.headers)}
        except Exception:
            return None

    # ----------------------------------------------------------
    # 辅助方法
    # ----------------------------------------------------------

    def _extract_endpoints(self, target: ScanTarget) -> List[Dict]:
        """从 ScanTarget 提取端点（含表单参数 + SSRF 特征参数）"""
        endpoints = []
        url = target.url.rstrip("/")
        parsed = urlparse(url)

        # 1. URL query params that look like SSRF targets
        if parsed.query:
            params = {k: v[0] if v else "test" for k, v in parse_qs(parsed.query).items()}
            endpoints.append({
                "url": f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                "params": params,
                "method": "GET",
                "param_type": "query",
            })

        # 2. target.data / target.params
        target_data = getattr(target, "data", None) or {}
        if target_data:
            endpoints.append({
                "url": url,
                "params": dict(target_data),
                "method": "POST",
                "param_type": "body",
            })
        target_params = getattr(target, "params", None) or {}
        if target_params:
            endpoints.append({
                "url": url,
                "params": dict(target_params),
                "method": "GET",
                "param_type": "query",
            })

        # 3. 从 HTML 表单提取参数
        html = getattr(target, "html", "") or ""
        if html:
            import re
            form_re = re.compile(
                r'<form[^>]*\baction\s*=\s*["\']([^"\']*)["\'][^>]*>',
                re.IGNORECASE,
            )
            method_re = re.compile(
                r'\bmethod\s*=\s*["\']([^"\']+)["\']',
                re.IGNORECASE,
            )
            input_re = re.compile(
                r'<input[^>]*\bname\s*=\s*["\']([^"\']+)["\'][^>]*(?:\bvalue\s*=\s*["\']([^"\']*)["\'])?',
                re.IGNORECASE,
            )

            for form_m in form_re.finditer(html):
                action = form_m.group(1).strip()
                form_start = form_m.start()
                form_end = html.find("</form>", form_start)
                if form_end == -1:
                    form_end = form_start + 2000
                form_body = html[form_start:form_end]
                method_m = method_re.search(form_m.group(0))
                method = method_m.group(1).upper() if method_m else "GET"

                if action.startswith("/"):
                    form_url = f"{parsed.scheme}://{parsed.netloc}{action}"
                elif action and not action.startswith("http"):
                    form_url = urljoin(url, action)
                else:
                    form_url = action or url

                params = {}
                for inp_m in input_re.finditer(form_body):
                    name, value = inp_m.group(1), inp_m.group(2) or "test"
                    if name:
                        params[name] = value

                if params and form_url.startswith(parsed.scheme):
                    endpoints.append({
                        "url": form_url.rstrip("/"),
                        "params": params,
                        "method": method,
                        "param_type": "body" if method == "POST" else "query",
                    })

        # P10: Reduced synthetic SSRF paths — crawler discovers real ones
        ssrf_paths = [
            ("/fetch", {"url": "http://127.0.0.1"}),
            ("/proxy", {"url": "http://127.0.0.1"}),
            ("/load", {"url": "http://127.0.0.1"}),
        ]
        base = parsed.scheme + "://" + parsed.netloc
        for path, default_params in ssrf_paths:
            full_url = base + path
            if full_url not in [e["url"] for e in endpoints]:
                endpoints.append({
                    "url": full_url,
                    "params": default_params,
                    "method": "GET",
                    "param_type": "query",
                })

        return endpoints

    @staticmethod
    def _is_input_reflection_ssrf(response_text: str, baseline_text: str, payload: str) -> bool:
        """
        P16: 检测 SSRF 是否是输入反射误报。
        
        如果去掉 payload 后的响应与 baseline 几乎一样，说明 payload 只是被回显了，
        application 并没有真的发起服务端请求。
        
        Returns:
            True = 这是误报（输入反射），应该跳过
            False = 可能是真正的 SSRF
        """
        if not payload or payload not in response_text:
            return False
        # 从响应中移除所有 payload 出现，再和 baseline 比较
        cleaned = response_text.replace(payload, "")
        # 归一化：去除空白差异后比较
        cleaned_norm = " ".join(cleaned.split())
        baseline_norm = " ".join(baseline_text.split()) if baseline_text else ""
        if not baseline_norm:
            return False
        # 长度相似度：如果 cleaned 和 baseline 长度差 < 5%，说明只是回显
        len_diff = abs(len(cleaned_norm) - len(baseline_norm))
        max_len = max(len(cleaned_norm), len(baseline_norm), 1)
        if len_diff / max_len < 0.05:
            return True
        # 内容相似度：简单重叠系数
        baseline_words = set(baseline_norm.split())
        if not baseline_words:
            return False
        cleaned_words = set(cleaned_norm.split())
        overlap = len(cleaned_words & baseline_words) / len(baseline_words)
        return overlap > 0.92

    def _check_ssrf_success(self, response_text: str, payload: str = None) -> bool:
        """
        Check if SSRF payload succeeded.

        Detection modes (ordered by confidence):
        1. Cloud metadata: response contains AWS/GCP/Azure metadata content
        2. Internal service fingerprint: /etc/passwd, win.ini, SSH banner, FTP header
        3. Connection error from SSRF attempt (weaker signal, must be specific to SSRF)
        4. Payload URL echoed verbatim in response (weakest, secondary verification needed)
        """
        text_lower = response_text.lower()

        # 1. Cloud metadata / internal service patterns (high confidence)
        for pattern in SSRF_SUCCESS_PATTERNS:
            if pattern.lower() in text_lower:
                return True

        # 2. Internal service file content (direct evidence of file read via SSRF)
        internal_file_indicators = [
            "root:x:0:0:", "nobody:x:", "daemon:x:",  # /etc/passwd
            "[fonts]", "[extensions]", "[Mail]",  # win.ini
        ]
        file_score = sum(1 for ind in internal_file_indicators if ind.lower() in text_lower)
        if file_score >= 1:
            return True

        if payload:
            # 3. Connection error specific to the SSRF target URL (server tried to connect)
            ssrf_error_keywords = [
                "connection refused", "connection timed out",
                "no route to host", "network is unreachable",
                "failed to open stream", "getaddrinfo",
                "name or service not known", "php_network_getaddresses",
            ]
            if any(kw in text_lower for kw in ssrf_error_keywords):
                return True

            # 4. Internal service banners (strong fingerprint)
            banner_indicators = [
                "ssh-",  # SSH protocol banner
                "220 ",  # FTP/SMTP greeting
                "redis_version:",  # Redis INFO response
            ]
            if any(ind in text_lower for ind in banner_indicators):
                return True

        return False

    def _check_ssrf_connection_error(self, response_text: str) -> bool:
        """
        Check if response shows connection error from attempted SSRF.
        This is a weaker signal but helps detect blind SSRF.
        """
        text_lower = response_text.lower()
        error_markers = [
            "connection refused", "connection timed out",
            "no route to host", "network is unreachable",
            "connection reset", "cannot connect",
            "could not connect", "unable to connect",
            "failed to open stream", "getaddrinfo",
            "name or service not known", "php_network_getaddresses",
        ]
        return any(m in text_lower for m in error_markers)

    @staticmethod
    def _build_ssrf_evidence(response_text: str, payload: str, param_name: str) -> str:
        """P9: Build specific SSRF evidence based on actual response content."""
        text_lower = response_text.lower()
        # Cloud metadata
        for marker, label in [
            ("secretaccesskey", "AWS SecretAccessKey"),
            ("accesskeyid", "AWS AccessKeyId"),
            ("ami-id", "AWS AMI-ID metadata"),
            ("instance-id", "AWS Instance-ID metadata"),
            ("compute/metadata", "Azure Compute Metadata"),
            ("azenvironment", "Azure Environment metadata"),
        ]:
            if marker in text_lower:
                return f"SSRF confirmed: {label} exposed via parameter '{param_name}' (payload: {payload})"
        # Internal service fingerprint
        for marker, label in [
            ("root:x:0:0:", "/etc/passwd content"),
            ("[extensions]", "win.ini content"),
            ("ssh-", "SSH banner"),
            ("220 ", "FTP/SMTP banner"),
            ("redis", "Redis response"),
        ]:
            if marker in text_lower:
                return f"SSRF confirmed: {label} accessed via parameter '{param_name}' (payload: {payload})"
        # Echoed payload
        if payload in response_text:
            return f"SSRF: payload URL echoed in response via parameter '{param_name}'"
        # Connection attempt evidence
        for keyword in ["connection refused", "connection timed out", "no route to host",
                        "failed to open stream", "getaddrinfo"]:
            if keyword in text_lower:
                return f"SSRF (blind): '{keyword}' via parameter '{param_name}' (payload: {payload})"
        return f"SSRF detected via parameter '{param_name}' (payload: {payload})"

    def _get_severity_for_response(self, response_text: str) -> Severity:
        """Determine severity based on what data was exposed"""
        text_lower = response_text.lower()

        if any(p in text_lower for p in ["secretaccesskey", "accesskeyid", "token"]):
            return Severity.CRITICAL
        if any(p in text_lower for p in ["ami-id", "instance-id", "computemetadata", "azEnvironment"]):
            return Severity.CRITICAL
        if "root:x:0:0:" in text_lower or "[extensions]" in text_lower:
            return Severity.HIGH

        return Severity.HIGH

    async def test_cloud_metadata(self, target: ScanTarget, endpoint: str) -> List[Vulnerability]:
        """Test for cloud metadata access specifically"""
        vulnerabilities = []
        url = urljoin(target.url, endpoint)

        for param in self.SSRF_PARAM_PATTERNS[:5]:
            for metadata_url in CLOUD_METADATA_PAYLOADS:
                try:
                    test_url = f"{url}?{param}={metadata_url}"
                    resp = await self.session.get(test_url, timeout=10)

                    if resp and self._check_ssrf_success(resp.text):
                        vuln = Vulnerability(
                            type=VulnerabilityType.SSRF,
                            severity=Severity.CRITICAL,
                            url=url,
                            title="Cloud Metadata Exposure via SSRF",
                            description="The application allows access to cloud metadata endpoints.",
                            evidence=f"Cloud metadata accessible via parameter '{param}'",
                            payload=metadata_url,
                            method="GET",
                            http_response=resp.text[:500],
                            confidence=Confidence.HIGH,
                        )
                        vulnerabilities.append(vuln)
                        break

                except Exception:
                    continue

        return vulnerabilities
