"""
XXE (XML External Entity) Detector

Detects XML External Entity injection vulnerabilities by sending
malicious XML payloads and checking for file disclosure or error patterns.
Supports OOB (Out-of-Band) detection with automatic callback verification.
"""

import logging
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urljoin, urlparse

from ...core.session import HTTPPool
from ...models import Confidence, ScanTarget, Severity, Vulnerability, VulnerabilityType
from ..base import DetectionModule, ModuleInfo, register_module
from .payloads import (
    CLASSIC_PAYLOADS,
    PARAM_ENTITY_PAYLOADS,
    SOAP_PAYLOADS,
    SVG_PAYLOADS,
    WAF_BYPASS_PAYLOADS,
    XXE_SUCCESS_PATTERNS,
)

logger = logging.getLogger("wvs.module.xxe")


MODULE_INFO = ModuleInfo(
    name="xxe",
    description="XML External Entity injection detection",
    author="WVS Team",
    version="1.0.0",
    enabled_by_default=True,
    tags=["xxe", "xml", "injection", "file-disclosure"],
)


@register_module
class XXEDetector(DetectionModule):
    """XXE vulnerability detector"""

    XML_CONTENT_TYPES = [
        "application/xml",
        "text/xml",
        "application/soap+xml",
        "application/xml-dtd",
    ]

    XML_EXTENSIONS = [".xml", ".soap", ".wsdl", ".xsd", ".svg"]

    def __init__(self, config: Optional[Any] = None, session: Optional[HTTPPool] = None):
        super().__init__(config)
        self.session = session
        self._found_vulns: List[Vulnerability] = []
        self._checked_urls: set = set()

    @classmethod
    def get_info(cls) -> ModuleInfo:
        return MODULE_INFO

    # ----------------------------------------------------------
    # Core Entry Point
    # ----------------------------------------------------------

    async def _scan_impl(self, target: ScanTarget) -> List[Vulnerability]:
        """Scan target for XXE"""
        self._found_vulns = []

        # 1. Use target.params/data directly (from scanner/crawler)
        target_params = getattr(target, "params", None) or {}
        target_data = getattr(target, "data", None) or {}
        if target_params:
            await self._scan_endpoint(target.url, target_params.copy(), "GET", "query")
        elif target_data:
            await self._scan_endpoint(target.url, target_data.copy(), "POST", "body")

        # 2. Supplement endpoints
        endpoints = self._extract_endpoints(target)
        logger.info(f"[XXE] Starting detection, {len(endpoints)} endpoints total")

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
                logger.debug(f"[XXE] Error testing {url}: {e}")

        logger.info(f"[XXE] Detection complete, found {len(self._found_vulns)} vulnerabilities")
        return self._found_vulns

    # ----------------------------------------------------------
    # Main Detection Flow
    # ----------------------------------------------------------

    async def _scan_endpoint(
        self,
        url: str,
        params: Dict[str, str],
        method: str,
        param_type: str,
    ) -> None:
        """Run XXE detection on a single endpoint"""
        if not params:
            return

        # P10: merged payloads — limit to most effective ones
        all_payloads = CLASSIC_PAYLOADS[:4] + PARAM_ENTITY_PAYLOADS[:3] + SOAP_PAYLOADS[:2] + WAF_BYPASS_PAYLOADS[:2]

        for payload in all_payloads:
            try:
                # Try XXE payload on each parameter
                test_params = params.copy()
                for param_name in params:
                    test_params[param_name] = payload

                response = await self._send_request(method, url, test_params, param_type)
                if response is None:
                    continue

                if self._check_xxe_success(response.get("text", "")):
                    vuln = Vulnerability(
                        type=VulnerabilityType.XXE,
                        severity=Severity.HIGH,
                        url=url,
                        title="XML External Entity Injection (XXE)",
                        description="The application is vulnerable to XXE. Attackers can read arbitrary files from the server.",
                        evidence="File content detected after sending XXE payload",
                        payload=payload[:200] + "..." if len(payload) > 200 else payload,
                        method=method,
                        parameter=list(params.keys())[0] if params else None,
                        parameter_type=param_type,
                        context={"request_params": {k: v for k, v in test_params.items() if k in params}},
                        http_response=response.get("text", "")[:500],
                        confidence=Confidence.HIGH,
                    )
                    self._found_vulns.append(vuln)
                    logger.info(f"[XXE] Found vulnerability: {url}")
                    return  # Stop after finding one

            except Exception as e:
                logger.debug(f"[XXE] Error testing {url}: {e}")
                continue

        # P7: For POST endpoints, also send XML as the full request body
        # (many XXE endpoints expect XML in body, not as form params)
        if method.upper() == "POST":
            for payload in all_payloads[:6]:  # test first 6 payloads as full body
                try:
                    response = await self._send_xml_body(url, payload)
                    if response is None:
                        continue
                    if self._check_xxe_success(response.get("text", "")):
                        vuln = Vulnerability(
                            type=VulnerabilityType.XXE,
                            severity=Severity.HIGH,
                            url=url,
                            title="XML External Entity Injection (XXE)",
                            description="XXE via XML POST body.",
                            evidence="File content detected after sending XXE XML body",
                            payload=payload[:200] + "..." if len(payload) > 200 else payload,
                            method="POST",
                            parameter="(xml body)",
                            parameter_type="body",
                            confidence=Confidence.HIGH,
                        )
                        self._found_vulns.append(vuln)
                        logger.info(f"[XXE] Found vulnerability (full XML body): {url}")
                        return
                except Exception as e:
                    logger.debug(f"[XXE] XML body test error {url}: {e}")

        # OOB detection (if OOB manager is configured)
        if self._oob_manager:
            await self._test_oob_xxe(url, params, method, param_type)

    async def _test_oob_xxe(
        self,
        url: str,
        params: Dict[str, str],
        method: str,
        param_type: str,
    ) -> None:
        """
        OOB XXE detection: send payload with callback URL, wait for server to initiate outbound request

        Uses base class _test_oob_payload method for automatic callback verification
        """
        if not self._oob_manager:
            return

        # Build OOB payload templates
        oob_templates = [
            """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "{callback_url}">
  %xxe;
]>
<foo>test</foo>""",
            """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "{callback_url}">
]>
<foo>&xxe;</foo>""",
        ]

        vuln = await self._test_oob_payload(
            url=url,
            params=params,
            param_name=list(params.keys())[0] if params else "data",
            method=method,
            param_type=param_type,
            payload_templates=oob_templates,
            timeout=15.0,
        )

        if vuln:
            # Update vulnerability info
            vuln.title = "XXE (Out-of-Band)"
            vuln.description = "XXE vulnerability confirmed via OOB callback"
            self._found_vulns.append(vuln)
            logger.warning(f"[XXE] OOB callback confirmed: {url}")

    async def _send_request(
        self,
        method: str,
        url: str,
        params: Dict[str, str],
        param_type: str,
    ) -> Optional[Dict[str, Any]]:
        """Send HTTP request"""
        headers = {"Content-Type": "application/xml"}
        try:
            if method.upper() == "GET":
                resp = await self.session.get(url, params=params, headers=headers, timeout=10)
            else:
                resp = await self.session.post(url, data=params, headers=headers, timeout=10)
            if resp is None:
                return None
            return {"status_code": resp.status_code, "text": resp.text, "headers": dict(resp.headers)}
        except Exception:
            return None

    # ----------------------------------------------------------
    # Helper Methods
    # ----------------------------------------------------------

    def _extract_endpoints(self, target: ScanTarget) -> List[Dict]:
        """Extract endpoints from ScanTarget (including form parameters)"""
        endpoints = []
        url = target.url.rstrip("/")

        # 1. Parse URL query string
        parsed = urlparse(url)
        if parsed.query:
            params = {k: v[0] if v else "test" for k, v in parse_qs(parsed.query).items()}
            endpoints.append(
                {
                    "url": f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                    "params": params,
                    "method": "GET",
                    "param_type": "query",
                }
            )

        # 2. target.data / target.params
        target_data = getattr(target, "data", None) or {}
        if target_data:
            endpoints.append(
                {
                    "url": url,
                    "params": dict(target_data),
                    "method": "POST",
                    "param_type": "body",
                }
            )
        target_params = getattr(target, "params", None) or {}
        if target_params:
            endpoints.append(
                {
                    "url": url,
                    "params": dict(target_params),
                    "method": "GET",
                    "param_type": "query",
                }
            )

        # 3. Extract parameters from HTML forms (solves Metasploitable2 form injection point misses)
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
                    endpoints.append(
                        {
                            "url": form_url.rstrip("/"),
                            "params": params,
                            "method": method,
                            "param_type": "body" if method == "POST" else "query",
                        }
                    )

        # P10: Reduced synthetic XML endpoints — crawler discovers real ones
        xml_paths = [
            "/upload",
            "/import",
            "/api/xml",
            "/soap",
            "/webservice",
            "/xmlrpc",
            "/xml-rpc",
            "/services",
            "/api/upload",
            "/api/import",
            "/callback",
            "/webhook",
        ]
        base = parsed.scheme + "://" + parsed.netloc
        for path in xml_paths:
            full_url = base + path
            if full_url not in [e["url"] for e in endpoints]:
                endpoints.append(
                    {
                        "url": full_url,
                        "params": {"data": "test"},
                        "method": "POST",
                        "param_type": "body",
                    }
                )

        return endpoints

    async def _send_xml_body(self, url: str, body: str) -> Optional[Dict[str, Any]]:
        """P7: Send XML payload as raw POST body with Content-Type: application/xml."""
        headers = {"Content-Type": "application/xml"}
        try:
            resp = await self.session.post(url, content=body, headers=headers, timeout=10)
            if resp is None:
                return None
            return {"status_code": resp.status_code, "text": resp.text, "headers": dict(resp.headers)}
        except Exception:
            return None

    def _check_xxe_success(self, response_text: str) -> bool:
        """
        Check if XXE payload succeeded.

        Three detection modes:
        1. File content: response contains known file content patterns (e.g., /etc/passwd)
        2. Error-based: response shows XML parser processing our entity
        3. P7: OS file content markers (direct file read evidence)
        """
        text_lower = response_text.lower()

        # 1. File content disclosure (strongest signal)
        for pattern in XXE_SUCCESS_PATTERNS:
            if pattern.lower() in text_lower:
                return True

        # P10: OS file content markers — must be specific enough to avoid
        # matching standard HTML content (e.g. "ubuntu" in page footer)
        file_content_indicators = [
            # /etc/passwd patterns (highly specific)
            "root:x:0:0:",
            "nobody:x:",
            "daemon:x:",
            "bin:x:",
            ":/bin/bash",
            ":/sbin/nologin",
            # /etc/hosts (tab-separated)
            "127.0.0.1\tlocalhost",
            "::1\tlocalhost",
            # Windows ini files
            "[fonts]",
            "[extensions]",
            "[Mail]",
            "[boot loader]",
            "default=multi(0)",
            # /proc files (tab-separated key:value)
            "model name\t:",
            "MemTotal:",
            "SwapTotal:",
            "processor\t:",
            "vendor_id\t:",
        ]
        file_score = sum(1 for ind in file_content_indicators if ind.lower() in text_lower)
        if file_score >= 2:
            return True

        # 2. Entity-related errors (parser tried to resolve our entity)
        # P10: Each pattern must be XML-parser-specific — generic file-not-found
        # patterns like "cannot find" / "no such file" match any 404 page.
        entity_error_patterns = [
            "xmlparseentityref",
            "entity 'xxe'",
            "external entity",
            "failed to load external entity",
            "warning: domdocument::loadxml(",
            "simplexml_load_string():",
            "xml_parse():",
            "xml_parse_error",
            "xml parser",
            "xml external entity",
            "xml_parser_create",
        ]
        for pattern in entity_error_patterns:
            if pattern in text_lower:
                return True

        return False

    async def check_upload(self, target: ScanTarget, upload_url: str) -> List[Vulnerability]:
        """Check for XXE in file upload"""
        vulnerabilities = []

        for svg_payload in SVG_PAYLOADS:
            try:
                files = {"file": ("test.svg", svg_payload, "image/svg+xml")}
                resp = await self.session.post(upload_url, files=files, timeout=10)
                if resp and self._check_xxe_success(resp.text):
                    vuln = Vulnerability(
                        type=VulnerabilityType.XXE,
                        severity=Severity.HIGH,
                        url=upload_url,
                        title="XXE in File Upload (SVG)",
                        description="File upload endpoint vulnerable to XXE via SVG.",
                        evidence="File content detected after uploading malicious SVG",
                        payload=svg_payload[:200] + "..." if len(svg_payload) > 200 else svg_payload,
                        method="POST",
                        http_response=resp.text[:500],
                        confidence=Confidence.HIGH,
                    )
                    vulnerabilities.append(vuln)
                    break
            except Exception as e:
                logger.debug(f"[XXE] Upload test error: {e}")
                continue

        return vulnerabilities
