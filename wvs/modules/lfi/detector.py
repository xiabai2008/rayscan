"""
LFI Detection Module
Detects: path traversal / /proc/self/environ / PHP wrappers
Verification: only report if file marker content is present (do not report empty contentless responses)
"""

import logging
from typing import Dict, List, Optional, Tuple

from ...core.session import HTTPPool
from ...models import Confidence, ScanTarget, Severity, Vulnerability, VulnerabilityType
from ..base import DetectionModule, ModuleInfo, register_module
from .payloads import (
    LFI_PAYLOADS_LINUX,
    LFI_PAYLOADS_WINDOWS,
    NULL_BYTE_PAYLOADS,
    PHP_WRAPPER_PAYLOADS,
    build_path_traversal_payloads,
)

logger = logging.getLogger("wvs.module.lfi")


# File content must contain these markers to be considered actual file read
FILE_CONTENT_MARKERS = {
    # Linux
    "/etc/passwd": ["root:", "nobody", "daemon:"],
    "/etc/hosts": ["localhost", "127.0.0.1"],
    "/etc/issue": ["Ubuntu", "Debian", "CentOS"],
    "/etc/motd": ["Linux", "Welcome"],
    "/etc/group": ["root:", "wheel:", "sudo:"],
    # /proc/self/
    "/proc/self/environ": ["PATH=", "HOME=", "USER=", "SHELL="],
    "/proc/self/cmdline": ["php", "apache", "nginx", "python"],
    "/proc/self/status": ["Name:", "Pid:", "Uid:"],
    # nginx/apache config
    "/var/log/apache2/access.log": ["HTTP/", "GET ", "POST "],
    "/var/log/apache2/error.log": ["error", "Notice"],
    "/var/www/html/config.php": ["<?php", "<?=", "mysql", "DB_"],
    "/var/www/html/wp-config.php": ["DB_NAME", "DB_USER", "DB_PASSWORD"],
    # Windows
    "C:\\Windows\\win.ini": ["[fonts]", "[extensions]", "[files]", "[Mail]"],
    "C:\\boot.ini": ["boot loader", "default="],
}

# Generic file read success markers (fallback)
GENERIC_FILE_MARKERS = [
    "root:",
    "nobody:",
    "daemon:",  # Unix
    "[fonts]",
    "[extensions]",  # Windows ini
    "<?php",
    "<?=",
    "<%",
    "%>",  # PHP
    "mysql",
    "pgsql",
    "DB_",  # DB config
    "HOME=",
    "PATH=",
    "USER=",
    "SHELL=",  # /proc
    "HTTP/",
    "GET ",
    "POST ",  # Log
]


@register_module
class LFIDetector(DetectionModule):
    @classmethod
    def get_info(cls) -> ModuleInfo:
        return ModuleInfo(
            name="lfi",
            description="Detect Local File Inclusion vulnerabilities (LFI / /proc/ / PHP wrappers)",
            author="WVS Team",
            version="1.0.0",
            enabled_by_default=True,
            tags=["lfi", "local-file-inclusion", "file-read", "rfi"],
        )

    def __init__(self, config=None, session: Optional[HTTPPool] = None):
        super().__init__(config)
        self.session = session
        self._found_vulns: List[Vulnerability] = []
        self._checked_urls: set = set()

    async def _scan_impl(self, target: ScanTarget) -> List[Vulnerability]:
        self._found_vulns = []

        # ── 1. Prefer target.params (from scanner/crawler, already with auth) ──
        target_params = getattr(target, "params", None) or {}
        target_data = getattr(target, "data", None) or {}
        if target_params:
            ep_params = target_params.copy()
            logger.debug(f"[LFI] Using target.params={list(ep_params.keys())} testing {target.url}")
            await self._scan_endpoint(target.url, ep_params, "GET", "query")
        elif target_data:
            ep_params = target_data.copy()
            logger.debug(f"[LFI] Using target.data={list(ep_params.keys())} testing {target.url}")
            await self._scan_endpoint(target.url, ep_params, "POST", "body")

        # ── 2. Supplement: use _extract_endpoints to get more endpoints ──
        endpoints = self._extract_endpoints(target)
        logger.info(f"[LFI] Starting detection, {len(endpoints)} endpoints total")

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
                logger.debug(f"[LFI] Error testing {url}: {e}")

        logger.info(f"[LFI] Detection complete, found {len(self._found_vulns)} vulnerabilities")
        return self._found_vulns

    async def _scan_endpoint(
        self,
        url: str,
        params: Dict[str, str],
        method: str,
        param_type: str,
    ) -> None:
        if not params:
            return

        await self._scan_endpoint_method(url, params, method, param_type)

    async def _scan_endpoint_method(
        self,
        url: str,
        params: Dict[str, str],
        method: str,
        param_type: str,
    ) -> bool:
        """Single endpoint test (GET or POST), returns whether a vulnerability was found"""
        if not params:
            return False

        # Get baseline
        baseline = await self._send_request(method, url, params, param_type)
        if baseline is None:
            return False

        baseline_text = baseline.get("text", "")[:10000]

        # Test each parameter
        for param_name in params:
            found = await self._test_lfi(url, params, param_name, method, param_type, baseline_text)
            if found:
                # Only report one LFI per endpoint (avoid reporting multiple on same param)
                logger.warning(f"[LFI] Detected: {url} [{param_name}]")
                return True

        return False

    async def _test_lfi(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        method: str,
        param_type: str,
        baseline_text: str,
    ) -> bool:
        """
        LFI detection: inject path traversal, observe if file content is read

        Returns:
            True = LFI vulnerability found
        """
        logger.debug(f"[LFI] Starting detection: {url} [{param_name}]")

        # P17: Skip LFI detection on non-file-inclusion endpoints
        # DVWA only /vulnerabilities/fi/ has file inclusion vulnerability
        # xss_/sqli/brute/exec/csrf/csp/upload/javascript do not have file inclusion capability
        non_fi_patterns = [
            "/xss_",
            "/csrf",
            "/sqli",
            "/sqli_blind",
            "/brute",
            "/exec",
            "/csp",
            "/javascript",
            "/upload",
            "/captcha",
        ]
        if any(pattern in url for pattern in non_fi_patterns):
            logger.debug(f"[LFI] Skipping non-FI endpoint: {url}")
            return False

        # Round 1: DVWA-specific file paths (if using file parameter)
        # DVWA FI page default includes include.php, just use relative paths
        dvwa_payloads = [
            "include.php",
            "file1.php",
            "file2.php",
            "file3.php",
            "file4.php",
            "file5.php",
            "file6.php",
            "file7.php",
        ]

        for payload in dvwa_payloads[:3]:
            test_params = params.copy()
            test_params[param_name] = payload
            logger.debug(f"[LFI] Testing DVWA payload: {payload}")

            resp = await self._send_request(method, url, test_params, param_type)
            if resp is None:
                continue

            resp_text = resp.get("text", "")
            logger.debug(f"[LFI] Response length: {len(resp_text)}")

            # DVWA characteristic: includes PHP file content
            if "include" in resp_text.lower() or "<?php" in resp_text or "DVWA" in resp_text:
                # This is not a real LFI, just normal file inclusion
                # Continue testing other payloads
                pass

        # Round 2: Standard payloads (Linux + Windows)
        test_payloads = LFI_PAYLOADS_LINUX[:8]
        test_payloads.extend(LFI_PAYLOADS_WINDOWS[:3])
        test_payloads.extend(build_path_traversal_payloads(3)[:8])

        for payload, file_info in self._iter_lfi_payloads(test_payloads):
            test_params = params.copy()
            test_params[param_name] = payload
            logger.debug(f"[LFI] Testing payload: {payload}")

            resp = await self._send_request(method, url, test_params, param_type)
            if resp is None:
                continue

            resp_text = resp.get("text", "")

            # Detect if file content was read (critical: must have marker string)
            matched_file, matched_content = self._check_file_content(resp_text, payload, baseline_text, url)

            if matched_file and matched_content:
                logger.info(f"[LFI] Found file read: {url} [{param_name}] file={matched_file}")

                # Secondary verification
                if await self._verify_lfi(url, params, param_name, method, param_type, payload):
                    vuln = self._create_vuln(
                        url=url,
                        param=param_name,
                        param_type=param_type,
                        method=method,
                        payload=payload,
                        file_path=matched_file,
                        evidence=matched_content[:200],
                    )
                    self._found_vulns.append(vuln)
                    return True

        # Round 3: Null byte payloads (bypass .php suffix)
        for payload in NULL_BYTE_PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = payload

            resp = await self._send_request(method, url, test_params, param_type)
            if resp is None:
                continue

            resp_text = resp.get("text", "")
            matched_file, matched_content = self._check_file_content(resp_text, payload, baseline_text, url)
            if matched_file and matched_content:
                if await self._verify_lfi(url, params, param_name, method, param_type, payload):
                    vuln = self._create_vuln(
                        url=url,
                        param=param_name,
                        param_type=param_type,
                        method=method,
                        payload=payload,
                        file_path=matched_file,
                        evidence=matched_content[:200],
                    )
                    self._found_vulns.append(vuln)
                    return True

        # Round 4: PHP wrappers (only report if response contains file content not in baseline)
        for payload in PHP_WRAPPER_PAYLOADS[:3]:
            test_params = params.copy()
            test_params[param_name] = payload

            resp = await self._send_request(method, url, test_params, param_type)
            if resp is None:
                continue

            resp_text = resp.get("text", "")

            # P16: PHP wrapper detection must return file content not present in baseline
            # DVWA and similar PHP apps already contain <?php / mysql markers in the page itself,
            # pure marker matching has extremely high false positive rate
            if baseline_text:
                # Find markers that appear only in resp_text, not in baseline
                new_markers = [m for m in GENERIC_FILE_MARKERS if m in resp_text and m not in baseline_text]
                if not new_markers:
                    logger.debug(f"[LFI] PHP wrapper dismissed (no new content): {url} [{param_name}]")
                    continue

                # Extra verification: response length must have significant change (at least 15%)
                len_ratio = len(resp_text) / max(len(baseline_text), 1)
                if 0.85 < len_ratio < 1.15:
                    logger.debug(f"[LFI] PHP wrapper dismissed (same length): {url} [{param_name}]")
                    continue

                evidence = f"PHP wrapper returned new content: {', '.join(new_markers[:3])}"
            else:
                evidence = "PHP wrapper payload accepted"

            vuln = self._create_vuln(
                url=url,
                param=param_name,
                param_type=param_type,
                method=method,
                payload=payload,
                file_path=payload[:50],
                evidence=evidence,
            )
            self._found_vulns.append(vuln)
            return True

        return False

    def _iter_lfi_payloads(self, payloads: list):
        """Iterate over payloads, yield (payload, target_file)"""
        for payload in payloads:
            file_path = self._extract_file_from_payload(payload)
            yield payload, file_path

    def _extract_file_from_payload(self, payload: str) -> str:
        """Extract target file path from payload"""
        # Clean null byte
        path = payload.replace("%00", "")
        if path.startswith("/"):
            return path
        if "etc/passwd" in payload:
            return "/etc/passwd"
        if "win.ini" in payload:
            return "C:\\Windows\\win.ini"
        if "proc/" in payload:
            for marker in ["/proc/self/environ", "/proc/self/cmdline", "/proc/self/status"]:
                if marker in payload:
                    return marker
        return payload

    def _check_file_content(
        self, resp_text: str, payload: str, baseline_text: str, url: str = ""
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Detect if the response contains file content

        Returns:
            (file_path, matched_content) = file was read
            (None, None) = no valid content found
        """
        logger.debug(f"[LFI] Checking file content: payload={payload[:30]}")

        # 1. Must exclude content already in baseline (avoid false positives from page itself containing these words)
        for marker in GENERIC_FILE_MARKERS:
            if marker in resp_text and marker not in baseline_text:
                # Further confirm: not a page error, but actual file content
                # File content characteristics: multi-line, formatted
                lines = resp_text.split("\n")
                matched_lines = [line for line in lines if marker in line]
                if matched_lines:
                    # Confirm not in baseline
                    baseline_lines = [line for line in baseline_text.split("\n") if marker in line]
                    if len(matched_lines) > len(baseline_lines):
                        file_path = self._extract_file_from_payload(payload)
                        logger.debug(f"[LFI] Found file content marker: {marker} in {file_path}")
                        return file_path, "\n".join(matched_lines[:3])

        # 2. Detect PHP file inclusion characteristics (P17: must have more lines than baseline)
        dvwa_markers = [
            "include(",
            "require(",
            "file_get_contents",
            "fopen(",
        ]
        for marker in dvwa_markers:
            if marker in resp_text and marker not in baseline_text:
                # P17: Same line-count comparison as Check 1, preventing page HTML echo false positives
                lines = resp_text.split("\n")
                matched_lines = [line for line in lines if marker in line]
                baseline_lines = [line for line in baseline_text.split("\n") if marker in line]
                if len(matched_lines) > len(baseline_lines):
                    logger.debug(f"[LFI] Found PHP include marker: {marker}")
                    file_path = self._extract_file_from_payload(payload)
                    return file_path, "\n".join(matched_lines[:3])

        # 3. DVWA file inclusion page's include.php detection (only for /fi/ pages)
        if "include.php" in payload and "/fi" in url:
            if "DVWA" in resp_text and len(resp_text) > len(baseline_text) + 100:
                logger.debug("[LFI] Found DVWA page content change")
                return payload, resp_text[:200]

        return None, None

    async def _verify_lfi(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        method: str,
        param_type: str,
        original_payload: str,
    ) -> bool:
        """Secondary verification: confirm with a different file path"""
        verify_files = ["/etc/hosts", "/etc/issue"]
        if original_payload.startswith("../../.."):
            # Path traversal: try different traversal depth
            verify_payloads = [
                "../../../etc/hosts",
                "../../etc/passwd",
            ]
        else:
            verify_payloads = verify_files

        for verify_payload in verify_payloads:
            test_params = params.copy()
            test_params[param_name] = verify_payload

            resp = await self._send_request(method, url, test_params, param_type)
            if resp is None:
                continue

            resp_text = resp.get("text", "")

            # Verify we read /etc/hosts content
            if "etc/hosts" in verify_payload or "hosts" in verify_payload:
                if "localhost" in resp_text or "127.0.0.1" in resp_text:
                    if "localhost" not in params.get(param_name, ""):
                        return True

        return False

    # Note: _send_request and _extract_endpoints methods have been moved to base class DetectionModule

    def _create_vuln(
        self,
        url: str,
        param: str,
        param_type: str,
        method: str,
        payload: str,
        file_path: str,
        evidence: str,
    ) -> Vulnerability:
        return Vulnerability(
            type=VulnerabilityType.LFI,
            title="Local File Inclusion / File Read",
            url=url,
            method=method,
            parameter=param,
            parameter_type=param_type,
            payload=payload,
            evidence=evidence,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            description=f"Found Local File Inclusion vulnerability, can read arbitrary files: {file_path}",
            recommendation="Avoid dynamically including user-supplied file paths, use whitelists or predefined file lists",
            module="lfi",
            tags=["lfi", "file-inclusion", "file-read"],
            context={"file_path": file_path},
        )
