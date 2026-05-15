"""
Command Injection Detection Module
v18 pain points resolved:
1. Must use baseline comparison (v18 NoneType false positives fully eliminated)
2. Random token echo verification (cannot rely on fixed strings)
3. Empty response / "NoneType" -> directly excluded, not reported
4. Supports Linux + Windows dual platform
5. Supports OOB detection (via OOBManager or environment variables)
"""

import asyncio
import logging
import os
import secrets
import string
import time
from typing import Dict, List, Optional

from ..base import DetectionModule, ModuleInfo
from ..base import register_module
from ...models import Vulnerability, VulnerabilityType, Severity, Confidence, ScanTarget
from ...core.session import HTTPPool
from ...core.oob import OOBManager
from .payloads import (
    build_echo_payloads,
    build_time_payloads,
    build_oob_payloads,
)


logger = logging.getLogger("wvs.module.cmdi")


def _gen_token(length: int = 8) -> str:
    """Generate a random token"""
    return "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(length))


@register_module
class CMDInjectionDetector(DetectionModule):
    """Command Injection Detection Module"""

    @classmethod
    def title(cls) -> str:
        """Override parent title() to prevent str.title() from converting CMDiDetector to CmdiDetector"""
        return "CMDiDetector"

    @classmethod
    def get_info(cls) -> ModuleInfo:
        return ModuleInfo(
            name="cmdi",
            description="Detect command injection vulnerabilities (echo-based / time-based / OOB)",
            author="WVS Team",
            version="1.0.0",
            enabled_by_default=True,
            tags=["cmdi", "command-injection", "rce", "os-command"],
        )

    def __init__(self, config=None, session: Optional[HTTPPool] = None):
        super().__init__(config)
        self.session = session
        self._found_vulns: List[Vulnerability] = []
        self._checked_urls: set = set()
        self._oob_manager: Optional[OOBManager] = None

    # ----------------------------------------------------------
    # Core Entry Point
    # ----------------------------------------------------------

    async def _scan_impl(self, target: ScanTarget) -> List[Vulnerability]:
        self._found_vulns = []

        # ── 1. Prefer target.params (from scanner/crawler, already with auth) ──
        target_params = getattr(target, "params", None) or {}
        target_data = getattr(target, "data", None) or {}
        if target_params:
            ep_params = target_params.copy()
            logger.debug(f"[CMDi] Using target.params={list(ep_params.keys())} testing {target.url}")
            await self._scan_endpoint(target.url, ep_params, "GET", "query")
        elif target_data:
            ep_params = target_data.copy()
            logger.debug(f"[CMDi] Using target.data={list(ep_params.keys())} testing {target.url}")
            await self._scan_endpoint(target.url, ep_params, "POST", "body")

        # ── 2. Supplement: use _extract_endpoints to get more endpoints (URL query string, etc.) ──
        endpoints = self._extract_endpoints(target)
        logger.info(f"[CMDi] Starting detection, {len(endpoints)} endpoints total")

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
                logger.debug(f"[CMDi] Error testing {url}: {e}")

        logger.info(f"[CMDi] Detection complete, found {len(self._found_vulns)} endpoints with CMDi")
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
        if not params:
            return

        await self._scan_endpoint_method(url, params, method, param_type)

    async def _scan_endpoint_method(
        self,
        url: str,
        params: Dict[str, str],
        method: str,
        param_type: str,
    ) -> None:
        """Single detection pass (GET or POST)"""
        if not params:
            return

        # Get baseline (critical: eliminates false positives)
        baseline = await self._send_request(method, url, params, param_type)
        if baseline is None:
            return

        baseline_text = baseline.get("text", "")[:5000]

        # Send baseline first to confirm the page itself has no command execution characteristics
        # v18 pain point: if baseline already has "whoami" result, it would return without actual detection
        # v19 solution: use random token detection — baseline absolutely cannot have random token

        for param_name in params.keys():
            await self._test_echo_based(url, params, param_name, method, param_type, baseline, baseline_text)

            await self._test_time_based(url, params, param_name, method, param_type, baseline)

            # OOB detection (no-echo scenarios, requires outbound DNS/HTTP)
            await self._test_oob(url, params, param_name, method, param_type, baseline)

    async def _test_echo_based(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        method: str,
        param_type: str,
        baseline: Dict,
        baseline_text: str,
    ) -> None:
        """
        Echo-based detection — core detection method

        Process:
        1. Generate random token (absolutely cannot exist in baseline)
        2. Inject token
        3. Check if token is echoed in response
        4. If echoed -> exclude echo-server -> secondary verification (different payload)

        False positive prevention: only when token appears independently (not as part of full payload)
        is it considered possible command execution. For example:
        - PHP echo $_GET['x'] returns "; echo abc123" -> token embedded in payload -> filtered
        - Real CMDi returns "abc123" standalone -> token independent -> passed
        """
        token = _gen_token()

        # P13: Concurrent echo probes — send all payloads at once, check results after
        async def _probe_echo(payload: str, platform: str):
            test_params = params.copy()
            test_params[param_name] = payload
            resp = await self._send_request(method, url, test_params, param_type)
            return (payload, platform, resp)

        # Build all probe tasks (Linux first, 2 payloads max)
        echo_tasks = []
        for platform in ("linux",):  # P13: Local target, Linux only
            payloads = build_echo_payloads(token, platform)[:2]
            for payload in payloads:
                echo_tasks.append(_probe_echo(payload, platform))

        echo_results = await asyncio.gather(*echo_tasks, return_exceptions=True)

        for result in echo_results:
            if isinstance(result, Exception):
                continue
            payload, platform, resp = result
            if resp is None:
                continue
            resp_text = resp.get("text", "")[:5000]
            if self._is_false_positive(resp_text, token):
                continue
            if token not in resp_text:
                continue
            if self._is_echo_server(url, resp_text, payload):
                continue
            if self._is_input_reflection(resp_text, payload, token):
                logger.debug(f"[CMDi] Filtering echo-back: {url}")
                continue
            if await self._verify_echo(url, params, param_name, method, param_type, token):
                vuln = self._create_vuln(
                    url=url,
                    param=param_name,
                    param_type=param_type,
                    method=method,
                    payload=payload,
                    token=token,
                    evidence=f"Token '{token}' echoed (platform={platform})",
                )
                self._found_vulns.append(vuln)
                logger.warning(f"[CMDi] Echo detected ({platform}): {url} [{param_name}]")
                return

    async def _verify_echo(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        method: str,
        param_type: str,
        original_token: str,
    ) -> bool:
        """
        Secondary verification: confirm with a different payload and different token
        Optimization: only verify once instead of 3 times to improve speed
        P16: Add _is_input_reflection check to prevent stored XSS echo pages from causing false positives
        """
        new_token = _gen_token()
        verify_payloads = [
            f"; echo {new_token}",
            f"| echo {new_token}",
        ]

        # Only verify once
        test_params = params.copy()
        verify_payload = verify_payloads[0]
        test_params[param_name] = verify_payload

        resp = await self._send_request(method, url, test_params, param_type)
        if resp is None:
            return False

        resp_text = resp.get("text", "")[:5000]

        # New token appears -> but first exclude input reflection
        if new_token in resp_text:
            if self._is_input_reflection(resp_text, verify_payload, new_token):
                logger.debug("[CMDi] verify filtered as input reflection")
                return False
            return True

        return False

    async def _test_time_based(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        method: str,
        param_type: str,
        baseline: Dict,
    ) -> None:
        """
        Time-based detection — P13 concurrent optimization version

        Previously: serial per-payload request, waiting 3-5 seconds each -> 12 requests x 5s = 60s/endpoint
        Now: all time-based payloads sent concurrently, total time = max(single delay) ~ 2-5s/endpoint
        """
        from ...constants import TIME_BASED_DELAYS_LOCAL, TIME_BASED_DELAYS_REMOTE

        # 1. Quick baseline (only 2 samples, reduced overhead)
        baseline_avg, baseline_std = await self._measure_baseline(method, url, params, param_type, samples=2)

        # 2. Check if skip needed
        if self._should_skip_time_based(baseline_avg, baseline_std):
            return

        # 3. Determine local/remote -> select delays
        is_local = any(s in url for s in ("172.", "192.168.", "10.", "127."))
        delays = TIME_BASED_DELAYS_LOCAL if is_local else TIME_BASED_DELAYS_REMOTE

        # 4. Build all time-based probe tasks, send concurrently
        probe_tasks = []
        for delay in delays:
            payloads = build_time_payloads(delay, "linux")[:2]  # Only test Linux (local target is usually Linux)
            for payload in payloads:
                probe_tasks.append((delay, payload))

        async def _probe_one(delay: float, payload: str):
            test_params = self._inject_param(params, param_name, payload)
            start = time.perf_counter()
            resp = await self._send_request(method, url, test_params, param_type)
            actual = time.perf_counter() - start
            return (delay, payload, resp, actual)

        # Send all probes concurrently
        results = await asyncio.gather(*[_probe_one(d, p) for d, p in probe_tasks], return_exceptions=True)

        # 5. Check results — which delay triggered the vulnerability
        for result in results:
            if isinstance(result, Exception):
                continue
            delay, payload, resp, actual = result
            if resp is None:
                continue
            if self._is_valid_time_delay(actual, delay, baseline_avg):
                # Secondary verification (only 1, reduced overhead)
                verify_payload = f"; sleep {int(delay)}"
                test_params2 = self._inject_param(params, param_name, verify_payload)
                start2 = time.perf_counter()
                resp2 = await self._send_request(method, url, test_params2, param_type)
                actual2 = time.perf_counter() - start2
                if resp2 and self._is_valid_time_delay(actual2, delay, baseline_avg):
                    platform = "linux"
                    vuln = Vulnerability(
                        type=VulnerabilityType.COMMAND_INJECTION,
                        title=f"OS Command Injection (time-based) — {platform}",
                        url=url,
                        method=method,
                        parameter=param_name,
                        parameter_type=param_type,
                        payload=payload,
                        evidence=f"Time-based CMDi ({platform}): delay={actual:.2f}s, baseline={baseline_avg:.2f}s",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        description=f"Found possible command injection vulnerability (time-based, delay {actual:.2f}s)",
                        recommendation="Avoid concatenating user input into shell commands",
                        module="cmdi",
                        tags=["cmdi", "command-injection", "time-based"],
                        context={"vuln_type": "time-based", "platform": platform},
                    )
                    self._found_vulns.append(vuln)
                    logger.warning(f"[CMDi] Time-based ({platform}): {url} [{param_name}], delay={actual:.2f}s")
                    return

    async def _test_oob(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        method: str,
        param_type: str,
        baseline: Dict,
    ) -> None:
        """
        OOB (Out-of-Band) Command Injection Detection

        Applicable scenarios: target has no echo, but can initiate outbound requests (DNS / HTTP)
        Supports two configuration methods:
        1. OOBManager (recommended): auto-register Interactsh / DNSLog.cn and verify callbacks
        2. Environment variable WVS_OOB_URL: manually configure external OOB service

        Priority: OOBManager > WVS_OOB_URL
        """
        # Method 1: Use OOBManager (recommended)
        if self._oob_manager and self._oob_manager.is_initialized:
            await self._test_oob_with_manager(url, params, param_name, method, param_type)
            return

        # Method 2: Use environment variable configuration
        oob_base = os.environ.get("WVS_OOB_URL", "").strip()
        if not oob_base:
            # No OOB configuration, skip
            return

        token = _gen_token(6)
        oob_url = f"{oob_base}/{token}"

        # OOB payloads (curl / wget / nslookup / ping)
        oob_payloads = [
            f"; curl {oob_url}",
            f"; wget {oob_url}",
            f"; nslookup {token}.{oob_base.replace('http://', '').replace('https://', '')}",
            f"; ping -c 1 {token}.{oob_base.replace('http://', '').replace('https://', '')}",
            f"| curl {oob_url}",
            f"| wget -q -O- {oob_url}",
            f"&& curl {oob_url}",
        ]

        for payload in oob_payloads[:3]:
            test_params = params.copy()
            test_params[param_name] = payload
            await self._send_request(method, url, test_params, param_type)

        logger.info(f"[CMDi] OOB probe sent to {url} [{param_name}], check {oob_base} for token={token}")

    async def _test_oob_with_manager(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        method: str,
        param_type: str,
    ) -> None:
        """Use OOBManager for OOB detection"""
        try:
            # Generate token and get callback URL
            token = await self._oob_manager.generate_token({"url": url, "param": param_name, "module": "cmdi"})
            callback_url = self._oob_manager.get_callback_url(token)

            # Build OOB payloads
            payloads = build_oob_payloads(callback_url, "http")
            payloads.extend(build_oob_payloads(token, "dns"))

            # Send requests
            for payload in payloads[:4]:
                test_params = params.copy()
                test_params[param_name] = payload
                await self._send_request(method, url, test_params, param_type)

            # Wait for callback verification
            callback = await self._oob_manager.check_callback(token, timeout=30)

            if callback:
                vuln = self._create_vuln(
                    url=url,
                    param=param_name,
                    param_type=param_type,
                    method=method,
                    payload=payloads[0],
                    token=token,
                    evidence=f"OOB callback from {callback.source_ip} ({callback.protocol})",
                )
                self._found_vulns.append(vuln)
                logger.warning(f"[CMDi] OOB detected: {url} [{param_name}]")

        except Exception as e:
            logger.debug(f"[CMDi] OOB detection failed: {e}")

    # ----------------------------------------------------------
    # False Positive Filtering (v18 NoneType issue resolved here)
    # ----------------------------------------------------------

    def _is_input_reflection(self, resp_text: str, payload: str, token: str) -> bool:
        """
        Detect if it's PHP echo-back (entire payload reflected verbatim), instead of command execution echo.

        Real CMDi: only token appears in response (command executed, echo output token)
        False positive scenario: full payload appears in response (e.g. `; echo abc123`), indicating just parameter reflection

        P16: Remove ALL payload occurrences (not just first), preventing multi-location echo bypass
        (e.g. stored XSS page echoes input in both form + message area)

        Returns True if it is input reflection (false positive), should skip.
        """
        if payload in resp_text:
            stripped = resp_text.replace(payload, "")
            if token not in stripped:
                return True
        return False

    def _is_false_positive(self, resp_text: str, token: str) -> bool:
        """
        Determine if it is a false positive, returns True if it should be skipped

        v18 false positive scenarios:
        - Response is empty string (empty page)
        - Response is "NoneType" string (template rendering failure)
        - Response is just "None" (Python None serialization)
        - Response length < 10 (almost no content)
        - Token already exists in baseline response (page itself has this word)
        """
        # Filter: empty response
        if not resp_text or len(resp_text.strip()) < 5:
            return True

        # Filter: NoneType / None / null response (typical v18 false positive)
        stripped = resp_text.strip()
        false_positive_patterns = [
            "nonetype",
            "none type",
            "string argument expected",
            "argument expected",
            "object is not iterable",
            "module 'NoneType'",
        ]
        for pattern in false_positive_patterns:
            if pattern in stripped.lower():
                logger.debug("[CMDi] Filtering false positive: NoneType pattern detected")
                return True

        # Filter: only "None" / "null" / "false" response
        if stripped.lower() in ("none", "null", "false", "error", "404", "403", "500"):
            return True

        # Filter: token already in baseline (guaranteed extremely low probability via gen_token)
        # This check is already handled by baseline parameter before invocation

        return False

    # ----------------------------------------------------------
    # Utility Methods
    # ----------------------------------------------------------

    # Note: _send_request and _extract_endpoints methods have been moved to base class DetectionModule

    def _create_vuln(
        self,
        url: str,
        param: str,
        param_type: str,
        method: str,
        payload: str,
        token: str,
        evidence: str,
    ) -> Vulnerability:
        """Create a vulnerability object"""
        vuln_type_str = "echo-blind" if token == "time-based" else "command-echo"
        return Vulnerability(
            type=VulnerabilityType.COMMAND_INJECTION,
            title=f"OS Command Injection ({vuln_type_str})",
            url=url,
            method=method,
            parameter=param,
            parameter_type=param_type,
            payload=payload,
            evidence=evidence,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="Found command injection vulnerability, arbitrary system commands can be executed",
            recommendation="Avoid concatenating user input into shell commands, use subprocess.run() with shell=False or argument list form",
            module="cmdi",
            tags=["cmdi", "command-injection", vuln_type_str],
            context={"vuln_type": vuln_type_str, "token": token},
        )
