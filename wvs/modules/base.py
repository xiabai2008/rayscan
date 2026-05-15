"""
Detection module base class.
Provides a unified module interface with plugin-style extensibility.

Refactored: extracted common methods to reduce duplication across detectors.
"""

import asyncio
import logging
import statistics
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING
from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse

from ..models import Vulnerability, ScanTarget, ModuleConfig, Severity, Confidence, VulnerabilityType
from ..config import ConfigManager
from ..constants import (
    DEFAULT_VERIFY_SSL,
    TIME_BASED_BASELINE_SAMPLES,
    TIME_BASED_MAX_BASELINE_STD,
    TIME_BASED_MAX_BASELINE_AVG,
    TIME_BASED_THRESHOLD_FACTOR,
    TIME_BASED_MIN_DELAY_FACTOR,
    TIME_BASED_VERIFICATION_ATTEMPTS,
)

if TYPE_CHECKING:
    from ..core.oob import OOBManager


logger = logging.getLogger(__name__)


@dataclass
class ModuleInfo:
    """Module metadata."""

    name: str
    description: str
    author: str = "WVS Team"
    version: str = "1.0.0"
    enabled_by_default: bool = True
    tags: List[str] = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = []


class DetectionModule(ABC):
    """
    Base class for all detection modules.

    Every detector should inherit from this class and implement the unified interface.
    """

    def __init__(self, config: Optional[ConfigManager] = None, session: Optional[Any] = None):
        """
        Initialize the module.

        Args:
            config: ConfigManager instance.
            session: HTTPPool session (with auth cookies baked in).
        """
        self.config = config or ConfigManager()
        self.session = session  # HTTPPool session (with auth cookies)
        self.module_config = self._get_module_config()
        self.info = self.get_info()
        self.logger = logging.getLogger(f"wvs.module.{self.info.name}")

        # Runtime state
        self._enabled = self.module_config.enabled
        self._stats = {"requests_made": 0, "vulnerabilities_found": 0, "errors": 0, "start_time": None, "end_time": None}

        # In-scan state
        self._found_vulns: List[Vulnerability] = []
        self._checked_urls: set = set()
        self._active_session = session

        # P18: serializes scan() calls to prevent _found_vulns concurrency race
        self._scan_lock = asyncio.Lock()

        # OOB manager (optional, injected by scanner)
        self._oob_manager: Optional["OOBManager"] = None

        # WAF bypass auto-switch (P4 optimisation)
        self._waf_detected: bool = False

        # Cookie-mode persistent client (connection-pool reuse)
        self._cookie_client: Optional[Any] = None

        # Baseline cache: avoid duplicate baseline requests for the same endpoint (P4 perf)
        self._baseline_cache: Dict[str, Dict[str, Any]] = {}
        self._global_baseline_cache: Optional[Dict[str, Dict[str, Any]]] = None  # cross-module shared cache
        self._echo_server_checked: Dict[str, bool] = {}

    def _get_module_config(self) -> ModuleConfig:
        """Get this module's configuration."""
        module_name = self.get_info().name
        return self.config.get_scanner_config().get_module_config(module_name)

    @classmethod
    @abstractmethod
    def get_info(cls) -> ModuleInfo:
        """
        Return module metadata.

        Returns:
            A ModuleInfo instance describing this module.
        """
        pass

    @property
    def enabled(self) -> bool:
        """Whether this module is enabled."""
        return self._enabled and self.module_config.enabled

    @enabled.setter
    def enabled(self, value: bool):
        """Set the module's enabled state."""
        self._enabled = value

    def enable(self):
        """Enable this module."""
        self.enabled = True
        self.logger.info(f"Module {self.info.name} enabled")

    def disable(self):
        """Disable this module."""
        self.enabled = False
        self.logger.info(f"Module {self.info.name} disabled")

    async def scan(self, target: ScanTarget, session: Optional[Any] = None) -> List[Vulnerability]:
        """
        Scan the target.

        Args:
            target: The scan target.
            session: HTTPPool session (with auth cookies), preferred over self.session.

        Returns:
            List of discovered vulnerabilities.
        """
        if not self.enabled:
            self.logger.debug(f"Module {self.info.name} disabled, skipping scan")
            return []

        # Prefer the passed-in session, fall back to self.session
        self._active_session = session if session is not None else self.session

        self._stats["start_time"] = asyncio.get_event_loop().time()
        self.logger.info(f"Starting scan of {target.url} with module {self.info.name}")

        # P18: serialize scan() — _found_vulns is instance-scoped, not concurrent-safe
        async with self._scan_lock:
            try:
                vulnerabilities = await self._scan_impl(target)
                self._stats["vulnerabilities_found"] += len(vulnerabilities)

                if vulnerabilities:
                    self.logger.info(f"Found {len(vulnerabilities)} vulnerabilities on {target.url}")
                else:
                    self.logger.debug(f"No vulnerabilities found on {target.url}")

            except Exception as e:
                self._stats["errors"] += 1
                self.logger.error(f"Module {self.info.name} scan failed: {e}")
                vulnerabilities = []

        self._stats["end_time"] = asyncio.get_event_loop().time()
        return vulnerabilities

    @abstractmethod
    async def _scan_impl(self, target: ScanTarget) -> List[Vulnerability]:
        """
        Actual scan implementation.

        Subclasses must override this method.

        Args:
            target: The scan target.

        Returns:
            List of discovered vulnerabilities.
        """
        pass

    # ==================== Shared HTTP request helpers ====================

    async def _send_request(
        self,
        method: str,
        url: str,
        params: Dict[str, str],
        param_type: str = "query",
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Unified HTTP request method.

        Args:
            method: HTTP method (GET/POST).
            url: Target URL.
            params: Query/body/cookie parameters.
            param_type: Parameter location (query/body/cookie).
            headers: Extra request headers.
            timeout: Request timeout.

        Returns:
            Response dict {"status_code", "text", "headers"} or None on failure.
        """
        try:
            if not self._active_session:
                raise RuntimeError("HTTPPool session not set")

            req_timeout = timeout or self.module_config.timeout
            kwargs: Dict[str, Any] = {"timeout": req_timeout}

            if headers:
                kwargs["headers"] = headers

            # Cookie param type: use a cached httpx client with custom Cookie header
            if param_type == "cookie":
                import httpx
                from urllib.parse import urljoin, urlparse as url_parse

                # Merge existing cookies with test parameters
                existing_cookies = {}
                if hasattr(self._active_session, "_get_httpx_client"):
                    existing_cookies = dict(self._active_session._get_httpx_client().cookies)
                merged_cookies = {**existing_cookies, **params}

                # Reuse persistent client to avoid connection churn
                verify_ssl = self.config.get("verify_ssl", DEFAULT_VERIFY_SSL)
                if self._cookie_client is None:
                    self._cookie_client = httpx.AsyncClient(
                        verify=verify_ssl,
                        timeout=req_timeout,
                        follow_redirects=False,
                    )
                cookie_client = self._cookie_client
                cookie_str = "; ".join(f"{k}={v}" for k, v in merged_cookies.items())
                req_headers = {"Cookie": cookie_str}
                if headers:
                    req_headers.update(headers)

                resp = await cookie_client.request(method.upper(), url, headers=req_headers)

                # Follow same-domain redirect once
                if resp.status_code in (301, 302, 303, 307, 308):
                    loc = resp.headers.get("location") or resp.headers.get("Location")
                    if loc:
                        final_url = urljoin(url, loc)
                        if url_parse(final_url).netloc == url_parse(url).netloc:
                            resp = await cookie_client.request(method.upper(), final_url, headers=req_headers)

                self._stats["requests_made"] += 1
                return {
                    "status_code": resp.status_code,
                    "text": resp.text,
                    "headers": dict(resp.headers),
                }

            # Normal query/body params
            if method.upper() == "GET":
                kwargs["params"] = params
            else:
                # POST: param_type decides whether to use body or query
                if param_type == "body":
                    kwargs["data"] = params
                else:
                    kwargs["params"] = params

            response = await self._active_session.request(method.upper(), url, **kwargs)
            self._stats["requests_made"] += 1

            return {
                "status_code": response.status_code,
                "text": response.text,
                "headers": dict(response.headers),
            }
        except Exception as e:
            self.logger.debug(f"Request failed: {url} - {e}")
            self._stats["errors"] += 1
            return None

    # ==================== Endpoint extraction ====================

    def _extract_endpoints(self, target: ScanTarget) -> List[Dict[str, Any]]:
        """
        Extract testable endpoints from a ScanTarget.

        Handles:
        - URL query parameters
        - POST body data
        - Cookie parameters
        - URL fragments (for DOM-based detection)

        Args:
            target: The scan target.

        Returns:
            List of endpoint dicts: [{"url": str, "params": dict, "method": str, "param_type": str}, ...]
        """
        endpoints = []
        url = target.url.rstrip("/")
        parsed = urlparse(url)

        # 1. URL query parameters
        if parsed.query:
            query_params = parse_qs(parsed.query)
            flat_params = {k: v[0] if v else "" for k, v in query_params.items()}
            endpoints.append(
                {
                    "url": url.split("?")[0],
                    "params": flat_params,
                    "method": "GET",
                    "param_type": "query",
                }
            )

        # 2. POST body data
        if target.data:
            endpoints.append(
                {
                    "url": url,
                    "params": target.data.copy() if isinstance(target.data, dict) else dict(target.data),
                    "method": "POST",
                    "param_type": "body",
                }
            )

        # 3. target.params (injected by scanner/crawler)
        if hasattr(target, "params") and target.params:
            endpoints.append(
                {
                    "url": url.split("?")[0],
                    "params": target.params.copy() if isinstance(target.params, dict) else dict(target.params),
                    "method": "GET",
                    "param_type": "query",
                }
            )

        return endpoints

    # ==================== Echo-server detection (P4: reduce reflection false positives) ====================

    def _is_echo_server(self, url: str, resp_text: str, payload: str) -> bool:
        """
        Check if the target is an echo-server (e.g. httpbin.org) to avoid reflection false positives.

        Echo-server characteristics:
        1. Payload appears verbatim in the response with no surrounding HTML (JSON/plain-text echo)
        2. Response contains obvious debug/echo structures (e.g. httpbin's "args" / "url" fields)
        3. Multiple different payloads produce the same structure with only the payload value changing

        Returns True if the target behaves like an echo-server.
        """
        cache_key = f"{url}|{payload[:20]}"
        if cache_key in self._echo_server_checked:
            return self._echo_server_checked[cache_key]

        # Pure JSON echo-server heuristics
        json_indicators = ['"args"', '"url"', '"headers"', '"origin"', '"form"']
        json_score = sum(1 for ind in json_indicators if ind in resp_text)

        # Payload reflected verbatim inside a JSON string value
        if json_score >= 2:
            import re

            quoted_payload = re.escape(payload)
            if re.search(f'"[^"]*{quoted_payload}[^"]*"', resp_text):
                self._echo_server_checked[cache_key] = True
                return True

        # HTML debug echo heuristics
        debug_indicators = ["Request Details", "Query String Parameters", "Your Input:", "You entered:", "Debug Information"]
        if any(ind in resp_text for ind in debug_indicators):
            if payload in resp_text:
                self._echo_server_checked[cache_key] = True
                return True

        self._echo_server_checked[cache_key] = False
        return False

    # ==================== Baseline cache (P4: performance) ====================

    async def _get_cached_baseline(
        self,
        method: str,
        url: str,
        params: Dict[str, str],
        param_type: str = "query",
    ) -> Optional[Dict[str, Any]]:
        """Get a cached baseline response to avoid duplicate requests. Checks local cache first, then global."""
        cache_key = f"{method}|{url}|{param_type}|{sorted(params.keys())}"
        if cache_key in self._baseline_cache:
            return self._baseline_cache[cache_key]
        if self._global_baseline_cache and cache_key in self._global_baseline_cache:
            self._baseline_cache[cache_key] = self._global_baseline_cache[cache_key]
            return self._baseline_cache[cache_key]
        baseline = await self._send_request(method, url, params, param_type)
        if baseline:
            self._baseline_cache[cache_key] = baseline
            if self._global_baseline_cache is not None:
                self._global_baseline_cache[cache_key] = baseline
        return baseline

    # ==================== Vulnerability creation ====================

    def _create_vuln(
        self,
        url: str,
        param: str,
        param_type: str,
        method: str,
        payload: str,
        vuln_type: str = "detected",
        severity: Severity = Severity.HIGH,
        confidence: Confidence = Confidence.HIGH,
        evidence: str = "",
        description: str = "",
        recommendation: str = "",
        context: Optional[Dict[str, Any]] = None,
        explicit_vuln_type: Optional[VulnerabilityType] = None,
    ) -> Vulnerability:
        """
        Unified vulnerability object factory.

        Args:
            url: Target URL.
            param: Parameter name.
            param_type: Parameter type.
            method: HTTP method.
            payload: Payload used.
            vuln_type: Vulnerability sub-type (e.g. error-based, time-based, reflected).
            severity: Severity level.
            confidence: Confidence level.
            evidence: Evidence string.
            description: Description.
            recommendation: Remediation advice.
            context: Extra context dict.
            explicit_vuln_type: Override the auto-mapped VulnerabilityType.

        Returns:
            A Vulnerability instance.
        """
        # P12: Guarantee evidence is never empty/null — fall back to payload-based description
        if not evidence:
            evidence = f"Detected via {self.info.name.upper()} ({vuln_type}) using payload: {payload[:60]}"

        # Module name to VulnerabilityType mapping (must cover all modules to avoid falling back to OTHER)
        vuln_type_map = {
            "sqli": VulnerabilityType.SQL_INJECTION,
            "xss": VulnerabilityType.XSS,
            "cmdi": VulnerabilityType.COMMAND_INJECTION,
            "lfi": VulnerabilityType.LFI,
            "xxe": VulnerabilityType.XXE,
            "ssrf": VulnerabilityType.SSRF,
            "rce": VulnerabilityType.REMOTE_CODE_EXECUTION,
            "api": VulnerabilityType.API_SECURITY,
            "sensitive": VulnerabilityType.INFO_DISCLOSURE,
            "waf": VulnerabilityType.INSECURE_CONFIG,
        }

        module_name = self.info.name.lower()
        vuln_enum_type = explicit_vuln_type or vuln_type_map.get(module_name)
        if vuln_enum_type is None:
            logger.warning(
                f"[{module_name}] module name not in vuln_type_map — falling back to OTHER. Add '{module_name}' to base.py:vuln_type_map to fix."
            )
            vuln_enum_type = VulnerabilityType.OTHER

        return Vulnerability(
            type=vuln_enum_type,
            title=f"{module_name.upper()} ({vuln_type})",
            url=url,
            method=method,
            parameter=param,
            parameter_type=param_type,
            payload=payload,
            evidence=evidence,
            severity=severity,
            confidence=confidence,
            description=description or f"Detected {module_name.upper()} vulnerability via {vuln_type} method",
            recommendation=recommendation,
            module=self.info.name,
            tags=[self.info.name, vuln_type],
            context=context or {},
        )

    # ==================== Baseline comparison ====================

    async def _get_baseline(
        self,
        method: str,
        url: str,
        params: Dict[str, str],
        param_type: str = "query",
    ) -> Optional[Dict[str, Any]]:
        """
        Fetch a baseline response for comparison.

        Args:
            method: HTTP method.
            url: Target URL.
            params: Parameters.
            param_type: Parameter type.

        Returns:
            Baseline response dict or None.
        """
        return await self._send_request(method, url, params, param_type)

    def _is_response_different(
        self,
        response: Optional[Dict[str, Any]],
        baseline: Optional[Dict[str, Any]],
        threshold: float = 0.1,
    ) -> bool:
        """
        Check if the response differs significantly from the baseline.

        Uses multiple signals:
        - Status code change
        - Length difference beyond threshold
        - Content hash difference

        Args:
            response: Test response.
            baseline: Baseline response.
            threshold: Length difference ratio threshold.

        Returns:
            True if significantly different.
        """
        if not response or not baseline:
            return True

        if response.get("status_code") != baseline.get("status_code"):
            return True

        resp_text = response.get("text", "")
        base_text = baseline.get("text", "")

        # Length comparison
        if len(resp_text) == 0 or len(base_text) == 0:
            return len(resp_text) != len(base_text)

        length_diff = abs(len(resp_text) - len(base_text)) / max(len(resp_text), len(base_text))
        if length_diff > threshold:
            return True

        # Hash comparison
        if hash(resp_text) != hash(base_text):
            return True

        return False

    # ==================== OOB support ====================

    def set_oob_manager(self, oob_manager: "OOBManager"):
        """
        Set the OOB manager.

        Args:
            oob_manager: OOB manager instance.
        """
        self._oob_manager = oob_manager

    def set_waf_detected(self, detected: bool = True):
        """Called by Scanner to inform the module that a WAF was detected — use bypass payloads."""
        self._waf_detected = detected
        if detected:
            self.logger.info(f"[{self.info.name}] WAF detected — using bypass payloads")

    def set_global_baseline_cache(self, cache: Dict[str, Dict[str, Any]]):
        """Inject a cross-module shared baseline cache to avoid duplicate requests across modules."""
        self._global_baseline_cache = cache

    async def _test_oob_payload(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        method: str,
        param_type: str,
        payload_templates: List[str],
        timeout: float = 15.0,
    ) -> Optional[Vulnerability]:
        """
        Generic OOB payload test method.

        Args:
            url: Target URL.
            params: Parameter dict.
            param_name: Parameter name to inject.
            method: HTTP method.
            param_type: Parameter type.
            payload_templates: Payload templates supporting {callback_url} and {token} placeholders.
            timeout: Callback wait timeout.

        Returns:
            Vulnerability if callback detected, else None.
        """
        if not self._oob_manager:
            return None

        try:
            # Generate token
            token = await self._oob_manager.generate_token(
                {
                    "url": url,
                    "param": param_name,
                    "module": self.info.name,
                }
            )

            callback_url = self._oob_manager.get_callback_url(token)
            dns_url = self._oob_manager.get_dns_callback(token)

            # Send payloads
            for template in payload_templates:
                payload = template.format(
                    callback_url=callback_url,
                    token=token,
                    dns_url=dns_url,
                )
                test_params = params.copy()
                test_params[param_name] = payload
                await self._send_request(method, url, test_params, param_type)

            # Poll for callback
            callback = await self._oob_manager.check_callback(token, timeout=timeout)

            if callback:
                return self._create_vuln(
                    url=url,
                    param=param_name,
                    param_type=param_type,
                    method=method,
                    payload="OOB payload",
                    vuln_type="oob",
                    evidence=f"OOB callback from {callback.source_ip}: {callback.protocol}",
                    confidence=Confidence.HIGH,  # OOB callback confirms real vulnerability
                    context={
                        "callback_source": callback.source_ip,
                        "callback_protocol": callback.protocol,
                        "callback_data": callback.data[:500] if callback.data else "",
                    },
                )

        except Exception as e:
            self.logger.debug(f"OOB test failed: {e}")

        return None

    # ==================== Time-based detection helpers ====================

    def _inject_param(self, params: Dict[str, str], param_name: str, payload: str) -> Dict[str, str]:
        """
        Inject a payload into a parameter dict.

        Args:
            params: Original parameter dict.
            param_name: Parameter name to inject.
            payload: Payload value.

        Returns:
            New parameter dict with the payload injected.
        """
        new_params = params.copy()
        new_params[param_name] = payload
        return new_params

    async def _measure_baseline(
        self,
        method: str,
        url: str,
        params: Dict[str, str],
        param_type: str,
        samples: int = TIME_BASED_BASELINE_SAMPLES,
    ) -> Tuple[float, float]:
        """
        Measure baseline response time.

        Args:
            method: HTTP method.
            url: Target URL.
            params: Parameter dict.
            param_type: Parameter type.
            samples: Number of samples.

        Returns:
            (mean response time, standard deviation).
        """
        times = []
        for _ in range(samples):
            start = time.perf_counter()
            await self._send_request(method, url, params, param_type)
            elapsed = time.perf_counter() - start
            times.append(elapsed)

        avg = statistics.mean(times)
        std = statistics.stdev(times) if len(times) > 1 else 0
        return avg, std

    def _is_valid_time_delay(
        self,
        actual_delay: float,
        expected_delay: float,
        baseline_avg: float,
    ) -> bool:
        """
        Determine whether a delay indicates a vulnerability.

        Threshold: actual > baseline_avg * factor + 1.0
        Also requires: actual >= expected * min_factor

        Args:
            actual_delay: Actual response time.
            expected_delay: Expected delay (the N in SLEEP(N)).
            baseline_avg: Baseline average response time.

        Returns:
            True if this looks like a valid vulnerability indication.
        """
        threshold = baseline_avg * TIME_BASED_THRESHOLD_FACTOR + 1.0
        min_valid = expected_delay * TIME_BASED_MIN_DELAY_FACTOR

        return actual_delay > threshold and actual_delay >= min_valid

    async def _verify_time_based(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        method: str,
        param_type: str,
        expected_delay: float,
        baseline_avg: float,
        verify_payloads: List[str],
    ) -> bool:
        """
        Time-based secondary verification.

        Uses different payloads to verify the delay is not coincidental.

        Args:
            url: Target URL.
            params: Parameter dict.
            param_name: Parameter name.
            method: HTTP method.
            param_type: Parameter type.
            expected_delay: Expected delay.
            baseline_avg: Baseline average response time.
            verify_payloads: List of verification payloads.

        Returns:
            True if verification passed.
        """
        success_count = 0
        attempts = min(TIME_BASED_VERIFICATION_ATTEMPTS, len(verify_payloads))

        for payload in verify_payloads[:attempts]:
            test_params = self._inject_param(params, param_name, payload)

            start = time.perf_counter()
            resp = await self._send_request(method, url, test_params, param_type)
            actual = time.perf_counter() - start

            if resp and self._is_valid_time_delay(actual, expected_delay, baseline_avg):
                success_count += 1

        return success_count >= TIME_BASED_VERIFICATION_ATTEMPTS

    def _should_skip_time_based(self, baseline_avg: float, baseline_std: float) -> bool:
        """
        Decide whether to skip time-based detection.

        Args:
            baseline_avg: Baseline average response time.
            baseline_std: Baseline standard deviation.

        Returns:
            True if detection should be skipped.
        """
        if baseline_std > TIME_BASED_MAX_BASELINE_STD:
            self.logger.debug(f"[Time-based] Network variance too high (std={baseline_std:.2f}s), skipping")
            return True

        if baseline_avg > TIME_BASED_MAX_BASELINE_AVG:
            self.logger.debug(f"[Time-based] Baseline response too slow ({baseline_avg:.2f}s), skipping")
            return True

        return False

    def get_config(self) -> Dict[str, Any]:
        """
        Get module configuration.

        Returns:
            Configuration dict.
        """
        return {
            "enabled": self.enabled,
            "timeout": self.module_config.timeout,
            "threads": self.module_config.threads,
            "depth": self.module_config.depth,
            "custom_params": self.module_config.custom_params,
        }

    def update_config(self, **kwargs):
        """
        Update module configuration.

        Args:
            **kwargs: Configuration parameters.
        """
        for key, value in kwargs.items():
            if hasattr(self.module_config, key):
                setattr(self.module_config, key, value)
                self.logger.debug(f"Updated config {key} = {value}")

    def get_stats(self) -> Dict[str, Any]:
        """
        Get module statistics.

        Returns:
            Statistics dict.
        """
        stats = self._stats.copy()

        # Compute duration
        if stats["start_time"] and stats["end_time"]:
            stats["duration"] = stats["end_time"] - stats["start_time"]
        else:
            stats["duration"] = 0

        # Add basic info
        stats.update({"module_name": self.info.name, "module_version": self.info.version, "enabled": self.enabled})

        return stats

    def reset_stats(self):
        """Reset module statistics."""
        self._stats = {"requests_made": 0, "vulnerabilities_found": 0, "errors": 0, "start_time": None, "end_time": None}

    def validate(self) -> bool:
        """
        Validate module configuration.

        Returns:
            True if configuration is valid.
        """
        try:
            if self.module_config.timeout <= 0:
                self.logger.warning(f"Module {self.info.name} timeout must be > 0")
                return False

            if self.module_config.threads <= 0:
                self.logger.warning(f"Module {self.info.name} threads must be > 0")
                return False

            if self.module_config.depth <= 0:
                self.logger.warning(f"Module {self.info.name} depth must be > 0")
                return False

            return True

        except Exception as e:
            self.logger.error(f"Module {self.info.name} validation failed: {e}")
            return False

    async def test(self) -> bool:
        """
        Test module functionality.

        Returns:
            True if the test passes.
        """
        self.logger.info(f"Testing module {self.info.name}")

        try:
            # Basic functionality test
            if not self.validate():
                self.logger.error(f"Module {self.info.name} config validation failed")
                return False

            # Module-specific tests can be added here
            # e.g. payload loading, network connectivity checks

            self.logger.info(f"Module {self.info.name} test passed")
            return True

        except Exception as e:
            self.logger.error(f"Module {self.info.name} test failed: {e}")
            return False

    def __str__(self) -> str:
        """Human-readable string representation."""
        return f"{self.info.name} ({self.info.version}) - {self.info.description}"


class ModuleFactory:
    """
    Module factory.

    Responsible for creating and managing detection module instances.
    """

    _modules: Dict[str, type] = {}

    @classmethod
    def register(cls, module_class: type):
        """
        Register a module class.

        Args:
            module_class: The module class to register.
        """
        if not issubclass(module_class, DetectionModule):
            raise TypeError(f"{module_class} must inherit from DetectionModule")

        module_info = module_class.get_info()
        cls._modules[module_info.name] = module_class

        logger.info(f"Registered module: {module_info.name}")

    @classmethod
    def create(cls, module_name: str, config: Optional[ConfigManager] = None) -> DetectionModule:
        """
        Create a module instance.

        Args:
            module_name: Module name.
            config: ConfigManager instance.

        Returns:
            Module instance.

        Raises:
            KeyError: If the module is not registered.
        """
        if module_name not in cls._modules:
            raise KeyError(f"Module '{module_name}' is not registered")

        module_class = cls._modules[module_name]
        return module_class(config)

    @classmethod
    def list_modules(cls) -> List[str]:
        """
        List all registered modules.

        Returns:
            List of module name strings.
        """
        return list(cls._modules.keys())

    @classmethod
    def get_module_info(cls, module_name: str) -> Optional[ModuleInfo]:
        """
        Get module info by name.

        Args:
            module_name: Module name.

        Returns:
            ModuleInfo object, or None if not registered.
        """
        if module_name not in cls._modules:
            return None

        module_class = cls._modules[module_name]
        return module_class.get_info()

    @classmethod
    def create_all(cls, config: Optional[ConfigManager] = None, enabled_only: bool = True) -> Dict[str, DetectionModule]:
        """
        Create instances of all registered modules.

        Args:
            config: ConfigManager instance.
            enabled_only: If True, only create enabled modules.

        Returns:
            Dict mapping module name to instance.
        """
        modules = {}

        for module_name in cls.list_modules():
            try:
                module = cls.create(module_name, config)

                if enabled_only and not module.enabled:
                    continue

                modules[module_name] = module

            except Exception as e:
                logger.error(f"Failed to create module {module_name}: {e}")

        return modules


# Decorator: auto-register module
def register_module(module_class: type) -> type:
    """
    Decorator that automatically registers a module.

    Usage:
        @register_module
        class SQLiModule(DetectionModule):
            ...
    """
    ModuleFactory.register(module_class)
    return module_class


if __name__ == "__main__":
    # Test module system
    print("Testing module system...")

    # Create a test module
    @register_module
    class TestModule(DetectionModule):
        @classmethod
        def get_info(cls):
            return ModuleInfo(name="test", description="Test module", version="1.0.0")

        async def _scan_impl(self, target):
            print(f"Test module scanning: {target.url}")
            return []

    # Test module factory
    print("\n1. Module factory test:")
    modules = ModuleFactory.list_modules()
    print(f"  Registered modules: {modules}")

    # Create module instance
    print("\n2. Create module instance:")
    test_module = ModuleFactory.create("test")
    print(f"  Module: {test_module}")
    print(f"  Module info: {test_module.info}")
    print(f"  Module config: {test_module.get_config()}")

    # Test scan
    print("\n3. Test scan:")

    target = ScanTarget(url="http://example.com")

    async def run_test():
        vulnerabilities = await test_module.scan(target)
        print(f"  Vulnerabilities found: {len(vulnerabilities)}")

    asyncio.run(run_test())  # noqa: F405 — asyncio imported at module level

    print("\nTests complete!")
