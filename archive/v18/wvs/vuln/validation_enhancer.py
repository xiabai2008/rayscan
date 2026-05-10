"""WVS v18 - 漏洞验证增强模块

提供二次验证机制以减少误报：
1. 时间盲注验证：多次测试、排除抖动、置信区间
2. CMDI验证：随机token回显验证
3. XSS反射验证：标记完整性和位置验证
4. 网络重试：指数退避
5. 误报过滤：基线对比和启发式规则
"""
import asyncio
import re
import time
import secrets
import string
import statistics
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Callable, Any
from urllib.parse import quote


@dataclass
class ValidationResult:
    """验证结果"""
    is_valid: bool
    confidence: float          # 0.0 - 1.0
    evidence: str              # 验证证据
    details: Dict = field(default_factory=dict)
    retry_count: int = 0       # 重试次数


@dataclass
class RetryStats:
    """重试统计"""
    total_attempts: int = 0
    success_on_retry: int = 0
    final_failure: int = 0
    avg_backoff: float = 0.0


class ValidationEnhancer:
    """漏洞验证增强器"""

    # 时间盲注验证配置
    TIME_TEST_COUNT = 3           # 测试次数
    TIME_STDDEV_THRESHOLD = 0.5   # 标准差阈值(秒)
    TIME_MIN_DELAY = 2.0          # 最小有效延迟(秒)
    TIME_CONFIDENCE_THRESHOLD = 0.7  # 置信度阈值

    # CMDI验证配置
    CMDI_TOKEN_LENGTH = 16        # 随机token长度
    CMDI_TIMEOUT = 10             # 超时时间(秒)

    # XSS验证配置
    XSS_REFLECTION_MARKERS = [
        "WVS_XSS_",
        "WVS_VERIFY_",
    ]

    # 重试配置
    MAX_RETRIES = 3
    BACKOFF_DELAYS = [1, 2, 4, 8]  # 指数退避

    # 误报过滤配置
    FALSE_POSITIVE_PATTERNS = [
        # 框架错误信息
        r"Stack trace:",
        r"at \w+\(\)",
        r"Exception in thread",
        r"Caused by:",
        r"javax\.servlet",
        r"org\.springframework",
        r"django\.",
        r"Flask\.",
        r"Express\.",
        r"NodeJS\.",
        r"Apache\.",
        r"Nginx\.",

        # 通用错误页面
        r"404 Not Found",
        r"403 Forbidden",
        r"500 Internal Server Error",
        r"502 Bad Gateway",
        r"503 Service Unavailable",

        # 调试信息
        r"Debug mode",
        r"DEBUG:",
        r"\[DEBUG\]",
        r"console\.log",
        r"print_r\(",
        r"var_dump\(",
    ]

    def __init__(self, config: Dict = None):
        self.config = config or self.default_config()
        self.retry_stats = RetryStats()
        self._false_positive_re = re.compile(
            '|'.join(self.FALSE_POSITIVE_PATTERNS), re.IGNORECASE
        )

    def default_config(self) -> Dict:
        """默认配置"""
        return {
            "time_test_count": self.TIME_TEST_COUNT,
            "time_stddev_threshold": self.TIME_STDDEV_THRESHOLD,
            "time_min_delay": self.TIME_MIN_DELAY,
            "time_confidence_threshold": self.TIME_CONFIDENCE_THRESHOLD,
            "cmdi_token_length": self.CMDI_TOKEN_LENGTH,
            "cmdi_timeout": self.CMDI_TIMEOUT,
            "max_retries": self.MAX_RETRIES,
            "backoff_delays": self.BACKOFF_DELAYS.copy(),
            "retry_on_connection_error": True,
        }

    async def validate_sqli_time_based(
        self,
        session,
        url: str,
        param: str,
        payload: str,
        method: str = "GET",
        baseline_duration: float = 1.0
    ) -> ValidationResult:
        """验证时间盲注漏洞

        对疑似时间盲注的请求进行多次重复测试，排除网络抖动，
        计算置信区间，确认是否为有效延迟。

        Args:
            session: aiohttp ClientSession
            url: 目标URL
            param: 测试参数
            payload: 时间盲注payload
            method: HTTP方法
            baseline_duration: 基线响应时间

        Returns:
            ValidationResult: 验证结果
        """
        test_count = self.config.get("time_test_count", self.TIME_TEST_COUNT)
        stddev_threshold = self.config.get("time_stddev_threshold", self.TIME_STDDEV_THRESHOLD)
        min_delay = self.config.get("time_min_delay", self.TIME_MIN_DELAY)
        confidence_threshold = self.config.get("time_confidence_threshold", self.TIME_CONFIDENCE_THRESHOLD)

        durations = []

        for i in range(test_count):
            try:
                # 单次请求计时（修复双重请求 bug）
                start = time.perf_counter()
                if method.upper() == "GET":
                    test_params = {param: payload}
                    async with session.get(url, params=test_params,
                                           timeout=aiohttp.ClientTimeout(total=30)) as resp:
                        await resp.text()
                else:
                    test_data = {param: payload}
                    async with session.request(method, url, data=test_data,
                                               timeout=aiohttp.ClientTimeout(total=30)) as resp:
                        await resp.text()
                duration = time.perf_counter() - start

                durations.append(duration)
                await asyncio.sleep(0.5)  # 请求间隔

            except asyncio.TimeoutError:
                durations.append(30.0)
            except Exception as e:
                return ValidationResult(
                    is_valid=False,
                    confidence=0.0,
                    evidence=f"Request failed: {str(e)}",
                    details={"error": str(e)}
                )

        if len(durations) < 2:
            return ValidationResult(
                is_valid=False,
                confidence=0.0,
                evidence="Insufficient test data",
                details={"durations": durations}
            )

        # 排除最高和最低延迟
        sorted_durations = sorted(durations)
        filtered_durations = sorted_durations[1:-1] if len(sorted_durations) > 2 else sorted_durations

        if not filtered_durations:
            filtered_durations = durations

        avg_duration = statistics.mean(filtered_durations)

        # 计算标准差
        if len(filtered_durations) > 1:
            stddev = statistics.stdev(filtered_durations)
        else:
            stddev = 0.0

        # 计算有效延迟（排除基线）
        effective_delay = avg_duration - baseline_duration

        # 计算置信度
        if effective_delay >= min_delay:
            # 标准差小说明结果稳定，置信度高
            if stddev < stddev_threshold:
                confidence = 1.0 - (stddev / stddev_threshold) * 0.3
                confidence = max(confidence, confidence_threshold)
            else:
                confidence = 0.5

            is_valid = confidence >= confidence_threshold

            return ValidationResult(
                is_valid=is_valid,
                confidence=confidence,
                evidence=f"Delay: {effective_delay:.2f}s, StdDev: {stddev:.2f}s",
                details={
                    "durations": durations,
                    "filtered_durations": filtered_durations,
                    "avg_duration": avg_duration,
                    "stddev": stddev,
                    "effective_delay": effective_delay,
                    "baseline_duration": baseline_duration
                }
            )
        else:
            return ValidationResult(
                is_valid=False,
                confidence=0.3,
                evidence=f"Effective delay {effective_delay:.2f}s below threshold {min_delay}s",
                details={
                    "durations": durations,
                    "avg_duration": avg_duration,
                    "effective_delay": effective_delay
                }
            )

    async def validate_cmdi_echo(
        self,
        session,
        url: str,
        param: str,
        payload: str,
        method: str = "GET",
        os_type: str = "auto"
    ) -> ValidationResult:
        """验证CMDI命令执行漏洞

        生成随机token，发送验证payload，检查响应是否包含完整token。
        支持多种OS命令格式。

        Args:
            session: aiohttp ClientSession
            url: 目标URL
            param: 测试参数
            payload: 原始payload（用于判断注入点）
            method: HTTP方法
            os_type: 操作系统类型 (auto/unix/windows)

        Returns:
            ValidationResult: 验证结果
        """
        # 生成随机token
        token = self._generate_random_token(
            self.config.get("cmdi_token_length", self.CMDI_TOKEN_LENGTH)
        )

        # 生成多种验证payload
        verify_payloads = self._generate_cmdi_payloads(token, os_type)

        for verify_payload in verify_payloads:
            try:
                if method.upper() == "GET":
                    test_params = {param: verify_payload}
                    async with session.get(url, params=test_params,
                                           timeout=aiohttp.ClientTimeout(total=self.CMDI_TIMEOUT)) as resp:
                        content = await resp.text()
                else:
                    test_data = {param: verify_payload}
                    async with session.request(method, url, data=test_data,
                                               timeout=aiohttp.ClientTimeout(total=self.CMDI_TIMEOUT)) as resp:
                        content = await resp.text()

                # 检查响应是否包含完整token
                if token in content:
                    return ValidationResult(
                        is_valid=True,
                        confidence=0.95,
                        evidence=f"Token '{token}' found in response",
                        details={
                            "token": token,
                            "verify_payload": verify_payload,
                            "os_type": os_type
                        }
                    )

                # 检查部分token（如果输出被截断）
                token_prefix = token[:8]
                if token_prefix in content:
                    return ValidationResult(
                        is_valid=True,
                        confidence=0.7,
                        evidence=f"Partial token found in response",
                        details={
                            "token": token,
                            "verify_payload": verify_payload,
                            "partial_match": True
                        }
                    )

                await asyncio.sleep(0.3)

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                continue

        return ValidationResult(
            is_valid=False,
            confidence=0.0,
            evidence=f"Token '{token}' not found in any response",
            details={
                "token": token,
                "payloads_tested": len(verify_payloads)
            }
        )

    async def validate_xss_reflection(
        self,
        session,
        url: str,
        param: str,
        payload: str,
        method: str = "GET"
    ) -> ValidationResult:
        """验证XSS反射漏洞

        发送包含特定标记的payload，检查标记是否完整反射在HTML中，
        并验证反射位置。

        Args:
            session: aiohttp ClientSession
            url: 目标URL
            param: 测试参数
            payload: XSS payload
            method: HTTP方法

        Returns:
            ValidationResult: 验证结果
        """
        # 生成唯一的标记
        marker = f"WVS_XSS_{self._generate_random_token(8)}"

        # 构建带标记的payload
        marker_payload = payload.replace("<script>", f"<script>{marker}</script>")
        if marker_payload == payload:  # 如果payload不包含script，使用完整标记
            marker_payload = f"{marker}{payload}"

        try:
            if method.upper() == "GET":
                test_params = {param: marker_payload}
                async with session.get(url, params=test_params,
                                       timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    content = await resp.text()
            else:
                test_data = {param: marker_payload}
                async with session.request(method, url, data=test_data,
                                           timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    content = await resp.text()

            # 检查标记是否完整反射
            if marker in content:
                # 分析反射位置
                position = self._analyze_reflection_position(content, marker)

                confidence = 0.8
                evidence = f"Marker reflected in {position['location']}"

                # 高危位置：script标签内、事件处理器中
                if position.get("in_script") or position.get("in_event_handler"):
                    confidence = 0.95
                    evidence += " (high risk)"
                elif position.get("in_attribute"):
                    confidence = 0.85
                    evidence += " (medium risk)"

                return ValidationResult(
                    is_valid=True,
                    confidence=confidence,
                    evidence=evidence,
                    details={
                        "marker": marker,
                        "position": position,
                        "payload": marker_payload
                    }
                )
            else:
                return ValidationResult(
                    is_valid=False,
                    confidence=0.2,
                    evidence=f"Marker not reflected in response",
                    details={"marker": marker}
                )

        except Exception as e:
            return ValidationResult(
                is_valid=False,
                confidence=0.0,
                evidence=f"Request failed: {str(e)}",
                details={"error": str(e)}
            )

    async def retry_request(
        self,
        session,
        request_func: Callable,
        max_retries: int = None,
        *args,
        **kwargs
    ) -> Tuple[Any, bool]:
        """带退避的重试机制

        指数退避重试：1s, 2s, 4s, 8s
        智能重试：只重试连接错误，不重试400/500错误

        Args:
            session: aiohttp ClientSession
            request_func: 请求函数
            max_retries: 最大重试次数
            *args, **kwargs: 传递给request_func的参数

        Returns:
            Tuple[(响应, 成功标志)]
        """
        max_retries = max_retries or self.config.get("max_retries", self.MAX_RETRIES)
        backoff_delays = self.config.get("backoff_delays", self.BACKOFF_DELAYS)

        last_error = None

        for attempt in range(max_retries + 1):
            try:
                self.retry_stats.total_attempts += 1

                result = await request_func(session, *args, **kwargs)

                # 如果是aiohttp响应，检查状态码
                if hasattr(result, 'status'):
                    status = result.status

                    # 400-599 错误不重试
                    if 400 <= status < 600:
                        return result, True  # 返回结果，让调用方处理

                return result, True

            except (aiohttp.ClientError, asyncio.TimeoutError,
                    ConnectionError, OSError) as e:
                last_error = e
                self.retry_stats.total_attempts += 1

                if attempt < max_retries:
                    # 计算退避时间
                    delay = backoff_delays[min(attempt, len(backoff_delays) - 1)]

                    # 添加抖动
                    import random
                    delay = delay * (0.5 + random.random())

                    await asyncio.sleep(delay)
                    self.retry_stats.success_on_retry += 1
                    continue
                else:
                    self.retry_stats.final_failure += 1
                    raise last_error

        return None, False

    async def filter_false_positives(
        self,
        baseline_content: str,
        test_content: str,
        payload: str = ""
    ) -> Tuple[bool, str]:
        """误报过滤

        通过基线对比、噪声检测和启发式规则过滤常见误报。

        Args:
            baseline_content: 正常响应内容
            test_content: 测试响应内容
            payload: 使用的payload（可选）

        Returns:
            Tuple[(是否为误报, 原因)]
        """
        # 1. 基线对比：内容完全相同可能是误报
        if baseline_content == test_content:
            return True, "Response identical to baseline"

        # 2. 检查是否包含常见误报模式
        if self._false_positive_re.search(test_content):
            return True, "Contains false positive pattern (framework error)"

        # 3. 启发式规则：检查payload是否被转义
        if payload:
            # 检查HTML转义
            escaped_markers = [
                ("<script>", "&lt;script&gt;"),
                ("<img", "&lt;img"),
                ("onerror", "onerror"),  # 如果被转义应该是onerror
            ]

            for marker, escaped in escaped_markers:
                if marker in payload:
                    if escaped in test_content and marker not in test_content:
                        return True, "Payload appears to be HTML-escaped"

        # 4. 检查错误信息
        error_indicators = [
            r"SQL syntax.*?error",
            r"mysql.*?error",
            r"sqlite.*?error",
            r"PostgreSQL.*?error",
            r"ORA-\d+",
        ]

        for pattern in error_indicators:
            if re.search(pattern, test_content, re.IGNORECASE):
                # 如果只是返回了数据库错误页面，而不是实际执行
                if "404" not in test_content and "500" not in test_content[:200]:
                    # 需要进一步检查是否真的是注入
                    pass

        return False, ""

    # 辅助方法

    def _generate_random_token(self, length: int = 16) -> str:
        """生成随机token"""
        alphabet = string.ascii_lowercase + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    def _generate_cmdi_payloads(self, token: str, os_type: str) -> List[str]:
        """生成CMDI验证payload"""
        payloads = []

        if os_type == "auto":
            # 自动检测，尝试所有格式
            payloads.extend(self._generate_cmdi_payloads(token, "unix"))
            payloads.extend(self._generate_cmdi_payloads(token, "windows"))
        elif os_type == "unix":
            payloads = [
                f"; echo {token}",
                f"| echo {token}",
                f"&& echo {token}",
                f"`echo {token}`",
                f"$(echo {token})",
                f"; printf {token}",
                f"| printf {token}",
            ]
        elif os_type == "windows":
            payloads = [
                f"& echo {token}",
                f"| echo {token}",
                f"&& echo {token}",
            ]

        return payloads

    def _analyze_reflection_position(self, content: str, marker: str) -> Dict:
        """分析反射位置"""
        position = {
            "location": "unknown",
            "in_script": False,
            "in_event_handler": False,
            "in_attribute": False,
            "in_tag": False,
        }

        # 查找marker在内容中的位置
        marker_lower = marker.lower()
        content_lower = content.lower()

        idx = content_lower.find(marker_lower)
        if idx == -1:
            return position

        # 获取周围上下文（前后100个字符）
        start = max(0, idx - 100)
        end = min(len(content), idx + len(marker) + 100)
        context = content[start:end]

        # 检查是否在script标签内
        if re.search(r'<script[^>]*>.*?' + re.escape(marker), content, re.IGNORECASE | re.DOTALL):
            position["location"] = "script_tag"
            position["in_script"] = True
        # 检查是否在事件处理器中
        elif re.search(r'on\w+\s*=\s*["\']?[^"\']*?' + re.escape(marker), content, re.IGNORECASE):
            position["location"] = "event_handler"
            position["in_event_handler"] = True
        # 检查是否在HTML属性中
        elif re.search(r'<\w+\s+[^>]*=.*?' + re.escape(marker), content, re.IGNORECASE):
            position["location"] = "html_attribute"
            position["in_attribute"] = True
        # 检查是否在HTML标签内
        elif re.search(r'<[^>]+>' + re.escape(marker), content, re.IGNORECASE):
            position["location"] = "html_tag"
            position["in_tag"] = True
        else:
            position["location"] = "plain_text"

        return position

    def get_retry_stats(self) -> RetryStats:
        """获取重试统计"""
        return self.retry_stats

    def reset_stats(self):
        """重置统计"""
        self.retry_stats = RetryStats()


# 导入aiohttp用于类型提示
import aiohttp