"""
检测模块基类
实现统一的模块接口，支持插件化扩展

重构：提取公共方法，减少各检测器的重复代码
"""
import asyncio
import logging
import statistics
import time
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List, Optional, Tuple, TYPE_CHECKING
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
    """模块信息"""
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
    检测模块基类
    
    所有检测模块都应该继承这个类，实现统一的接口
    """
    
    def __init__(self, config: Optional[ConfigManager] = None, session: Optional[Any] = None):
        """
        初始化模块

        Args:
            config: 配置管理器
            session: HTTPPool session（带认证 cookie）
        """
        self.config = config or ConfigManager()
        self.session = session  # HTTPPool session（带认证 cookie）
        self.module_config = self._get_module_config()
        self.info = self.get_info()
        self.logger = logging.getLogger(f"wvs.module.{self.info.name}")

        # 运行时状态
        self._enabled = self.module_config.enabled
        self._stats = {
            "requests_made": 0,
            "vulnerabilities_found": 0,
            "errors": 0,
            "start_time": None,
            "end_time": None
        }

        # 检测过程中的状态
        self._found_vulns: List[Vulnerability] = []
        self._checked_urls: set = set()
        self._active_session = session

        # P18: serializes scan() calls to prevent _found_vulns concurrency race
        self._scan_lock = asyncio.Lock()

        # OOB 管理器（可选，由扫描器注入）
        self._oob_manager: Optional["OOBManager"] = None

        # WAF bypass 自动切换（P4 优化）
        self._waf_detected: bool = False

        # 基线缓存：避免对同一 endpoint 重复请求基线 (P4 性能优化)
        self._baseline_cache: Dict[str, Dict[str, Any]] = {}
        self._global_baseline_cache: Optional[Dict[str, Dict[str, Any]]] = None  # 跨模块共享
        self._echo_server_checked: Dict[str, bool] = {}

    def _get_module_config(self) -> ModuleConfig:
        """获取模块配置"""
        module_name = self.get_info().name
        return self.config.get_scanner_config().get_module_config(module_name)
    
    @classmethod
    @abstractmethod
    def get_info(cls) -> ModuleInfo:
        """
        获取模块信息
        
        Returns:
            ModuleInfo对象
        """
        pass
    
    @property
    def enabled(self) -> bool:
        """模块是否启用"""
        return self._enabled and self.module_config.enabled
    
    @enabled.setter
    def enabled(self, value: bool):
        """设置模块启用状态"""
        self._enabled = value
    
    def enable(self):
        """启用模块"""
        self.enabled = True
        self.logger.info(f"模块 {self.info.name} 已启用")
    
    def disable(self):
        """禁用模块"""
        self.enabled = False
        self.logger.info(f"模块 {self.info.name} 已禁用")
    
    async def scan(self, target: ScanTarget, session: Optional[Any] = None) -> List[Vulnerability]:
        """
        扫描目标
        
        Args:
            target: 扫描目标
            session: HTTPPool session（带认证 cookie），优先于 self.session
            
        Returns:
            发现的漏洞列表
        """
        if not self.enabled:
            self.logger.debug(f"模块 {self.info.name} 已禁用，跳过扫描")
            return []
        
        # 优先用传入的 session，其次用 self.session
        self._active_session = session if session is not None else self.session

        self._stats["start_time"] = asyncio.get_event_loop().time()
        self.logger.info(f"开始扫描 {target.url} 使用模块 {self.info.name}")
        
        # P18: serialize scan() — _found_vulns is instance-scoped, not concurrent-safe
        async with self._scan_lock:
            try:
                vulnerabilities = await self._scan_impl(target)
                self._stats["vulnerabilities_found"] += len(vulnerabilities)

                if vulnerabilities:
                    self.logger.info(f"在 {target.url} 发现 {len(vulnerabilities)} 个漏洞")
                else:
                    self.logger.debug(f"在 {target.url} 未发现漏洞")

            except Exception as e:
                self._stats["errors"] += 1
                self.logger.error(f"模块 {self.info.name} 扫描失败: {e}")
                vulnerabilities = []

        self._stats["end_time"] = asyncio.get_event_loop().time()
        return vulnerabilities
    
    @abstractmethod
    async def _scan_impl(self, target: ScanTarget) -> List[Vulnerability]:
        """
        实际的扫描实现

        子类必须实现这个方法

        Args:
            target: 扫描目标

        Returns:
            发现的漏洞列表
        """
        pass

    # ==================== 通用 HTTP 请求方法 ====================

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
        统一的 HTTP 请求方法

        Args:
            method: HTTP 方法 (GET/POST)
            url: 目标 URL
            params: 参数字典
            param_type: 参数类型 (query/body/cookie)
            headers: 额外请求头
            timeout: 请求超时

        Returns:
            响应字典 {"status_code", "text", "headers"} 或 None（失败时）
        """
        try:
            if not self._active_session:
                raise RuntimeError("HTTPPool session not set")

            req_timeout = timeout or self.module_config.timeout
            kwargs: Dict[str, Any] = {"timeout": req_timeout}

            if headers:
                kwargs["headers"] = headers

            # Cookie 参数类型：使用独立的 httpx client 发送带自定义 Cookie 的请求
            if param_type == "cookie":
                import httpx
                from urllib.parse import urljoin, urlparse as url_parse

                # 获取现有 cookies 并合并测试参数
                existing_cookies = {}
                if hasattr(self._active_session, '_get_httpx_client'):
                    existing_cookies = dict(self._active_session._get_httpx_client().cookies)
                merged_cookies = {**existing_cookies, **params}

                # 创建临时 client 发送带测试 Cookie 的请求
                # 使用配置的 SSL 验证设置（默认启用）
                verify_ssl = self.config.get("verify_ssl", DEFAULT_VERIFY_SSL)
                async with httpx.AsyncClient(verify=verify_ssl, timeout=req_timeout, follow_redirects=False) as tmp_client:
                    cookie_str = "; ".join(f"{k}={v}" for k, v in merged_cookies.items())
                    req_headers = {"Cookie": cookie_str}
                    if headers:
                        req_headers.update(headers)

                    resp = await tmp_client.request(method.upper(), url, headers=req_headers)

                    # 处理重定向（同域名内跟随一次）
                    if resp.status_code in (301, 302, 303, 307, 308):
                        loc = resp.headers.get("location") or resp.headers.get("Location")
                        if loc:
                            final_url = urljoin(url, loc)
                            if url_parse(final_url).netloc == url_parse(url).netloc:
                                resp = await tmp_client.request(method.upper(), final_url, headers=req_headers)

                    self._stats["requests_made"] += 1
                    return {
                        "status_code": resp.status_code,
                        "text": resp.text,
                        "headers": dict(resp.headers),
                    }

            # 普通 query/body 参数
            if method.upper() == "GET":
                kwargs["params"] = params
            else:
                # POST 请求：根据 param_type 决定参数位置
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
            self.logger.debug(f"请求失败: {url} - {e}")
            self._stats["errors"] += 1
            return None

    # ==================== 端点提取方法 ====================

    def _extract_endpoints(self, target: ScanTarget) -> List[Dict[str, Any]]:
        """
        从 ScanTarget 提取可测试的端点

        处理：
        - URL 查询参数
        - POST body 数据
        - Cookie 参数
        - URL 片段（用于 DOM-based 检测）

        Args:
            target: 扫描目标

        Returns:
            端点列表：[{"url": str, "params": dict, "method": str, "param_type": str}, ...]
        """
        endpoints = []
        url = target.url.rstrip("/")
        parsed = urlparse(url)

        # 1. URL 查询参数
        if parsed.query:
            query_params = parse_qs(parsed.query)
            flat_params = {k: v[0] if v else "" for k, v in query_params.items()}
            endpoints.append({
                "url": url.split("?")[0],
                "params": flat_params,
                "method": "GET",
                "param_type": "query",
            })

        # 2. POST body 数据
        if target.data:
            endpoints.append({
                "url": url,
                "params": target.data.copy() if isinstance(target.data, dict) else dict(target.data),
                "method": "POST",
                "param_type": "body",
            })

        # 3. target.params（来自 scanner/crawler 注入的参数）
        if hasattr(target, 'params') and target.params:
            endpoints.append({
                "url": url.split("?")[0],
                "params": target.params.copy() if isinstance(target.params, dict) else dict(target.params),
                "method": "GET",
                "param_type": "query",
            })

        return endpoints

    # ==================== Echo-Server 检测（P4: 减少反射型误报）====================

    def _is_echo_server(self, url: str, resp_text: str, payload: str) -> bool:
        """
        检测目标是否为 echo-server（如 httpbin.org），避免反射型误报。

        Echo-server 特征：
        1. 响应中 payload 原样完整出现，且周围没有 HTML 标签（JSON/纯文本回显）
        2. 响应包含明显的调试/echo 结构（如 httpbin 的 "args" / "url" 字段）
        3. 多个不同的 payload 测试后，响应结构相同仅 payload 值不同

        返回 True 表示目标是 echo-server，应降低置信度。
        """
        cache_key = f"{url}|{payload[:20]}"
        if cache_key in self._echo_server_checked:
            return self._echo_server_checked[cache_key]

        # 纯 JSON echo-server 特征
        json_indicators = ['"args"', '"url"', '"headers"', '"origin"', '"form"']
        json_score = sum(1 for ind in json_indicators if ind in resp_text)

        # payload 原样反射在 JSON 值中（非 HTML 上下文）
        if json_score >= 2:
            # payload 出现在 JSON 字符串值位置（被引号包裹）
            import re
            quoted_payload = re.escape(payload)
            if re.search(f'"[^"]*{quoted_payload}[^"]*"', resp_text):
                self._echo_server_checked[cache_key] = True
                return True

        # HTML debug echo 特征
        debug_indicators = ["Request Details", "Query String Parameters",
                           "Your Input:", "You entered:", "Debug Information"]
        if any(ind in resp_text for ind in debug_indicators):
            if payload in resp_text:
                self._echo_server_checked[cache_key] = True
                return True

        self._echo_server_checked[cache_key] = False
        return False

    # ==================== 缓存基线（P4: 性能优化）====================

    async def _get_cached_baseline(
        self,
        method: str,
        url: str,
        params: Dict[str, str],
        param_type: str = "query",
    ) -> Optional[Dict[str, Any]]:
        """获取缓存的基线响应，避免对同一 endpoint 重复请求。先查本地缓存，再查全局共享缓存。"""
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

    # ==================== 漏洞创建方法 ====================

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
        统一的漏洞对象创建方法

        Args:
            url: 目标 URL
            param: 参数名
            param_type: 参数类型
            method: HTTP 方法
            payload: 使用的 payload
            vuln_type: 漏洞子类型 (如 error-based, time-based, reflected)
            severity: 严重程度
            confidence: 置信度
            evidence: 证据
            description: 描述
            recommendation: 修复建议
            context: 额外上下文
            explicit_vuln_type: 显式指定漏洞类型（覆盖模块名自动映射）。

        Returns:
            Vulnerability 对象
        """
        # P12: Guarantee evidence is never empty/null — fall back to payload-based description
        if not evidence:
            evidence = f"Detected via {self.info.name.upper()} ({vuln_type}) using payload: {payload[:60]}"

        # 模块名到漏洞类型的映射（必须包含所有模块名，避免回退到 OTHER）
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
                f"[{module_name}] module name not in vuln_type_map — falling back to OTHER. "
                f"Add '{module_name}' to base.py:vuln_type_map to fix."
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

    # ==================== 基线对比方法 ====================

    async def _get_baseline(
        self,
        method: str,
        url: str,
        params: Dict[str, str],
        param_type: str = "query",
    ) -> Optional[Dict[str, Any]]:
        """
        获取基线响应用于对比

        Args:
            method: HTTP 方法
            url: 目标 URL
            params: 参数
            param_type: 参数类型

        Returns:
            基线响应字典或 None
        """
        return await self._send_request(method, url, params, param_type)

    def _is_response_different(
        self,
        response: Optional[Dict[str, Any]],
        baseline: Optional[Dict[str, Any]],
        threshold: float = 0.1,
    ) -> bool:
        """
        检测响应是否与基线有显著差异

        使用多个指标：
        - 状态码变化
        - 长度差异超过阈值
        - 内容哈希差异

        Args:
            response: 测试响应
            baseline: 基线响应
            threshold: 长度差异阈值（比例）

        Returns:
            是否有显著差异
        """
        if not response or not baseline:
            return True

        if response.get("status_code") != baseline.get("status_code"):
            return True

        resp_text = response.get("text", "")
        base_text = baseline.get("text", "")

        # 长度对比
        if len(resp_text) == 0 or len(base_text) == 0:
            return len(resp_text) != len(base_text)

        length_diff = abs(len(resp_text) - len(base_text)) / max(len(resp_text), len(base_text))
        if length_diff > threshold:
            return True

        # 哈希对比
        if hash(resp_text) != hash(base_text):
            return True

        return False

    # ==================== OOB 支持方法 ====================

    def set_oob_manager(self, oob_manager: "OOBManager"):
        """
        设置 OOB 管理器

        Args:
            oob_manager: OOB 管理器实例
        """
        self._oob_manager = oob_manager

    def set_waf_detected(self, detected: bool = True):
        """由 Scanner 调用：告知检测器目标存在 WAF，应使用 bypass payloads。"""
        self._waf_detected = detected
        if detected:
            self.logger.info(f"[{self.info.name}] WAF detected — using bypass payloads")

    def set_global_baseline_cache(self, cache: Dict[str, Dict[str, Any]]):
        """注入跨模块共享的基线缓存，避免多个模块对同一 endpoint 重复请求基线。"""
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
        通用的 OOB payload 测试方法

        Args:
            url: 目标 URL
            params: 参数字典
            param_name: 要注入的参数名
            method: HTTP 方法
            param_type: 参数类型
            payload_templates: payload 模板列表，支持 {callback_url} 和 {token} 占位符
            timeout: 回调等待超时

        Returns:
            如果检测到回调，返回 Vulnerability；否则返回 None
        """
        if not self._oob_manager:
            return None

        try:
            # 生成 token
            token = await self._oob_manager.generate_token({
                "url": url,
                "param": param_name,
                "module": self.info.name,
            })

            callback_url = self._oob_manager.get_callback_url(token)
            dns_url = self._oob_manager.get_dns_callback(token)

            # 发送 payload
            for template in payload_templates:
                payload = template.format(
                    callback_url=callback_url,
                    token=token,
                    dns_url=dns_url,
                )
                test_params = params.copy()
                test_params[param_name] = payload
                await self._send_request(method, url, test_params, param_type)

            # 轮询验证回调
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
                    confidence=Confidence.HIGH,  # OOB 回调证明漏洞真实存在
                    context={
                        "callback_source": callback.source_ip,
                        "callback_protocol": callback.protocol,
                        "callback_data": callback.data[:500] if callback.data else "",
                    },
                )

        except Exception as e:
            self.logger.debug(f"OOB 测试失败: {e}")

        return None

    # ==================== Time-based 检测公共方法 ====================

    def _inject_param(self, params: Dict[str, str], param_name: str, payload: str) -> Dict[str, str]:
        """
        在参数字典中注入 payload

        Args:
            params: 原始参数字典
            param_name: 要注入的参数名
            payload: 要注入的 payload

        Returns:
            新的参数字典
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
        测量基线响应时间

        Args:
            method: HTTP 方法
            url: 目标 URL
            params: 参数字典
            param_type: 参数类型
            samples: 采样次数

        Returns:
            (平均响应时间, 标准差)
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
        判断延迟是否指示存在漏洞

        阈值计算：actual > baseline_avg * factor + 1.0
        同时需要满足：actual >= expected * min_factor

        Args:
            actual_delay: 实际延迟时间
            expected_delay: 预期延迟时间（SLEEP(N) 中的 N）
            baseline_avg: 基线平均响应时间

        Returns:
            是否为有效的漏洞指示
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
        Time-based 二次验证

        使用不同的 payload 验证多次，确保不是偶然延迟

        Args:
            url: 目标 URL
            params: 参数字典
            param_name: 参数名
            method: HTTP 方法
            param_type: 参数类型
            expected_delay: 预期延迟
            baseline_avg: 基线平均响应时间
            verify_payloads: 验证 payload 列表

        Returns:
            是否验证通过
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
        判断是否应该跳过 time-based 检测

        Args:
            baseline_avg: 基线平均响应时间
            baseline_std: 基线标准差

        Returns:
            True 表示应该跳过
        """
        if baseline_std > TIME_BASED_MAX_BASELINE_STD:
            self.logger.debug(f"[Time-based] 网络波动过大 (std={baseline_std:.2f}s)，跳过检测")
            return True

        if baseline_avg > TIME_BASED_MAX_BASELINE_AVG:
            self.logger.debug(f"[Time-based] 基线响应时间过长 ({baseline_avg:.2f}s)，跳过检测")
            return True

        return False
    
    def get_config(self) -> Dict[str, Any]:
        """
        获取模块配置
        
        Returns:
            配置字典
        """
        return {
            "enabled": self.enabled,
            "timeout": self.module_config.timeout,
            "threads": self.module_config.threads,
            "depth": self.module_config.depth,
            "custom_params": self.module_config.custom_params
        }
    
    def update_config(self, **kwargs):
        """
        更新模块配置
        
        Args:
            **kwargs: 配置参数
        """
        for key, value in kwargs.items():
            if hasattr(self.module_config, key):
                setattr(self.module_config, key, value)
                self.logger.debug(f"更新配置 {key} = {value}")
    
    def get_stats(self) -> Dict[str, Any]:
        """
        获取模块统计信息
        
        Returns:
            统计字典
        """
        stats = self._stats.copy()
        
        # 计算持续时间
        if stats["start_time"] and stats["end_time"]:
            stats["duration"] = stats["end_time"] - stats["start_time"]
        else:
            stats["duration"] = 0
        
        # 添加基本信息
        stats.update({
            "module_name": self.info.name,
            "module_version": self.info.version,
            "enabled": self.enabled
        })
        
        return stats
    
    def reset_stats(self):
        """重置统计信息"""
        self._stats = {
            "requests_made": 0,
            "vulnerabilities_found": 0,
            "errors": 0,
            "start_time": None,
            "end_time": None
        }
    
    def validate(self) -> bool:
        """
        验证模块配置
        
        Returns:
            配置是否有效
        """
        try:
            if self.module_config.timeout <= 0:
                self.logger.warning(f"模块 {self.info.name} 超时时间必须大于0")
                return False
            
            if self.module_config.threads <= 0:
                self.logger.warning(f"模块 {self.info.name} 线程数必须大于0")
                return False
            
            if self.module_config.depth <= 0:
                self.logger.warning(f"模块 {self.info.name} 深度必须大于0")
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"模块 {self.info.name} 验证失败: {e}")
            return False
    
    async def test(self) -> bool:
        """
        测试模块功能
        
        Returns:
            测试是否通过
        """
        self.logger.info(f"测试模块 {self.info.name}")
        
        try:
            # 基本功能测试
            if not self.validate():
                self.logger.error(f"模块 {self.info.name} 配置验证失败")
                return False
            
            # 这里可以添加模块特定的测试
            # 例如：测试payload加载、网络连接等
            
            self.logger.info(f"模块 {self.info.name} 测试通过")
            return True
            
        except Exception as e:
            self.logger.error(f"模块 {self.info.name} 测试失败: {e}")
            return False
    
    def __str__(self) -> str:
        """友好的字符串表示"""
        return f"{self.info.name} ({self.info.version}) - {self.info.description}"


class ModuleFactory:
    """
    模块工厂
    
    负责创建和管理检测模块实例
    """
    
    _modules: Dict[str, type] = {}
    
    @classmethod
    def register(cls, module_class: type):
        """
        注册模块类
        
        Args:
            module_class: 模块类
        """
        if not issubclass(module_class, DetectionModule):
            raise TypeError(f"{module_class} 必须继承自 DetectionModule")
        
        module_info = module_class.get_info()
        cls._modules[module_info.name] = module_class
        
        logger.info(f"注册模块: {module_info.name}")
    
    @classmethod
    def create(cls, module_name: str, config: Optional[ConfigManager] = None) -> DetectionModule:
        """
        创建模块实例
        
        Args:
            module_name: 模块名称
            config: 配置管理器
            
        Returns:
            模块实例
            
        Raises:
            KeyError: 模块未注册
        """
        if module_name not in cls._modules:
            raise KeyError(f"模块 '{module_name}' 未注册")
        
        module_class = cls._modules[module_name]
        return module_class(config)
    
    @classmethod
    def list_modules(cls) -> List[str]:
        """
        列出所有注册的模块
        
        Returns:
            模块名称列表
        """
        return list(cls._modules.keys())
    
    @classmethod
    def get_module_info(cls, module_name: str) -> Optional[ModuleInfo]:
        """
        获取模块信息
        
        Args:
            module_name: 模块名称
            
        Returns:
            ModuleInfo对象，如果模块未注册则返回None
        """
        if module_name not in cls._modules:
            return None
        
        module_class = cls._modules[module_name]
        return module_class.get_info()
    
    @classmethod
    def create_all(cls, config: Optional[ConfigManager] = None, 
                  enabled_only: bool = True) -> Dict[str, DetectionModule]:
        """
        创建所有模块实例
        
        Args:
            config: 配置管理器
            enabled_only: 是否只创建启用的模块
            
        Returns:
            模块名称到实例的映射
        """
        modules = {}
        
        for module_name in cls.list_modules():
            try:
                module = cls.create(module_name, config)
                
                if enabled_only and not module.enabled:
                    continue
                    
                modules[module_name] = module
                
            except Exception as e:
                logger.error(f"创建模块 {module_name} 失败: {e}")
        
        return modules


# 装饰器：自动注册模块
def register_module(module_class: type) -> type:
    """
    自动注册模块的装饰器
    
    用法:
        @register_module
        class SQLiModule(DetectionModule):
            ...
    """
    ModuleFactory.register(module_class)
    return module_class


if __name__ == "__main__":
    # 测试模块系统
    print("测试模块系统...")
    
    # 创建一个测试模块
    @register_module
    class TestModule(DetectionModule):
        @classmethod
        def get_info(cls):
            return ModuleInfo(
                name="test",
                description="测试模块",
                version="1.0.0"
            )
        
        async def _scan_impl(self, target):
            print(f"测试模块扫描: {target.url}")
            return []
    
    # 测试模块工厂
    print("\n1. 模块工厂测试:")
    modules = ModuleFactory.list_modules()
    print(f"  注册的模块: {modules}")
    
    # 创建模块实例
    print("\n2. 创建模块实例:")
    test_module = ModuleFactory.create("test")
    print(f"  模块: {test_module}")
    print(f"  模块信息: {test_module.info}")
    print(f"  模块配置: {test_module.get_config()}")
    
    # 测试扫描
    print("\n3. 测试扫描:")
    import asyncio
    
    target = ScanTarget(url="http://example.com")
    
    async def run_test():
        vulnerabilities = await test_module.scan(target)
        print(f"  发现的漏洞: {len(vulnerabilities)}")
    
    asyncio.run(run_test())
    
    print("\n测试完成！")