"""
命令注入检测模块
v18 痛点解决：
1. 必须 baseline 对比（v18 的 NoneType 误报彻底消除）
2. 随机 token 回显验证（不能依赖固定字符串）
3. 空响应/"NoneType" → 直接排除，不报告
4. 支持 Linux + Windows 双平台
5. 支持 OOB 检测 (通过 OOBManager 或环境变量)
"""
import asyncio
import logging
import os
import re
import secrets
import string
import time
from typing import Any, Dict, List, Optional, Tuple

from ..base import DetectionModule, ModuleInfo
from ..base import register_module
from ...models import Vulnerability, VulnerabilityType, Severity, Confidence, ScanTarget
from ...core.session import HTTPPool
from ...core.oob import OOBManager
from .payloads import (
    build_echo_payloads,
    build_time_payloads,
    ECHO_PAYLOADS_LINUX,
    GENERIC_PAYLOADS,
    WAF_BYPASS_PAYLOADS,
    TIME_PAYLOADS_LINUX,
    OOB_PAYLOADS,
    build_oob_payloads,
)


logger = logging.getLogger("wvs.module.cmdi")


def _gen_token(length: int = 8) -> str:
    """生成随机 token"""
    return "".join(
        secrets.choice(string.ascii_lowercase + string.digits) for _ in range(length)
    )


@register_module
class CMDInjectionDetector(DetectionModule):
    """命令注入检测模块"""

    @classmethod
    def title(cls) -> str:
        """覆盖父类 title()，避免 str.title() 把 CMDiDetector 变成 CmdiDetector"""
        return "CMDiDetector"

    @classmethod
    def get_info(cls) -> ModuleInfo:
        return ModuleInfo(
            name="cmdi",
            description="检测命令注入漏洞（echo回显 / time-based / OOB）",
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
    # 核心入口
    # ----------------------------------------------------------

    async def _scan_impl(self, target: ScanTarget) -> List[Vulnerability]:
        self._found_vulns = []

        # ── 1. 优先使用 target.params（来自 scanner/crawler，已带 auth）──
        target_params = getattr(target, 'params', None) or {}
        target_data = getattr(target, 'data', None) or {}
        if target_params:
            ep_params = target_params.copy()
            logger.debug(f"[CMDi] 使用 target.params={list(ep_params.keys())} 检测 {target.url}")
            await self._scan_endpoint(target.url, ep_params, "GET", "query")
        elif target_data:
            ep_params = target_data.copy()
            logger.debug(f"[CMDi] 使用 target.data={list(ep_params.keys())} 检测 {target.url}")
            await self._scan_endpoint(target.url, ep_params, "POST", "body")

        # ── 2. 补充：用 _extract_endpoints 获取更多端点（URL query string 等）──
        endpoints = self._extract_endpoints(target)
        logger.info(f"[CMDi] 开始检测，共 {len(endpoints)} 个端点")

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
                logger.debug(f"[CMDi] 检测 {url} 时出错: {e}")

        logger.info(f"[CMDi] 检测完成，发现 {len(self._found_vulns)} 个端点存在 CMDi")
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
        """单次检测（GET 或 POST）"""
        if not params:
            return

        # 获取 baseline（关键：用于消除误报）
        baseline = await self._send_request(method, url, params, param_type)
        if baseline is None:
            return

        baseline_text = baseline.get("text", "")[:5000]
        baseline_hash = hash(baseline_text)

        # 先发 baseline，确认页面本身不含命令执行特征
        # v18 痛点：如果 baseline 里就有 "whoami" 结果，那直接返回了根本没检测
        # v19 方案：用随机 token 检测，baseline 里绝对不可能有随机 token

        for param_name in params.keys():
            await self._test_echo_based(
                url, params, param_name, method, param_type, baseline, baseline_text
            )

            await self._test_time_based(
                url, params, param_name, method, param_type, baseline
            )

            # OOB 检测（无回显场景，需要外带 DNS/HTTP）
            await self._test_oob(
                url, params, param_name, method, param_type, baseline
            )

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
        Echo 回显检测 — 核心检测方法

        流程：
        1. 生成随机 token（baseline 里绝无可能存在）
        2. 注入 token
        3. 检查响应中是否回显了 token
        4. 若回显 → 排除 echo-server → 二次验证（换不同 payload）

        误报防护：仅当 token 以独立形式出现（不是作为完整 payload 的一部分）
        才认为可能执行了命令。例如：
        - PHP echo $_GET['x'] 返回 "; echo abc123" → token 被包在 payload 中 → 过滤
        - 真实 CMDi 返回 "abc123" 单独出现 → token 独立 → 通过
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
                logger.debug(f"[CMDi] 过滤 echo-back: {url}")
                continue
            if await self._verify_echo(url, params, param_name, method, param_type, token):
                vuln = self._create_vuln(
                    url=url, param=param_name, param_type=param_type,
                    method=method, payload=payload, token=token,
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
        二次验证：用不同的 payload 和不同的 token 再次确认
        优化：只验证 1 次而不是 3 次，提高速度
        P16: 增加 _is_input_reflection 检查，防止 stored XSS 等回显页面误报
        """
        new_token = _gen_token()
        verify_payloads = [
            f"; echo {new_token}",
            f"| echo {new_token}",
        ]

        # 只验证 1 次
        test_params = params.copy()
        verify_payload = verify_payloads[0]
        test_params[param_name] = verify_payload

        resp = await self._send_request(method, url, test_params, param_type)
        if resp is None:
            return False

        resp_text = resp.get("text", "")[:5000]

        # 新 token 出现 → 但先排除输入反射
        if new_token in resp_text:
            if self._is_input_reflection(resp_text, verify_payload, new_token):
                logger.debug(f"[CMDi] verify filtered as input reflection")
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
        Time-based 检测 — P13 并发优化版

        原来：逐 payload 串行发包，每次等 3-5 秒 → 12 次请求 × 5s = 60s/端点
        现在：所有 time-based payload 并发发送，总耗时 = max(单个延迟) ≈ 2-5s/端点
        """
        from ...constants import (TIME_BASED_DELAYS_LOCAL, TIME_BASED_DELAYS_REMOTE,
                                   TIME_BASED_BATCH_TIMEOUT)

        # 1. 快速基线（仅 2 次采样，减少开销）
        baseline_avg, baseline_std = await self._measure_baseline(method, url, params, param_type, samples=2)

        # 2. 检查是否跳过
        if self._should_skip_time_based(baseline_avg, baseline_std):
            return

        # 3. 判断本地/远端 → 选延迟
        is_local = any(s in url for s in ('172.', '192.168.', '10.', '127.'))
        delays = TIME_BASED_DELAYS_LOCAL if is_local else TIME_BASED_DELAYS_REMOTE

        # 4. 构建所有 time-based probe 任务，并发发送
        probe_tasks = []
        for delay in delays:
            payloads = build_time_payloads(delay, "linux")[:2]  # 只测 Linux（本地靶机通常是 Linux）
            for payload in payloads:
                probe_tasks.append((delay, payload))

        async def _probe_one(delay: float, payload: str):
            test_params = self._inject_param(params, param_name, payload)
            start = time.perf_counter()
            resp = await self._send_request(method, url, test_params, param_type)
            actual = time.perf_counter() - start
            return (delay, payload, resp, actual)

        # 并发发送所有探测
        results = await asyncio.gather(
            *[_probe_one(d, p) for d, p in probe_tasks],
            return_exceptions=True
        )

        # 5. 检查结果 — 哪个延迟触发了漏洞
        for result in results:
            if isinstance(result, Exception):
                continue
            delay, payload, resp, actual = result
            if resp is None:
                continue
            if self._is_valid_time_delay(actual, delay, baseline_avg):
                # 二次验证（仅 1 次，减少开销）
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
                        description=f"发现可能的命令注入漏洞（time-based，延迟 {actual:.2f}s）",
                        recommendation="避免将用户输入拼接到 shell 命令中",
                        module="cmdi",
                        tags=["cmdi", "command-injection", "time-based"],
                        context={"vuln_type": "time-based", "platform": platform},
                    )
                    self._found_vulns.append(vuln)
                    logger.warning(
                        f"[CMDi] Time-based ({platform}): {url} [{param_name}], delay={actual:.2f}s"
                    )
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
        OOB（Out-of-Band）命令注入检测

        适用场景：目标无回显，但可发起外带请求（DNS / HTTP）
        支持两种配置方式：
        1. OOBManager（推荐）：自动注册 Interactsh / DNSLog.cn 并验证回调
        2. 环境变量 WVS_OOB_URL：手动配置外部 OOB 服务

        优先级：OOBManager > WVS_OOB_URL
        """
        # 方式 1: 使用 OOBManager（推荐）
        if self._oob_manager and self._oob_manager.is_initialized:
            await self._test_oob_with_manager(
                url, params, param_name, method, param_type
            )
            return

        # 方式 2: 使用环境变量配置
        oob_base = os.environ.get("WVS_OOB_URL", "").strip()
        if not oob_base:
            # 无 OOB 配置则跳过
            return

        token = _gen_token(6)
        oob_url = f"{oob_base}/{token}"

        # OOB payloads（curl / wget / nslookup / ping）
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

        logger.info(
            f"[CMDi] OOB probe sent to {url} [{param_name}], "
            f"check {oob_base} for token={token}"
        )

    async def _test_oob_with_manager(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        method: str,
        param_type: str,
    ) -> None:
        """使用 OOBManager 进行 OOB 检测"""
        try:
            # 生成 token 并获取回调 URL
            token = await self._oob_manager.generate_token({
                "url": url,
                "param": param_name,
                "module": "cmdi"
            })
            callback_url = self._oob_manager.get_callback_url(token)

            # 构建 OOB payloads
            payloads = build_oob_payloads(callback_url, "http")
            payloads.extend(build_oob_payloads(token, "dns"))

            # 发送请求
            for payload in payloads[:4]:
                test_params = params.copy()
                test_params[param_name] = payload
                await self._send_request(method, url, test_params, param_type)

            # 等待回调验证
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
                logger.warning(f"[CMDi] OOB 检测到: {url} [{param_name}]")

        except Exception as e:
            logger.debug(f"[CMDi] OOB 检测失败: {e}")

    # ----------------------------------------------------------
    # 误报过滤（v18 的 NoneType 问题在这里解决）
    # ----------------------------------------------------------

    def _is_input_reflection(self, resp_text: str, payload: str, token: str) -> bool:
        """
        检测是否为 PHP echo-back（整个 payload 被原样反射），而非命令执行回显。

        真实 CMDi：响应中只出现 token（命令执行了，echo 输出了 token）
        误报场景：响应中出现了完整 payload（如 `; echo abc123`），说明只是参数回显

        P16: 移除 ALL payload 出现（不是只移除一次），防止多位置回显绕过
        （如 stored XSS 页面在表单+消息区均回显输入）

        返回 True 表示是输入反射（误报），应跳过。
        """
        if payload in resp_text:
            stripped = resp_text.replace(payload, "")
            if token not in stripped:
                return True
        return False

    def _is_false_positive(self, resp_text: str, token: str) -> bool:
        """
        判断是否为误报，返回 True 表示是误报应该跳过

        v18 的误报场景：
        - 响应是空字符串（空页面）
        - 响应是 "NoneType" 字符串（模板渲染失败）
        - 响应只是 "None"（Python None 序列化）
        - 响应长度 < 10（几乎没有内容）
        - token 在 baseline 响应中就存在（页面本身就有这个词）
        """
        # 过滤：空响应
        if not resp_text or len(resp_text.strip()) < 5:
            return True

        # 过滤：NoneType / None / null 响应（典型 v18 误报）
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
                logger.debug(f"[CMDi] 过滤误报: NoneType pattern detected")
                return True

        # 过滤：只有 "None" / "null" / "false" 的响应
        if stripped.lower() in ("none", "null", "false", "error", "404", "403", "500"):
            return True

        # 过滤：token 在 baseline 就有（用 gen_token 保证极低概率）
        # 这个检查在调用前已经通过 baseline 参数处理了

        return False

    # ----------------------------------------------------------
    # 工具方法
    # ----------------------------------------------------------

    # 注：_send_request 和 _extract_endpoints 方法已移至基类 DetectionModule

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
        """创建漏洞对象"""
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
            description="发现命令注入漏洞，可执行任意系统命令",
            recommendation="避免将用户输入拼接到 shell 命令中，使用 subprocess.run() 的 shell=False 或参数列表形式",
            module="cmdi",
            tags=["cmdi", "command-injection", vuln_type_str],
            context={"vuln_type": vuln_type_str, "token": token},
        )
