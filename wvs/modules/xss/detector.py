"""
XSS 检测模块
检测：reflected / stored / DOM-based XSS
支持：OOB 检测（Blind XSS）
"""
import logging
import re
import secrets
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse

from ..base import DetectionModule, ModuleInfo, register_module
from ...models import Vulnerability, VulnerabilityType, Severity, Confidence, ScanTarget
from ...core.session import HTTPPool
from ...core.oob import OOBManager
from .payloads import (
    REFLECTED_PAYLOADS,
    STORED_PAYLOADS,
    DOM_PAYLOADS,
    ENCODED_PAYLOADS,
    WAF_BYPASS_PAYLOADS,
    generate_stored_xss_marker,
    STORED_XSS_CALLBACK_PAYLOADS,
)


logger = logging.getLogger("wvs.module.xss")


@register_module
class XSSDetector(DetectionModule):

    @classmethod
    def get_info(cls) -> ModuleInfo:
        return ModuleInfo(
            name="xss",
            description="检测 XSS 漏洞（reflected / stored / DOM-based）",
            author="WVS Team",
            version="1.0.0",
            enabled_by_default=True,
            tags=["xss", "cross-site-scripting", "stored-xss", "reflected-xss"],
        )

    def __init__(self, config=None, session: Optional[HTTPPool] = None):
        super().__init__(config)
        self.session = session
        self._found_vulns: List[Vulnerability] = []
        self._checked_urls: set = set()
        self._oob_manager: Optional[OOBManager] = None

    async def _scan_impl(self, target: ScanTarget) -> List[Vulnerability]:
        self._found_vulns = []

        # ── 1. 优先使用 target.params（来自 scanner/crawler，已带 auth）──
        target_params = getattr(target, 'params', None) or {}
        target_data = getattr(target, 'data', None) or {}
        if target_params:
            ep_params = target_params.copy()
            logger.debug(f"[XSS] 使用 target.params={list(ep_params.keys())} 检测 {target.url}")
            await self._scan_endpoint(target.url, ep_params, "GET", "query")
        elif target_data:
            ep_params = target_data.copy()
            logger.debug(f"[XSS] 使用 target.data={list(ep_params.keys())} 检测 {target.url}")
            await self._scan_endpoint(target.url, ep_params, "POST", "body")

        # ── 2. 补充：用 _extract_endpoints 获取更多端点 ──
        endpoints = self._extract_endpoints(target)
        logger.info(f"[XSS] 开始检测，共 {len(endpoints)} 个端点")

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
                logger.debug(f"[XSS] 检测 {url} 时出错: {e}")

        logger.info(f"[XSS] 检测完成，发现 {len(self._found_vulns)} 个漏洞")
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

        baseline = await self._send_request(method, url, params, param_type)
        if baseline is None:
            return

        baseline_text = baseline.get("text", "")

        for param_name in params.keys():
            # 反射检测
            await self._test_reflected(url, params, param_name, method, param_type, baseline_text)

            # DOM 检测
            await self._test_dom(url, params, param_name, param_type, baseline_text)

            # 存储型 XSS 检测（Blind XSS）
            await self._test_stored_xss(url, params, param_name, method, param_type)

    async def _test_stored_xss(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        method: str,
        param_type: str,
    ) -> None:
        """
        检测存储型 XSS / Blind XSS

        两种检测方式：
        1. OOB 检测（推荐）：注入回调 payload，检查是否收到回调
        2. 本地检测：注入标记，在关联页面查找标记是否出现
        """
        # 方式 1: 使用 OOBManager（推荐）
        if self._oob_manager and self._oob_manager.is_initialized:
            await self._test_stored_oob(url, params, param_name, method, param_type)
            return

        # 方式 2: 本地检测 — 注入后回查多个可能的展示位置
        marker = generate_stored_xss_marker()

        # 构建存储型 payload
        test_params = params.copy()
        test_params[param_name] = marker

        # 发送注入请求
        resp = await self._send_request(method, url, test_params, param_type)
        if resp is None:
            return

        # 构建回查 URL 列表（动态生成 + 常见路径）
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        path_parts = parsed.path.rstrip('/').split('/')

        display_urls = []

        # 1. 同页面回查（存储型 XSS 常见于同页显示）
        display_urls.append(url)

        # 2. 父级目录索引页
        for i in range(len(path_parts) - 1, 0, -1):
            parent = '/'.join(path_parts[:i]) or '/'
            display_urls.append(base + parent)
            display_urls.append(base + parent + '/index.php')
            display_urls.append(base + parent + '/index.html')

        # 3. 同级常见展示页
        sibling_names = [
            "view.php", "show.php", "display.php", "read.php", "detail.php",
            "list.php", "index.php", "home.php", "guestbook.php", "comments.php",
            "add-to-your-blog.php", "blog.php", "forum.php", "board.php",
        ]
        parent_dir = '/'.join(path_parts[:-1]) if len(path_parts) > 1 else ''
        for name in sibling_names:
            display_urls.append(f"{base}{parent_dir}/{name}")

        # 4. 根目录常见页
        for name in ["index.php", "index.html", "home.php", "guestbook.php"]:
            display_urls.append(f"{base}/{name}")

        checked = set()
        for display_url in display_urls:
            if display_url in checked or display_url == url:
                # url already checked as #1 above — but we re-check it separately
                pass
            if display_url in checked:
                continue
            checked.add(display_url)
            try:
                display_resp = await self._send_request("GET", display_url, {}, "query")
                if display_resp and marker in display_resp.get("text", ""):
                    vuln = self._create_vuln(
                        url=url,
                        param=param_name,
                        param_type=param_type,
                        method=method,
                        payload=marker,
                        vuln_type="stored",
                        evidence=f"Stored XSS marker '{marker}' reflected on {display_url}",
                    )
                    self._found_vulns.append(vuln)
                    logger.warning(f"[XSS] Stored XSS 检测到: {url} [{param_name}] reflected on {display_url}")
                    return
            except Exception:
                continue

    async def _test_stored_oob(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        method: str,
        param_type: str,
    ) -> None:
        """使用 OOB 检测 Blind XSS"""
        try:
            token = await self._oob_manager.generate_token({
                "url": url,
                "param": param_name,
                "module": "xss"
            })
            callback_url = self._oob_manager.get_callback_url(token)

            # 构建 Blind XSS payload
            payload = f"<script src='{callback_url}'></script>"

            test_params = params.copy()
            test_params[param_name] = payload
            await self._send_request(method, url, test_params, param_type)

            # 等待回调
            callback = await self._oob_manager.check_callback(token, timeout=30)

            if callback:
                vuln = self._create_vuln(
                    url=url,
                    param=param_name,
                    param_type=param_type,
                    method=method,
                    payload=payload,
                    vuln_type="stored-blind",
                    evidence=f"Blind XSS OOB callback received from {callback.source_ip}",
                )
                self._found_vulns.append(vuln)
                logger.warning(f"[XSS] Blind XSS 检测到: {url} [{param_name}]")

        except Exception as e:
            logger.debug(f"[XSS] Blind XSS 检测失败: {e}")

    async def _test_reflected(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        method: str,
        param_type: str,
        baseline_text: str,
    ) -> None:
        """
        检测反射型 XSS
        流程：注入 payload → 检测是否原样/变形反射在 HTML 中 → 二次验证
        """
        logger.debug(f"[XSS] 开始反射型检测: {url} [{param_name}]")

        # 第一轮：测试最可能触发的 payload (P7: +polyglot +WAF bypass)
        priority_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "'><script>alert(1)</script>",
            '"><script>alert(1)</script>',
            "<SCRIPT>alert(1)</SCRIPT>",
            "<ScRiPt>alert(1)</ScRiPt>",
            # P7: polyglot + encoding bypass
            "javascript:alert(1)",
            "\"'><img src=x onerror=alert(1)>",
            "';alert(1);//",
            "<img src=x onerror=alert(1) ",
            "<<SCRIPT>alert(1);//<</SCRIPT>",
            "<details open ontoggle=alert(1)>",
            "<body onload=alert(1)>",
            "<input autofocus onfocus=alert(1)>",
        ]

        for payload in priority_payloads:
            test_params = params.copy()
            test_params[param_name] = payload
            logger.debug(f"[XSS] 测试 payload: {payload[:30]}")

            resp = await self._send_request(method, url, test_params, param_type)
            if resp is None:
                continue

            resp_text = resp.get("text", "")[:20000]

            # 检测反射
            reflected, evidence = self._check_reflection(resp_text, payload, baseline_text)
            if reflected:
                if self._is_echo_server(url, resp_text, payload):
                    logger.debug(f"[XSS] 忽略 echo-server 反射: {url}")
                    continue
                logger.info(f"[XSS] 发现反射: {url} [{param_name}] payload={payload[:30]}")
                # 二次验证：换不同 payload
                if await self._verify_reflected(url, params, param_name, method, param_type):
                    vuln = self._create_vuln(
                        url=url,
                        param=param_name,
                        param_type=param_type,
                        method=method,
                        payload=payload,
                        vuln_type="reflected",
                        evidence=evidence or f"Reflected XSS: payload '{payload}' reflected in response",
                    )
                    self._found_vulns.append(vuln)
                    logger.warning(f"[XSS] Reflected 确认: {url} [{param_name}]")
                    return

        # 第二轮：测试更多 payloads
        test_payloads = list(REFLECTED_PAYLOADS[:15])
        test_payloads.extend(ENCODED_PAYLOADS[:5])

        for payload in test_payloads:
            if payload in priority_payloads:
                continue
            test_params = params.copy()
            test_params[param_name] = payload

            resp = await self._send_request(method, url, test_params, param_type)
            if resp is None:
                continue

            resp_text = resp.get("text", "")[:20000]

            # 检测反射
            reflected, evidence = self._check_reflection(resp_text, payload, baseline_text)
            if reflected:
                if self._is_echo_server(url, resp_text, payload):
                    logger.debug(f"[XSS] 忽略 echo-server 反射 (round 2): {url}")
                    continue
                # 二次验证：换不同 payload
                if await self._verify_reflected(url, params, param_name, method, param_type):
                    vuln = self._create_vuln(
                        url=url,
                        param=param_name,
                        param_type=param_type,
                        method=method,
                        payload=payload,
                        vuln_type="reflected",
                        evidence=evidence or f"Reflected XSS: payload '{payload}' reflected in response",
                    )
                    self._found_vulns.append(vuln)
                    logger.warning(f"[XSS] Reflected 检测到: {url} [{param_name}]")
                    return

    async def _test_dom(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        param_type: str,
        baseline_text: str,
    ) -> None:
        """
        检测 DOM-based XSS
        通过注入特殊标记，观察 URL 中是否有可控点
        """
        dom_markers = [
            "#<script>alert(1)</script>",
            "#<img src=x onerror=alert(1)>",
            "#'><script>alert(document.domain)</script>",
        ]

        # 将 DOM payload 注入到 URL fragment
        for payload in dom_markers[:2]:
            test_url = url + payload

            resp = await self._send_request("GET", test_url, {}, param_type)
            if resp is None:
                continue

            resp_text = resp.get("text", "")[:20000]

            # DOM XSS 的特征：payload 出现在响应中（可能编码）
            reflected, evidence = self._check_reflection(resp_text, payload, baseline_text)
            if reflected:
                vuln = self._create_vuln(
                    url=url,
                    param=param_name,
                    param_type=param_type,
                    method="GET",
                    payload=payload,
                    vuln_type="dom-based",
                    evidence=evidence or f"DOM-based XSS: fragment payload '{payload}' reflected in response",
                )
                self._found_vulns.append(vuln)
                logger.warning(f"[XSS] DOM-based 检测到: {url}")
                return

    def _check_reflection(self, resp_text: str, payload: str, baseline_text: str) -> Tuple[bool, str]:
        """
        检测 payload 是否被反射（可能在不同编码形式下）

        P9 fix: Guarantee evidence is never empty. Every return path
        now includes a specific evidence string describing what was found.

        Returns:
            (is_reflected, evidence) — 是否被反射 + 详细证据（never empty on True）
        """
        # 1. Payload appears verbatim in response AND not in baseline (strongest)
        if payload in resp_text and payload not in baseline_text:
            idx = resp_text.find(payload)
            context = resp_text[max(0, idx-30):idx+len(payload)+30]
            return True, f"XSS payload reflected verbatim in response body at offset {idx}"

        # 2. HTML-decoded payload appears (and not in baseline)
        decoded = self._html_decode(payload)
        if decoded in resp_text and decoded != payload and decoded not in baseline_text:
            idx = resp_text.find(decoded)
            return True, f"XSS payload reflected after HTML-decode at offset {idx}"

        # P7: URL-encoded payload reflected as decoded HTML
        from urllib.parse import quote
        encoded = quote(payload, safe='')
        if encoded != payload and encoded not in baseline_text:
            decoded_from_encoded = self._html_decode(encoded)
            if decoded_from_encoded in resp_text and decoded_from_encoded not in baseline_text:
                idx = resp_text.find(decoded_from_encoded)
                return True, f"XSS payload reflected after URL-decode at offset {idx}"

        # 3. XSS structural detection — actual script/event-handler injection
        #    Must be NEW content not present in baseline
        evidence = ""

        # Check for new <script> tags with content
        script_re = re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL)
        resp_scripts = script_re.findall(resp_text)
        base_scripts = script_re.findall(baseline_text)
        if len(resp_scripts) > len(base_scripts):
            for s in resp_scripts:
                if "alert" in s.lower() or "prompt" in s.lower():
                    evidence = f"New <script> tag with alert/prompt injected in response"
                    break

        # Check for new event handlers with alert/prompt
        if not evidence:
            event_handlers = ["onerror", "onload", "onclick", "onfocus", "onmouseover"]
            for handler in event_handlers:
                pattern = re.compile(
                    rf'{handler}\s*=\s*["\']?\s*(?:javascript:)?\s*alert',
                    re.IGNORECASE,
                )
                if pattern.search(resp_text) and not pattern.search(baseline_text):
                    evidence = f"New event handler '{handler}=alert()' injected in response"
                    break

        if evidence:
            return True, evidence

        # 4. Partial reflection: payload fragments with structural context
        script_tag_patterns = [
            (r"<script[^>]*>.*?alert.*?</script>", "New <script>alert() in response"),
            (r"onerror\s*=\s*[\"']?alert", "New onerror=alert handler in response"),
            (r"<img[^>]+onerror", "New <img onerror> tag in response"),
            (r"<svg[^>]+onload", "New <svg onload> tag in response"),
            (r"<body[^>]+onload", "New <body onload> attribute in response"),
            (r"<input[^>]+onfocus", "New <input onfocus> tag in response"),
        ]
        for pattern, label in script_tag_patterns:
            match = re.search(pattern, resp_text, re.IGNORECASE)
            if match:
                baseline_match = re.search(pattern, baseline_text, re.IGNORECASE)
                if not baseline_match:
                    return True, label

        return False, ""

    def _html_decode(self, text: str) -> str:
        """HTML 解码 + URL 解码"""
        import html as _html
        result = _html.unescape(text)
        # URL-decode: servers may reflect %3Cscript%3E as <script>
        try:
            from urllib.parse import unquote
            result = unquote(result)
        except Exception:
            pass
        return result

    async def _verify_reflected(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        method: str,
        param_type: str,
    ) -> bool:
        """二次验证：用不同的 payload 确认 — P8: tightened to require structural injection evidence"""
        logger.debug(f"[XSS] 开始二次验证: {url} [{param_name}]")

        verify_payloads = [
            '<svg onload=alert(1)>',
            '<img src=x onerror=alert(1)>',
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            '<img src=x onerror="alert(1)">',
            "<SCRIPT>alert(1)</SCRIPT>",
        ]

        # Get fresh baseline for comparison
        baseline_resp = await self._send_request(method, url, params.copy(), param_type)
        baseline_text = baseline_resp.get("text", "")[:20000] if baseline_resp else ""

        for verify_payload in verify_payloads[:3]:
            test_params = params.copy()
            test_params[param_name] = verify_payload
            resp = await self._send_request(method, url, test_params, param_type)
            if resp is None:
                continue

            resp_text = resp.get("text", "")[:20000]

            # P8: Use _check_reflection for consistent structural detection
            reflected, _ = self._check_reflection(resp_text, verify_payload, baseline_text)
            if reflected:
                logger.debug(f"[XSS] 验证成功: structural reflection detected")
                return True

            # P8: Also check verbatim reflection (but must NOT be in baseline)
            if verify_payload in resp_text and verify_payload not in baseline_text:
                logger.debug(f"[XSS] 验证成功: payload verbatim reflected (not in baseline)")
                return True

        return False

    # 注：_send_request, _extract_endpoints, _create_vuln 方法已移至基类 DetectionModule

