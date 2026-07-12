"""
XSS Detection Module
Detects: reflected / stored / DOM-based XSS
Supports: OOB detection (Blind XSS)
"""

import logging
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from ...core.oob import OOBManager
from ...core.session import HTTPPool
from ...models import ScanTarget, Vulnerability
from ..base import DetectionModule, ModuleInfo, register_module
from .context_analyzer import (
    XSS_CHECKER,
    ReflectionContext,
    analyze_reflection,
    select_payload,
)
from .payloads import (
    REFLECTED_PAYLOADS,
    generate_stored_xss_marker,
)

logger = logging.getLogger("wvs.module.xss")


@register_module
class XSSDetector(DetectionModule):
    @classmethod
    def get_info(cls) -> ModuleInfo:
        return ModuleInfo(
            name="xss",
            description="Detect XSS vulnerabilities (reflected / stored / DOM-based)",
            author="WVS Team",
            version="1.0.0",
            enabled_by_default=True,
            category="core",
            priority=20,
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

        # ── 1. Prefer target.params (from scanner/crawler, already with auth) ──
        target_params = getattr(target, "params", None) or {}
        target_data = getattr(target, "data", None) or {}
        if target_params:
            ep_params = target_params.copy()
            logger.debug(f"[XSS] Using target.params={list(ep_params.keys())} testing {target.url}")
            await self._scan_endpoint(target.url, ep_params, "GET", "query")
        elif target_data:
            ep_params = target_data.copy()
            logger.debug(f"[XSS] Using target.data={list(ep_params.keys())} testing {target.url}")
            await self._scan_endpoint(target.url, ep_params, "POST", "body")

        # ── 2. Supplement: use _extract_endpoints to get more endpoints ──
        endpoints = self._extract_endpoints(target)
        logger.info(f"[XSS] Starting detection, {len(endpoints)} endpoints total")

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
                logger.debug(f"[XSS] Error testing {url}: {e}")

        logger.info(f"[XSS] Detection complete, found {len(self._found_vulns)} vulnerabilities")
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

        # P23: Limit parameters per endpoint to avoid form-storm on dense pages.
        # Forms like add-to-your-blog.php with 8+ inputs generate 24+ XSS tests
        # per endpoint. Sample the most promising parameter names first.
        param_names = list(params.keys())
        if len(param_names) > 4:
            # Prioritize parameters whose names suggest user-facing output
            high_priority = {
                "page",
                "q",
                "query",
                "search",
                "text",
                "msg",
                "message",
                "comment",
                "content",
                "body",
                "title",
                "subject",
                "name",
                "username",
                "cat",
                "category",
                "id",
                "uid",
                "pid",
            }
            prioritized = [p for p in param_names if p.lower() in high_priority]
            remaining = [p for p in param_names if p.lower() not in high_priority]
            param_names = prioritized + remaining[: max(4 - len(prioritized), 1)]
            self.logger.debug(f"[XSS] Sampled {len(param_names)}/{len(params)} params for {url}")

        baseline = await self._send_request(method, url, params, param_type)
        if baseline is None:
            return

        baseline_text = baseline.get("text", "")

        for param_name in param_names:
            # Reflected XSS test
            await self._test_reflected(url, params, param_name, method, param_type, baseline_text)

            # Polyglot XSS test (multi-context payloads)
            await self._test_polyglot(url, params, param_name, method, param_type, baseline_text)

            # Mutation XSS (mXSS) test
            await self._test_mxss(url, params, param_name, method, param_type, baseline_text)

            # SSTI (template injection) test
            await self._test_ssti(url, params, param_name, method, param_type, baseline_text)

            # DOM-based XSS test
            await self._test_dom(url, params, param_name, param_type, baseline_text)

            # Stored XSS test — skip POST forms to avoid data pollution
            # (add-to-your-blog, register, comment forms)
            if method == "GET":
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
        Detect stored XSS / Blind XSS

        Two detection methods:
        1. OOB detection (recommended): inject callback payload, check for callbacks
        2. Local detection: inject marker, check related pages for marker appearance
        """
        # Method 1: Use OOBManager (recommended)
        if self._oob_manager and self._oob_manager.is_initialized:
            await self._test_stored_oob(url, params, param_name, method, param_type)
            return

        # Method 2: Local detection — inject and then check multiple possible display locations
        marker = generate_stored_xss_marker()

        # Build stored payload
        test_params = params.copy()
        test_params[param_name] = marker

        # Send injection request
        resp = await self._send_request(method, url, test_params, param_type)
        if resp is None:
            return

        # Build list of URLs to re-check (dynamically generated + common paths)
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        path_parts = parsed.path.rstrip("/").split("/")

        display_urls = []

        # 1. Same page check (stored XSS often appears on the same page)
        display_urls.append(url)

        # 2. Parent directory index pages
        for i in range(len(path_parts) - 1, 0, -1):
            parent = "/".join(path_parts[:i]) or "/"
            display_urls.append(base + parent)
            display_urls.append(base + parent + "/index.php")
            display_urls.append(base + parent + "/index.html")

        # 3. Sibling common display pages
        sibling_names = [
            "view.php",
            "show.php",
            "display.php",
            "read.php",
            "detail.php",
            "list.php",
            "index.php",
            "home.php",
            "guestbook.php",
            "comments.php",
            "add-to-your-blog.php",
            "blog.php",
            "forum.php",
            "board.php",
        ]
        parent_dir = "/".join(path_parts[:-1]) if len(path_parts) > 1 else ""
        for name in sibling_names:
            display_urls.append(f"{base}{parent_dir}/{name}")

        # 4. Root common pages
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
                    logger.warning(f"[XSS] Stored XSS detected: {url} [{param_name}] reflected on {display_url}")
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
        """Use OOB detection for Blind XSS"""
        try:
            token = await self._oob_manager.generate_token({"url": url, "param": param_name, "module": "xss"})
            callback_url = self._oob_manager.get_callback_url(token)

            # Build Blind XSS payload
            payload = f"<script src='{callback_url}'></script>"

            test_params = params.copy()
            test_params[param_name] = payload
            await self._send_request(method, url, test_params, param_type)

            # Wait for callback
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
                logger.warning(f"[XSS] Blind XSS detected: {url} [{param_name}]")

        except Exception as e:
            logger.debug(f"[XSS] Blind XSS detection failed: {e}")

    async def _test_polyglot(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        method: str,
        param_type: str,
        baseline_text: str,
    ) -> None:
        """
        Polyglot XSS detection — one payload tests HTML/attribute/JS/URL contexts at once.
        """
        from .payloads import POLYGLOT_PAYLOADS

        for payload in POLYGLOT_PAYLOADS[:5]:
            test_params = params.copy()
            test_params[param_name] = payload
            resp = await self._send_request(method, url, test_params, param_type)
            if resp is None:
                continue
            resp_text = resp.get("text", "")[:20000]
            reflected, evidence = self._check_reflection(resp_text, payload, baseline_text)
            if reflected:
                vuln = self._create_vuln(
                    url=url,
                    param=param_name,
                    param_type=param_type,
                    method=method,
                    payload=payload[:80],
                    vuln_type="reflected",
                    evidence=evidence or "Polyglot XSS: multi-context payload reflected",
                )
                self._found_vulns.append(vuln)
                logger.info(f"[XSS] Polyglot XSS: {url} [{param_name}]")
                return

    async def _test_mxss(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        method: str,
        param_type: str,
        baseline_text: str,
    ) -> None:
        """
        Mutation XSS (mXSS) detection — payloads that exploit browser parser mutations.
        """
        from .payloads import MXSS_PAYLOADS

        for payload in MXSS_PAYLOADS[:8]:
            test_params = params.copy()
            test_params[param_name] = payload
            resp = await self._send_request(method, url, test_params, param_type)
            if resp is None:
                continue
            resp_text = resp.get("text", "")[:20000]
            reflected, evidence = self._check_reflection(resp_text, payload, baseline_text)
            if reflected:
                vuln = self._create_vuln(
                    url=url,
                    param=param_name,
                    param_type=param_type,
                    method=method,
                    payload=payload[:80],
                    vuln_type="reflected",
                    evidence=evidence or "mXSS payload reflected — verify browser-side mutation",
                )
                self._found_vulns.append(vuln)
                logger.info(f"[XSS] mXSS payload reflected: {url} [{param_name}]")
                return

    async def _test_ssti(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        method: str,
        param_type: str,
        baseline_text: str,
    ) -> None:
        """
        SSTI (Server-Side Template Injection) detection.
        Tests for template engine evaluation in reflected content.
        """
        from .payloads import SSTI_PAYLOADS

        for payload in SSTI_PAYLOADS[:10]:
            test_params = params.copy()
            test_params[param_name] = payload
            resp = await self._send_request(method, url, test_params, param_type)
            if resp is None:
                continue
            resp_text = resp.get("text", "")[:20000]

            # SSTI detection: check for math evaluation (7*7=49)
            if "49" in resp_text and "7*7" not in baseline_text:
                # Template engine evaluated the expression!
                vuln = self._create_vuln(
                    url=url,
                    param=param_name,
                    param_type=param_type,
                    method=method,
                    payload=payload,
                    vuln_type="ssti",
                    evidence="SSTI: '7*7' evaluated to '49' in response — template engine active",
                )
                self._found_vulns.append(vuln)
                logger.info(f"[XSS] SSTI detected: {url} [{param_name}] (7*7=49)")
                return

            # Also check for generic reflection of template syntax
            reflected, evidence = self._check_reflection(resp_text, payload, baseline_text)
            if reflected and any(kw in resp_text.lower() for kw in ("config", "self", "__class__")):
                vuln = self._create_vuln(
                    url=url,
                    param=param_name,
                    param_type=param_type,
                    method=method,
                    payload=payload[:80],
                    vuln_type="ssti",
                    evidence=evidence or "Template syntax reflected with context clues",
                )
                self._found_vulns.append(vuln)
                logger.info(f"[XSS] SSTI reflection: {url} [{param_name}]")
                return

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
        Detect reflected XSS (upgraded with XSStrike context-aware analysis).

        Phase 1: Inject unique marker → analyze reflection context
        Phase 2: Select context-optimized payloads → test
        Phase 3: Fallback with generic payloads if context analysis fails
        """
        logger.debug(f"[XSS] Starting reflected XSS test: {url} [{param_name}]")

        # ── Phase 1: Context analysis (XSStrike concept) ──
        test_params = params.copy()
        test_params[param_name] = XSS_CHECKER
        ctx_resp = await self._send_request(method, url, test_params, param_type)

        context: Optional[ReflectionContext] = None
        if ctx_resp:
            ctx_text = ctx_resp.get("text", "")[:20000]
            contexts = analyze_reflection(ctx_text, XSS_CHECKER)
            # Find first executable context
            for c in contexts:
                if c.is_executable():
                    context = c
                    logger.debug(
                        f"[XSS] Context: {c.context} | tag={c.tag} | type={c.attr_type} | quote={c.quote_char}"
                    )
                    break
            if not contexts:
                logger.debug(f"[XSS] Marker not reflected: {url} [{param_name}]")
                return
            if context and not context.is_executable():
                logger.debug(f"[XSS] Non-executable context ({context.context}), trying escape")

        # ── Phase 2: Context-aware payloads ──
        if context:
            targeted_payloads = select_payload(context)[:7]
        else:
            # No context detected — use polyglot + generic
            targeted_payloads = [
                "\"'><img src=x onerror=alert(1)>",
                "'><script>alert(1)</script>",
                "<svg onload=alert(1)>",
                "<body onload=alert(1)>",
            ]

        for payload in targeted_payloads:
            test_params = params.copy()
            test_params[param_name] = payload
            logger.debug(f"[XSS] Testing payload [{context.context if context else 'generic'}]: {payload[:40]}")

            resp = await self._send_request(method, url, test_params, param_type)
            if resp is None:
                continue

            resp_text = resp.get("text", "")[:20000]
            reflected, evidence = self._check_reflection(resp_text, payload, baseline_text)

            if reflected:
                if self._is_echo_server(url, resp_text, payload):
                    logger.debug(f"[XSS] Ignoring echo-server reflection: {url}")
                    continue
                logger.info(
                    f"[XSS] Found reflection [{context.context if context else 'generic'}]: "
                    f"{url} [{param_name}] payload={payload[:30]}"
                )
                if await self._verify_reflected(url, params, param_name, method, param_type):
                    ctx_info = f" context={context.context}" if context else ""
                    vuln = self._create_vuln(
                        url=url,
                        param=param_name,
                        param_type=param_type,
                        method=method,
                        payload=payload,
                        vuln_type="reflected",
                        evidence=(
                            evidence or f"Reflected XSS ({context.context}{ctx_info}): payload '{payload}' reflected"
                        ),
                    )
                    self._found_vulns.append(vuln)
                    logger.warning(
                        f"[XSS] Reflected confirmed [{context.context if context else 'generic'}]: {url} [{param_name}]"
                    )
                    return

        # ── Phase 3: Fallback generic payloads ──
        fallback_payloads = list(REFLECTED_PAYLOADS[:8])
        for payload in fallback_payloads:
            if payload in targeted_payloads:
                continue
            test_params = params.copy()
            test_params[param_name] = payload

            resp = await self._send_request(method, url, test_params, param_type)
            if resp is None:
                continue

            resp_text = resp.get("text", "")[:20000]
            reflected, evidence = self._check_reflection(resp_text, payload, baseline_text)

            if reflected:
                if self._is_echo_server(url, resp_text, payload):
                    continue
                if await self._verify_reflected(url, params, param_name, method, param_type):
                    vuln = self._create_vuln(
                        url=url,
                        param=param_name,
                        param_type=param_type,
                        method=method,
                        payload=payload,
                        vuln_type="reflected",
                        evidence=evidence or f"Reflected XSS: payload '{payload}' reflected",
                    )
                    self._found_vulns.append(vuln)
                    logger.warning(f"[XSS] Reflected detected: {url} [{param_name}]")
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
        Detect DOM-based XSS
        By injecting special markers, observe controllable points in the URL
        """
        dom_markers = [
            "#<script>alert(1)</script>",
            "#<img src=x onerror=alert(1)>",
            "#'><script>alert(document.domain)</script>",
        ]

        # Inject DOM payload into URL fragment
        for payload in dom_markers[:2]:
            test_url = url + payload

            resp = await self._send_request("GET", test_url, {}, param_type)
            if resp is None:
                continue

            resp_text = resp.get("text", "")[:20000]

            # DOM XSS characteristic: payload appears in response (possibly encoded)
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
                logger.warning(f"[XSS] DOM-based detected: {url}")
                return

    def _check_reflection(self, resp_text: str, payload: str, baseline_text: str) -> Tuple[bool, str]:
        """
        Detect if the payload is reflected (possibly in different encoding forms).

        P9 fix: Guarantee evidence is never empty. Every return path
        now includes a specific evidence string describing what was found.

        Returns:
            (is_reflected, evidence) — Whether reflected + detailed evidence (never empty on True)
        """
        # 1. Payload appears verbatim in response AND not in baseline (strongest)
        if payload in resp_text and payload not in baseline_text:
            idx = resp_text.find(payload)
            return True, f"XSS payload reflected verbatim in response body at offset {idx}"

        # 2. HTML-decoded payload appears (and not in baseline)
        decoded = self._html_decode(payload)
        if decoded in resp_text and decoded != payload and decoded not in baseline_text:
            idx = resp_text.find(decoded)
            return True, f"XSS payload reflected after HTML-decode at offset {idx}"

        # P7: URL-encoded payload reflected as decoded HTML
        from urllib.parse import quote

        encoded = quote(payload, safe="")
        if encoded != payload and encoded not in baseline_text:
            decoded_from_encoded = self._html_decode(encoded)
            if decoded_from_encoded in resp_text and decoded_from_encoded not in baseline_text:
                idx = resp_text.find(decoded_from_encoded)
                return True, f"XSS payload reflected after URL-decode at offset {idx}"

        # 3. XSS structural detection — actual script/event-handler injection
        #    Must be NEW content not present in baseline
        evidence = ""

        # Check for new <script> tags with content
        script_re = re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL)
        resp_scripts = script_re.findall(resp_text)
        base_scripts = script_re.findall(baseline_text)
        if len(resp_scripts) > len(base_scripts):
            for s in resp_scripts:
                if "alert" in s.lower() or "prompt" in s.lower():
                    evidence = "New <script> tag with alert/prompt injected in response"
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
        """HTML decode + URL decode"""
        import html as _html

        result = _html.unescape(text)
        # URL-decode: servers may reflect %3Cscript%3E as <script>
        try:
            from urllib.parse import unquote

            result = unquote(result)
        except Exception:  # noqa: S110
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
        """Secondary verification: confirm with a different payload — P8: tightened to require structural injection evidence"""
        logger.debug(f"[XSS] Starting secondary verification: {url} [{param_name}]")

        verify_payloads = [
            "<svg onload=alert(1)>",
            "<img src=x onerror=alert(1)>",
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
                logger.debug("[XSS] Verification successful: structural reflection detected")
                return True

            # P8: Also check verbatim reflection (but must NOT be in baseline)
            if verify_payload in resp_text and verify_payload not in baseline_text:
                logger.debug("[XSS] Verification successful: payload verbatim reflected (not in baseline)")
                return True

        return False

    # Note: _send_request, _extract_endpoints, _create_vuln methods have been moved to base class DetectionModule
