"""DOM XSS 检测模块 (v2.2 T2.3 — 真实 headless 验证,替代已移除的伪检测)。

原理:
- Playwright headless Chromium 打开目标页,URL fragment 注入标记载荷
  (`<img src=x onerror=window.__raydomxss=N>` / `<svg onload=...>` 变体)
- 若页面将 location.hash 写入 innerHTML/document.write 等 HTML sink,
  载荷会真实执行并设置全局标记 → 检出
- 无 Playwright 或浏览器不可用时静默跳过(报告中不产生该模块结果)

误报防线:
- 标记全局变量名含随机前缀,页面自身不可能预置
- 无 hash 写入路径的页面载荷不会执行 → 不报
- 需要真实执行(事件回调设置标记),纯反射不触发
"""

from __future__ import annotations

import logging
import uuid
from typing import List, Optional

from ...models import Confidence, ScanTarget, Severity, Vulnerability
from ..base import DetectionModule, ModuleInfo, register_module

logger = logging.getLogger("wvs.module.domxss")

try:
    from playwright.sync_api import sync_playwright

    HAS_PLAYWRIGHT = True
except ImportError:  # pragma: no cover - 可选依赖
    HAS_PLAYWRIGHT = False

# 页面类路径特征(资产/接口路径不做浏览器验证,控制耗时)
_SKIP_SUFFIXES = (
    ".js",
    ".css",
    ".json",
    ".png",
    ".jpg",
    ".gif",
    ".ico",
    ".svg",
    ".woff",
    ".woff2",
    ".env",
    ".sql",
    ".xml",
    ".txt",
    ".md",
)


@register_module
class DOMXSSDetector(DetectionModule):
    """DOM XSS 检测 — headless 浏览器真实执行验证。"""

    @classmethod
    def get_info(cls) -> ModuleInfo:
        return ModuleInfo(
            name="domxss",
            description="DOM XSS 检测 (headless Chromium hash 注入真实执行验证)",
            author="RayScan Team",
            version="1.0.0",
            enabled_by_default=False,  # lite 模块
            category="lite",
            priority=60,
            tags=["dom", "xss", "headless", "business-logic"],
        )

    def __init__(self, config=None, session=None):
        super().__init__(config, session)
        self._probed: set = set()
        self._probe_budget = int(self.config.get("modules.domxss.max_probes", 12))

    @staticmethod
    def _available() -> bool:
        return HAS_PLAYWRIGHT

    async def _scan_impl(self, target: ScanTarget) -> List[Vulnerability]:
        if not HAS_PLAYWRIGHT:
            return []

        url = target.url.split("#")[0]
        from urllib.parse import urlparse

        parsed = urlparse(url)
        path = parsed.path or "/"
        # 仅验证页类路径(资产/接口不做浏览器验证);带 query 端点的注入向量由主动模块覆盖
        if any(path.lower().endswith(s) for s in _SKIP_SUFFIXES):
            return []
        if parsed.query:
            return []
        # 预算控制:浏览器启动昂贵,每实例最多验证 N 个不同 URL
        if url in self._probed or len(self._probed) >= self._probe_budget:
            return []
        self._probed.add(url)

        vuln = await self._verify_hash_injection(url)
        return [vuln] if vuln else []

    async def _verify_hash_injection(self, url: str) -> Optional[Vulnerability]:
        """对单 URL 做 hash 注入真实执行验证(线程池中跑同步 Playwright)。"""
        import asyncio

        loop = asyncio.get_running_loop()
        marker_prefix = f"ray{uuid.uuid4().hex[:8]}"
        try:
            result = await loop.run_in_executor(None, self._probe_with_browser, url, marker_prefix)
        except Exception as e:  # noqa: BLE001
            logger.debug("[DOMXSS] 浏览器验证失败 %s: %s", url, e)
            return None
        if not result:
            return None

        sink_desc, payload = result
        self._explain("signal", f"hash 载荷经 {sink_desc} 真实执行", {"url": url})
        self._explain("decision", "headless 浏览器确认 DOM sink 执行了注入载荷 — 真实 DOM XSS")
        return self._create_vuln(
            url=url,
            param="location.hash",
            param_type="fragment",
            method="GET",
            payload=payload[:80],
            vuln_type="dom-xss",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            evidence=f"hash 注入载荷经 DOM sink({sink_desc})在 headless Chromium 中真实执行(标记 {marker_prefix})",
            description="页面将 location.hash 写入 HTML sink 且未净化,注入载荷真实执行",
            recommendation=(
                "不要将 location.hash/location.search 写入 innerHTML/document.write;使用 textContent 或对 HTML 转义。"
            ),
            context={"sink": sink_desc, "marker": marker_prefix},
        )

    def _probe_with_browser(self, url: str, marker_prefix: str) -> Optional[tuple]:
        """同步 Playwright 探测:返回 (sink 描述, 触发载荷) 或 None。"""
        # 载荷经 hash 传输,无需编码 <>(浏览器对 hash 原样处理;页面侧 substring 后直接入 sink)
        payloads = [
            (f'<img src=x onerror="window.{marker_prefix}=1">', "innerHTML/document.write"),
            (f'<svg onload="window.{marker_prefix}=2"></svg>', "innerHTML/document.write(svg)"),
        ]
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                context = browser.new_context()
                for payload, sink in payloads:
                    page = context.new_page()
                    try:
                        page.goto(url, wait_until="domcontentloaded", timeout=15000)
                        # hash 注入后重新加载,触发 hash 写入路径
                        sep = "&" if "?" in url else "?"
                        page.goto(
                            f"{url}{sep}__ray={marker_prefix}#{payload}", wait_until="domcontentloaded", timeout=15000
                        )
                        page.wait_for_timeout(1200)
                        fired = page.evaluate(f"window.{marker_prefix} === 1 || window.{marker_prefix} === 2")
                        if fired:
                            return sink, payload
                    except Exception as e:  # noqa: BLE001
                        logger.debug("[DOMXSS] 载荷探测异常 %s: %s", payload[:30], e)
                    finally:
                        page.close()
            finally:
                browser.close()
        return None
