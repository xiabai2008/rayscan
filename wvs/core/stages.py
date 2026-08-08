"""扫描编排的预置 Stage (Phase 2: P2-1)。

从 WAVScanner.scan() 中抽取的独立阶段:
- WAFDetectionStage : Step 0 WAF 检测并广播结果到各模块
- LabAuthStage      : Step 1.8 靶机识别与自动认证
- OADetectionStage  : Step 1.9 OA 指纹检测与专项激活
- DedupStage        : Phase 3 去重(委托 scanner 既有逻辑)

这些 Stage 由 ScanOrchestrator 编排;WAVScanner.scan() 作为 facade 委托它们,
保持对 CLI/测试的向后兼容。
"""

from __future__ import annotations

import logging

from ..models import ScanTarget
from .orchestrator import ScanContext, ScanStage

logger = logging.getLogger(__name__)


class WAFDetectionStage(ScanStage):
    """Step 0: WAF 检测,将结果广播到所有模块(启用 WAF bypass payload)。"""

    name = "waf-detection"

    async def run(self, ctx: ScanContext) -> None:
        target = ctx.target
        if not target:
            return
        if not ctx.config.get("enable_waf_detection", True) or "waf" not in self.scanner._modules:
            return
        try:
            waf_module = self.scanner._modules["waf"]
            waf_target = ScanTarget(url=target.url)
            await waf_module.scan(waf_target)
            waf_result = waf_module.get_result() if hasattr(waf_module, "get_result") else None
            if waf_result and waf_result.detected:
                logger.info(f"\n[!] WAF Detected: {waf_result.vendor} (confidence: {waf_result.confidence:.0%})")
                for mod in self.scanner._modules.values():
                    if hasattr(mod, "set_waf_detected"):
                        mod.set_waf_detected(True)
        except Exception as e:  # noqa: BLE001
            logger.debug("[Stage:WAF] WAF detection skipped: %s", e)


class LabAuthStage(ScanStage):
    """Step 1.8: 靶机识别与自动认证(DVWA/Mutillidae 等 lab profile)。"""

    name = "lab-auth"

    async def run(self, ctx: ScanContext) -> None:
        target = ctx.target
        if not target:
            return
        from .lab_profiles import detect_lab_profile

        if not target.cookies and not self.scanner._lab_profile:
            self.scanner._lab_profile = detect_lab_profile(target.url)
            if self.scanner._lab_profile:
                self.scanner._lab_base_url = target.url
                logger.info("[Stage:Lab] 检测到靶机: %s", self.scanner._lab_profile.name)
                if self.scanner._lab_profile.login_path:
                    await self.scanner._do_lab_auth()
        self.scanner.session._lab_mode = self.scanner._lab_profile is not None


class OADetectionStage(ScanStage):
    """Step 1.9: OA 系统指纹检测,命中后激活 OA 专项检测。"""

    name = "oa-detection"

    async def run(self, ctx: ScanContext) -> None:
        target = ctx.target
        if not target:
            return
        if "oa" not in self.scanner._modules or not ctx.config.get("modules.oa.enabled", True):
            return
        self.scanner._oa_detected = False
        try:
            import httpx

            from .nuclei_template_manager import detect_oa_fingerprint

            async with httpx.AsyncClient(timeout=10, verify=ctx.config.get("verify_ssl", True)) as client:
                resp = await client.get(target.url, follow_redirects=True)
                oa_name = detect_oa_fingerprint(target.url, resp.text)
                if oa_name:
                    logger.info("[OA] 检测到 OA 系统: %s — 激活 OA 专项检测", oa_name)
                    self.scanner._oa_detected = True
                    oa_mod = self.scanner._modules.get("oa")
                    if oa_mod and hasattr(oa_mod, "_detected_oa"):
                        oa_mod._detected_oa = oa_name
        except Exception:  # noqa: BLE001
            self.scanner._oa_detected = False


class DedupStage(ScanStage):
    """Phase 3: 漏洞去重与置信度(委托 scanner 既有 _deduplicate)。"""

    name = "dedup"

    async def run(self, ctx: ScanContext) -> None:
        if not ctx.raw_vulns:
            ctx.unique_vulns = []
            return
        ctx.unique_vulns = self.scanner._deduplicate(ctx.raw_vulns)
