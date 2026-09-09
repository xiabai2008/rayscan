"""扫描编排的预置 Stage (Phase 2: P2-1)。

从 WAVScanner.scan() 中抽取的独立阶段:
- WAFDetectionStage : Step 0 WAF 检测并广播结果到各模块
- LabAuthStage      : Step 1.8 靶机识别与自动认证
- OADetectionStage  : Step 1.9 OA 指纹检测与专项激活
- ResumeStage       : --resume 恢复(checkpoint 漏洞合并 + 已完成模块跳过)
- CrawlDetectStage  : Phase 1/2 爬取 + 流式检测 + 端点定型 + JSPathfinder
- DedupStage        : Phase 3 去重(委托 scanner 既有逻辑)

这些 Stage 由 ScanOrchestrator 编排;WAVScanner.scan() 作为 facade 委托它们,
保持对 CLI/测试的向后兼容。
"""

from __future__ import annotations

import asyncio
import logging
from typing import List

from ..models import ScanTarget, Vulnerability
from .crawler import DiscoveredEndpoint
from .lab_profiles import detect_lab_profile, get_lab_endpoints
from .orchestrator import ScanContext, ScanStage

try:
    from .lab_profiles import detect_lab_profile_from_paths
except ImportError:

    def detect_lab_profile_from_paths(url, paths):
        return detect_lab_profile(url)


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


class ResumeStage(ScanStage):
    """--resume 恢复:合并上次 checkpoint 已发现漏洞 + 跳过已完成模块(S2)。

    合并的漏洞追加到 ctx.raw_vulns(与流式检测发现一同进入去重),
    已完成模块从 scanner._modules 移除(后续 stage 不再执行它们)。
    """

    name = "resume"

    async def run(self, ctx: ScanContext) -> None:
        scanner = self.scanner
        scanner._modules_done = []
        resume_cp = getattr(scanner, "_resume_checkpoint", None)
        if not resume_cp:
            return
        for vdict in resume_cp.get("vulnerabilities", []):
            try:
                v = Vulnerability.from_dict(vdict)
                ctx.raw_vulns.append(v)
                logger.info(f"[resume] 复用已发现漏洞: {v.url} ({v.type.value})")
            except Exception:  # noqa: BLE001
                logger.debug("[resume] 反序列化漏洞失败,跳过")
        skip_modules = set(resume_cp.get("modules_done", []))
        if skip_modules:
            logger.info(f"[resume] 跳过已完成模块: {sorted(skip_modules)}")
            for m in list(scanner._modules.keys()):
                if m in skip_modules:
                    scanner._modules.pop(m)


class CrawlDetectStage(ScanStage):
    """Phase 1/2:爬取 + 流式检测(爬一批测一批)+ 端点定型 + JSPathfinder。

    从 WAVScanner.scan() 的 Phase 1 整块迁移:
    - 分批爬取,每批立刻全模块并发检测(超时预算内提前收敛)
    - 端点优先级排序 / lab 端点合并 / 参数补全
    - Phase 1.5 JSPathfinder(默认关)
    产出:ctx.endpoints(定型后端点表)、ctx.raw_vulns(resume 漏洞 + 流式发现 + JS 发现)
    """

    name = "crawl-detect"

    async def run(self, ctx: ScanContext) -> None:
        scanner = self.scanner
        target = ctx.target
        if not target:
            return

        # ── Crawl + 流式检测 ──
        logger.info("\n[*] Phase 1/4: Crawling + streaming detection...")
        scanner._call_progress("crawl", 0, 100, 3)

        # 分批爬取：先爬一批立刻检测，不等全部爬完
        BATCH_SIZE = 10  # 每批检测端点数

        # 限制爬取深度：实战目标快速收敛，留时间给检测
        max_crawl = scanner.config.get("crawl_max_urls", 300)
        max_pages = 30 if not scanner._lab_profile else 150  # 实战30页，靶机150页
        scanner.crawler.max_urls_per_run = min(max_crawl, max_pages)
        scanner.crawler.max_depth = 2 if not scanner._lab_profile else 4  # 实战浅爬

        all_endpoints: List[DiscoveredEndpoint] = []
        all_vulns = ctx.raw_vulns

        async def _crawl_and_detect():
            """爬取+检测循环：爬一批，测一批"""
            module_names = list(scanner._modules.keys())
            # 全局并发信号量:一次创建,跨模块共享,真正限制总并发(P2-4)
            concurrency = max(1, int(scanner.config.get("concurrent_endpoints", 10)))
            global_sem = asyncio.Semaphore(concurrency)
            try:
                # 第一次爬取
                eps = await scanner.crawler.crawl(target.url, scanner.session)
                all_endpoints.extend(eps)

                # T0 修复：crawler 未产出端点（单页无链接且 seed 全 404）时，
                # 兜底至少测目标本身——否则流式检测整体跳过（检测模块完全不执行）
                if not eps:
                    eps = [DiscoveredEndpoint(url=target.url, method="GET", source_url=target.url, source_depth=1)]
                    all_endpoints.extend(eps)

                # 分批检测已爬到的端点
                if eps:
                    enriched = await scanner.crawler.discover_params_batch(eps, scanner.session)
                    for i, ep in enumerate(enriched):
                        if i < len(eps):
                            eps[i].parameters = ep.parameters or eps[i].parameters
                            eps[i].param_types = ep.param_types or eps[i].param_types

                    for batch_idx in range(0, len(eps), BATCH_SIZE):
                        if scanner._timeout_remaining() < 30:
                            break
                        batch = eps[batch_idx : batch_idx + BATCH_SIZE]
                        for mod_name in module_names:
                            if mod_name not in scanner._modules:
                                continue
                            try:
                                vulns = await scanner._run_module_concurrent(
                                    mod_name,
                                    target,
                                    batch,
                                    concurrency=concurrency,
                                    global_sem=global_sem,
                                )
                                all_vulns.extend(vulns)
                                if vulns:
                                    logger.info(f"[+] {mod_name}: found {len(vulns)} in batch")
                            except Exception as e:
                                logger.debug(f"[Scanner] {mod_name} batch error: {e}")
                        # S2 checkpoint: 每批流式检测后按间隔限流落盘(崩溃/超时恢复)
                        try:
                            scanner._try_save_checkpoint(target, all_vulns, eps)
                        except Exception as e:  # noqa: BLE001
                            logger.debug(f"[Scanner] checkpoint save failed: {e}")

            except Exception:
                logger.exception("[Scanner] 爬取失败")

        await _crawl_and_detect()

        scanner._call_progress("crawl", 100, 100, 10)
        scanner._stats["endpoints_discovered"] = len(all_endpoints)
        crawler_stats = scanner.crawler.get_stats()
        logger.info(
            f"\r[*] Crawled {crawler_stats.get('pages_crawled', 0)} pages, "
            f"discovered {len(all_endpoints)} endpoints, "
            f"found {crawler_stats.get('forms_found', 0)} forms"
        )

        # P8: Prioritize endpoints
        endpoints = scanner._prioritize_endpoints(all_endpoints)

        if not endpoints:
            endpoints = [DiscoveredEndpoint(url=target.url, method="GET", source_url=target.url, source_depth=1)]

        # ── Re-detect lab profile from discovered paths ──
        if not scanner._lab_profile:
            discovered_paths = [ep.url for ep in endpoints]
            scanner._lab_profile = detect_lab_profile_from_paths(target.url, discovered_paths)
            if scanner._lab_profile:
                scanner._lab_base_url = target.url
                logger.info(f"[*] Detected lab profile from endpoints: {scanner._lab_profile.name}")
                if not target.cookies:
                    await scanner._do_lab_auth()

        # ── Append lab endpoints ──
        if scanner._lab_profile:
            lab_eps = get_lab_endpoints(scanner._lab_profile, target.url)
            added = 0
            merged = 0
            for lep in lab_eps:
                existing = None
                lep_norm = scanner._normalize_url(lep.url)
                for e in endpoints:
                    if scanner._normalize_url(e.url) == lep_norm:
                        existing = e
                        break
                if existing is None:
                    endpoints.append(lep)
                    added += 1
                else:
                    if not existing.parameters and lep.parameters:
                        existing.parameters = lep.parameters.copy()
                        merged += 1
                    if existing.method == "GET" and lep.method != "GET":
                        existing.method = lep.method
                        merged += 1
                    if not existing.param_types and lep.param_types:
                        existing.param_types = lep.param_types.copy()
                        merged += 1
            logger.info(f"[*] Lab profile ({scanner._lab_profile.name}): +{added} endpoints, merged {merged}")

        # ── Parameter discovery for endpoints without params ──
        endpoints_without_params = [e for e in endpoints if not e.parameters]
        if endpoints_without_params:
            logger.info(f"[*] Running parameter discovery on {len(endpoints_without_params)} endpoints...")
            enriched = await scanner.crawler.discover_params_batch(endpoints_without_params, scanner.session)
            for i, ep in enumerate(endpoints_without_params):
                if i < len(enriched) and enriched[i].parameters:
                    ep.parameters = enriched[i].parameters
                    ep.param_types = enriched[i].param_types

        # ── Phase 1.5 — JS endpoint & secret analysis (JSPathfinder) ──
        # Disabled by default in v1.1.0 (sqli+xss focus). Enable with modules.jspathfinder.enabled=true
        if scanner.config.get("modules.jspathfinder.enabled", False):
            logger.info("\n[*] Phase 1.5/4: JS analysis (JSPathFinder)...")
            scanner._call_progress("jspathfinder", 0, 1, 12)
            try:
                scanner._jspathfinder_vulns = await scanner._run_jspathfinder(target)
                logger.info(f"[+] JSPathFinder: {len(scanner._jspathfinder_vulns)} finds")
            except Exception as e:
                logger.exception("[Scanner] jspathfinder phase failed")
                scanner._jspathfinder_vulns = []
            scanner._call_progress("jspathfinder", 1, 1, 15)
        else:
            scanner._jspathfinder_vulns = []

        # ── 流式检测完成 ──
        logger.info(f"[*] Phase 2/4: Streaming detection done ({len(all_vulns)} raw findings)")

        # ── Merge JSPathfinder findings (disabled by default) ──
        if getattr(scanner, "_jspathfinder_vulns", None):
            all_vulns.extend(scanner._jspathfinder_vulns)

        ctx.endpoints = endpoints


class DedupStage(ScanStage):
    """Phase 3: 漏洞去重与置信度(委托 scanner 既有 _deduplicate)。"""

    name = "dedup"

    async def run(self, ctx: ScanContext) -> None:
        logger.info("[*] Phase 3/4: Deduplication & confidence...")
        if not ctx.raw_vulns:
            ctx.unique_vulns = []
            return
        ctx.unique_vulns = self.scanner._deduplicate(ctx.raw_vulns)


class NucleiStage(ScanStage):
    """Phase 3.5: Nuclei 外部引擎扫描(默认启用),结果并入去重集合。

    nuclei CLI 可用 → 智能模板扫描;不可用 → 内置回退模板(内容特征验证)。
    与主流程发现合并后统一去重。
    """

    name = "nuclei"

    async def run(self, ctx: ScanContext) -> None:
        if not ctx.target or not ctx.config.get("nuclei.enabled", True):
            return
        try:
            nuclei_vulns = await self.scanner._run_nuclei(ctx.target)
            if nuclei_vulns:
                logger.info(f"[+] Nuclei: {len(nuclei_vulns)} findings(已合并)")
                ctx.unique_vulns = self.scanner._deduplicate(ctx.unique_vulns + nuclei_vulns)
        except Exception as e:  # noqa: BLE001
            logger.debug(f"[Scanner] Nuclei phase failed: {e}")


class AIVerifyStage(ScanStage):
    """Phase 3.6: AI 误报复核(T1.2,默认关,--ai-verify 开启)。

    medium+ 候选按批复核:确认打 ai_confirmed,存疑降级打 ai_disputed
    (只降级不删除);请求失败/输出不可解析整批原样返回。
    """

    name = "ai-verify"

    async def run(self, ctx: ScanContext) -> None:
        if not ctx.config.get("ai.verify", False) or not ctx.unique_vulns:
            return
        try:
            from ..ai import AIVerifier, LLMClient

            ai_client = LLMClient(ctx.config)
            if ai_client.available:
                verifier = AIVerifier(ctx.config, ai_client)
                ctx.unique_vulns = await verifier.verify_batch(ctx.unique_vulns)
                logger.info(
                    f"[AI] 复核完成: {verifier.reviewed_count} 条已复核, "
                    f"{verifier.confirmed_count} 确认 / {verifier.disputed_count} 存疑降级"
                )
            else:
                logger.warning("[AI] --ai-verify 已开启但未配置 LLM_API_KEY，跳过 AI 复核")
        except Exception as e:
            logger.debug(f"[Scanner] AI verify phase failed: {e}")


class CheckpointStage(ScanStage):
    """扫描收尾:保存最终 checkpoint(S2,供 --resume 合并)。"""

    name = "checkpoint"

    async def run(self, ctx: ScanContext) -> None:
        if not ctx.target:
            return
        try:
            self.scanner._save_checkpoint(ctx.target.url, ctx.unique_vulns, ctx.endpoints)
        except Exception as e:  # noqa: BLE001
            logger.debug(f"[Scanner] final checkpoint save failed: {e}")
