"""
RayScan main scanner engine.

Coordinates: crawler → detection modules → dedup → reporting.
No hardcoded lab paths — lab-specific logic lives in core/lab_profiles.py.
"""

import asyncio
import json
import logging
import time
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from ..config import ConfigManager
from ..models import (
    ScanResult,
    ScanTarget,
    Vulnerability,
)
from ..plugins.auth import FormLoginAuth
from .crawler import DiscoveredEndpoint, WebCrawler
from .dedup import ResultDeduplicator, prioritize_endpoints
from .scanner_integrations import ScannerIntegrationsMixin
from .session import HTTPPool

logger = logging.getLogger(__name__)

# T2.1: module loading is registry-driven. The set of enabled modules is derived
# from the ModuleFactory registry (single source of truth) using each module's
# ``category`` field ("core" loads by default, "lite" only with --all-modules,
# "optional" never auto-loaded), instead of the previously hardcoded
# _MODULE_PRIORITY / _LITE_MODULE_PRIORITY lists. See _resolve_enabled_modules().


class WAVScanner(ScannerIntegrationsMixin):
    """Web Application Vulnerability Scanner — main orchestrator."""

    def __init__(
        self,
        config: Optional[ConfigManager] = None,
        session: Optional[HTTPPool] = None,
    ):
        """
        初始化扫描器

        Args:
            config: 配置管理器（默认为全局配置）
            session: HTTPPool 实例（默认新建）
        """
        self.config = config or ConfigManager()
        self.session = session or HTTPPool(self.config)

        crawl_depth = self.config.get("crawl_depth", 5)
        crawl_max = self.config.get("crawl_max_urls", 1000)
        prefix_max = self.config.get("crawl_max_urls_per_prefix", 50)
        self.crawler = WebCrawler(
            max_depth=crawl_depth,
            max_urls_per_run=crawl_max,
            max_urls_per_prefix=prefix_max,
            user_agent=self.config.get("user_agent", "WVS/19.0"),
        )
        # T3.2: --js-render 实验性开关（对实战目标启用 SPA 检测 + Playwright 渲染爬取）
        self.crawler._js_render = bool(self.config.get("crawler.js_render", False))

        # 已加载的检测模块 {module_name -> module_instance}
        self._modules: Dict[str, Any] = {}
        self._loaded_module_names: List[str] = []
        # 漏洞去重器（_deduplicate / DedupStage 依赖）
        self.dedup = ResultDeduplicator()
        self._global_baseline_cache: Dict[str, Dict[str, Any]] = {}  # Cross-module baseline cache

        # 去重集合（存储 Vulnerability 的去重签名）
        # dedup handled by self.dedup

        # 运行时统计
        self._stats: Dict[str, Any] = {
            "start_time": 0.0,
            "end_time": 0.0,
            "total_requests": 0,
            "endpoints_discovered": 0,
            "endpoints_scanned": 0,
            "modules_run": 0,
            "errors": 0,
            "vulns_by_type": {},
        }

        # 超时抢救：增量收集部分扫描结果
        self._partial_vulns: List[Vulnerability] = []
        self._modules_completed: List[str] = []
        self._scan_max_time: int = 0  # CLI 设置，用于超时判断

        # 是否加载全部模块（包括 lite 模块——必须在 _resolve_enabled_modules 之前初始化）
        self._load_all_modules = False

        # 启用的模块列表（按优先级顺序）
        self._enabled_modules = self._resolve_enabled_modules()

        # 靶机自动识别（lab profiles）
        self._lab_profile: Optional[Any] = None
        self._lab_base_url: Optional[str] = None

        # 集成开关（默认关闭，避免未导入的集成模块导致崩溃）
        self._integrations_enabled = False

        # 漏洞去重缓存(dedup 依赖,scan() 会 clear 它)
        self._vuln_seen: set = set()

        # Nuclei 集成实例(懒加载;config nuclei.enabled 默认 True,接入主流程)
        self._nuclei_integration: Optional[Any] = None

        # S2 checkpoint 复活:初始化防 AttributeError(save_checkpoint 引用)
        self._modules_done: List[str] = []  # 已完成模块(按批)
        self._last_checkpoint_time: float = 0.0
        self._checkpoint_interval: float = 30.0  # 落盘间隔(秒)
        self._resume_checkpoint: Optional[Dict[str, Any]] = None  # CLI --resume 注入

        # 扫描编排器 (Phase 2: P2-1) — 默认装配预置 stages,WAVScanner.scan() 作为 facade
        self._orchestrator = self._build_orchestrator()

    def _build_orchestrator(self):
        """装配默认扫描编排器(可被子类覆盖以替换/增删 stage)。"""
        from .orchestrator import ScanOrchestrator
        from .stages import (
            AIVerifyStage,
            CheckpointStage,
            CrawlDetectStage,
            DedupStage,
            LabAuthStage,
            NucleiStage,
            OADetectionStage,
            ResumeStage,
            WAFDetectionStage,
        )

        return ScanOrchestrator(
            self,
            stages=[
                WAFDetectionStage(self),
                LabAuthStage(self),
                OADetectionStage(self),
                ResumeStage(self),
                CrawlDetectStage(self),
                DedupStage(self),
                NucleiStage(self),
                AIVerifyStage(self),
                CheckpointStage(self),
            ],
        )

    @staticmethod
    def _ensure_params(ep: DiscoveredEndpoint) -> tuple:
        """
        确保 DiscoveredEndpoint.parameters 包含 URL query 参数。
        Crawler 有时丢失 query string，这里补全。

        Returns:
            (params_dict, param_types_dict) — 保证非空或有值
        """
        if ep.parameters:
            return ep.parameters, ep.param_types

        parsed = urlparse(ep.url)
        if parsed.query:
            qs = parse_qs(parsed.query, keep_blank_values=True)
            # parse_qs 返回 {key: [val]} → 扁平化
            params = {k: v[0] if len(v) == 1 else v[0] for k, v in qs.items()}
            param_types = dict.fromkeys(params, "query")
            return params, param_types

        return {}, {}

    # ─────────────────────────────────────────────────────────────
    # 模块管理
    # ─────────────────────────────────────────────────────────────

    def _resolve_enabled_modules(self) -> List[str]:
        """从 ModuleFactory 注册表（唯一事实源）解析出要启用的模块列表

        - ``category="core"`` 模块默认加载（sqli + xss）。
        - ``category="lite"`` 模块仅在 --all-modules / modules.all=true 时加载。
        - ``category="optional"`` 模块永不自动加载（仅由其自身配置开关启用，如 jspathfinder）。

        默认模式下，每个 core 模块还受 ``modules.<name>.enabled`` 配置项约束（默认 True）。
        """
        from ..modules import register_all_modules
        from ..modules.base import ModuleFactory

        # 确保注册表已填充（幂等；即使调用方未导入 wvs.modules 也安全）。
        register_all_modules()

        def _meta(name: str) -> "tuple[str, int]":
            info = ModuleFactory.get_module_info(name)
            category = info.category if info else "lite"
            priority = info.priority if info else 100
            return category, priority

        load_all = self._load_all_modules or self.config.get("modules.all", False)

        if load_all:
            candidates = [name for name in ModuleFactory.list_modules() if _meta(name)[0] in ("core", "lite")]
        else:
            candidates = [name for name in ModuleFactory.list_modules() if _meta(name)[0] == "core"]
            # 尊重每个模块的启用/禁用配置（默认启用）。
            enabled: List[str] = []
            for name in candidates:
                cfg = self.config.get(f"modules.{name}", {})
                if isinstance(cfg, dict) and cfg.get("enabled", True):
                    enabled.append(name)
            candidates = enabled

        # 稳定排序：优先级数字小者先执行，其次按名称。
        candidates.sort(key=lambda n: (_meta(n)[1], n))
        return candidates

    # ── Auth ────────────────────────────────────────────────────

    async def _do_lab_auth(self) -> bool:
        """Try automatic authentication for recognised lab targets."""
        if not self._lab_profile or not self._lab_profile.login_path:
            return False
        lp = self._lab_profile
        base = self._lab_base_url or ""
        if not base:
            return False
        login_url = base.rstrip("/") + lp.login_path
        try:
            logger.info(f"[*] Detected lab target ({lp.name}), auto-authenticating...")
            provider = FormLoginAuth(
                login_url=login_url,
                username=lp.login_params.get("username", "admin"),
                password=lp.login_params.get("password", "password"),
                extra_fields={k: v for k, v in lp.login_params.items() if k not in ("username", "password")},
                success_check=lp.login_success_marker,
            )
            result = await provider.authenticate(self.session._get_httpx_client())
            if result.get("authenticated"):
                for name, value in result.get("cookies", {}).items():
                    self.session.set_cookie(base, name, value)
                if lp.default_security_level:
                    self.session.set_cookie(base, "security", lp.default_security_level)
                logger.info(f"[+] {lp.name} auth OK ({len(result.get('cookies', {}))} cookies)")
                return True
            else:
                logger.info(f"[-] {lp.name} login failed: {result.get('error', 'unknown')}")
                # P17: Warn that scan results will be limited without auth
                if self._lab_profile:
                    logger.warning("[!] Scan results may be incomplete — vulnerabilities may be behind login")
        except Exception as e:
            logger.info(f"[*] {lp.name} auto-auth skipped: {e}")
        return False

    def load_module(self, module_name: str) -> bool:
        """
        加载单个检测模块（从 ModuleFactory 注册表按名取实例）

        Args:
            module_name: 模块名（如 "sqli", "cmdi"）

        Returns:
            是否加载成功
        """
        if module_name in self._modules:
            return True

        # T2.1: 单一事实源 = ModuleFactory 注册表。删除了原先的 __import__ +
        # 命名变体兜底逻辑。注册表由 register_all_modules() 在导入时填充（幂等）。
        from ..modules import register_all_modules
        from ..modules.base import ModuleFactory

        register_all_modules()

        try:
            instance = ModuleFactory.create(module_name, self.config, self.session)
        except KeyError:
            logger.warning(f"[Scanner] 模块 {module_name} 未在 ModuleFactory 注册表中找到")
            return False
        except Exception:
            logger.exception(f"[Scanner] 加载模块 {module_name} 失败")
            return False

        self._modules[module_name] = instance
        # 显式 --modules 加载即视为启用:覆盖 config 默认(如 jspathfinder 默认 enabled=False)。
        # enabled 是合成属性 _enabled AND module_config.enabled,两处都要打开,
        # 否则模块加载成功却静默空转(--modules jspathfinder 曾因此完全不执行)
        instance._enabled = True
        instance.module_config.enabled = True
        self._loaded_module_names.append(module_name)
        logger.info(f"[Scanner] 已加载模块: {module_name} (session: {id(self.session)})")
        return True

    def load_all_modules(self) -> None:
        """加载所有已启用的模块"""
        for name in self._enabled_modules:
            self.load_module(name)

    def _endpoint_base_key(self, url: str, params: Dict) -> str:
        """
        端点去重键：相同路径+参数名视为一个端点
        例如 index.php?page=a 和 index.php?page=b 视为同一个测试目标
        """
        parsed = urllib.parse.urlparse(url)
        path = parsed.path.rstrip("/")
        if params:
            param_names = sorted(params.keys())
            return f"{path}?{'&'.join(param_names)}"
        return path

    # ── Concurrent module runner ─────────────────────────────────

    async def _run_module_concurrent(
        self,
        module_name: str,
        target: "ScanTarget",
        endpoints: List["DiscoveredEndpoint"],
        concurrency: int,
        global_sem: asyncio.Semaphore,
    ) -> List[Vulnerability]:
        """运行单个检测模块，端点级别并发扫描。"""
        if module_name not in self._modules:
            return []

        module = self._modules[module_name]
        ep_sem = asyncio.Semaphore(concurrency)

        async def _scan_one(ep: "DiscoveredEndpoint") -> List[Vulnerability]:
            async with ep_sem:
                if not ep.url:
                    return []
                ep_url = ep.url
                parsed = urlparse(ep_url)
                # 第五轮：API 端点（is_api）不做目录尾斜杠修复——SPA 捕获的
                # /rest/user/login 是精确路径，加斜杠 → 404（真实 API 语义）
                if (
                    not ep.is_api
                    and not parsed.query
                    and "." not in parsed.path.split("/")[-1]
                    and not parsed.path.endswith("/")
                ):
                    ep_url = ep_url.rstrip("/") + "/"

                if ep.method.upper() == "POST":
                    ep_target = ScanTarget(
                        url=ep_url,
                        methods=[ep.method],
                        cookies=target.cookies,
                        headers=target.headers,
                        auth=target.auth,
                        data=ep.parameters,
                        param_types=ep.param_types,
                    )
                else:
                    ep_target = ScanTarget(
                        url=ep_url,
                        methods=[ep.method],
                        cookies=target.cookies,
                        headers=target.headers,
                        auth=target.auth,
                        params=ep.parameters,
                        param_types=ep.param_types,
                    )
                try:
                    found: List[Vulnerability] = await module.scan(ep_target)
                except Exception as e:
                    logger.debug(f"[Scanner] {module_name} EP {ep.url}: {e}")
                    found = []
                for v in found:
                    v.module = module_name
                    v.parameter = list(ep.parameters.keys())[0] if ep.parameters else None
                    v.parameter_type = ep.param_types.get(v.parameter or "", "query")
                return found

        async with global_sem:
            tasks = [_scan_one(ep) for ep in endpoints]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            all_vulns: List[Vulnerability] = []
            for res in results:
                if isinstance(res, Exception):
                    logger.debug(f"[Scanner] {module_name} concurrent scan error: {res}")
                elif isinstance(res, list):
                    all_vulns.extend(res)
            self._partial_vulns.extend(all_vulns)
            return all_vulns

    # ── Dedup (P5 improved: aggressive URL+param normalization to merge dupes) ──

    @staticmethod
    def _normalize_url(url: str) -> str:
        """Strip query string and fragment, normalize trailing slash."""
        return url.split("?")[0].split("#")[0].rstrip("/")

    @staticmethod
    def _normalize_vuln_url(url: str) -> str:
        """URL 归一化（去尾斜杠/统一 scheme）用于漏洞去重。"""
        return str(ResultDeduplicator.normalize_vuln_url(url))

    def _vuln_signature(self, v: Vulnerability) -> str:
        """漏洞签名：type + url + evidence（用于跨引擎去重）。"""
        return str(self.dedup.signature(v))

    def _deduplicate(self, vulns: List[Vulnerability]) -> List[Vulnerability]:
        """扫描结果去重（按漏洞签名）。"""
        return list(self.dedup.deduplicate(vulns))

    def _oa_tech_hints(self) -> List[str]:
        """T3.4 模板策展：OA 指纹命中 → Nuclei 模板 tech 标签（未命中返回空）。

        _modules 用 getattr 防御式读取（checkpoint/单测路径可能使用未完整初始化的实例）。
        """
        oa_mod = (getattr(self, "_modules", None) or {}).get("oa")
        oa_name = getattr(oa_mod, "_detected_oa", None) if oa_mod else None
        if not oa_name:
            return []
        try:
            from ..modules.oa.detector import oa_tech_stack_for

            return oa_tech_stack_for(oa_name)
        except Exception:  # noqa: BLE001
            return []

    async def _run_nuclei(self, target: ScanTarget) -> List[Vulnerability]:
        """S2 接入:运行 Nuclei 外部引擎(模板扫描),结果由主流程去重合并。

        nuclei CLI 可用 → 智能模板扫描;CLI 不可用 → 内置回退模板(S1 内容特征验证)。
        T3.4 策展:OA 指纹命中时只选 tech 匹配模板,淘汰泛匹配。
        """
        from ..integrations.nuclei_integration import NucleiIntegration

        if self._nuclei_integration is None:
            self._nuclei_integration = NucleiIntegration(config=self.config, use_template_manager=True)

        if not self._nuclei_integration.is_available:
            logger.info("[Nuclei] nuclei CLI 不可用，使用内置回退模板（内容特征验证）")

        tech_hints = self._oa_tech_hints()
        if tech_hints:
            logger.info(f"[Nuclei] 模板策展: 按目标技术栈 {tech_hints} 精选模板")
        result = await self._nuclei_integration.scan(
            target.url,
            cookies=target.cookies or None,
            severities=None,  # 默认全部严重级，由结果合并后统一去重/排序
            tech_stack=tech_hints or None,
        )
        return result if isinstance(result, list) else []

    def _call_progress(self, module_name: str, done: int, total: int, pct: int = 0):
        """向 GUI 发送进度回调（如果有注册回调的话）"""
        if hasattr(self, "_progress_callback") and self._progress_callback:
            try:
                self._progress_callback(module_name, done, total, pct)
            except Exception:
                logger.debug(f"[Scanner] Progress callback failed for {module_name}", exc_info=True)

    # ── Timeout helpers ────────────────────────────────────────

    def _elapsed(self) -> float:
        """已用时间（秒）。"""
        start = self._stats.get("start_time") or 0.0
        return time.time() - float(start)

    def _timeout_remaining(self) -> float:
        """距超时剩余时间（秒）。"""
        if not self._scan_max_time or self._scan_max_time <= 0:
            return float("inf")
        return max(0.0, self._scan_max_time - self._elapsed())

    # ── Checkpoint save/load ─────────────────────────────────────

    # -- Checkpoint (原生文件实现,与 ResultDeduplicator 路径一致) --

    def _checkpoint_file(self, target_url: str) -> Path:
        """checkpoint 文件路径。"""
        return Path(ResultDeduplicator._checkpoint_path(target_url))

    def _try_save_checkpoint(
        self, target: ScanTarget, vulns: List[Vulnerability], endpoints: List[DiscoveredEndpoint]
    ) -> None:
        """S2 checkpoint:按 _checkpoint_interval 间隔限流落盘,避免每批都写盘。"""
        now = time.time()
        if now - self._last_checkpoint_time >= self._checkpoint_interval:
            self._save_checkpoint(target.url, vulns, endpoints)

    def _save_checkpoint(
        self, target_url: str, vulns: List[Vulnerability], endpoints: List[DiscoveredEndpoint]
    ) -> None:
        """Save incremental scan results to disk for crash/timeout resilience."""
        try:
            cp = self._checkpoint_file(target_url)
            data = {
                "target": target_url,
                "vulnerabilities": [v.to_dict() for v in vulns],
                "modules_done": list(getattr(self, "_modules_done", [])),
                "endpoints_found": len(endpoints),
                "requests_made": self.session.get_stats().get("total_requests", 0),
                "timestamp": time.time(),
            }
            cp.write_text(json.dumps(data, ensure_ascii=False, default=str), encoding="utf-8")
            self._last_checkpoint_time = time.time()
        except Exception as e:  # noqa: BLE001
            logger.debug(f"Checkpoint save failed: {e}")

    def load_checkpoint(self, target_url: str) -> Optional[Dict[str, Any]]:
        """Load a previously saved checkpoint for --resume."""
        cp = self._checkpoint_file(target_url)
        if cp.exists():
            try:
                parsed = json.loads(cp.read_text(encoding="utf-8"))
                return parsed if isinstance(parsed, dict) else None
            except Exception as e:  # noqa: BLE001
                logger.warning(f"Checkpoint load failed: {e}")
        return None

    # ── Endpoint prioritization ─────────────────────────────────

    @staticmethod
    def _prioritize_endpoints(endpoints: List[DiscoveredEndpoint]) -> List[DiscoveredEndpoint]:
        """Sort endpoints (delegated to prioritize_endpoints)."""
        return list(prioritize_endpoints(endpoints))

    # ── Core scan flow ──────────────────────────────────────────

    async def scan(self, target: ScanTarget) -> ScanResult:
        """
        执行完整扫描流程(facade:扫描全流程由编排器 Stage 流水线执行)。

        流水线 stages(v2.2-⑩ 迁移完成):
        WAF 检测 → 靶机认证 → OA 检测 → --resume 恢复 →
        爬取+流式检测 → 去重 → Nuclei → AI 复核 → 最终 checkpoint

        Args:
            target: 扫描目标（URL + 认证信息 + 自定义参数）

        Returns:
            ScanResult: 扫描结果（含漏洞列表、请求统计、耗时）

        Raises:
            不会抛出异常，所有错误被捕获并记录到 result.errors
        """
        self._stats["start_time"] = time.time()
        self._vuln_seen.clear()
        self._stats["errors"] = 0

        result = ScanResult(target=target)

        # ── Step 1: 加载模块（必须在 _print_header 之前，以便显示加载的模块）──
        # 如果 CLI 已手动加载了指定模块（--modules），跳过自动加载
        if not self._modules:
            # Re-resolve enabled modules in case CLI set _load_all_modules
            if hasattr(self, "_load_all_modules") and self._load_all_modules:
                self._enabled_modules = self._resolve_enabled_modules()
            self.load_all_modules()
        self._stats["modules_run"] = len(self._modules)
        logger.info(f"[Scanner] 启用模块: {list(self._modules.keys())}")

        self._print_header(target)

        # ── Inject manual cookies ──
        if target.cookies:
            for name, value in target.cookies.items():
                self.session.set_cookie(target.url, name, value)
            print(f"[+] 注入 {len(target.cookies)} 个 session cookie")

        # ══════════════════════════════════════════════════════════════
        # 单趟编排流水线(单 stage 失败告警不阻断,由 ScanOrchestrator 保证)
        # ══════════════════════════════════════════════════════════════
        from .orchestrator import ScanContext

        orchestrator = self._orchestrator or self._build_orchestrator()
        ctx = ScanContext(self)
        ctx.target = target
        ctx.result = result
        await orchestrator.run(ctx)

        # ── Stage 失败可观测:转入报告 errors 与统计(不阻断,与 fail-soft 语义一致) ──
        for failure in ctx.stage_failures:
            result.errors.append(failure)
            self._stats["errors"] += 1

        # ── Report(保持异常向上传播语义,留在 facade) ──
        unique_vulns = ctx.unique_vulns

        # 更新每个漏洞的扫描统计
        for v in unique_vulns:
            # 更新类型计数
            t = v.type.value
            self._stats["vulns_by_type"][t] = self._stats["vulns_by_type"].get(t, 0) + 1

        # 按严重程度排序（严重的在前面）
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        unique_vulns.sort(key=lambda v: severity_order.get(v.severity.value, 5))

        result.vulnerabilities = unique_vulns

        # ── Report ──
        logger.info("[*] Phase 4/4: Generating report...")
        self._stats["end_time"] = time.time()
        result.duration = self._stats["end_time"] - self._stats["start_time"]
        result.requests_made = self.session.get_stats()["total_requests"]
        result.endpoints_found = len(ctx.endpoints)
        result.modules_run = len(self._modules)

        self._print_summary(result)

        return result

    # Integrations moved to ScannerIntegrationsMixin (scanner_integrations.py)
    # Progress helpers moved to ScannerIntegrationsMixin (scanner_integrations.py)
