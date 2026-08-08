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
from ..plugins.auth import APIKeyAuth, BasicAuth, BearerTokenAuth, CookieAuth, FormLoginAuth
from .crawler import DiscoveredEndpoint, WebCrawler
from .dedup import ResultDeduplicator, prioritize_endpoints
from .lab_profiles import detect_lab_profile, get_lab_endpoints
from .scanner_integrations import ScannerIntegrationsMixin
from .session import HTTPPool

try:
    from .lab_profiles import detect_lab_profile_from_paths
except ImportError:

    def detect_lab_profile_from_paths(url, paths):
        return detect_lab_profile(url)


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
        # dedup handled by self.dedup
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
        self._lab_profile = None
        self._lab_base_url = None

        # 集成开关（默认关闭，避免未导入的集成模块导致崩溃）
        self._integrations_enabled = False

        # 漏洞去重缓存(dedup 依赖,scan() 会 clear 它)
        self._vuln_seen: set = set()

        # Nuclei 集成实例(懒加载;config nuclei.enabled 默认 True,接入主流程)
        self._nuclei_integration = None

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
        from .stages import DedupStage, LabAuthStage, OADetectionStage, WAFDetectionStage

        return ScanOrchestrator(
            self,
            stages=[
                WAFDetectionStage(self),
                LabAuthStage(self),
                OADetectionStage(self),
                DedupStage(self),
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
        base = self._lab_base_url
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

    async def _do_authenticate(self, target: ScanTarget) -> Dict[str, Any]:
        """
        执行登录认证并注入 cookie 到 session

        Args:
            target: 扫描目标（含 auth_config）

        Returns:
            auth_result dict
        """
        ac = target.auth_config
        auth_type = ac.get("type", "form").lower()

        if auth_type == "form":
            provider = FormLoginAuth(
                login_url=ac["login_url"],
                username=ac.get("username", ""),
                password=ac.get("password", ""),
                username_field=ac.get("username_field", "username"),
                password_field=ac.get("password_field", "password"),
                extra_fields=ac.get("extra_fields"),
                success_check=ac.get("success_check"),
                fail_check=ac.get("fail_check"),
            )
        elif auth_type == "bearer":
            provider = BearerTokenAuth(
                token=ac.get("token", ""),
                header=ac.get("header", "Authorization"),
            )
        elif auth_type == "basic":
            provider = BasicAuth(
                username=ac.get("username", ""),
                password=ac.get("password", ""),
            )
        elif auth_type == "apikey":
            provider = APIKeyAuth(
                key=ac.get("api_key", ""),
                header=ac.get("header", "X-API-Key"),
            )
        elif auth_type == "cookie":
            provider = CookieAuth(
                cookies=ac.get("cookies", {}),
            )
        else:
            return {"authenticated": False, "error": f"未知认证类型: {auth_type}"}

        # 执行认证，拿到 cookies/headers
        result = await provider.authenticate(self.session._get_httpx_client())

        if result.get("authenticated"):
            # 将 cookies 注入到 HTTPPool 的 cookie jar
            for name, value in result.get("cookies", {}).items():
                self.session.set_cookie(target.url, name, value)
            # 将 auth headers 注入
            for hname, hvalue in result.get("headers", {}).items():
                self.session.set_header(hname, hvalue)

        return result

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

    async def _run_module(
        self,
        module_name: str,
        target: ScanTarget,
        endpoints: List[DiscoveredEndpoint],
        semaphore: asyncio.Semaphore,
    ) -> List[Vulnerability]:
        """
        运行单个检测模块（带并发控制）

        Args:
            module_name: 模块名
            target: 扫描目标
            endpoints: 待测试端点列表
            semaphore: 并发控制信号量

        Returns:
            发现的漏洞列表
        """
        if module_name not in self._modules:
            return []

        module = self._modules[module_name]

        async with semaphore:
            vulns: List[Vulnerability] = []

            for ep in endpoints:
                if not ep.url:
                    continue

                # URL 尾部斜杠修复：Apache/目录型 URL 需要尾部斜杠
                # e.g. /dvwa/vulnerabilities/sqli → /dvwa/vulnerabilities/sqli/
                ep_url = ep.url
                parsed = urlparse(ep_url)
                path_part = parsed.path
                # 无查询参数、无扩展名、无尾部斜杠 → 可能是目录
                if not parsed.query and "." not in path_part.split("/")[-1] and not path_part.endswith("/"):
                    ep_url = ep_url.rstrip("/") + "/"

                # 构建当前端点的 ScanTarget
                # POST 方法时用 data 字段（body），GET 方法时用 params（query）
                if ep.method.upper() == "POST":
                    ep_target = ScanTarget(
                        url=ep_url,
                        methods=[ep.method],
                        cookies=target.cookies,
                        headers=target.headers,
                        auth=target.auth,
                        data=ep.parameters,
                    )
                else:
                    ep_target = ScanTarget(
                        url=ep_url,
                        methods=[ep.method],
                        cookies=target.cookies,
                        headers=target.headers,
                        auth=target.auth,
                        params=ep.parameters,
                    )

                try:
                    found = await module.scan(ep_target)
                except Exception as e:
                    logger.debug(f"[Scanner] 模块 {module_name} 扫描 {ep.url} 出错: {e}")
                    found = []

                for v in found:
                    v.module = module_name
                    v.parameter = list(ep.parameters.keys())[0] if ep.parameters else None
                    v.parameter_type = ep.param_types.get(v.parameter or "", "query")
                    vulns.append(v)

            return vulns

    async def _run_module_no_semaphore(
        self,
        module_name: str,
        target: ScanTarget,
        endpoints: List[DiscoveredEndpoint],
    ) -> List[Vulnerability]:
        """运行单个检测模块（无外部 semaphore，只用 HTTPPool 内部限流）"""
        if module_name not in self._modules:
            return []

        module = self._modules[module_name]
        vulns: List[Vulnerability] = []

        for ep in endpoints:
            if not ep.url:
                continue

            # URL 尾部斜杠修复（同上）
            ep_url = ep.url
            parsed = urlparse(ep_url)
            if not parsed.query and "." not in parsed.path.split("/")[-1] and not parsed.path.endswith("/"):
                ep_url = ep_url.rstrip("/") + "/"

            # Preserve auth data from the original target
            auth_data = getattr(target, "auth", None) or getattr(target, "auth_config", None)
            if ep.method.upper() == "POST":
                ep_target = ScanTarget(
                    url=ep_url,
                    methods=[ep.method],
                    cookies=target.cookies,
                    headers=target.headers,
                    auth=auth_data,
                    data=ep.parameters,
                )
            else:
                ep_target = ScanTarget(
                    url=ep_url,
                    methods=[ep.method],
                    cookies=target.cookies,
                    headers=target.headers,
                    auth=auth_data,
                    params=ep.parameters,
                )

            try:
                found = await module.scan(ep_target)
            except asyncio.CancelledError:
                # 超时取消：保存部分结果并停止
                self._partial_vulns.extend(vulns)
                raise
            except Exception as e:
                logger.debug(f"[Scanner] 模块 {module_name} 扫描 {ep.url} 出错: {e}")
                found = []

            for v in found:
                v.module = module_name
                v.parameter = list(ep.parameters.keys())[0] if ep.parameters else None
                v.parameter_type = ep.param_types.get(v.parameter or "", "query")
                vulns.append(v)

        # 模块完成：保存完整结果到 partial（超时抢救用）
        self._partial_vulns.extend(vulns)
        return vulns

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
                if not parsed.query and "." not in parsed.path.split("/")[-1] and not parsed.path.endswith("/"):
                    ep_url = ep_url.rstrip("/") + "/"

                if ep.method.upper() == "POST":
                    ep_target = ScanTarget(
                        url=ep_url,
                        methods=[ep.method],
                        cookies=target.cookies,
                        headers=target.headers,
                        auth=target.auth,
                        data=ep.parameters,
                    )
                else:
                    ep_target = ScanTarget(
                        url=ep_url,
                        methods=[ep.method],
                        cookies=target.cookies,
                        headers=target.headers,
                        auth=target.auth,
                        params=ep.parameters,
                    )
                try:
                    found = await module.scan(ep_target)
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
        return ResultDeduplicator.normalize_vuln_url(url)

    def _vuln_signature(self, v: Vulnerability) -> str:
        return self.dedup.signature(v)

    def _deduplicate(self, vulns: List[Vulnerability]) -> List[Vulnerability]:
        return self.dedup.deduplicate(vulns)

    async def _run_nuclei(self, target: ScanTarget) -> List[Vulnerability]:
        """S2 接入:运行 Nuclei 外部引擎(模板扫描),结果由主流程去重合并。

        nuclei CLI 可用 → 智能模板扫描;CLI 不可用 → 内置回退模板(S1 内容特征验证)。
        """
        from ..integrations.nuclei_integration import NucleiIntegration

        if self._nuclei_integration is None:
            self._nuclei_integration = NucleiIntegration(config=self.config, use_template_manager=True)

        if not self._nuclei_integration.is_available:
            logger.info("[Nuclei] nuclei CLI 不可用，使用内置回退模板（内容特征验证）")

        return await self._nuclei_integration.scan(
            target.url,
            cookies=target.cookies or None,
            severities=None,  # 默认全部严重级，由结果合并后统一去重/排序
        )

    def _call_progress(self, module_name: str, done: int, total: int, pct: int = 0):
        """向 GUI 发送进度回调（如果有注册回调的话）"""
        if hasattr(self, "_progress_callback") and self._progress_callback:
            try:
                self._progress_callback(module_name, done, total, pct)
            except Exception:
                logger.debug(f"[Scanner] Progress callback failed for {module_name}", exc_info=True)

    # ── Timeout helpers ────────────────────────────────────────

    def _elapsed(self) -> float:
        return time.time() - self._stats["start_time"]

    def _timeout_remaining(self) -> float:
        if not self._scan_max_time or self._scan_max_time <= 0:
            return float("inf")
        return max(0.0, self._scan_max_time - self._elapsed())

    # ── Checkpoint save/load ─────────────────────────────────────

    # -- Checkpoint (原生文件实现,与 ResultDeduplicator 路径一致) --

    def _checkpoint_file(self, target_url: str) -> Path:
        return ResultDeduplicator._checkpoint_path(target_url)

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
                return json.loads(cp.read_text(encoding="utf-8"))
            except Exception as e:  # noqa: BLE001
                logger.warning(f"Checkpoint load failed: {e}")
        return None

    # ── Endpoint prioritization ─────────────────────────────────

    @staticmethod
    def _prioritize_endpoints(endpoints: List[DiscoveredEndpoint]) -> List[DiscoveredEndpoint]:
        """Sort endpoints (delegated to prioritize_endpoints)."""
        return prioritize_endpoints(endpoints)

    # ── Core scan flow ──────────────────────────────────────────

    async def scan(self, target: ScanTarget) -> ScanResult:
        """
        执行完整扫描流程。

        流程分为四个阶段:
        1. 加载检测模块并做 WAF 检测
        2. 靶机识别与自动认证（DVWA/Metasploitable2 等）
        3. 爬取 + 流式检测（边爬边测，不等全部爬完）
        4. 外部集成扫描 + 结果去重合并

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

        # ── Step 0: WAF detection (run first, broadcast results to all modules) ──
        # (已抽取为 WAFDetectionStage,由编排器执行)

        # ── Inject manual cookies ──
        if target.cookies:
            for name, value in target.cookies.items():
                self.session.set_cookie(target.url, name, value)
            print(f"[+] 注入 {len(target.cookies)} 个 session cookie")

        # ══════════════════════════════════════════════════════════════
        # Step 0 + 1.8 + 1.9: 编排器执行 WAF 检测 / 靶机认证 / OA 检测
        # ══════════════════════════════════════════════════════════════
        if self._orchestrator is not None:
            from .orchestrator import ScanContext

            ctx = ScanContext(self)
            ctx.target = target
            await self._orchestrator.run(ctx)

        # ── Crawl + 流式检测 ──
        logger.info("\n[*] Phase 1/4: Crawling + streaming detection...")
        self._call_progress("crawl", 0, 100, 3)

        # 分批爬取：先爬一批立刻检测，不等全部爬完
        BATCH_SIZE = 10  # 每批检测端点数

        # 限制爬取深度：实战目标快速收敛，留时间给检测
        max_crawl = self.config.get("crawl_max_urls", 300)
        max_pages = 30 if not self._lab_profile else 150  # 实战30页，靶机150页
        self.crawler.max_urls_per_run = min(max_crawl, max_pages)
        self.crawler.max_depth = 2 if not self._lab_profile else 4  # 实战浅爬

        all_endpoints: List[DiscoveredEndpoint] = []
        all_vulns_before_dedup: List[Vulnerability] = []

        # S2 resume:合并上次 checkpoint 已发现漏洞 + 跳过已完成模块
        self._modules_done = []
        if getattr(self, "_resume_checkpoint", None):
            cp = self._resume_checkpoint
            for vdict in cp.get("vulnerabilities", []):
                try:
                    v = Vulnerability.from_dict(vdict)
                    all_vulns_before_dedup.append(v)
                    logger.info(f"[resume] 复用已发现漏洞: {v.url} ({v.type.value})")
                except Exception:  # noqa: BLE001
                    logger.debug("[resume] 反序列化漏洞失败,跳过")
            skip_modules = set(cp.get("modules_done", []))
            if skip_modules:
                logger.info(f"[resume] 跳过已完成模块: {sorted(skip_modules)}")
                for m in list(self._modules.keys()):
                    if m in skip_modules:
                        self._modules.pop(m)

        async def _crawl_and_detect():
            """爬取+检测循环：爬一批，测一批"""
            module_names = list(self._modules.keys())
            # 全局并发信号量:一次创建,跨模块共享,真正限制总并发(P2-4)
            concurrency = max(1, int(self.config.get("concurrent_endpoints", 10)))
            global_sem = asyncio.Semaphore(concurrency)
            try:
                # 第一次爬取
                eps = await self.crawler.crawl(target.url, self.session)
                all_endpoints.extend(eps)

                # T0 修复：crawler 未产出端点（单页无链接且 seed 全 404）时，
                # 兜底至少测目标本身——否则流式检测整体跳过（检测模块完全不执行）
                if not eps:
                    eps = [DiscoveredEndpoint(url=target.url, method="GET", source_url=target.url, source_depth=1)]
                    all_endpoints.extend(eps)

                # 分批检测已爬到的端点
                if eps:
                    enriched = await self.crawler.discover_params_batch(eps, self.session)
                    for i, ep in enumerate(enriched):
                        if i < len(eps):
                            eps[i].parameters = ep.parameters or eps[i].parameters
                            eps[i].param_types = ep.param_types or eps[i].param_types

                    for batch_idx in range(0, len(eps), BATCH_SIZE):
                        if self._timeout_remaining() < 30:
                            break
                        batch = eps[batch_idx : batch_idx + BATCH_SIZE]
                        for mod_name in module_names:
                            if mod_name not in self._modules:
                                continue
                            try:
                                vulns = await self._run_module_concurrent(
                                    mod_name,
                                    target,
                                    batch,
                                    concurrency=concurrency,
                                    global_sem=global_sem,
                                )
                                all_vulns_before_dedup.extend(vulns)
                                if vulns:
                                    logger.info(f"[+] {mod_name}: found {len(vulns)} in batch")
                            except Exception as e:
                                logger.debug(f"[Scanner] {mod_name} batch error: {e}")
                        # S2 checkpoint: 每批流式检测后按间隔限流落盘(崩溃/超时恢复)
                        try:
                            self._try_save_checkpoint(target, all_vulns_before_dedup, eps)
                        except Exception as e:  # noqa: BLE001
                            logger.debug(f"[Scanner] checkpoint save failed: {e}")

            except Exception:
                logger.exception("[Scanner] 爬取失败")

        await _crawl_and_detect()

        self._call_progress("crawl", 100, 100, 10)
        self._stats["endpoints_discovered"] = len(all_endpoints)
        crawler_stats = self.crawler.get_stats()
        logger.info(
            f"\r[*] Crawled {crawler_stats.get('pages_crawled', 0)} pages, "
            f"discovered {len(all_endpoints)} endpoints, "
            f"found {crawler_stats.get('forms_found', 0)} forms"
        )

        # P8: Prioritize endpoints
        endpoints = self._prioritize_endpoints(all_endpoints)

        if not endpoints:
            endpoints = [DiscoveredEndpoint(url=target.url, method="GET", source_url=target.url, source_depth=1)]

        # ── Re-detect lab profile from discovered paths ──
        if not self._lab_profile:
            discovered_paths = [ep.url for ep in endpoints]
            self._lab_profile = detect_lab_profile_from_paths(target.url, discovered_paths)
            if self._lab_profile:
                self._lab_base_url = target.url
                logger.info(f"[*] Detected lab profile from endpoints: {self._lab_profile.name}")
                if not target.cookies:
                    await self._do_lab_auth()

        # ── Append lab endpoints ──
        if self._lab_profile:
            lab_eps = get_lab_endpoints(self._lab_profile, target.url)
            added = 0
            merged = 0
            for lep in lab_eps:
                existing = None
                lep_norm = self._normalize_url(lep.url)
                for e in endpoints:
                    if self._normalize_url(e.url) == lep_norm:
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
            logger.info(f"[*] Lab profile ({self._lab_profile.name}): +{added} endpoints, merged {merged}")

        # ── Parameter discovery for endpoints without params ──
        endpoints_without_params = [e for e in endpoints if not e.parameters]
        if endpoints_without_params:
            logger.info(f"[*] Running parameter discovery on {len(endpoints_without_params)} endpoints...")
            enriched = await self.crawler.discover_params_batch(endpoints_without_params, self.session)
            for i, ep in enumerate(endpoints_without_params):
                if i < len(enriched) and enriched[i].parameters:
                    ep.parameters = enriched[i].parameters
                    ep.param_types = enriched[i].param_types

        # ── Phase 1.5 — JS endpoint & secret analysis (JSPathfinder) ──
        # Disabled by default in v1.1.0 (sqli+xss focus). Enable with modules.jspathfinder.enabled=true
        if self.config.get("modules.jspathfinder.enabled", False):
            logger.info("\n[*] Phase 1.5/4: JS analysis (JSPathFinder)...")
            self._call_progress("jspathfinder", 0, 1, 12)
            try:
                self._jspathfinder_vulns = await self._run_jspathfinder(target)
                logger.info(f"[+] JSPathFinder: {len(self._jspathfinder_vulns)} finds")
            except Exception as e:
                logger.exception("[Scanner] jspathfinder phase failed")
                self._jspathfinder_vulns = []
            self._call_progress("jspathfinder", 1, 1, 15)
        else:
            self._jspathfinder_vulns = []

        # ── 流式检测完成 ──
        logger.info(f"[*] Phase 2/4: Streaming detection done ({len(all_vulns_before_dedup)} raw findings)")

        all_vulns = all_vulns_before_dedup

        # ── Merge JSPathfinder findings (disabled by default) ──
        if getattr(self, "_jspathfinder_vulns", None):
            all_vulns.extend(self._jspathfinder_vulns)

        # ── Dedup (通过编排器 DedupStage 执行) ──
        logger.info("[*] Phase 3/4: Deduplication & confidence...")
        if self._orchestrator is not None:
            from .orchestrator import ScanContext

            ctx = ScanContext(self)
            ctx.raw_vulns = all_vulns
            await self._orchestrator.run(ctx)
            unique_vulns = ctx.unique_vulns
        else:
            unique_vulns = self._deduplicate(all_vulns)

        # ── Phase 3.5: Nuclei 外部引擎(默认启用;CLI 可用走模板扫描,不可用走内置回退) ──
        if self.config.get("nuclei.enabled", True):
            try:
                nuclei_vulns = await self._run_nuclei(target)
                if nuclei_vulns:
                    logger.info(f"[+] Nuclei: {len(nuclei_vulns)} findings(已合并)")
                    unique_vulns = self._deduplicate(unique_vulns + nuclei_vulns)
            except Exception as e:  # noqa: BLE001
                logger.debug(f"[Scanner] Nuclei phase failed: {e}")

        # ── Phase 3.6: AI 误报复核（T1.2，默认关，--ai-verify 开启） ──
        if self.config.get("ai.verify", False) and unique_vulns:
            try:
                from ..ai import AIVerifier, LLMClient

                ai_client = LLMClient(self.config)
                if ai_client.available:
                    verifier = AIVerifier(self.config, ai_client)
                    unique_vulns = await verifier.verify_batch(unique_vulns)
                    logger.info(
                        f"[AI] 复核完成: {verifier.reviewed_count} 条已复核, "
                        f"{verifier.confirmed_count} 确认 / {verifier.disputed_count} 存疑降级"
                    )
                else:
                    logger.warning("[AI] --ai-verify 已开启但未配置 LLM_API_KEY，跳过 AI 复核")
            except Exception as e:
                logger.debug(f"[Scanner] AI verify phase failed: {e}")

        # S2 checkpoint: 扫描结束保存最终 checkpoint(供 --resume 合并)
        try:
            self._save_checkpoint(target.url, unique_vulns, endpoints)
        except Exception as e:  # noqa: BLE001
            logger.debug(f"[Scanner] final checkpoint save failed: {e}")

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
        result.endpoints_found = len(endpoints)
        result.modules_run = len(self._modules)

        self._print_summary(result)

        return result

    # Integrations moved to ScannerIntegrationsMixin (scanner_integrations.py)
    # Progress helpers moved to ScannerIntegrationsMixin (scanner_integrations.py)
