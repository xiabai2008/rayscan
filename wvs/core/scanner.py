import urllib.parse
from urllib.parse import urlparse, parse_qs
"""
RayScan main scanner engine.

Coordinates: crawler → detection modules → dedup → reporting.
No hardcoded lab paths — lab-specific logic lives in core/lab_profiles.py.
"""

import asyncio
import gc
import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from ..config import ConfigManager
from ..models import (
    ScanResult,
    ScanTarget,
    Vulnerability,
)
from ..plugins.auth import FormLoginAuth, BearerTokenAuth, BasicAuth, APIKeyAuth, CookieAuth

from .crawler import WebCrawler, DiscoveredEndpoint
from .session import HTTPPool
from .scanner_integrations import ScannerIntegrationsMixin
from .lab_profiles import detect_lab_profile, get_lab_endpoints

try:
    from .lab_profiles import detect_lab_profile_from_paths
except ImportError:
    def detect_lab_profile_from_paths(url, paths):
        return detect_lab_profile(url)

logger = logging.getLogger(__name__)

# Module execution priority — faster/critical modules run first
_MODULE_PRIORITY = [
    "sqli",        # critical — test priority
    "xss",         # cross-site scripting
]

# Lite modules (loaded when --all-modules is set)
_LITE_MODULE_PRIORITY = [
    "sensitive",   # fast pattern-based checks
    "waf",         # WAF detection
    "cmdi",        # command injection
    "lfi",         # file inclusion
    "ssrf",        # server-side request forgery
    "xxe",         # XML external entity
    "rce",         # time-based (slowest)
    "api",         # API security
    "js_analysis", # JS sensitive info / endpoints
]


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

        # 已加载的检测模块 {module_name -> module_instance}
        self._modules: Dict[str, Any] = {}
        self._loaded_module_names: List[str] = []
        self._vuln_seen: Set[str] = set()
        self._global_baseline_cache: Dict[str, Dict[str, Any]] = {}  # Cross-module baseline cache

        # 去重集合（存储 Vulnerability 的去重签名）
        self._vuln_seen: Set[str] = set()

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
            param_types = {k: "query" for k in params}
            return params, param_types

        return {}, {}

    # ─────────────────────────────────────────────────────────────
    # 模块管理
    # ─────────────────────────────────────────────────────────────

    def _resolve_enabled_modules(self) -> List[str]:
        """从配置中解析出要启用的模块列表

        默认只加载核心模块（sqli + xss）。
        设置 load_all=True 或配置 modules.all=true 加载全部（含 lite 模块）。
        """
        if self._load_all_modules or self.config.get("modules.all", False):
            return list(_MODULE_PRIORITY + [m for m in _LITE_MODULE_PRIORITY if m not in _MODULE_PRIORITY])

        enabled = []
        for name in _MODULE_PRIORITY:
            cfg = self.config.get(f"modules.{name}", {})
            if isinstance(cfg, dict) and cfg.get("enabled", True):
                enabled.append(name)
        return enabled

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
        加载单个检测模块

        Args:
            module_name: 模块名（如 "sqli", "cmdi"）

        Returns:
            是否加载成功
        """
        if module_name in self._modules:
            return True

        try:
            # 尝试从 modules.<name>.detector 导入
            mod = __import__(
                f"wvs.modules.{module_name}.detector",
                fromlist=["detector"],
            )
            detector_cls = getattr(mod, "Detector", None)
            if detector_cls is None:
                # 策略1：尝试常见命名变体
                upper = module_name.upper()
                name_variants = [
                    f"{module_name.title()}Detector",   # CmdiDetector, XssDetector, LfiDetector
                    f"{upper}Detector",                  # CMDI, XSS, LFI → OK
                    "SQLiDetector",                     # sqli 特殊：混合大小写
                ]
                for variant in name_variants:
                    detector_cls = getattr(mod, variant, None)
                    if detector_cls:
                        break

                # 策略2：兜底 —— 遍历模块找所有 *Detector 类
                if detector_cls is None:
                    for attr_name in dir(mod):
                        if attr_name.endswith("Detector") and attr_name != "DetectionModule":
                            detector_cls = getattr(mod, attr_name)
                            logger.info(f"[Scanner] 自动发现检测类: {attr_name} (for module '{module_name}')")
                            break

            if detector_cls is None:
                raise ImportError(f"No Detector class found in wvs.modules.{module_name}.detector")

            instance = detector_cls(self.config, session=self.session)
            self._modules[module_name] = instance
            self._loaded_module_names.append(module_name)
            logger.info(f"[Scanner] 已加载模块: {module_name} (session: {id(self.session)})")
            return True

        except ImportError as e:
            logger.warning(f"[Scanner] 模块 {module_name} 不可用: {e}")
            return False
        except Exception as e:
            logger.exception(f"[Scanner] 加载模块 {module_name} 失败")
            return False

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
        path = parsed.path.rstrip('/')
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
        """Strip query string AND fragment for dedup — /get?name=test#x and /get are the same endpoint."""
        u = url.split("?")[0].split("#")[0].rstrip("/")
        import re

        u = re.sub(r"/\d+$", "/:id", u)
        # Collapse static resource sub-paths — /themes/original/css/foo.css → /themes/*
        u = re.sub(r"/(css|js|img|images|themes|theme|static|assets|fonts|locale|lang)/.+", r"/\1/*", u, flags=re.IGNORECASE)
        # P8: Collapse dynamic path segments — /user/123/profile → /user/:id/profile
        u = re.sub(r"/(\d{2,})/", "/:id/", u)
        # P8: Collapse hash-like segments — /page/a1b2c3 → /page/:hash
        u = re.sub(r"/[/]?[a-f0-9]{16,}", "/:hash", u)
        return u

    def _vuln_signature(self, v: Vulnerability) -> str:
        """
        计算漏洞去重签名

        基于 (type, url, parameter, payload) 的组合。
        同一漏洞只报告一次。URL 经过归一化（去掉查询参数和锚点）。
        """
        parts = [
            v.type.value,
            self._normalize_vuln_url(v.url or ""),
            v.parameter or "",
            v.payload or "",
        ]
        return "|".join(parts).lower()

    def _deduplicate(self, vulns: List[Vulnerability]) -> List[Vulnerability]:
        """During dedup, keep the highest severity vulnerability; if same severity, keep higher confidence."""
        seen: Set[str] = set()
        unique: Dict[str, Vulnerability] = {}
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        conf_order = {"certain": 0, "high": 1, "medium": 2, "low": 3}

        for v in vulns:
            sig = self._vuln_signature(v)
            if sig not in unique:
                unique[sig] = v
            else:
                existing = unique[sig]
                # Keep higher severity
                if severity_order.get(v.severity.value, 5) < severity_order.get(existing.severity.value, 5):
                    unique[sig] = v
                # Same severity: keep higher confidence
                elif severity_order.get(v.severity.value, 5) == severity_order.get(existing.severity.value, 5):
                    if conf_order.get(v.confidence.value, 5) < conf_order.get(existing.confidence.value, 5):
                        unique[sig] = v
        return list(unique.values())

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

    def _checkpoint_file(self, target_url: str) -> Path:
        import tempfile
        url_hash = hashlib.md5(target_url.encode()).hexdigest()[:12]
        return Path(tempfile.gettempdir()) / f"rayscan_checkpoint_{url_hash}.json"

    def _save_checkpoint(self, target_url: str, vulns: List[Vulnerability], endpoints: List[DiscoveredEndpoint]) -> None:
        """Save incremental scan results to disk for crash/timeout resilience."""
        try:
            cp = self._checkpoint_file(target_url)
            data = {
                "target": target_url,
                "vulnerabilities": [v.to_dict() for v in vulns],
                "modules_done": list(self._modules_done),
                "endpoints_found": len(endpoints),
                "requests_made": self.session.get_stats().get("total_requests", 0),
                "timestamp": time.time(),
            }
            cp.write_text(json.dumps(data, ensure_ascii=False, default=str), encoding="utf-8")
            self._last_checkpoint_time = time.time()
        except Exception as e:
            logger.debug(f"Checkpoint save failed: {e}")

    def load_checkpoint(self, target_url: str) -> Optional[Dict[str, Any]]:
        """Load a previously saved checkpoint for --resume."""
        cp = self._checkpoint_file(target_url)
        if cp.exists():
            try:
                return json.loads(cp.read_text(encoding="utf-8"))
            except Exception as e:
                logger.warning(f"Checkpoint load failed: {e}")
        return None

    # ── Endpoint prioritization ─────────────────────────────────

    @staticmethod
    def _prioritize_endpoints(endpoints: List[DiscoveredEndpoint]) -> List[DiscoveredEndpoint]:
        """Sort endpoints so most promising (dynamic, parameterised) ones are scanned first."""

        def score(ep: DiscoveredEndpoint) -> int:
            s = 0
            if ep.parameters:
                s -= 100  # has params → highest priority
            if ep.method.upper() == "POST":
                s -= 50  # POST endpoints often more interesting
            s -= min(len(ep.parameters or {}), 10)  # more params → higher priority
            if any(k.lower() in ("id", "page", "file", "path", "url", "cmd", "exec", "query", "search") for k in (ep.parameters or {})):
                s -= 30  # interesting param names
            return s

        return sorted(endpoints, key=score)

    # ── Core scan flow ──────────────────────────────────────────

    async def scan(self, target: ScanTarget) -> ScanResult:  # noqa: C901
        self._stats["start_time"] = time.time()
        self._vuln_seen.clear()
        self._stats["errors"] = 0

        result = ScanResult(target=target)

        # ── Step 1: 加载模块（必须在 _print_header 之前，以便显示加载的模块）──
        # 如果 CLI 已手动加载了指定模块（--modules），跳过自动加载
        if not self._modules:
            self.load_all_modules()
        self._stats["modules_run"] = len(self._modules)
        logger.info(f"[Scanner] 启用模块: {list(self._modules.keys())}")

        self._print_header(target)

        # ── Step 0: WAF detection (run first, broadcast results to all modules) ──
        if self.config.get("enable_waf_detection", True) and "waf" in self._modules:
            try:
                waf_module = self._modules["waf"]
                waf_target = ScanTarget(url=target.url)
                await waf_module.scan(waf_target)
                waf_result = waf_module.get_result() if hasattr(waf_module, "get_result") else None
                if waf_result and waf_result.detected:
                    logger.info(f"\n[!] WAF Detected: {waf_result.vendor} (confidence: {waf_result.confidence:.0%})")
                    for mod in self._modules.values():
                        if hasattr(mod, "set_waf_detected"):
                            mod.set_waf_detected(True)
            except Exception as e:
                logger.debug(f"[Scanner] WAF detection skipped: {e}")

        # ── Inject manual cookies ──
        if target.cookies:
            for name, value in target.cookies.items():
                self.session.set_cookie(target.url, name, value)
            print(f"[+] 注入 {len(target.cookies)} 个 session cookie")

        # ══════════════════════════════════════════════════════════════
        # Step 1.8: 探测 DVWA 并认证（统一入口，只执行一次）
        # ══════════════════════════════════════════════════════════════
        _dvwa_base: Optional[str] = None
        if not target.cookies:
            base_url = target.url.rstrip("/")
            # 快速探测常见 DVWA 路径
            for login_url in [
                f"{base_url}/dvwa/login.php",
                f"{base_url}/login.php",
            ]:
                try:
                    r = await self.session.get(login_url, timeout=5)
                    if "dvwa" in r.text.lower():
                        _dvwa_base = login_url.rsplit("/login.php", 1)[0]
                        break
                except Exception:
                    logger.debug(f"[Scanner] DVWA base guess failed for {login_url}", exc_info=True)

        # ── Crawl ──
        logger.info("\n[*] Phase 1/4: Crawling...")
        self._call_progress("crawl", 0, 100, 3)
        try:
            endpoints = await self.crawler.crawl(target.url, self.session)
        except Exception as e:
            logger.exception("[Scanner] 爬取失败")
            endpoints = []
            self._stats["errors"] += 1
        self._call_progress("crawl", 100, 100, 10)

        self._stats["endpoints_discovered"] = len(endpoints)
        crawler_stats = self.crawler.get_stats()
        logger.info(
            f"\r[*] Crawled {crawler_stats.get('pages_crawled', 0)} pages, "
            f"discovered {len(endpoints)} endpoints, "
            f"found {crawler_stats.get('forms_found', 0)} forms"
        )

        # P8: Prioritize endpoints — scan dynamic/promising endpoints first
        endpoints = self._prioritize_endpoints(endpoints)

        if not endpoints:
            endpoints = [DiscoveredEndpoint(url=target.url, method="GET", source_url=target.url, source_depth=1)]

        # ── Re-detect lab profile from discovered paths (for IP targets) ──
        if not self._lab_profile:
            discovered_paths = [ep.url for ep in endpoints]
            self._lab_profile = detect_lab_profile_from_paths(target.url, discovered_paths)
            if self._lab_profile:
                self._lab_base_url = target.url
                logger.info(f"[*] Detected lab profile from endpoints: {self._lab_profile.name}")
                if not target.cookies:
                    await self._do_lab_auth()

        # ── Append lab endpoints (from profile, not hardcoded) ──
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
                    # Merge: lab profile has authoritative params/method for known targets
                    if not existing.parameters and lep.parameters:
                        existing.parameters = lep.parameters.copy()
                        merged += 1
                    if existing.method == "GET" and lep.method != "GET":
                        existing.method = lep.method
                        merged += 1
                    if not existing.param_types and lep.param_types:
                        existing.param_types = lep.param_types.copy()
                        merged += 1
            logger.info(f"[*] Lab profile ({self._lab_profile.name}): +{added} endpoints, merged params into {merged}")

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
        if self.config.get("modules.jspathfinder.enabled", True):
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

        # ── Concurrent detection (P5: global concurrency limiter) ──
        logger.info("[*] Phase 2/4: Running detectors (concurrent)...")

        # Inject cross-module baseline cache
        self._global_baseline_cache.clear()
        for mod in self._modules.values():
            if hasattr(mod, "set_global_baseline_cache"):
                mod.set_global_baseline_cache(self._global_baseline_cache)

        # P5: Modules that require parameters to be useful — skip on parameterless endpoints
        PARAM_REQUIRED_MODULES = {"sqli", "xss", "cmdi", "rce", "lfi", "ssrf", "xxe"}

        remaining = self._timeout_remaining()
        if remaining < 60:
            logger.warning(f"[!] Only {remaining:.0f}s remaining before timeout — detection may be incomplete")
        total_tasks = len(endpoints) * len(self._modules)
        completed_tasks = 0
        all_vulns: List[Vulnerability] = []
        lock = asyncio.Lock()

        # P19: Configurable rate limiting — safe defaults for fragile targets
        raw_concurrent = self.config.get("concurrent_endpoints", 8) * min(len(self._modules), 3)
        max_concurrent_requests = min(
            raw_concurrent,
            self.config.get("max_concurrent_requests", 10),
        )
        global_sem = asyncio.Semaphore(max_concurrent_requests)

        # P5: Filter endpoints for param-required modules
        endpoints_with_params = [e for e in endpoints if e.parameters]
        endpoints_without_params = [e for e in endpoints if not e.parameters]

        # P23: Limit POST endpoints to avoid form-storm on dense pages.
        # Mutillidae's add-to-your-blog.php + register.php have 8+ fields
        # each, and crawling finds them repeatedly with different ?page= values.
        POST_ENDPOINT_LIMIT = self.config.get("max_post_endpoints", 12)
        post_eps = [e for e in endpoints if e.method == "POST"]
        if len(post_eps) > POST_ENDPOINT_LIMIT:
            # Keep GET endpoints, sample the most interesting POST endpoints
            get_eps = [e for e in endpoints if e.method != "POST"]
            # Sort POST endpoints by parameter count (fewer params = faster to test)
            post_eps.sort(key=lambda ep: len(ep.parameters))
            sampled_post = post_eps[:POST_ENDPOINT_LIMIT]
            logger.warning(
                f"[!] POST endpoint limit ({len(post_eps)} > {POST_ENDPOINT_LIMIT}) — "
                f"sampling {len(sampled_post)} most compact"
            )
            endpoints = get_eps + sampled_post
            # Re-filter after sampling
            endpoints_with_params = [e for e in endpoints if e.parameters]
            endpoints_without_params = [e for e in endpoints if not e.parameters]

        # P10: Track requests per module for budget enforcement
        _requests_before: Dict[str, int] = {}
        MODULE_MAX_REQUESTS = 1000  # P14: tighter budget (was 3000) — SQLi payloads already slimmed

        # P5: Process modules sequentially, endpoints concurrently within each module.
        async def run_and_track(module_name: str) -> List[Vulnerability]:
            nonlocal completed_tasks
            # P10: Check request budget — if this module has already made too many
            # requests without findings, skip it
            reqs_made = self.session.get_stats().get("total_requests", 0)
            _requests_before.setdefault(module_name, reqs_made)
            module_reqs = reqs_made - _requests_before.get(module_name, reqs_made)
            if module_reqs > MODULE_MAX_REQUESTS:
                logger.warning(f"[!] Skipping module '{module_name}' — request budget exceeded ({module_reqs})")
                async with lock:
                    completed_tasks += len(endpoints)
                    self._print_progress(completed_tasks, total_tasks, module_name)
                return []

            if self._timeout_remaining() < 30:
                logger.warning(f"[!] Skipping module '{module_name}' — timeout approaching")
                async with lock:
                    completed_tasks += len(endpoints)
                    self._print_progress(completed_tasks, total_tasks, module_name)
                return []

            # P5: Skip param-injection modules on parameterless endpoints
            if module_name in PARAM_REQUIRED_MODULES:
                module_endpoints = endpoints_with_params
            else:
                module_endpoints = endpoints

            if not module_endpoints:
                async with lock:
                    completed_tasks += len(endpoints)
                    self._print_progress(completed_tasks, total_tasks, module_name)
                return []

            # P23: Trim POST form parameters — keep only security-relevant ones
            # to avoid form-storm on blog/message/register forms with many fields.
            POST_PRIORITY_PARAMS = {"username", "password", "pass", "email", "id", "uid", "pid",
                                    "page", "file", "path", "url", "cmd", "exec", "query", "search",
                                    "q", "cat", "category", "name", "title", "comment", "content"}
            for ep in module_endpoints:
                if ep.method.upper() == "POST" and len(ep.parameters) > 3:
                    trimmed = {k: v for k, v in ep.parameters.items() if k.lower() in POST_PRIORITY_PARAMS}
                    if trimmed:
                        ep.parameters = trimmed

            # P11: Stricter per-module endpoint cap + early exit for better performance
            MAX_EP_PER_MODULE = 50  # increased from 25 — more endpoints = more findings
            if module_name in PARAM_REQUIRED_MODULES and len(module_endpoints) > MAX_EP_PER_MODULE:
                # Prioritize and keep the most promising endpoints
                module_endpoints = self._prioritize_endpoints(module_endpoints)[:MAX_EP_PER_MODULE]

            # P11: More aggressive early exit — test first 5 endpoints; 3 consecutive no-finds → skip module
            EARLY_EXIT_SAMPLE = 6  # increased from 3 — more samples before early exit
            if len(module_endpoints) > EARLY_EXIT_SAMPLE and module_name in PARAM_REQUIRED_MODULES:
                sample_eps = module_endpoints[:EARLY_EXIT_SAMPLE]
                concurrency = self.config.get("concurrent_endpoints", 12)
                sample_vulns = await self._run_module_concurrent(
                    module_name,
                    target,
                    sample_eps,
                    concurrency,
                    global_sem,
                )
                if not sample_vulns:
                    async with lock:
                        completed_tasks += len(endpoints)
                        self._print_progress(completed_tasks, total_tasks, module_name)
                    return []
                # Found something — scan ALL remaining endpoints too
                remaining_eps = module_endpoints[EARLY_EXIT_SAMPLE:]
                rest_vulns = await self._run_module_concurrent(
                    module_name,
                    target,
                    remaining_eps,
                    concurrency,
                    global_sem,
                )
                vulns = sample_vulns + rest_vulns
            else:
                concurrency = self.config.get("concurrent_endpoints", 12)
                vulns = await self._run_module_concurrent(
                    module_name,
                    target,
                    module_endpoints,
                    concurrency,
                    global_sem,
                )

            async with lock:
                completed_tasks += len(endpoints)
                self._print_progress(completed_tasks, total_tasks, module_name)
            return vulns

        # P5: Run modules in batches of 3 to bound memory usage.
        # P8: Sort modules by priority — faster/critical modules first.
        module_names = sorted(
            self._modules.keys(),
            key=lambda m: _MODULE_PRIORITY.index(m) if m in _MODULE_PRIORITY else 99,
        )
        self._modules_done = []
        for batch_start in range(0, len(module_names), 3):
            batch = module_names[batch_start: batch_start + 3]
            if self._timeout_remaining() < 30:
                logger.warning("[!] Timeout approaching — skipping remaining modules")
                break
            for mod_name in batch:
                self._call_progress(mod_name, 0, 100, 15 + (batch_start / max(len(module_names), 1)) * 75)
            batch_tasks = [run_and_track(name) for name in batch]
            results = await asyncio.gather(*batch_tasks, return_exceptions=True)
            for name, res in zip(batch, results):
                if isinstance(res, Exception):
                    logger.error(f"[Scanner] module error: {res}")
                    self._stats["errors"] += 1
                elif isinstance(res, list):
                    all_vulns.extend(res)
                if name not in self._modules_done:
                    self._modules_done.append(name)
            # P5: Release memory between batches to prevent OOM/SIGKILL
            gc.collect()
            # P8: Auto-save checkpoint after each batch for crash/timeout resilience
            self._save_checkpoint(target.url, all_vulns, endpoints)

        # ── Merge JSPathfinder findings ──
        if getattr(self, "_jspathfinder_vulns", None):
            all_vulns.extend(self._jspathfinder_vulns)

        # ── Dedup ──
        logger.info("[*] Phase 3/4: Deduplication & confidence...")
        unique_vulns = self._deduplicate(all_vulns)

        # 更新每个漏洞的扫描统计
        for v in unique_vulns:
            # 更新类型计数
            t = v.type.value
            self._stats["vulns_by_type"][t] = self._stats["vulns_by_type"].get(t, 0) + 1

        # 按严重程度排序（严重的在前面）
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        unique_vulns.sort(
            key=lambda v: severity_order.get(v.severity.value, 5)
        )

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
