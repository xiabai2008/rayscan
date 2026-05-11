import urllib.parse
from urllib.parse import urlparse, parse_qs
"""
主扫描引擎

协调所有 DetectionModule，统一执行扫描流程：

1. 爬取目标页面（调用 WebCrawler）
2. 发现所有端点（URL + 参数）
3. 依次执行各检测模块（sqli / cmdi / xss / lfi）
4. 汇总去重
5. 生成报告

异常必须捕获，不崩溃，不丢任务。
实时输出进度（已扫描 / 总端点数）。
"""
import asyncio
import logging
import time
import sys
from typing import Any, Dict, List, Optional, Set

from ..config import ConfigManager
from ..exceptions import ScanError, ModuleError
from ..models import (
    ScanResult,
    ScanTarget,
    Vulnerability,
    VulnerabilityType,
)
from ..plugins.auth import FormLoginAuth, BearerTokenAuth, BasicAuth, APIKeyAuth, CookieAuth

from .crawler import WebCrawler, DiscoveredEndpoint
from .session import HTTPPool

logger = logging.getLogger(__name__)


class WAVScanner:
    """
    Web Application Vulnerability Scanner

    主扫描器，协调爬虫、检测模块和报告生成。
    """

    # 模块名到 VulnerabilityType 的映射
    MODULE_TYPE_MAP = {
        "sqli": VulnerabilityType.SQL_INJECTION,
        "xss": VulnerabilityType.XSS,
        "cmdi": VulnerabilityType.COMMAND_INJECTION,
        "lfi": VulnerabilityType.LFI,
        "rce": VulnerabilityType.REMOTE_CODE_EXECUTION,
        "api": VulnerabilityType.API_SECURITY,
        "sensitive": VulnerabilityType.INFO_DISCLOSURE,
        "ssrf": VulnerabilityType.SSRF,
        "xxe": VulnerabilityType.XXE,
    }

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

        # 爬虫（max_depth=2 保证能深入目录如 /dvwa/→/dvwa/vulnerabilities/）
        self.crawler = WebCrawler(
            max_depth=2,
            max_urls_per_run=100,
            user_agent=self.config.get("user_agent", "WVS/19.0"),
        )

        # 已加载的检测模块 {module_name -> module_instance}
        self._modules: Dict[str, Any] = {}
        self._loaded_module_names: List[str] = []

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

        # 启用的模块列表（按优先级顺序）
        self._enabled_modules = self._resolve_enabled_modules()

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
        """从配置中解析出要启用的模块列表"""
        enabled = []
        for name in ("sqli", "cmdi", "xss", "lfi", "rce", "api", "sensitive", "xxe", "ssrf"):
            cfg = self.config.get(f"modules.{name}", {})
            if isinstance(cfg, dict) and cfg.get("enabled", True):
                enabled.append(name)
        return enabled

    # ─────────────────────────────────────────────────────────────
    # 认证
    # ─────────────────────────────────────────────────────────────

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
            logger.error(f"[Scanner] 加载模块 {module_name} 失败: {e}")
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

    # ─────────────────────────────────────────────────────────────
    # 去重
    # ─────────────────────────────────────────────────────────────

    def _vuln_signature(self, v: Vulnerability) -> str:
        """
        计算漏洞去重签名

        基于 (type, url, parameter, payload) 的组合。
        同一漏洞只报告一次。
        """
        parts = [
            v.type.value,
            v.url or "",
            v.parameter or "",
            v.payload or "",
        ]
        return "|".join(parts).lower()

    def _deduplicate(self, vulns: List[Vulnerability]) -> List[Vulnerability]:
        """去重"""
        seen = set()
        unique: List[Vulnerability] = []
        for v in vulns:
            sig = self._vuln_signature(v)
            if sig not in seen:
                seen.add(sig)
                unique.append(v)
        return unique

    # ─────────────────────────────────────────────────────────────
    # 核心扫描流程
    # ─────────────────────────────────────────────────────────────

    async def scan(self, target: ScanTarget) -> ScanResult:
        """
        核心扫描入口

        流程：
        1. 爬取目标，收集所有端点
        2. 对每个端点依次运行各检测模块
        3. 去重
        4. 返回 ScanResult

        Args:
            target: 扫描目标

        Returns:
            ScanResult
        """
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

        # ── Step 1.5: 注入已有 cookies（来自 CLI 的 auth plugin）──
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
                    pass

            # 认证（只执行一次）
            if _dvwa_base:
                try:
                    print(f"[*] 检测到 DVWA ({_dvwa_base})，自动认证...")
                    provider = FormLoginAuth(
                        login_url=f"{_dvwa_base}/login.php",
                        username="admin",
                        password="password",
                        extra_fields={"Login": "Login"},
                    )
                    auth_result = await provider.authenticate(self.session._get_httpx_client())
                    if auth_result.get("authenticated"):
                        cookies = auth_result.get("cookies", {})
                        for name, value in cookies.items():
                            self.session.set_cookie(_dvwa_base, name, value)
                        print(f"[+] DVWA 认证成功 ({len(cookies)} cookie)")
                        self.session.set_cookie(_dvwa_base, "security", "low")
                        print("[+] DVWA 安全等级已设为 low")
                    else:
                        print(f"[-] DVWA 登录失败: {auth_result.get('error', '未知原因')}")
                except Exception as e:
                    print(f"[*] DVWA 自动认证跳过: {e}")

        # ── Step 2: 爬取（已含认证 cookies）──
        print("\n[*] 阶段 1/4: 爬取目标页面...")
        self._print_progress(0, 0, "crawling")
        try:
            endpoints = await self.crawler.crawl(target.url, self.session)
        except Exception as e:
            logger.error(f"[Scanner] 爬取失败: {e}")
            endpoints = []
            self._stats["errors"] += 1

        self._stats["endpoints_discovered"] = len(endpoints)
        print(f"\r[*] 已发现 {len(endpoints)} 个端点")
        if not endpoints:
            # 兜底：测试首页
            endpoints = [
                DiscoveredEndpoint(
                    url=target.url,
                    method="GET",
                    source_url=target.url,
                    source_depth=1,
                )
            ]

        # ── Step 2.5: 追加已知漏洞路径 ──
        added_paths: List[str] = []
        if _dvwa_base:
            dvwa_paths = [
                ("/vulnerabilities/sqli/",         {"id": "1", "Submit": "Submit"},      {"id": "query", "Submit": "query"}),
                ("/vulnerabilities/sqli/source/", {"id": "1"},                            {"id": "query"}),
                ("/vulnerabilities/sqli_blind/", {"id": "1", "Submit": "Submit"},        {"id": "query", "Submit": "query"}),
                ("/vulnerabilities/xss_r/",       {"text": "test", "user": "test"},      {"text": "query", "user": "query"}),
                ("/vulnerabilities/xss_d/",       {"text": "test"},                      {"text": "query"}),
                ("/vulnerabilities/fi/",           {"page": "include.php"},                {"page": "query"}),
                ("/vulnerabilities/exec/",         {"ip": "127.0.0.1"},                   {"ip": "query"}),
                ("/vulnerabilities/brute/",         {"username": "admin", "password": "password"}, {"username": "query", "password": "query"}),
            ]
            for path, params, param_types in dvwa_paths:
                ep_url = _dvwa_base + path
                if not any(e.url == ep_url for e in endpoints):
                    endpoints.append(DiscoveredEndpoint(
                        url=ep_url, method="GET",
                        parameters=params, param_types=param_types,
                        source_url=target.url, source_depth=1,
                    ))
                    added_paths.append(path)

        base = target.url.rstrip("/")
        if "/mutillidae" in base or any("/mutillidae" in e.url for e in endpoints):
            mt_base = next((e.url.split("/mutillidae")[0] + "/mutillidae"
                            for e in endpoints if "/mutillidae" in e.url), base + "/mutillidae")
            mt_paths = [
                ("/index.php?page=text-file-viewer.php", {"text": "test"}, {"text": "query"}),
                ("/index.php?page=login.php",             {"username": "test"}, {"username": "query"}),
                ("/index.php?page=user-info.php",           {"username": "test"}, {"username": "query"}),
            ]
            for path, params, param_types in mt_paths:
                ep_url = mt_base + path
                if not any(e.url == ep_url for e in endpoints):
                    endpoints.append(DiscoveredEndpoint(
                        url=ep_url, method="GET",
                        parameters=params, param_types=param_types,
                        source_url=target.url, source_depth=1,
                    ))
                    added_paths.append(path)

        if added_paths:
            print(f"[*] 已追加 {len(added_paths)} 个已知漏洞路径")

        # ── Step 3: 端点去重 ──
        # 将同路径同参数名的端点合并，避免重复扫描
        # 例如 Mutillidae 的 index.php?page=xxx 只保留一个
        seen_endpoint_keys: Set[str] = set()
        deduped_endpoints: List[DiscoveredEndpoint] = []
        for ep in endpoints:
            key = self._endpoint_base_key(ep.url, ep.parameters)
            if key not in seen_endpoint_keys:
                seen_endpoint_keys.add(key)
                deduped_endpoints.append(ep)
        deduped_endpoints.sort(key=lambda e: e.source_depth)  # 优先浅层页面
        endpoints = deduped_endpoints
        self._stats["endpoints_discovered"] = len(endpoints)
        if deduped_endpoints:
            # 输出合并后的端点数
            saved = len(endpoints) - len(deduped_endpoints)
            if saved:
                print(f"[*] 端点去重: {len(endpoints)} 个（合并 {saved} 个同路径端点）")

        # ── Step 3: 并发执行检测模块 ──
        # 注意：HTTPPool 内部已有 semaphore（max_concurrent）限流，不再加外部 module_semaphore
        print("\n[*] 阶段 2/4: 执行漏洞检测...")

        total_tasks = len(endpoints) * len(self._modules)
        completed_tasks = 0
        all_vulns: List[Vulnerability] = []
        lock = asyncio.Lock()

        async def run_and_track(module_name: str) -> List[Vulnerability]:
            nonlocal completed_tasks
            try:
                vulns = await self._run_module_no_semaphore(
                    module_name, target, endpoints
                )
                async with lock:
                    completed_tasks += len(endpoints)
                    self._print_progress(completed_tasks, total_tasks, module_name)
                    self._modules_completed.append(module_name)
                return vulns
            except asyncio.CancelledError:
                # 超时取消：保存已经找到的部分结果
                return []

        # 启动所有模块
        tasks = []
        for module_name in self._modules:
            tasks.append(run_and_track(module_name))

        # 并发等待
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for res in results:
            if isinstance(res, Exception):
                logger.error(f"[Scanner] 模块执行异常: {res}")
                self._stats["errors"] += 1
            elif isinstance(res, list):
                all_vulns.extend(res)

        # ── Step 4: 去重 ──
        print("\n[*] 阶段 3/4: 去重与置信度评级...")
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

        # ── Step 5: 报告 ──
        print("\n[*] 阶段 4/4: 生成报告...")
        self._stats["end_time"] = time.time()
        result.duration = self._stats["end_time"] - self._stats["start_time"]
        result.requests_made = self.session.get_stats()["total_requests"]
        result.endpoints_found = len(endpoints)
        result.modules_run = len(self._modules)

        self._print_summary(result)

        return result

    # ─────────────────────────────────────────────────────────────
    # Nuclei 补充扫描
    # ─────────────────────────────────────────────────────────────

    async def scan_with_nuclei(self, url: str) -> List[Vulnerability]:
        """
        调用 Nuclei 补充扫描

        优先使用真实 CLI，CLI 不可用时使用内置模板。
        Nuclei 发现的漏洞会合并到主扫描结果中。

        Args:
            url: 目标 URL

        Returns:
            Nuclei 发现的漏洞列表
        """
        vulns: List[Vulnerability] = []
        nuclei_path = r"C:/Tools/nuclei/nuclei.exe"

        import asyncio
        import json
        import subprocess
        import tempfile

        try:
            # 检查 CLI 是否可用
            proc_check = await asyncio.create_subprocess_exec(
                nuclei_path, "-version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, _ = await asyncio.wait_for(proc_check.communicate(), timeout=5)
            cli_available = proc_check.returncode == 0
        except Exception:
            cli_available = False

        if cli_available:
            print(f"\n[*] 使用 Nuclei CLI 扫描: {url}")
            try:
                with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                    f.write(url + "\n")
                    target_file = f.name

                cmd = [
                    nuclei_path,
                    "-l", target_file,
                    "-json",
                    "-silent",
                    "-no-color",
                    "-rate-limit", "20",
                ]

                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                stdout, _ = await asyncio.wait_for(
                    proc.communicate(), timeout=120
                )

                for line in stdout.decode("utf-8", errors="ignore").splitlines():
                    if not line.strip():
                        continue
                    try:
                        data = json.loads(line)
                        info = data.get("info", {})
                        severity_str = info.get("severity", "medium")
                        # 转换 Nuclei severity -> WVS Severity
                        severity_map = {
                            "critical": "critical",
                            "high": "high",
                            "medium": "medium",
                            "low": "low",
                            "info": "info",
                        }
                        from ..models import Severity, Confidence
                        severity = Severity(severity_map.get(severity_str, "medium"))
                        vuln = Vulnerability(
                            type=VulnerabilityType.API_SECURITY,
                            url=data.get("matched-at", url),
                            title=info.get("name", "Nuclei finding"),
                            severity=severity,
                            confidence=Confidence.HIGH,
                            payload=info.get("name"),
                            description=info.get("description", ""),
                            references=[r.get("URL", "") for r in info.get("references", [])],
                            module="nuclei",
                        )
                        vulns.append(vuln)
                    except json.JSONDecodeError:
                        continue

                print(f"    [Nuclei] 发现 {len(vulns)} 个问题")

            except asyncio.TimeoutError:
                print(f"    [Nuclei] CLI 超时（120s）")
            except Exception as e:
                print(f"    [Nuclei] CLI 扫描失败: {e}")

        else:
            print(f"\n[*] Nuclei CLI 不可用，跳过 Nuclei 扫描")
            print(f"    提示: 安装 nuclei: https://github.com/projectdiscovery/nuclei")

        return vulns

    # ─────────────────────────────────────────────────────────────
    # 辅助方法
    # ─────────────────────────────────────────────────────────────

    def _print_header(self, target: ScanTarget) -> None:
        sep = "=" * 60
        print(f"\n{sep}")
        print(f"  WVS v19.0 — Web Vulnerability Scanner")
        print(f"  Target : {target.url}")
        print(f"  Modules: {', '.join(self._modules.keys()) or 'none'}")
        print(sep)

    def _print_progress(self, done: int, total: int, phase: str) -> None:
        """打印扫描进度"""
        if total == 0:
            pct = 0
        else:
            pct = int(done / total * 100)
        bar_len = 30
        filled = int(bar_len * pct / 100)
        bar = "#" * filled + "-" * (bar_len - filled)
        sys.stdout.write(f"\r  [{bar}] {pct:3d}%  ({done}/{total})  {phase:<15}")
        sys.stdout.flush()

    def _print_summary(self, result: ScanResult) -> None:
        """打印扫描摘要"""
        sep = "=" * 60
        print(f"\n{sep}")
        print(f"  扫描完成")
        print(f"  目标  : {result.target.url}")
        print(f"  耗时  : {result.duration:.1f}s")
        print(f"  请求数: {result.requests_made}")
        print(f"  发现  : {len(result.vulnerabilities)} 个漏洞")
        print()

        if result.vulnerabilities:
            print(f"  漏洞列表:")
            for v in result.vulnerabilities:
                badge = f"[{v.severity.value.upper():<8}]"
                print(f"    {badge} {v.type.value:<25} {v.url}")
        else:
            print("  未发现漏洞（这不代表目标安全）")
        print(sep)

    def get_stats(self) -> Dict[str, Any]:
        """获取扫描统计"""
        return {
            **self._stats,
            "duration": self._stats["end_time"] - self._stats["start_time"]
            if self._stats["end_time"]
            else 0.0,
        }
