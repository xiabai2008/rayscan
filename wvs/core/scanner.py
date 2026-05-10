"""
WVS v19 Main Scanner Engine

Coordinates crawler → detection modules → dedup → reporting.
Completely generic — NO hardcoded lab paths.
Lab-specific logic lives in core/lab_profiles.py.
"""
import asyncio
import gc
import hashlib
import json
import logging
import time
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse, parse_qs

from ..config import ConfigManager
from ..exceptions import ScanError, ModuleError
from ..models import (
    ScanResult,
    ScanTarget,
    Vulnerability,
    VulnerabilityType,
)
from ..plugins.auth import FormLoginAuth, BearerTokenAuth, BasicAuth, APIKeyAuth, CookieAuth
# v19.2: External tool integrations (lazy-loaded in _run_integrations)

from .crawler import WebCrawler, DiscoveredEndpoint
from .session import HTTPPool
from .lab_profiles import detect_lab_profile, get_lab_endpoints
try:
    from .lab_profiles import detect_lab_profile_from_paths
except ImportError:
    detect_lab_profile_from_paths = lambda url, paths: detect_lab_profile(url)

logger = logging.getLogger(__name__)

# Module execution priority: faster + more critical modules first, slower/heavier last
_MODULE_PRIORITY = ["sqli", "xss", "lfi", "cmdi", "rce", "ssrf", "xxe", "api", "sensitive", "waf"]


class WAVScanner:
    """Web Application Vulnerability Scanner — main orchestrator."""

    def __init__(
        self,
        config: Optional[ConfigManager] = None,
        session: Optional[HTTPPool] = None,
    ):
        self.config = config or ConfigManager()
        self.session = session or HTTPPool(self.config)

        crawl_depth = self.config.get("crawl_depth", 2)
        crawl_max = self.config.get("crawl_max_urls", 100)
        self.crawler = WebCrawler(
            max_depth=crawl_depth,
            max_urls_per_run=crawl_max,
            user_agent=self.config.get("user_agent", "WVS/19.0"),
        )

        self._modules: Dict[str, Any] = {}
        self._loaded_module_names: List[str] = []
        self._vuln_seen: Set[str] = set()
        self._global_baseline_cache: Dict[str, Dict[str, Any]] = {}  # 跨模块基线缓存

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

        self._enabled_modules = self._resolve_enabled_modules()

        # v19.2: External tool integration state (lazy-init)
        self._sqlmap = None  # type: ignore[var-annotated]
        self._ffuf = None
        self._wappalyzer = None
        self._integrations_enabled = self.config.get("integrations.enabled", True)

        self._lab_profile = None  # populated during scan() if target matches a lab
        self._max_time: float = 0

        # Checkpoint auto-save for crash/timeout resilience
        self._checkpoint_path: Optional[Path] = None
        self._last_checkpoint_time: float = 0.0
        self._checkpoint_interval: float = 30.0  # save every 30s
        self._modules_done: List[str] = []  # track completed modules for checkpoint

    @staticmethod
    def _ensure_params(ep: DiscoveredEndpoint) -> tuple:
        if ep.parameters:
            return ep.parameters, ep.param_types
        parsed = urlparse(ep.url)
        if parsed.query:
            qs = parse_qs(parsed.query, keep_blank_values=True)
            params = {k: v[0] if len(v) == 1 else v[0] for k, v in qs.items()}
            param_types = {k: "query" for k in params}
            return params, param_types
        return {}, {}

    # ── Module management ───────────────────────────────────────

    def _resolve_enabled_modules(self) -> List[str]:
        all_modules = ("sqli", "cmdi", "xss", "lfi", "rce", "api", "sensitive", "xxe", "ssrf")
        enabled = []
        for name in all_modules:
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
            print(f"[*] Detected lab target ({lp.name}), auto-authenticating...")
            provider = FormLoginAuth(
                login_url=login_url,
                username=lp.login_params.get("username", "admin"),
                password=lp.login_params.get("password", "password"),
                extra_fields={k: v for k, v in lp.login_params.items()
                              if k not in ("username", "password")},
                success_check=lp.login_success_marker,
            )
            result = await provider.authenticate(self.session._get_httpx_client())
            if result.get("authenticated"):
                for name, value in result.get("cookies", {}).items():
                    self.session.set_cookie(base, name, value)
                if lp.default_security_level:
                    self.session.set_cookie(base, "security", lp.default_security_level)
                print(f"[+] {lp.name} auth OK ({len(result.get('cookies', {}))} cookies)")
                return True
            else:
                print(f"[-] {lp.name} login failed: {result.get('error', 'unknown')}")
                # P17: Warn that scan results will be limited without auth
                if self._lab_profile:
                    print(f"[!] Scan results may be incomplete — vulnerabilities may be behind login")
        except Exception as e:
            print(f"[*] {lp.name} auto-auth skipped: {e}")
        return False

    async def _do_authenticate(self, target: ScanTarget) -> Dict[str, Any]:
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
            provider = BearerTokenAuth(token=ac.get("token", ""), header=ac.get("header", "Authorization"))
        elif auth_type == "basic":
            provider = BasicAuth(username=ac.get("username", ""), password=ac.get("password", ""))
        elif auth_type == "apikey":
            provider = APIKeyAuth(key=ac.get("api_key", ""), header=ac.get("header", "X-API-Key"))
        elif auth_type == "cookie":
            provider = CookieAuth(cookies=ac.get("cookies", {}))
        else:
            return {"authenticated": False, "error": f"Unknown auth type: {auth_type}"}

        result = await provider.authenticate(self.session._get_httpx_client())
        if result.get("authenticated"):
            for name, value in result.get("cookies", {}).items():
                self.session.set_cookie(target.url, name, value)
            for hname, hvalue in result.get("headers", {}).items():
                self.session.set_header(hname, hvalue)
        return result

    # ── Module loading ──────────────────────────────────────────

    def load_module(self, module_name: str) -> bool:
        if module_name in self._modules:
            return True
        try:
            mod = __import__(f"wvs.modules.{module_name}.detector", fromlist=["detector"])
            detector_cls = getattr(mod, "Detector", None)
            if detector_cls is None:
                upper = module_name.upper()
                variants = [
                    f"{module_name.title()}Detector",
                    f"{upper}Detector",
                    "SQLiDetector",
                ]
                for variant in variants:
                    detector_cls = getattr(mod, variant, None)
                    if detector_cls:
                        break
                if detector_cls is None:
                    for attr_name in dir(mod):
                        if attr_name.endswith("Detector") and attr_name != "DetectionModule":
                            detector_cls = getattr(mod, attr_name)
                            logger.info(f"[Scanner] auto-discovered: {attr_name}")
                            break
            if detector_cls is None:
                raise ImportError(f"No Detector class in wvs.modules.{module_name}.detector")
            instance = detector_cls(self.config, session=self.session)
            self._modules[module_name] = instance
            self._loaded_module_names.append(module_name)
            logger.info(f"[Scanner] loaded: {module_name}")
            return True
        except ImportError as e:
            logger.warning(f"[Scanner] module {module_name} unavailable: {e}")
            return False
        except Exception as e:
            logger.error(f"[Scanner] module {module_name} load error: {e}")
            return False

    def load_all_modules(self) -> None:
        for name in self._enabled_modules:
            self.load_module(name)

    # ── Concurrent endpoint scanning (P3 upgrade) ──────────────

    async def _run_module_concurrent(
        self,
        module_name: str,
        target: ScanTarget,
        endpoints: List[DiscoveredEndpoint],
        concurrency: int = 5,
        global_sem: asyncio.Semaphore = None,
    ) -> List[Vulnerability]:
        """Run a module against all endpoints concurrently."""
        if module_name not in self._modules:
            return []

        module = self._modules[module_name]
        vulns: List[Vulnerability] = []
        # P19: per-module sem removed — P18 base lock already serializes same-module calls
        lock = asyncio.Lock()

        async def scan_one(ep: DiscoveredEndpoint):
            if not ep.url:
                return
            ep_url = ep.url
            parsed = urlparse(ep_url)
            if not parsed.query and "." not in parsed.path.split("/")[-1] and not parsed.path.endswith("/"):
                ep_url = ep_url.rstrip("/") + "/"

            # Preserve auth data from the original target
            auth_data = getattr(target, 'auth', None) or getattr(target, 'auth_config', None)
            if ep.method.upper() == "POST":
                ep_target = ScanTarget(
                    url=ep_url, methods=[ep.method],
                    cookies=target.cookies, headers=target.headers,
                    auth=auth_data, data=ep.parameters,
                )
            else:
                ep_target = ScanTarget(
                    url=ep_url, methods=[ep.method],
                    cookies=target.cookies, headers=target.headers,
                    auth=auth_data, params=ep.parameters,
                )

            # P19: inter-request delay to prevent overwhelming fragile targets
            _delay = self.config.get("request_delay_ms", 100) / 1000.0
            if _delay > 0:
                await asyncio.sleep(_delay)

            if global_sem:
                async with global_sem:
                    try:
                        found = await module.scan(ep_target)
                    except Exception as e:
                        logger.debug(f"[Scanner] {module_name} error on {ep.url}: {e}")
                        found = []
            else:
                try:
                    found = await module.scan(ep_target)
                except Exception as e:
                    logger.debug(f"[Scanner] {module_name} error on {ep.url}: {e}")
                    found = []
            async with lock:
                for v in found:
                    v.module = v.module or module_name
                    v.parameter = v.parameter or (list(ep.parameters.keys())[0] if ep.parameters else None)
                    if not v.parameter_type:
                        v.parameter_type = ep.param_types.get(v.parameter or "", "query")
                    # Trim large response bodies to prevent OOM
                    if v.http_response and len(v.http_response) > 2000:
                        v.http_response = v.http_response[:2000]
                    vulns.append(v)

        tasks = [scan_one(ep) for ep in endpoints]
        await asyncio.gather(*tasks, return_exceptions=True)
        return vulns

    # ── Dedup (P5 improved: aggressive URL+param normalization to merge dupes) ──

    @staticmethod
    def _normalize_vuln_url(url: str) -> str:
        """Strip query string AND fragment for dedup — /get?name=test#x and /get are the same endpoint."""
        u = url.split("?")[0].split("#")[0].rstrip("/")
        import re
        u = re.sub(r'/\d+$', '/:id', u)
        # Collapse static resource sub-paths — /themes/original/css/foo.css → /themes/*
        u = re.sub(r'/(css|js|img|images|themes|theme|static|assets|fonts|locale|lang)/.+',
                   r'/\1/*', u, flags=re.IGNORECASE)
        # P8: Collapse dynamic path segments — /user/123/profile → /user/:id/profile
        u = re.sub(r'/(\d{2,})/', '/:id/', u)
        # P8: Collapse hash-like segments — /page/a1b2c3 → /page/:hash
        u = re.sub(r'/[/]?[a-f0-9]{16,}', '/:hash', u)
        return u

    def _vuln_signature(self, v: Vulnerability) -> str:
        """Dedup key — normalized URL + type + parameter + evidence group.

        P7 fix: Include type to prevent cross-type merging. Include
        evidence group for info_disclosure/server-header/broken_auth
        dedup where same finding is reported via different parameters.
        When evidence_key is set, ignore parameter (it's irrelevant for
        evidence-based findings like server header disclosure).

        P12 fix: Extend evidence-aware dedup to RCE and 'other' types
        to prevent misclassified RCE findings from flooding.
        """
        norm_url = self._normalize_vuln_url(v.url or "")
        vtype = v.type.value if v.type else "unknown"
        param = v.parameter or ""

        evidence_key = ""
        skip_param = False

        if v.evidence:
            ev = v.evidence[:200]

            if vtype == "information_disclosure":
                if "Path accessible" in ev:
                    evidence_key = "path_accessible"
                    skip_param = True
                elif "Server header:" in ev:
                    evidence_key = "server_header"
                    skip_param = True
                elif "Pattern matched:" in ev:
                    evidence_key = "pattern:" + ev.split("Pattern matched:")[-1][:50]
                    skip_param = True
                elif "Sensitive Path Exposed:" in v.title or "Sensitive file exposed" in ev:
                    evidence_key = "sensitive_path:" + norm_url
                    skip_param = True
                elif "Sensitive Data:" in v.title:
                    evidence_key = "sensitive_data:" + (v.parameter or "")
                    skip_param = True
                else:
                    evidence_key = "info_ev:" + str(hash(ev) % 10000)

            elif vtype == "remote_code_execution" or vtype == "other":
                # RCE findings: token echo or code execution in same endpoint = same vuln
                if "token" in ev.lower() or "echo" in ev.lower() or "execution" in ev.lower():
                    evidence_key = "rce_token_echo:" + norm_url
                    skip_param = True
                elif "Time-based" in ev:
                    evidence_key = "rce_time_based:" + norm_url
                    skip_param = True
                elif "phpinfo" in ev.lower() or "system(" in ev.lower():
                    evidence_key = "rce_behavior:" + norm_url
                    skip_param = True
                else:
                    evidence_key = "rce_ev:" + str(hash(ev) % 10000)

            elif vtype == "broken_authentication":
                evidence_key = "auth_bypass:" + norm_url
                skip_param = True

        if skip_param:
            param = ""

        parts = [norm_url, vtype, param, evidence_key]
        return "|".join(parts).lower()

    def _deduplicate(self, vulns: List[Vulnerability]) -> List[Vulnerability]:
        """去重时保留严重程度最高的漏洞，同级别保留confidence更高的"""
        seen: Dict[str, Vulnerability] = {}
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        conf_order = {"certain": 0, "high": 1, "medium": 2, "low": 3}

        for v in vulns:
            sig = self._vuln_signature(v)
            if sig not in seen:
                seen[sig] = v
            else:
                existing = seen[sig]
                v_sev = severity_order.get(v.severity.value, 5)
                e_sev = severity_order.get(existing.severity.value, 5)
                if v_sev < e_sev:
                    seen[sig] = v
                elif v_sev == e_sev:
                    if conf_order.get(v.confidence.value, 4) < conf_order.get(existing.confidence.value, 4):
                        seen[sig] = v

        return list(seen.values())

    # ── Timeout helpers ────────────────────────────────────────

    def _elapsed(self) -> float:
        return time.time() - self._stats["start_time"]

    def _timeout_remaining(self) -> float:
        if not self._max_time or self._max_time <= 0:
            return float("inf")
        return max(0.0, self._max_time - self._elapsed())

    # ── Checkpoint save/load ─────────────────────────────────────

    def _checkpoint_file(self, target_url: str) -> Path:
        url_hash = hashlib.md5(target_url.encode()).hexdigest()[:12]
        return Path(f".wvs_checkpoint_{url_hash}.json")

    def _save_checkpoint(self, target_url: str, vulns: List[Vulnerability],
                         endpoints: List[DiscoveredEndpoint]) -> None:
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
                s -= 50   # POST endpoints often more interesting
            s -= min(len(ep.parameters or {}), 10)  # more params → higher priority
            if any(k.lower() in ("id", "page", "file", "path", "url", "cmd", "exec", "query", "search")
                   for k in (ep.parameters or {})):
                s -= 30   # interesting param names
            return s
        return sorted(endpoints, key=score)

    # ── Core scan flow ──────────────────────────────────────────

    async def scan(self, target: ScanTarget) -> ScanResult:
        self._stats["start_time"] = time.time()
        self._vuln_seen.clear()
        self._stats["errors"] = 0
        result = ScanResult(target=target)
        self._max_time = self.config.get("max_time", 0)

        if not self._modules:
            self.load_all_modules()
        self._stats["modules_run"] = len(self._modules)
        logger.info(f"[Scanner] modules: {list(self._modules.keys())}")

        self._print_header(target)

        # ── Step 0: WAF detection (run first, broadcast results to all modules) ──
        if self.config.get("enable_waf_detection", True) and "waf" in self._modules:
            try:
                waf_module = self._modules["waf"]
                waf_target = ScanTarget(url=target.url)
                await waf_module.scan(waf_target)
                waf_result = waf_module.get_result() if hasattr(waf_module, "get_result") else None
                if waf_result and waf_result.detected:
                    print(f"\n[!] WAF Detected: {waf_result.vendor} (confidence: {waf_result.confidence:.0%})")
                    for mod in self._modules.values():
                        if hasattr(mod, "set_waf_detected"):
                            mod.set_waf_detected(True)
            except Exception as e:
                logger.debug(f"[Scanner] WAF detection skipped: {e}")

        # ── Inject manual cookies ──
        if target.cookies:
            for name, value in target.cookies.items():
                self.session.set_cookie(target.url, name, value)

        # ── Lab profile detection (replaces hardcoded paths) ──
        self._lab_profile = detect_lab_profile(target.url)
        self._lab_base_url = target.url
        if self._lab_profile and not target.cookies:
            await self._do_lab_auth()

        # ── Crawl ──
        print("\n[*] Phase 1/4: Crawling...")
        try:
            endpoints = await self.crawler.crawl(target.url, self.session)
        except Exception as e:
            logger.error(f"[Scanner] crawl failed: {e}")
            endpoints = []
            self._stats["errors"] += 1

        self._stats["endpoints_discovered"] = len(endpoints)
        crawler_stats = self.crawler.get_stats()
        print(f"\r[*] Crawled {crawler_stats.get('pages_crawled', 0)} pages, "
              f"discovered {len(endpoints)} endpoints, "
              f"found {crawler_stats.get('forms_found', 0)} forms")

        # P8: Prioritize endpoints — scan dynamic/promising endpoints first
        endpoints = self._prioritize_endpoints(endpoints)

        if not endpoints:
            endpoints = [
                DiscoveredEndpoint(url=target.url, method="GET",
                                   source_url=target.url, source_depth=1)
            ]

        # ── Re-detect lab profile from discovered paths (for IP targets) ──
        if not self._lab_profile:
            discovered_paths = [ep.url for ep in endpoints]
            self._lab_profile = detect_lab_profile_from_paths(target.url, discovered_paths)
            if self._lab_profile:
                self._lab_base_url = target.url
                print(f"[*] Detected lab profile from endpoints: {self._lab_profile.name}")
                if not target.cookies:
                    await self._do_lab_auth()

        # ── Append lab endpoints (from profile, not hardcoded) ──
        if self._lab_profile:
            lab_eps = get_lab_endpoints(self._lab_profile, target.url)
            added = 0
            merged = 0
            # P19: normalize URLs before comparing (strip query/fragment —
            # crawler may record ?id=1&Submit=Submit while lab has clean path)
            def _normalize(u: str) -> str:
                return u.split("?")[0].split("#")[0].rstrip("/")
            for lep in lab_eps:
                existing = None
                lep_norm = _normalize(lep.url)
                for e in endpoints:
                    if _normalize(e.url) == lep_norm:
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
            print(f"[*] Lab profile ({self._lab_profile.name}): +{added} endpoints, merged params into {merged}")

        # ── Parameter discovery for endpoints without params ──
        endpoints_without_params = [e for e in endpoints if not e.parameters]
        if endpoints_without_params:
            print(f"[*] Running parameter discovery on {len(endpoints_without_params)} endpoints...")
            enriched = await self.crawler.discover_params_batch(
                endpoints_without_params, self.session
            )
            for i, ep in enumerate(endpoints_without_params):
                if i < len(enriched) and enriched[i].parameters:
                    ep.parameters = enriched[i].parameters
                    ep.param_types = enriched[i].param_types

        # ── v19.2: Phase 1.5 — JS endpoint & secret analysis (JSPathfinder) ──
        if self.config.get("modules.jspathfinder.enabled", True):
            print("\n[*] Phase 1.5/4: JS analysis (JSPathfinder)...")
            try:
                self._jspathfinder_vulns = await self._run_jspathfinder(target)
                print(f"[+] JSPathfinder: {len(self._jspathfinder_vulns)} finds")
            except Exception as e:
                logger.error(f"[Scanner] jspathfinder phase failed: {e}")
                self._jspathfinder_vulns = []
        else:
            self._jspathfinder_vulns = []

        # ── Concurrent detection (P5: global concurrency limiter) ──
        print("\n[*] Phase 2/4: Running detectors (concurrent)...")

        # 注入跨模块基线缓存
        self._global_baseline_cache.clear()
        for mod in self._modules.values():
            if hasattr(mod, "set_global_baseline_cache"):
                mod.set_global_baseline_cache(self._global_baseline_cache)

        # P5: Modules that require parameters to be useful — skip on parameterless endpoints
        PARAM_REQUIRED_MODULES = {"sqli", "xss", "cmdi", "rce", "lfi", "ssrf", "xxe"}
        NO_PARAM_MODULES = {"api", "sensitive", "waf"}

        remaining = self._timeout_remaining()
        if remaining < 60:
            print(f"[!] Only {remaining:.0f}s remaining before timeout — detection may be incomplete")
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
        request_delay_ms = self.config.get("request_delay_ms", 100)
        global_sem = asyncio.Semaphore(max_concurrent_requests)

        # P5: Filter endpoints for param-required modules
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
                print(f"\n[!] Skipping module '{module_name}' — request budget exceeded ({module_reqs})")
                async with lock:
                    completed_tasks += len(endpoints)
                    self._print_progress(completed_tasks, total_tasks, module_name)
                return []

            if self._timeout_remaining() < 30:
                print(f"\n[!] Skipping module '{module_name}' — timeout approaching")
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

            # P11: Stricter per-module endpoint cap + early exit for better performance
            MAX_EP_PER_MODULE = 25  # P14: tighter cap (was 40) — most labs have <10 truly dynamic endpoints
            if module_name in PARAM_REQUIRED_MODULES and len(module_endpoints) > MAX_EP_PER_MODULE:
                # Prioritize and keep the most promising endpoints
                module_endpoints = self._prioritize_endpoints(module_endpoints)[:MAX_EP_PER_MODULE]

            # P11: More aggressive early exit — test first 5 endpoints; 3 consecutive no-finds → skip module
            EARLY_EXIT_SAMPLE = 3  # P14: faster skip (was 5)
            if len(module_endpoints) > EARLY_EXIT_SAMPLE and module_name in PARAM_REQUIRED_MODULES:
                sample_eps = module_endpoints[:EARLY_EXIT_SAMPLE]
                concurrency = self.config.get("concurrent_endpoints", 12)
                sample_vulns = await self._run_module_concurrent(
                    module_name, target, sample_eps, concurrency, global_sem,
                )
                if not sample_vulns:
                    async with lock:
                        completed_tasks += len(endpoints)
                        self._print_progress(completed_tasks, total_tasks, module_name)
                    return []
                # Found something — scan ALL remaining endpoints too
                remaining_eps = module_endpoints[EARLY_EXIT_SAMPLE:]
                rest_vulns = await self._run_module_concurrent(
                    module_name, target, remaining_eps, concurrency, global_sem,
                )
                vulns = sample_vulns + rest_vulns
            else:
                concurrency = self.config.get("concurrent_endpoints", 12)
                vulns = await self._run_module_concurrent(
                    module_name, target, module_endpoints, concurrency, global_sem,
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
            batch = module_names[batch_start:batch_start + 3]
            if self._timeout_remaining() < 30:
                print(f"\n[!] Timeout approaching — skipping remaining modules")
                break
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

        # ── Phase 2b: External tool integrations ──
        if self._integrations_enabled:
            print("\n[*] Phase 2b/4: External integrations...")
            try:
                integration_vulns = await self._run_integrations(target, all_vulns, endpoints)
                all_vulns.extend(integration_vulns)
            except Exception as e:
                logger.error(f"[Scanner] integrations phase failed: {e}")
                self._stats["errors"] += 1

        # ── Merge JSPathfinder findings ──
        if getattr(self, '_jspathfinder_vulns', None):
            all_vulns.extend(self._jspathfinder_vulns)

        # ── Dedup ──
        print("\n[*] Phase 3/4: Deduplication & confidence...")
        unique_vulns = self._deduplicate(all_vulns)
        for v in unique_vulns:
            t = v.type.value
            self._stats["vulns_by_type"][t] = self._stats["vulns_by_type"].get(t, 0) + 1

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        unique_vulns.sort(key=lambda v: severity_order.get(v.severity.value, 5))

        result.vulnerabilities = unique_vulns

        # ── Report ──
        print("\n[*] Phase 4/4: Generating report...")
        self._stats["end_time"] = time.time()
        result.duration = self._stats["end_time"] - self._stats["start_time"]
        result.requests_made = self.session.get_stats()["total_requests"]
        result.endpoints_found = len(endpoints)
        result.modules_run = len(self._modules)

        self._print_summary(result)
        return result

    # ── v19.2: Integration orchestrator ────────────────────────

    async def _run_jspathfinder(
        self,
        target: ScanTarget,
    ) -> List[Vulnerability]:
        """Phase 1.5: Run JSPathfinder — JS secrets + endpoint discovery."""
        try:
            from ..modules.jspathfinder import JSPathfinderDetector
            detector = JSPathfinderDetector(config=self.config, session=self.session)
            return await detector.scan(target)
        except ImportError:
            logger.warning("[Scanner] JSPathfinder module not available")
            return []
        except Exception as e:
            logger.error(f"[Scanner] JSPathfinder error: {e}")
            return []

    async def _run_integrations(
        self,
        target: ScanTarget,
        all_vulns: List[Vulnerability],
        endpoints: List[DiscoveredEndpoint],
    ) -> List[Vulnerability]:
        """Phase 2b: Run all external tool integrations concurrently."""
        integration_vulns: List[Vulnerability] = []
        tasks = []
        base_url = target.url.rstrip("/")

        # ── Wappalyzer fingerprint ──
        if self.config.get("integrations.wappalyzer.enabled", True):
            if self._wappalyzer is None:
                from ..integrations import WappalyzerIntegration
                self._wappalyzer = WappalyzerIntegration(config=self.config)
            tasks.append(("wappalyzer", self._run_wappalyzer_fingerprint(base_url)))

        # ── ffuf directory discovery ──
        if self.config.get("integrations.ffuf.enabled", True):
            if self._ffuf is None:
                from ..integrations import FfufIntegration
                self._ffuf = FfufIntegration(config=self.config)
            if self._ffuf.is_available:
                tasks.append(("ffuf", self._run_ffuf_discovery(base_url)))

        # ── sqlmap (only if SQLi module found hints, or aggressive mode) ──
        sqli_enabled = self.config.get("integrations.sqlmap.enabled", True)
        if sqli_enabled:
            if self._sqlmap is None:
                from ..integrations import SqlmapIntegration
                self._sqlmap = SqlmapIntegration(config=self.config)
            if self._sqlmap.is_available:
                aggressive = self.config.get("integrations.sqlmap.aggressive", False)
                # Check if base modules found low-confidence SQLi hints
                sqli_hints = any(
                    v.type.value == "sql_injection"
                    for v in all_vulns
                )
                if sqli_hints or aggressive:
                    tasks.append(("sqlmap", self._run_sqlmap_scan(base_url, endpoints)))
                else:
                    print("[*] sqlmap: skipping (no SQLi hints, use --aggressive to force)")

        # ── Nuclei ──
        if self.config.get("integrations.nuclei.enabled", True):
            tasks.append(("nuclei", self.scan_with_nuclei(base_url)))

        if not tasks:
            return integration_vulns

        names = [n for n, _ in tasks]
        coros = [c for _, c in tasks]
        print(f"[*] Running: {', '.join(names)}")

        results = await asyncio.gather(*coros, return_exceptions=True)
        for name, result in zip(names, results):
            if isinstance(result, Exception):
                logger.warning(f"[Scanner] {name} integration failed: {result}")
                print(f"[!] {name}: error — {result}")
            elif isinstance(result, list):
                integration_vulns.extend(result)
                print(f"[+] {name}: found {len(result)} issues")
            else:
                print(f"[-] {name}: no results")

        return integration_vulns

    async def _run_wappalyzer_fingerprint(self, url: str) -> List[Vulnerability]:
        """Run Wappalyzer fingerprint, return 0 vulns (tech info stored on integration)."""
        try:
            fp = await self._wappalyzer.fingerprint(url)
            summary = fp.summary()
            print(f"    [Wappalyzer] {summary}")
            # Log recommendations for scan tuning
            recs = self._wappalyzer.get_scan_recommendations(fp)
            if recs.get("focus"):
                print(f"    [Wappalyzer] 建议关注: {', '.join(recs['focus'])}")
            if fp.has_waf:
                print(f"    [Wappalyzer] WAF 检测: {fp.waf_name or 'Yes'}")
                if hasattr(self, "_modules") and "waf" in self._modules:
                    waf_mod = self._modules["waf"]
                    if hasattr(waf_mod, "set_waf_detected"):
                        waf_mod.set_waf_detected(True)
            return []
        except Exception as e:
            print(f"    [Wappalyzer] failed: {e}")
            return []

    async def _run_ffuf_discovery(self, url: str) -> List[Vulnerability]:
        """Run ffuf directory/file discovery."""
        try:
            ffuf_url = url.rstrip("/") + "/FUZZ"
            return await self._ffuf.discover(
                url=ffuf_url,
                match_codes="200,204,301,302,307,401,403",
                rate=30,
            )
        except Exception as e:
            print(f"    [ffuf] failed: {e}")
            return []

    async def _run_sqlmap_scan(
        self,
        url: str,
        endpoints: List[DiscoveredEndpoint],
    ) -> List[Vulnerability]:
        """Run sqlmap on the target base URL."""
        try:
            level = self.config.get("integrations.sqlmap.level", 2)
            risk = self.config.get("integrations.sqlmap.risk", 1)
            # Prioritize parameter-rich endpoints for sqlmap
            param_endpoints = [
                e for e in endpoints
                if e.parameters and any(
                    k.lower() in ("id", "page", "query", "search", "cat", "user", "item")
                    for k in e.parameters
                )
            ]
            if param_endpoints:
                # Use the most promising endpoint
                target_url = param_endpoints[0].url
            else:
                target_url = url

            return await self._sqlmap.scan(
                url=target_url,
                level=level,
                risk=risk,
                techniques="BEUST",
            )
        except Exception as e:
            print(f"    [sqlmap] failed: {e}")
            return []

    # ── Nuclei integration (v19.2: extracted as a method) ──────

    async def scan_with_nuclei(self, url: str) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        import json
        nuclei_paths = [
            r"C:/Tools/nuclei/nuclei.exe",
            "nuclei",
            "/usr/local/bin/nuclei",
            "/usr/bin/nuclei",
        ]
        nuclei_path = None
        for p in nuclei_paths:
            try:
                proc = await asyncio.create_subprocess_exec(
                    p, "-version",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await asyncio.wait_for(proc.communicate(), timeout=5)
                if proc.returncode == 0:
                    nuclei_path = p
                    break
            except Exception:
                continue

        if not nuclei_path:
            print("\n[*] Nuclei CLI not available, skipping")
            return vulns

        print(f"\n[*] Running Nuclei: {url}")
        try:
            import tempfile
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                f.write(url + "\n")
                target_file = f.name

            cmd = [nuclei_path, "-l", target_file, "-json", "-silent",
                   "-no-color", "-rate-limit", "20"]
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            from ..models import Severity, Confidence

            for line in stdout.decode("utf-8", errors="ignore").splitlines():
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    info = data.get("info", {})
                    sev_str = info.get("severity", "medium")
                    sev_map = {"critical": "critical", "high": "high", "medium": "medium",
                               "low": "low", "info": "info"}
                    vuln = Vulnerability(
                        type=VulnerabilityType.API_SECURITY,
                        url=data.get("matched-at", url),
                        title=info.get("name", "Nuclei finding"),
                        severity=Severity(sev_map.get(sev_str, "medium")),
                        confidence=Confidence.HIGH,
                        payload=info.get("name"),
                        description=info.get("description", ""),
                        references=[r.get("URL", "") for r in info.get("references", [])],
                        module="nuclei",
                    )
                    vulns.append(vuln)
                except json.JSONDecodeError:
                    continue
            print(f"    [Nuclei] found {len(vulns)} issues")
        except asyncio.TimeoutError:
            print("    [Nuclei] timeout (120s)")
        except Exception as e:
            print(f"    [Nuclei] error: {e}")
        return vulns

    # ── Helpers ─────────────────────────────────────────────────

    def _print_header(self, target: ScanTarget) -> None:
        sep = "=" * 60
        print(f"\n{sep}")
        print(f"  WVS v19.2 — Web Vulnerability Scanner")
        print(f"  Target : {target.url}")
        profile_tag = f" [{self._lab_profile.name}]" if self._lab_profile else ""
        print(f"  Modules: {', '.join(self._modules.keys()) or 'none'}{profile_tag}")
        print(sep)

    def _print_progress(self, done: int, total: int, phase: str) -> None:
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
        sep = "=" * 60
        print(f"\n{sep}")
        print(f"  Scan complete")
        print(f"  Target   : {result.target.url}")
        print(f"  Duration : {result.duration:.1f}s")
        print(f"  Requests : {result.requests_made}")
        print(f"  Found    : {len(result.vulnerabilities)} vulnerabilities")
        print()

        if result.vulnerabilities:
            print("  Findings:")
            for v in result.vulnerabilities:
                badge = f"[{v.severity.value.upper():<8}]"
                print(f"    {badge} {v.type.value:<25} {v.url}")
        else:
            print("  No vulnerabilities found (target may still be vulnerable)")
        print(sep)

    def get_stats(self) -> Dict[str, Any]:
        return {
            **self._stats,
            "duration": self._stats["end_time"] - self._stats["start_time"]
            if self._stats["end_time"] else 0.0,
        }
