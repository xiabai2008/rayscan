"""
JSPathfinder 检测模块
JS文件路径发现、敏感信息分析、端点提取、漏洞线索检测

集成自 jspathfinder.py v1.0
在爬虫之后运行，分析所有JS资源
"""
import asyncio
import concurrent.futures
import logging
import os
import re
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from ..base import DetectionModule, ModuleInfo
from ..base import register_module
from ...models import Vulnerability, VulnerabilityType, Severity, Confidence, ScanTarget

logger = logging.getLogger("wvs.module.jspathfinder")

# ── 第三方依赖检查 ──
HAS_REQUESTS = False
try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    pass

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

HAS_PLAYWRIGHT = False
try:
    from playwright.sync_api import sync_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    pass

# ── 规则定义 ──

SECRET_PATTERNS = {
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "GitHub Token": r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}",
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws.{0,20}(?:secret|pwd|password).{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "Slack Token": r"xox[baprs]-[0-9A-Za-z\-]{10,}",
    "Stripe Key": r"(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}",
    "Heroku API Key": r"(?i)heroku.{0,20}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "Mailgun Key": r"key-[0-9a-zA-Z]{32}",
    "Twilio Key": r"SK[0-9a-fA-F]{32}",
    "JWT Token": r"eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+",
    "Private Key (RSA)": r"-----BEGIN\s(?:RSA\s)?PRIVATE\sKEY-----",
    "Private Key (OpenSSH)": r"-----BEGIN\sOPENSSH\sPRIVATE\sKEY-----",
    "Private Key (EC)": r"-----BEGIN\sEC\sPRIVATE\sKEY-----",
    "Database Connection": r"(?i)(?:jdbc|mongodb|mysql|postgres|redis|sqlite)://[^\s'\"<>]+",
    "FTP Credentials": r"(?i)ftp://[^:@]+:[^@]+@[^\s'\"<>]+",
    "Generic Password": r"(?i)(?:passwo?r?d|passwd|pwd|secret)\s*[:=]\s*['\"][^'\"]{3,}['\"]",
    "Email Address": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "Internal IP": r"\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b",
    "China ID Card": r"[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]",
    "S3 Bucket URL": r"https?://[a-z0-9.\-]+\.s3[.\-][a-z0-9\-]+\.amazonaws\.com/[^\s'\"<>]+",
    "Azure Storage": r"https?://[a-z0-9]+\.(?:blob|table|queue|file)\.core\.windows\.net/[^\s'\"<>]+",
    "CORS Misconfig": r"Access-Control-Allow-Origin\s*:\s*\*",
    "Hardcoded URL": r"(?i)(?:url|href|src|link|path|endpoint|base_url|api_url|host)\s*[:=]\s*['\"](https?://[^'\"]+)['\"]",
}

ENDPOINT_PATTERNS = [
    r"""['"`](/[a-zA-Z][a-zA-Z0-9_/\.\-{}\[\]?=&%:@+#]*\.[a-z]{2,6})['"`]""",
    r"""['"`](/api/[a-zA-Z][a-zA-Z0-9_/\.\-{}?=&%:\+@#]*)['"`]""",
    r"""['"`](/v\d+/[a-zA-Z][a-zA-Z0-9_/\.\-{}?=&%:\+@#]*)['"`]""",
    r"""['"`](/[a-z]+/[a-z]+/[a-zA-Z0-9_/\.\-{}?=&%:\+@#]*)['"`]""",
    r"""['"`](https?://[^\s'"`<>]+)['"`]""",
    r"""['"`](/graphql[\w\-\/]*)['"`]""",
    r"""['"`](/[a-z\-]*(?:swagger|openapi|api-doc|redoc)[a-z\-/0-9.]*)['"`]""",
    r"""['"`](wss?://[^\s'"`<>]+)['"`]""",
    r"""['"`]/(?:admin|dashboard|console|debug|manage|config|setup|install)(?:/[a-zA-Z0-9_\-\.]*)['"`]""",
]

VULN_KEYWORDS = {
    "SQLi": [r"(?i)select\s+.*\s+from\s+", r"(?i)union\s+.*\s+select\s+",
              r"(?i)insert\s+into\s+", r"(?i)update\s+.*\s+set\s+",
              r"(?i)delete\s+from\s+", r"(?i)drop\s+table\s+"],
    "XSS": [r"(?i)(?:innerHTML|outerHTML|document\.write|eval\s*\(|setTimeout\s*\(|setInterval\s*\()",
            r"(?i)location\s*=|location\.hash|document\.domain"],
    "SSRF": [r"(?i)(?:curl_exec|file_get_contents|readfile|fopen|fsockopen).*\$_(?:GET|POST|REQUEST)"],
    "LFI/RFI": [r"(?i)(?:include|require)(?:_once)?\s*\$_(?:GET|POST|REQUEST)"],
    "RCE": [r"(?i)(?:exec|system|passthru|shell_exec|popen|proc_open|eval)\s*\("],
    "Source Map": [r"""['"]((?:https?:)?//[^'"<>]*\.js\.map)['"]"""],
    "Debug Mode": [r"(?i)(?:debug\s*[:=]\s*true|DEBUG\s*=\s*True|APP_DEBUG|development.*mode)"],
}

KNOWN_LIB_PATTERNS = [
    '/jquery', '/vue.', '/vue-', '/vue/', '/semantic', '/fomantic',
    '/bootstrap', '/react.', '/react-', '/angular', '/lodash',
    '/moment', '/clipboard', '/emojify', '/polyfill',
]

SENSITIVE_PATHS = [
    ".git/config", ".env", ".env.example", ".env.local", ".DS_Store",
    "robots.txt", "sitemap.xml", "crossdomain.xml",
    "phpinfo.php", "info.php", "test.php",
    "admin/", "api/", "backup/", "config/", "logs/",
    "wp-admin/", "wp-content/", "wp-includes/",
    ".svn/entries", ".hg/", "WEB-INF/web.xml",
]


@register_module
class JSPathfinderDetector(DetectionModule):
    """JS路径发现 & 敏感信息分析模块"""

    # 类级别缓存：每个 target 只跑一次
    _target_cache: Dict[str, bool] = {}

    @classmethod
    def get_info(cls) -> ModuleInfo:
        return ModuleInfo(
            name="jspathfinder",
            description="JS文件路径发现 & 敏感信息分析（API密钥/Token/密码/端点）",
            author="WVS Team",
            version="1.0.0",
            enabled_by_default=True,
            tags=["discovery", "js", "secrets", "endpoints", "fuzz"],
        )

    def __init__(self, config=None, session=None):
        super().__init__(config, session)
        self._seen_js: Set[str] = set()
        self._seen_endpoints: Set[str] = set()
        self._found_vulns: List[Vulnerability] = []
        self._thread_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=getattr(self.module_config, 'threads', 10)
        )
        self._timeout = self.module_config.timeout
        self._use_playwright = (
            self.module_config.custom_params.get('use_playwright', False) and
            HAS_PLAYWRIGHT and
            self._check_playwright_available()
        )

    def _check_playwright_available(self) -> bool:
        """检测 Playwright 浏览器是否可用"""
        if not HAS_PLAYWRIGHT:
            return False
        try:
            p = sync_playwright().start()
            for ch in ['chrome', 'msedge', None]:
                try:
                    kw = {'channel': ch} if ch else {}
                    b = p.chromium.launch(headless=True, **kw)
                    b.close()
                    p.stop()
                    return True
                except Exception:
                    continue
            p.stop()
        except Exception:
            pass
        return False

    def _normalize_url(self, url: str) -> str:
        parsed = urlparse(url)
        path = parsed.path.rstrip("/")
        qs = "&".join(sorted(parsed.query.split("&"))) if parsed.query else ""
        return f"{parsed.scheme}://{parsed.netloc}{path}?{qs}"

    def _is_known_library(self, source: str) -> bool:
        return any(lib in source.lower() for lib in KNOWN_LIB_PATTERNS)

    def _get_target_key(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    # ── HTTP ──
    def _http_get(self, url: str, allow_redirects: bool = True) -> Optional[Any]:
        """同步 HTTP GET (在线程池中运行)"""
        try:
            resp = _requests.get(
                url, timeout=self._timeout, allow_redirects=allow_redirects,
                verify=False,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
                    "Accept": "*/*",
                }
            )
            return resp
        except Exception:
            return None

    # ── JS 提取 ──
    def _extract_js_sources(self, url: str) -> List[Dict]:
        """从HTML页面提取所有JS文件引用"""
        js_list = []
        resp = self._http_get(url)
        if not resp or resp.status_code != 200:
            return js_list

        html = resp.text
        if not HAS_BS4:
            # fallback: regex extraction
            for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
                src = m.group(1).strip()
                if src:
                    full_url = urljoin(url, src)
                    if full_url not in self._seen_js:
                        self._seen_js.add(full_url)
                        js_list.append({"url": full_url, "source": "external", "content": ""})
            # inline scripts
            for i, m in enumerate(re.finditer(r'<script[^>]*>([\s\S]*?)</script>', html, re.IGNORECASE)):
                content = m.group(1).strip()
                if len(content) > 20:
                    inline_url = f"{url}#inline-{i}"
                    if inline_url not in self._seen_js:
                        self._seen_js.add(inline_url)
                        js_list.append({"url": inline_url, "source": "inline", "content": content})
            return js_list

        soup = BeautifulSoup(html, 'html.parser')

        for tag in soup.find_all("script", src=True):
            src = tag["src"].strip()
            if src:
                full_url = urljoin(url, src)
                if full_url not in self._seen_js:
                    self._seen_js.add(full_url)
                    js_list.append({"url": full_url, "source": "external", "content": ""})

        for i, tag in enumerate(soup.find_all("script")):
            if not tag.get("src") and tag.string:
                content = tag.string.strip()
                if len(content) > 20:
                    inline_url = f"{url}#inline-{i}"
                    if inline_url not in self._seen_js:
                        self._seen_js.add(inline_url)
                        js_list.append({"url": inline_url, "source": "inline", "content": content})

        for tag in soup.find_all():
            for attr in tag.attrs:
                if attr.startswith("on") and isinstance(tag[attr], str):
                    content = tag[attr].strip()
                    if len(content) > 10:
                        ev_url = f"{url}#event-{attr}"
                        if ev_url not in self._seen_js:
                            self._seen_js.add(ev_url)
                            js_list.append({"url": ev_url, "source": "event", "content": content})

        for m in re.finditer(r'sourceMappingURL=([^\s\n]+)', html):
            map_url = urljoin(url, m.group(1))
            if map_url not in self._seen_js:
                self._seen_js.add(map_url)
                js_list.append({"url": map_url, "source": "sourcemap", "content": ""})

        return js_list

    # ── 内容下载 ──
    def _download_js(self, js_entry: Dict) -> str:
        if js_entry.get("content"):
            return js_entry["content"]
        if js_entry["url"].startswith("http"):
            resp = self._http_get(js_entry["url"])
            if resp and resp.status_code == 200:
                js_entry["content"] = resp.text
                return resp.text
        return ""

    # ── 敏感信息扫描 ──
    def _scan_secrets(self, content: str, source: str) -> List[Dict]:
        found = []
        for secret_type, pattern in SECRET_PATTERNS.items():
            for m in re.finditer(pattern, content, re.MULTILINE):
                value = m.group(0) if m.lastindex is None else m.group(1)
                if not value:
                    value = m.group(0)
                start = max(0, m.start() - 50)
                end = min(len(content), m.end() + 50)
                context = content[start:end].replace('\n', ' ')[:120]
                found.append({
                    "type": secret_type, "value": value[:200],
                    "source": source, "context": context
                })
        return found

    # ── 端点提取 ──
    def _extract_endpoints(self, content: str, source: str) -> List[Dict]:
        endpoints = []
        for pattern in ENDPOINT_PATTERNS:
            for m in re.finditer(pattern, content, re.MULTILINE):
                url_str = m.group(1) if m.lastindex else m.group(0)
                url_str = url_str.strip("'\"`")

                skip_exts = ('.png', '.jpg', '.svg', '.woff', '.ttf',
                            '.css', '.ico', '.webp', '.gif', '.eot')
                if any(skip in url_str.lower() for skip in skip_exts):
                    continue

                if url_str.startswith("http"):
                    full_url = url_str
                else:
                    base = source if source.startswith('http') else ""
                    full_url = urljoin(base or self._current_target, url_str)

                normalized = self._normalize_url(full_url)
                if normalized in self._seen_endpoints:
                    continue
                self._seen_endpoints.add(normalized)

                if '/api/' in url_str:
                    ep_type = "api"
                elif any(url_str.endswith(ext) for ext in ['.js', '.json', '.xml', '.html']):
                    ep_type = "static"
                elif url_str.startswith("ws"):
                    ep_type = "websocket"
                else:
                    ep_type = "path"

                endpoints.append({"url": full_url, "type": ep_type, "source": source})
        return endpoints

    # ── 漏洞关键字 ──
    def _scan_vuln_keywords(self, content: str, source: str) -> List[Dict]:
        hints = []
        for vuln_type, patterns in VULN_KEYWORDS.items():
            for pattern in patterns:
                for m in re.finditer(pattern, content):
                    start = max(0, m.start() - 30)
                    end = min(len(content), m.end() + 30)
                    ctx = content[start:end].replace('\n', ' ').strip()
                    hints.append({"type": vuln_type, "context": ctx, "source": source})
        return hints

    # ── 路径 FUZZ ──
    def _fuzz_paths(self, target_base: str, endpoints: List[Dict]) -> List[Dict]:
        """基于发现的端点进行路径探测"""
        results = []
        path_prefixes = {"/"}

        for ep in endpoints:
            try:
                parsed = urlparse(ep["url"])
                parts = parsed.path.strip("/").split("/")
                for i in range(1, len(parts)):
                    path_prefixes.add("/" + "/".join(parts[:i]))
                if parts and parts[0]:
                    path_prefixes.add("/" + parts[0])
            except Exception:
                pass

        targets_to_fuzz = set()
        for prefix in path_prefixes:
            for sp in SENSITIVE_PATHS:
                targets_to_fuzz.add(f"{prefix}/{sp}".replace("//", "/"))

        def fuzz_one(path: str):
            url = f"{target_base}{path}"
            try:
                resp = _requests.get(url, timeout=self._timeout, allow_redirects=False, verify=False,
                    headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code not in [404, 500, 503] and len(resp.text or "") > 0:
                    title = ""
                    tm = re.search(r'<title[^>]*>(.*?)</title>', resp.text or "", re.IGNORECASE | re.DOTALL)
                    if tm:
                        title = tm.group(1).strip()[:80]
                    return {"url": url, "status": resp.status_code,
                            "size": len(resp.text or ""), "title": title, "path": path}
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            futures = list(ex.map(fuzz_one, targets_to_fuzz))

        for f in futures:
            if f:
                results.append(f)
        results.sort(key=lambda x: x.get("status", 0))
        return results

    # ── 主扫描逻辑 ──
    async def _scan_impl(self, target: ScanTarget) -> List[Vulnerability]:
        target_key = self._get_target_key(target.url)

        # 同一个 base URL 只跑一次
        if target_key in self._target_cache:
            return []
        self._target_cache[target_key] = True
        self._current_target = target_key

        vulns: List[Vulnerability] = []
        logger.info(f"[JSPathfinder] 开始分析: {target_key}")

        loop = asyncio.get_event_loop()

        # Phase 1: 提取 JS 文件
        js_list = await loop.run_in_executor(
            self._thread_pool, self._extract_js_sources, target.url
        )
        external_js = [j for j in js_list if j["source"] == "external"]
        inline_js = [j for j in js_list if j["source"] in ("inline", "event")]
        logger.info(f"[JSPathfinder] 发现 {len(external_js)} 个外部JS, {len(inline_js)} 个内联JS")

        # Phase 2: 下载 + 分析每个 JS
        all_secrets: List[Dict] = []
        all_endpoints: List[Dict] = []
        all_hints: List[Dict] = []

        def analyze_one(js_entry: Dict):
            content = self._download_js(js_entry)
            if not content:
                return [], [], []

            sec = self._scan_secrets(content, js_entry["url"])
            eps = self._extract_endpoints(content, js_entry["url"])

            hnt = []
            if not self._is_known_library(js_entry["url"]):
                hnt = self._scan_vuln_keywords(content, js_entry["url"])

            return sec, eps, hnt

        # 分批在线程池运行
        futures = [
            loop.run_in_executor(self._thread_pool, analyze_one, j)
            for j in js_list
        ]
        results = await asyncio.gather(*futures)

        seen_secrets = set()
        for sec_out, eps_out, hnt_out in results:
            all_endpoints.extend(eps_out)
            all_hints.extend(hnt_out)
            for s in sec_out:
                key = (s["type"], s["value"])
                if key not in seen_secrets:
                    seen_secrets.add(key)
                    all_secrets.append(s)

        # Phase 3: 路径 FUZZ
        fuzzy = []
        if self.module_config.custom_params.get('fuzz', True):
            fuzzy = await loop.run_in_executor(
                self._thread_pool, self._fuzz_paths, target_key, all_endpoints
            )

        # ── 组装 Vulnerability ──
        # 1. 敏感信息 → Vulnerability
        for s in all_secrets:
            v = Vulnerability(
                type=VulnerabilityType.INFO_DISCLOSURE,
                title=f"JS敏感信息: {s['type']}",
                url=target_key,
                description=f"在 {s['source']} 中发现 {s['type']}: {s['value'][:100]}",
                evidence=s["context"][:200] if s.get("context") else "",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                module="jspathfinder",
                tags=["js", "secret", s["type"].lower().replace(" ", "-")],
                context={"source": s["source"], "secret_type": s["type"]},
                recommendation=f"移除或轮换 {s['type']}，不应在客户端代码中暴露敏感凭据",
            )
            vulns.append(v)

        # 2. 漏洞线索 → Vulnerability (INFO 级别)
        hint_types: Dict[str, List[Dict]] = {}
        for h in all_hints:
            ht = h["type"]
            if ht not in hint_types:
                hint_types[ht] = []
            hint_types[ht].append(h)

        for hint_type, items in hint_types.items():
            if len(items) > 0:
                sample_contexts = [it["context"][:100] for it in items[:3]]
                sources = list(set(it["source"] for it in items[:5]))
                v = Vulnerability(
                    type=VulnerabilityType.OTHER,
                    title=f"JS漏洞线索: {hint_type} ({len(items)}处)",
                    url=target_key,
                    description=f"在 {sources[0] if sources else 'unknown'} 等文件中发现 {hint_type} 相关代码模式",
                    evidence="\n".join(sample_contexts)[:300],
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    module="jspathfinder",
                    tags=["js", "hint", hint_type.lower().replace("/", "-")],
                    context={"hint_type": hint_type, "count": len(items), "sources": sources[:5]},
                )
                vulns.append(v)

        # 3. FUZZ 发现的路径 → Vulnerability
        for fr in fuzzy:
            if fr["status"] in [200, 301, 302, 403]:
                sev = Severity.INFO
                if any(p in fr["path"].lower() for p in [".env", ".git", ".svn", "backup", "config", "debug"]):
                    sev = Severity.HIGH
                elif any(p in fr["path"].lower() for p in ["phpinfo", "admin", "log", "wp-"]):
                    sev = Severity.MEDIUM

                v = Vulnerability(
                    type=VulnerabilityType.INSECURE_CONFIG,
                    title=f"敏感路径暴露: {fr['path']}",
                    url=fr["url"],
                    description=(f"路径 {fr['path']} 返回 HTTP {fr['status']}, "
                                + (f"大小 {fr['size']}B, 标题: {fr['title']}" if fr.get('title') else f"大小 {fr['size']}B")),
                    severity=sev,
                    confidence=Confidence.HIGH,
                    module="jspathfinder",
                    tags=["fuzz", "path-discovery"] + (
                        ["sensitive"] if sev != Severity.INFO else []
                    ),
                    context={"status": fr["status"], "size": fr["size"]},
                )
                vulns.append(v)

        logger.info(f"[JSPathfinder] 完成: {len(all_secrets)} 敏感信息, "
                    f"{len(all_endpoints)} 端点, {len(all_hints)} 漏洞线索, "
                    f"{len(fuzzy)} 路径发现, 总计 {len(vulns)} 个漏洞")
        return vulns
