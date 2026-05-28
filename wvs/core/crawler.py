"""
RayScan web crawler — recursive endpoint discovery.

- Deep crawling with configurable depth and URL budget
- Static HTML parsing via BeautifulSoup
- Optional JS rendering (Playwright)
- Parameter discovery: HTML forms, JS, common parameter names
- API endpoint discovery: Swagger/OpenAPI, GraphQL, JSON endpoints
- Sitemap / robots.txt parsing
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from bs4 import BeautifulSoup

from .crawler_parsers import CrawlerParsersMixin, _JS_URL_RE
from .session import HTTPPool

logger = logging.getLogger(__name__)


@dataclass
class FormField:
    name: str
    field_type: str
    default_value: Optional[str] = None
    options: List[str] = field(default_factory=list)


@dataclass
class DiscoveredEndpoint:
    url: str
    method: str = "GET"
    parameters: Dict[str, str] = field(default_factory=dict)
    param_types: Dict[str, str] = field(default_factory=dict)
    forms: List[FormField] = field(default_factory=list)
    source_url: Optional[str] = None
    source_depth: int = 0
    is_api: bool = False

    def param_signature(self) -> str:
        query_parts = []
        for k, v in sorted(self.parameters.items()):
            ptype = self.param_types.get(k, "query")
            if ptype == "query":
                query_parts.append(f"{k}={v}")
        sig = self.url.split("?")[0]
        if query_parts:
            sig += "?" + "&".join(query_parts)
        return sig

    def __hash__(self) -> int:
        return hash((self.url, self.method, self.param_signature()))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DiscoveredEndpoint):
            return False
        return self.url == other.url and self.method == other.method and self.param_signature() == other.param_signature()


# ── Constants ──────────────────────────────────────────────────

SKIP_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".bmp",
    ".ico",
    ".svg",
    ".webp",
    ".css",
    ".js",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp3",
    ".mp4",
    ".avi",
    ".webm",
    ".mov",
    ".zip",
    ".tar",
    ".gz",
    ".bz2",
    ".rar",
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
}

# Extensions that should NOT get parameter injection (static files)
STATIC_NO_PARAM_EXTENSIONS = {
    ".htm",
    ".html",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".svg",
    ".webp",
    ".css",
    ".js",
    ".ico",
    ".pdf",
    ".zip",
    ".txt",
}

CRAWLABLE_EXTENSIONS = {".html", ".htm", ".jsp", ".asp", ".aspx", ".php", ".do", ".action", ""}

# Natural delay range (seconds between requests) — randomized to avoid rate-limit patterns
CRAWL_DELAY_RANGE = (0.3, 1.5)

# Query parameter names that indicate page identity (preserved in URL keys)
PAGE_IDENT_PARAMS = {"page", "p", "action", "view", "id", "cat", "category", "product", "mode", "type", "Submit", "submit"}

# Common parameter names for discovery on parameterless endpoints
COMMON_PARAM_NAMES = [
    # SQLi targets
    "id",
    "uid",
    "pid",
    "page",
    "cat",
    "category",
    "product",
    "item",
    "news",
    "article",
    "user",
    "username",
    "user_id",
    "email",
    "account",
    # XSS targets
    "q",
    "query",
    "search",
    "keyword",
    "text",
    "message",
    "comment",
    "name",
    "title",
    "description",
    "content",
    "data",
    "value",
    "input",
    # CMDi / RCE targets
    "ip",
    "host",
    "domain",
    "target",
    "url",
    "cmd",
    "command",
    "exec",
    "ping",
    "file",
    "path",
    "dir",
    "folder",
    "filename",
    # LFI targets
    "page",
    "file",
    "include",
    "template",
    "view",
    "load",
    "open",
    "read",
    "lang",
    "language",
    "locale",
    # SSRF targets
    "url",
    "uri",
    "link",
    "src",
    "source",
    "redirect",
    "callback",
    "next",
    "return",
    "proxy",
    "fetch",
    # General
    "action",
    "type",
    "mode",
    "format",
    "debug",
    "test",
    "admin",
    # P5: DVWA / lab-specific parameter names that trigger vulnerable pages
    "Submit",
    "submit",
    "Login",
    "login",
    "btnSubmit",
    "btn_login",
    # P7: Metasploitable2 / DVWA / Mutillidae specific params
    "name",  # DVWA XSS reflected
    "mnt",
    "username",
    "password",  # Mutillidae
    "rt",
    "author",
    "mail",
    "url",
    "homepage",
    "content",  # comment forms
    "txtName",
    "mtxMessage",  # DVWA XSS stored
    "blog_entry",
    "comment_body",
    "guest_name",
]


# API path indicators for discovery
API_PATH_PATTERNS = [
    "/api/",
    "/v1/",
    "/v2/",
    "/v3/",
    "/rest/",
    "/graphql",
    "/swagger",
    "/openapi",
    "/docs",
    "/redoc",
    "/.well-known/",
    "/actuator",
    "/metrics",
    "/health",
    "/wp-json/",
    "/wp-admin/admin-ajax.php",
]


class WebCrawler(CrawlerParsersMixin):
    """Enhanced web crawler with parameter and API discovery."""

    def __init__(
        self,
        max_depth: int = 5,
        max_urls_per_run: int = 1000,
        max_urls_per_prefix: int = 50,
        respect_robots: bool = False,
        user_agent: str = "WVS/19.0",
        seed_paths: Optional[List[str]] = None,
    ):
        self.max_depth = max_depth
        self.max_urls_per_run = max_urls_per_run
        self.max_urls_per_prefix = max_urls_per_prefix
        self.respect_robots = respect_robots
        self.user_agent = user_agent
        self._seed_paths = seed_paths or self._DEFAULT_SEED_PATHS
        self._allowed_host: Optional[str] = None
        self._visited: Set[str] = set()
        self._endpoints: Set[DiscoveredEndpoint] = set()
        self._urls_to_visit: List[Tuple[str, int]] = []
        self._stats = {"pages_crawled": 0, "forms_found": 0, "errors": 0}
        self._prefix_hits: Dict[str, int] = {}
        self._prefix_warned: Set[str] = set()
        # Param discovery cache: avoid re-fetching same host
        self._param_discovery_done: Set[str] = set()
        # SPA detection
        self._spa_detected: bool = False
        self._spa_body_hash: Optional[str] = None
        self._spa_check_pages: List[int] = []  # page sizes of first pages
        self._spa_checked: bool = False
        # API mode (activated when SPA is detected)
        self._api_mode_extracted: bool = False
        self._skip_param_injection_extensions: Set[str] = STATIC_NO_PARAM_EXTENSIONS
        # UA rotation (Playwright JS rendering only — HTTP UA rotation handled by HTTPPool)
        self._ua_pool = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
        ]
        self._ua_idx = 0
        self._fake_ua = None
        try:
            from fake_useragent import UserAgent
            self._fake_ua = UserAgent()
        except Exception:  # noqa: S110
            pass
        # Random delay between requests to avoid rate-limit patterns
        self._delay_range = CRAWL_DELAY_RANGE

    # ── Main entry ──────────────────────────────────────────────

    async def crawl(self, target_url: str, session: HTTPPool) -> List[DiscoveredEndpoint]:  # noqa: C901
        target_url = self._normalize_url(target_url)
        self._urls_to_visit = [(target_url, 1)]
        self._visited.clear()
        self._endpoints.clear()
        self._allowed_host = urllib.parse.urlparse(target_url).netloc
        logger.info(f"[Crawler] host: {self._allowed_host}, max_depth: {self.max_depth}")

        # P17: Quick connectivity check — skip heavy probing if host is unreachable
        # Try up to 2 times with increasing timeout (some servers are slow to wake up)
        host_reachable = False
        for attempt, timeout_val in enumerate([8, 15], 1):
            try:
                resp = await session.get(target_url, timeout=timeout_val, follow_redirects=True)
                if resp.status_code < 500:
                    host_reachable = True
                    break
            except Exception:
                if attempt == 1:
                    logger.debug("[Crawler] retry connectivity check (attempt 2, timeout=15s)")
                    await asyncio.sleep(1)
        if not host_reachable:
            logger.warning(f"[Crawler] host {self._allowed_host} unreachable, returning single endpoint")
            self._endpoints.add(DiscoveredEndpoint(url=target_url, method="GET", source_url=target_url, source_depth=1))
            return list(self._endpoints)

        # P11: Seed with known Metasploitable2 common paths for multi-service targets
        is_lab = getattr(session, '_lab_mode', False)
        await self._seed_common_paths(target_url, session, is_lab=is_lab)

        # -- SPA detection: crawl 3 pages, compare body hashes --
        if not self._spa_checked:
            self._spa_detected, self._spa_body_hash = await self._check_spa(target_url, session)
            self._spa_checked = True
            if self._spa_detected:
                logger.warning(f"[Crawler] SPA detected (body hash: {hashlib.md5((self._spa_body_hash or '').encode()).hexdigest()[:8]}) — switching to JS API extraction + Playwright rendering")
                # In SPA mode: enable Playwright rendering for deeper content discovery
                self._js_render = True
                # Extract API endpoints from JS bundles
                api_eps = await self._extract_api_from_js(target_url, session)
                self._api_mode_extracted = True
                logger.info(f"[Crawler] SPA mode: extracted {len(api_eps)} API endpoints from JS")
                for ep in api_eps:
                    self._endpoints.add(ep)
                # Still return what we have — scanner will test the API endpoints
                return list(self._endpoints)

        # P7: Parse robots.txt first to discover hidden paths
        await self._parse_robots_txt(target_url, session)

        # P14: Stability-based early termination — threshold raised from 3→8,
        # only enforced when queue nearly empty to avoid premature termination.
        _stability_count = 0
        _last_endpoint_count = 0
        _stability_threshold = 8
        while self._urls_to_visit:
            if len(self._visited) >= self.max_urls_per_run:
                logger.warning(f"[Crawler] hit URL limit {self.max_urls_per_run}")
                break

            url, depth = self._urls_to_visit.pop(0)
            if depth > self.max_depth:
                continue
            if self._is_visited(url):
                continue

            # P22: Per-prefix limiting — prevent deep wiki / forum from dominating.
            # Compute a stable 2-segment prefix (/app/section/) and cap how many
            # URLs from each prefix we crawl.
            parsed = urllib.parse.urlparse(url)
            path_parts = parsed.path.strip("/").split("/") if parsed.path else []
            if len(path_parts) >= 2:
                prefix_key = ".".join(path_parts[:2])[:60]
            elif len(path_parts) == 1:
                prefix_key = path_parts[0]
            else:
                prefix_key = "/"
            prior = self._prefix_hits.get(prefix_key, 0)
            if prior >= self.max_urls_per_prefix:
                if prefix_key not in self._prefix_warned:
                    self._prefix_warned.add(prefix_key)
                    logger.warning(f"[Crawler] prefix limit reached for /{prefix_key.replace('.', '/')}/ — skipping deeper pages")
                continue
            self._prefix_hits[prefix_key] = prior + 1

            self._visited.add(self._url_key(url))

            discovered = await self.crawl_static(url, session, depth)
            # v19.2: JS rendering (Playwright) — disabled by default
            if getattr(self, "_js_render", False):
                try:
                    js_endpoints = await asyncio.wait_for(self.crawl_js(url, session, depth), timeout=30)
                    discovered.extend(js_endpoints)
                except BaseException:
                    logger.debug(f"[Crawler] JS rendering failed for {url}", exc_info=True)

            for ep in discovered:
                self._endpoints.add(ep)
                if ep.source_depth < self.max_depth:
                    new_url = self._normalize_url(ep.url)
                    if not self._is_visited(new_url):
                        self._urls_to_visit.append((new_url, depth + 1))

            # P24: Parameter discovery — probe common params on page URLs
            for ep in list(discovered)[:5]:  # Limit to first 5 per page
                parsed_ep = urllib.parse.urlparse(ep.url)
                # Skip static files — adding params to .htm/.html/.jpg etc is pointless
                ep_ext = os.path.splitext(parsed_ep.path)[1].lower()
                if ep_ext in self._skip_param_injection_extensions:
                    continue
                if parsed_ep.query:
                    # Page already has params; try adding more common ones
                    for extra_param in ["id", "page", "file", "cat", "type", "sort", "order", "debug"]:
                        if extra_param not in parsed_ep.query:
                            new_url = ep.url + ("&" if parsed_ep.query else "?") + f"{extra_param}=1"
                            if not self._is_visited(new_url):
                                self._urls_to_visit.append((new_url, depth + 1))

            self._stats["pages_crawled"] += 1
            # P14: Stability check — only fire when queue near-empty to
            # avoid premature termination while undiscovered URLs remain.
            if len(self._endpoints) == _last_endpoint_count:
                _stability_count += 1
                _queue_depth = len(self._urls_to_visit)
                if _stability_count >= _stability_threshold and _queue_depth < 5:
                    logger.info(
                        f"[Crawler] stability threshold reached ({_stability_threshold} pages w/o new endpoints, queue={_queue_depth}), stopping"
                    )
                    break
            else:
                _stability_count = 0
                _last_endpoint_count = len(self._endpoints)

            if self._stats["pages_crawled"] % 25 == 0:
                pct = min(100, int(len(self._visited) / self.max_urls_per_run * 100))
                logger.info(
                    f"[Crawler] {self._stats['pages_crawled']} pages, {len(self._endpoints)} endpoints, {len(self._urls_to_visit)} queued ({pct}%)"
                )

        # ── API discovery on the base host ──
        await self._discover_api_endpoints(target_url, session)

        # ── Submit GET forms to discover dynamic pages (P5 upgrade) ──
        await self._submit_get_forms(session)

        logger.info(f"[Crawler] done: {self._stats['pages_crawled']} pages, {len(self._endpoints)} endpoints")
        return list(self._endpoints)

    # ── Static HTML parsing ─────────────────────────────────────

    async def crawl_static(self, url: str, session: HTTPPool, depth: int = 1) -> List[DiscoveredEndpoint]:  # noqa: C901
        endpoints: List[DiscoveredEndpoint] = []
        timeout_val = max(getattr(session, "timeout", 30), 30)  # crawler needs >=30s for slow local servers

        # Anti-detection: random delay before request (from smart-crawler concept)
        import random
        await asyncio.sleep(random.uniform(*self._delay_range))

        # P14: retry with exponential backoff (from smart-crawler concept)
        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                resp = await session.get(url, timeout=timeout_val, follow_redirects=True)
                break
            except Exception as e:
                if attempt < max_attempts - 1:
                    backoff = 2 ** attempt  # 0→1s, 1→2s, 2→4s
                    logger.debug(f"[Crawler] retry {url} (attempt {attempt+1}/{max_attempts}): {e} (backoff={backoff}s)")
                    await asyncio.sleep(backoff)
                    continue
                logger.debug(f"[Crawler] failed {url} after {max_attempts} attempts: {e}")
                self._stats["errors"] += 1
                return endpoints

        final_url = str(resp.url)
        parsed_final = urllib.parse.urlparse(final_url)
        host_final = parsed_final.netloc.split(":")[0]
        allowed = self._allowed_host.split(":")[0] if self._allowed_host else None
        if allowed and host_final != allowed:
            logger.debug(f"[Crawler] redirect out of scope: {url} -> {final_url}")
            return endpoints

        if resp.status_code in (403, 404):
            return endpoints
        if not resp.is_success:
            return endpoints

        ct = resp.headers.get("content-type", "")
        if "text/html" not in ct and "application/xhtml" not in ct:
            return endpoints

        try:
            text = resp.text
        except (UnicodeDecodeError, RuntimeError):
            return endpoints

        soup = BeautifulSoup(text, "lxml")

        # ── <a href> ──
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"].strip()
            if not href or href.startswith("#") or href.startswith("javascript:") or href.startswith("mailto:"):
                continue
            full_url = self._join_url(url, href)
            if self._is_crawlable(full_url):
                endpoints.append(
                    DiscoveredEndpoint(
                        url=full_url,
                        method="GET",
                        source_url=url,
                        source_depth=depth,
                    )
                )

        # ── <form> ──
        for form in soup.find_all("form"):
            form_action = form.get("action", "").strip()
            form_method = (form.get("method", "GET") or "GET").upper()
            if not form_action or form_action in ("#", "#top"):
                full_url = url
            else:
                full_url = self._join_url(url, form_action)

            # Keep the URL's existing query params as defaults
            parsed = urllib.parse.urlparse(full_url)
            base_params: Dict[str, str] = {}
            if parsed.query:
                for k, v in urllib.parse.parse_qs(parsed.query).items():
                    base_params[k] = v[0] if v else ""

            fields: List[FormField] = []
            for tag_name in ("input", "textarea", "select"):
                for tag in form.find_all(tag_name):
                    name = tag.get("name", "") or tag.get("id", "")
                    if not name:
                        continue
                    ftype = (tag.get("type", "text") or "text").lower()
                    if tag_name == "textarea":
                        ftype = "textarea"
                    if tag_name == "select":
                        ftype = "select"
                    options = []
                    if ftype == "select":
                        for opt in tag.find_all("option"):
                            v = opt.get("value", "") or opt.get_text(strip=True)
                            if v:
                                options.append(v)
                    fields.append(FormField(name=name, field_type=ftype, default_value=tag.get("value"), options=options))

            param_types: Dict[str, str] = {}
            params: Dict[str, str] = {}
            # Merge URL query params first
            for k, v in base_params.items():
                param_types[k] = "query"
                params[k] = v
            for f in fields:
                if f.field_type in ("image", "reset", "file"):
                    continue
                if form_method == "GET":
                    param_types[f.name] = "query"
                else:
                    param_types[f.name] = "body"
                if f.name not in params:
                    params[f.name] = f.default_value or ""

            if fields:
                self._stats["forms_found"] += 1

            endpoints.append(
                DiscoveredEndpoint(
                    url=full_url,
                    method=form_method,
                    parameters=params,
                    param_types=param_types,
                    forms=fields,
                    source_url=url,
                    source_depth=depth,
                    is_api=self._is_api_url(full_url),
                )
            )

        # ── <area> (image maps) ──
        for area in soup.find_all("area", href=True):
            href = area["href"].strip()
            if href and not href.startswith("#") and not href.startswith("javascript:"):
                full_url = self._join_url(url, href)
                if self._is_crawlable(full_url):
                    endpoints.append(
                        DiscoveredEndpoint(
                            url=full_url,
                            method="GET",
                            source_url=url,
                            source_depth=depth,
                        )
                    )

        # ── <frame> / <iframe> ──
        for frame_tag in soup.find_all(["frame", "iframe"], src=True):
            src = frame_tag["src"].strip()
            if src and not src.startswith("javascript:") and not src.startswith("data:"):
                full_url = self._join_url(url, src)
                if self._is_crawlable(full_url):
                    endpoints.append(
                        DiscoveredEndpoint(
                            url=full_url,
                            method="GET",
                            source_url=url,
                            source_depth=depth,
                        )
                    )

        # ── <img src> ──
        for img in soup.find_all("img", src=True):
            src = img["src"].strip()
            full_url = self._join_url(url, src)
            if self._is_crawlable(full_url):
                endpoints.append(
                    DiscoveredEndpoint(
                        url=full_url,
                        method="GET",
                        source_url=url,
                        source_depth=depth,
                    )
                )

        # ── <script src> JS file URL extraction ──

        # ── HTML comments: extract URLs from commented-out links ──
        comment_pattern = re.compile(r"<!--(.*?)-->", re.DOTALL)
        url_in_text_re = re.compile(
            r"""(?:href|src|action|url)\s*=\s*["\']([^"\']+)["\']""",
            re.IGNORECASE,
        )
        for comment_match in comment_pattern.finditer(text):
            comment_text = comment_match.group(1)
            for url_match in url_in_text_re.finditer(comment_text):
                found_url = url_match.group(1)
                full_url = self._join_url(url, found_url)
                if self._is_crawlable(full_url):
                    endpoints.append(
                        DiscoveredEndpoint(
                            url=full_url,
                            method="GET",
                            source_url=url,
                            source_depth=depth,
                        )
                    )

        # ── <script src> JS file URL extraction ──
        for script in soup.find_all("script", src=True):
            src = script["src"].strip()
            full_url = self._join_url(url, src)
            js_eps = await self._extract_urls_from_js_file(full_url, session, url, depth)
            endpoints.extend(js_eps)

        # ── Inline JS URL extraction ──
        for script in soup.find_all("script"):
            text = script.string or ""
            if not text:
                continue
            for match in _JS_URL_RE.finditer(text):
                found_url = next((g for g in match.groups() if g), None)
                if found_url:
                    full_url = self._join_url(url, found_url)
                    if self._is_crawlable(full_url):
                        endpoints.append(
                            DiscoveredEndpoint(
                                url=full_url,
                                method="GET",
                                source_url=url,
                                source_depth=depth,
                            )
                        )

        # ── JSON API endpoints in inline scripts ──
        api_url_re = re.compile(
            r"""["'](?:apiUrl|api_url|baseURL|base_url|endpoint|serviceUrl|apiEndpoint)["']\s*:\s*["']([^"'\s]+)["']""",
            re.IGNORECASE,
        )
        for script in soup.find_all("script"):
            text = script.string or ""
            for m in api_url_re.finditer(text):
                found = m.group(1)
                full_url = self._join_url(url, found)
                endpoints.append(
                    DiscoveredEndpoint(
                        url=full_url,
                        method="GET",
                        source_url=url,
                        source_depth=depth,
                        is_api=True,
                    )
                )

        # ── Sitemap links ──
        for link in soup.find_all(["a", "link"]):
            href = link.get("href", "")
            if "sitemap" in href.lower() and href.endswith(".xml"):
                full = self._join_url(url, href)
                sitemap_eps = await self._parse_sitemap(full, session, depth)
                endpoints.extend(sitemap_eps)

        return endpoints

    # ── Parameter discovery ─────────────────────────────────────

    async def discover_params(self, endpoint: DiscoveredEndpoint, session: HTTPPool) -> DiscoveredEndpoint:
        """Try common parameter names on a parameterless endpoint.
        P5: Batched — one request tests multiple param names simultaneously,
        cutting param discovery requests from ~45/endpoint to ~5/endpoint."""
        if endpoint.parameters:
            return endpoint

        base_url = endpoint.url
        parsed = urllib.parse.urlparse(base_url)
        # Skip static files — no point injecting params into .htm/.html
        base_ext = os.path.splitext(parsed.path)[1].lower()
        if base_ext in self._skip_param_injection_extensions:
            return endpoint
        if parsed.query:
            qs = urllib.parse.parse_qs(parsed.query)
            endpoint.parameters = {k: v[0] if v else "" for k, v in qs.items()}
            endpoint.param_types = {k: "query" for k in endpoint.parameters}
            return endpoint

        found_params: Dict[str, str] = {}
        found_types: Dict[str, str] = {}
        reflected_params: Dict[str, str] = {}
        reflected_types: Dict[str, str] = {}

        test_value = "1"
        max_params = 20
        param_list = list(COMMON_PARAM_NAMES)[:max_params]

        # P5: Batch params into a single URL — e.g. /page?id=1&page=1&cat=1&...
        # Instead of N separate requests, make ceil(N/10) requests.
        batch_size = 10
        for i in range(0, len(param_list), batch_size):
            batch = param_list[i: i + batch_size]
            # Build single URL with all params in this batch
            sep = "&" if "?" in base_url else "?"
            qs_parts = [f"{p}={test_value}" for p in batch]
            test_url = base_url + sep + "&".join(qs_parts)

            try:
                resp = await session.get(test_url, timeout=8, follow_redirects=False)
                if resp.status_code < 400:
                    text = resp.text[:5000].lower()
                    for pname in batch:
                        if pname.lower() in text:
                            reflected_params[pname] = test_value
                            reflected_types[pname] = "query"
                        else:
                            # V3: Keep non-reflected params too — they may be blind injection points
                            found_params[pname] = test_value
                            found_types[pname] = "query"
            except Exception:
                logger.debug(f"[Crawler] Parameter discovery failed for {endpoint.url}", exc_info=True)

        # Reflected params take priority; add non-reflected as fallback
        endpoint.parameters = {**found_params, **reflected_params}
        endpoint.param_types = {**found_types, **reflected_types}
        if endpoint.parameters:
            logger.debug(f"[Crawler] discover_params({endpoint.url}): {len(reflected_params)} reflected, {len(found_params)} non-reflected kept")

        return endpoint

    async def discover_params_batch(self, endpoints: List[DiscoveredEndpoint], session: HTTPPool) -> List[DiscoveredEndpoint]:
        """Discover params for multiple endpoints concurrently. P5: amortized — one request tests multiple params."""
        # Only run param discovery once per host
        if not endpoints:
            return endpoints
        host = urllib.parse.urlparse(endpoints[0].url).netloc
        if host in self._param_discovery_done:
            return endpoints
        self._param_discovery_done.add(host)

        tasks = [self.discover_params(ep, session) for ep in endpoints]
        return list(await asyncio.gather(*tasks, return_exceptions=False))

    # ── API discovery ───────────────────────────────────────────

    async def _discover_api_endpoints(self, base_url: str, session: HTTPPool) -> None:
        """Probe common API paths and parse OpenAPI specs."""
        parsed_base = urllib.parse.urlparse(base_url)
        origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

        api_probes = [
            "/api/",
            "/api/v1/",
            "/swagger.json",
            "/v2/api-docs",
            "/v3/api-docs",
            "/openapi.json",
            "/graphql",
            "/actuator/health",
        ]

        tasks = []
        for probe in api_probes:
            probe_url = origin + probe
            tasks.append(self._probe_api_path(probe_url, session, base_url))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for eps in results:
            if isinstance(eps, list):
                for ep in eps:
                    self._endpoints.add(ep)

    async def _probe_api_path(self, url: str, session: HTTPPool, source_url: str) -> List[DiscoveredEndpoint]:
        endpoints: List[DiscoveredEndpoint] = []
        try:
            resp = await session.get(url, timeout=10, follow_redirects=True)
            if resp.status_code < 400:
                # If it's a JSON spec, parse it
                ct = resp.headers.get("content-type", "")
                if "json" in ct:
                    try:
                        spec = resp.json()
                        eps_from_spec = self._parse_openapi_spec(spec, url, source_url)
                        endpoints.extend(eps_from_spec)
                    except (json.JSONDecodeError, ValueError):
                        logger.debug(f"[Crawler] OpenAPI spec parse failed for {url}", exc_info=True)
                # Mark the path itself as an endpoint
                endpoints.append(
                    DiscoveredEndpoint(
                        url=url,
                        method="GET",
                        source_url=source_url,
                        source_depth=1,
                        is_api=True,
                    )
                )
        except Exception:
            logger.debug(f"[Crawler] SPA JS extraction failed", exc_info=True)
        return endpoints

    # ── Seed common paths (P11) ───────────────────────────────────

    # Common web app paths to seed on the target host (low-cost probes).
    # Only seed root-level app paths — sub-pages will be discovered
    # via the normal crawl link extraction.  Avoid deep wiki/forum
    # paths that would trigger unbounded recursive crawling.
    _DEFAULT_SEED_PATHS = [
        # ── 靶场 / CTF (仅当 is_lab=True 时探测) ──
        # ── 管理后台 ──
        # ── 管理后台 ──
        "/admin/",
        "/wp-admin/",
        "/administrator/",
        "/backend/",
        "/manager/",
        "/dashboard/",
        "/controlpanel/",
        "/cpanel/",
        # ── 数据库管理 ──
        "/phpMyAdmin/",
        "/phpPgAdmin/",
        "/adminer/",
        "/pma/",
        # ── API / 文档 ──
        "/api/",
        "/api/v1/",
        "/api/v2/",
        "/swagger/",
        "/swagger-ui/",
        "/api-docs/",
        "/graphql/",
        "/openapi.json",
        "/v1/",
        "/v2/",
        # ── CI/CD / 监控 ──
        "/jenkins/",
        "/grafana/",
        "/prometheus/",
        "/sonarqube/",
        "/nexus/",
        "/artifactory/",
        # ── 敏感文件 ──
        "/.env",
        "/.git/config",
        "/robots.txt",
        "/sitemap.xml",
        "/crossdomain.xml",
        "/phpinfo.php",
        "/info.php",
        "/test.php",
        "/server-status",
        "/actuator/",
        "/actuator/health",
        "/actuator/env",
        "/elmah.axd",
        # ── 其它框架 / 路径 ──
        "/dav/",
        "/twiki/",
        "/tikiwiki/",
        "/debug/",
        "/console/",
        "/.well-known/security.txt",
        "/wp-content/",
        "/wp-includes/",
        "/uploads/",
        "/backup/",
        "/backup.zip",
    ]

    def _lab_seed_paths(self) -> list:
        """靶场专用探测路径（仅实验室目标）"""
        return ["/dvwa/", "/mutillidae/", "/bodgeit/", "/webgoat/", "/juice-shop/", "/hackme/"]

    async def _seed_common_paths(self, target_url: str, session: HTTPPool, is_lab: bool = False) -> None:
        """P11: Probe common web app paths on the target to discover hidden services.

        Args:
            is_lab: True = 靶机目标（探测靶场路径）, False = 真实网站（跳过靶场路径）
        """
        parsed = urllib.parse.urlparse(target_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        probes = list(self._seed_paths)
        if is_lab:
            probes = self._lab_seed_paths() + probes
        probes = probes[:15]
        sem = asyncio.Semaphore(5)

        async def _probe_one(path: str):
            async with sem:
                full_url = origin + path
                if self._is_visited(full_url):
                    return
                try:
                    resp = await session.get(full_url, timeout=8, follow_redirects=False)
                    if resp.status_code < 400:
                        final_url = str(resp.url) if hasattr(resp, "url") else full_url
                        self._urls_to_visit.append((self._normalize_url(final_url), 1))
                        logger.debug(f"[Crawler] seed path found: {path} -> {final_url}")
                except (OSError, asyncio.TimeoutError) as e:
                    logger.debug(f"[Crawler] seed probe failed {path}: {e}")
                except Exception as e:
                    logger.debug(f"[Crawler] seed probe failed {path}: {e}")

        await asyncio.gather(*[_probe_one(p) for p in probes])
        logger.debug(f"[Crawler] seed paths queued: {len(self._urls_to_visit)} URLs")

    # ── Sitemap / Playwright rendering ──────────────────────────
    # _parse_sitemap and _parse_robots_txt moved to CrawlerParsersMixin (crawler_parsers.py)

    # ── GET form submission (P5: dynamic page discovery) ─────────

    async def _submit_get_forms(self, session: HTTPPool) -> None:
        """
        Submit discovered forms to uncover more dynamic pages.

        Principle: DVWA / Mutillidae and similar targets control page navigation through GET/POST
        parameters (e.g., ?page=add-to-your-blog.php); pages linked to these parameters
        cannot be discovered without form submission.
        P11: Also handle POST forms with login/navigation parameters.
        """
        forms = [ep for ep in self._endpoints if ep.parameters]

        submitted_count = 0
        for ep in forms:
            if submitted_count >= 40:  # P11: increased from 30 for deeper coverage
                break
            if ep.source_depth >= self.max_depth:
                continue

            # P11: Expanded nav params to cover more CMS/lab patterns
            nav_params = [
                "page",
                "p",
                "action",
                "view",
                "id",
                "cat",
                "category",
                "mode",
                "type",
                "section",
                "tab",
                "file",
                "include",
                "template",
                "lang",
                "topic",
                "forum",
                "thread",
                "post",
                "article",
                "news",
                "page_id",
                "content",
                "component",
                "layout",
                "module",
                "controller",
                "task",
                "option",
            ]
            if not any(p in nav_params for p in ep.parameters):
                continue

            try:
                if ep.method.upper() == "POST":
                    # Submit POST form to discover what pages it leads to
                    resp = await session.post(ep.url, data=ep.parameters, timeout=10, follow_redirects=True)
                    if resp.status_code < 400:
                        final_url = str(resp.url)
                        if not self._is_visited(final_url):
                            self._visited.add(self._url_key(final_url))
                            discovered = await self.crawl_static(final_url, session, ep.source_depth + 1)
                            for new_ep in discovered:
                                self._endpoints.add(new_ep)
                                new_url = self._normalize_url(new_ep.url)
                                if not self._is_visited(new_url):
                                    self._urls_to_visit.append((new_url, ep.source_depth + 1))
                            self._stats["pages_crawled"] += 1
                            submitted_count += 1
                else:
                    full_url = ep.url
                    qs = urllib.parse.urlencode(ep.parameters)
                    sep = "&" if "?" in full_url else "?"
                    submit_url = f"{full_url}{sep}{qs}"

                    if self._is_visited(submit_url):
                        continue

                    resp = await session.get(submit_url, timeout=10, follow_redirects=True)
                    if resp.status_code < 400:
                        self._visited.add(self._url_key(submit_url))
                        discovered = await self.crawl_static(submit_url, session, ep.source_depth + 1)
                        for new_ep in discovered:
                            self._endpoints.add(new_ep)
                            new_url = self._normalize_url(new_ep.url)
                            if not self._is_visited(new_url):
                                self._urls_to_visit.append((new_url, ep.source_depth + 1))
                        self._stats["pages_crawled"] += 1
                        submitted_count += 1
            except Exception:
                logger.debug(f"[Crawler] Form submit failed for {ep.url}", exc_info=True)
                continue

    # ── SPA Detection & JS API Extraction ───────────────────────

    async def _check_spa(self, target_url: str, session: HTTPPool) -> Tuple[bool, Optional[str]]:
        """Check if the target is a Single Page Application by comparing body content of 3 pages."""
        test_paths = ["/", "/admin", "/api", "/login", "/about"]
        bodies: List[str] = []
        for path in test_paths:
            try:
                url = urllib.parse.urljoin(target_url, path)
                resp = await session.get(url, timeout=8, follow_redirects=True)
                if resp.status_code < 400 and "text/html" in (resp.headers.get("content-type", "") or ""):
                    body = resp.text[:5000]  # compare first 5K chars
                    bodies.append(body)
            except Exception:
                logger.debug(f"[Crawler] SPA check request failed for {url}", exc_info=True)
                continue
            if len(bodies) >= 3:
                break
        if len(bodies) < 2:
            return False, None
        # If all bodies are the same (or very close), it's an SPA
        sizes = [len(b) for b in bodies]
        body0 = bodies[0]
        if all(abs(len(b) - len(body0)) < max(50, len(body0) * 0.05) for b in bodies):
            return True, body0
        return False, None

    async def _extract_api_from_js(self, target_url: str, session: HTTPPool) -> List[DiscoveredEndpoint]:
        """Extract API endpoints from JS bundles when SPA is detected.
        Fetches the main page, finds all <script src> tags, downloads JS files,
        and extracts API paths using regex."""
        eps: List[DiscoveredEndpoint] = []
        try:
            resp = await session.get(target_url, timeout=10, follow_redirects=True)
            if resp.status_code >= 400:
                return eps
            text = resp.text
            soup = BeautifulSoup(text, "lxml")
            js_urls = set()
            # Collect all JS file URLs
            for script in soup.find_all("script", src=True):
                src = script["src"]
                full_url = urllib.parse.urljoin(target_url, src)
                if full_url not in js_urls:
                    js_urls.add(full_url)
            # Download each JS and extract API paths
            api_pattern = re.compile(r"""['"`](/[a-zA-Z][a-zA-Z0-9_/\-\.{}?=&%@+#]*)['"`]""")
            api_prefix_pattern = re.compile(r"""['"`]((?:https?://[^/]+)?/(?:api|v[12]/|graphql|rest)/[^'"`\s]*)['"`]""")
            for js_url in js_urls:
                try:
                    js_resp = await session.get(js_url, timeout=8, follow_redirects=True)
                    if js_resp.status_code >= 400:
                        continue
                    js_text = js_resp.text
                    # Find potential API routes
                    for match in api_prefix_pattern.finditer(js_text):
                        path = match.group(1)
                        full_url = urllib.parse.urljoin(target_url, path)
                        eps.append(DiscoveredEndpoint(url=full_url, method="GET", is_api=True, source_url=target_url))
                    # Also find any URL with common API patterns
                    for match in api_pattern.finditer(js_text):
                        path = match.group(1)
                        if any(kw in path.lower() for kw in ["/api/", "/v1/", "/v2/", "/graphql", "/rest/", "/swagger"]):
                            full_url = urllib.parse.urljoin(target_url, path)
                            eps.append(DiscoveredEndpoint(url=full_url, method="GET", is_api=True, source_url=target_url))
                except Exception:
                    logger.debug(f"[Crawler] JS endpoint extraction failed", exc_info=True)
                    continue
        except Exception:
            logger.debug(f"[Crawler] JS API extraction failed", exc_info=True)
        # Deduplicate
        seen = set()
        unique_eps = []
        for ep in eps:
            if ep.url not in seen:
                seen.add(ep.url)
                unique_eps.append(ep)
        return unique_eps

    # ── JS / SPA rendering (Playwright) ─────────────────────────

    async def crawl_js(self, url: str, session: HTTPPool, depth: int = 1) -> List[DiscoveredEndpoint]:
        """
        Render page with Playwright — scroll, wait for lazy content, extract endpoints.
        From smart-crawler's dynamic rendering concept.
        """
        endpoints: List[DiscoveredEndpoint] = []

        try:
            from playwright.async_api import async_playwright
        except ImportError:
            logger.warning("[Crawler] playwright not installed, skipping JS render")
            return endpoints

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-setuid-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                    ],
                )
                context = await browser.new_context(
                    viewport={"width": 1920, "height": 1080},
                    user_agent=(
                        self._fake_ua.random
                        if self._fake_ua
                        else self._ua_pool[self._ua_idx]
                    ),
                )
                page = await context.new_page()

                # Navigate and wait for JS to settle
                await page.goto(url, wait_until="networkidle", timeout=30000)

                # Deep scroll — 3 full page scrolls to trigger lazy loading
                for _ in range(3):
                    await page.evaluate("window.scrollBy(0, window.innerHeight)")
                    await page.wait_for_timeout(1000)

                # Extract all links after rendering
                rendered_html = await page.content()
                soup = BeautifulSoup(rendered_html, "lxml")

                # Extract links (same logic as crawl_static)
                for a_tag in soup.find_all("a", href=True):
                    href = a_tag["href"].strip()
                    if not href or href.startswith("#") or href.startswith("javascript:"):
                        continue
                    full_url = self._join_url(url, href)
                    if full_url and self._is_crawlable(full_url) and not self._is_visited(full_url):
                        endpoints.append(
                            DiscoveredEndpoint(
                                url=full_url,
                                method="GET",
                                source_url=url,
                                source_depth=depth,
                                is_api=self._is_api_url(full_url),
                            )
                        )

                # Extract API calls embedded in scripts
                api_calls = await page.evaluate("""() => {
                    const apis = new Set();
                    document.querySelectorAll('script').forEach(s => {
                        const text = s.textContent || '';
                        const matches = text.match(/'([^']*(?:\\/api\\/|\\/v\\d+\\/|\\/graphql)[^']*)'/g);
                        if (matches) matches.forEach(m => apis.add(m.replace(/'/g, '')));
                    });
                    return Array.from(apis);
                }""")
                for api_path in api_calls:
                    full_url = self._join_url(url, api_path)
                    if full_url and self._is_crawlable(full_url) and not self._is_visited(full_url):
                        endpoints.append(
                            DiscoveredEndpoint(
                                url=full_url,
                                method="GET",
                                source_url=url,
                                source_depth=depth,
                                is_api=True,
                            )
                        )

                await browser.close()
                logger.info(f"[Crawler] JS rendered {url}: {len(endpoints)} endpoints found")

        except Exception as e:
            logger.warning(f"[Crawler] JS render failed for {url}: {e}")

        return endpoints

    # ── Internal helpers ────────────────────────────────────────

    # _extract_urls_from_js_file moved to CrawlerParsersMixin (crawler_parsers.py)

    def _normalize_url(self, url: str) -> str:
        """P13: Full URL normalization — lowercase host, sort query params, strip defaults."""
        url = url.strip()
        if not url.startswith("http"):
            url = "http://" + url
        if "#" in url:
            url = url.split("#", 1)[0]
        parsed = urllib.parse.urlparse(url)
        # Lowercase host
        netloc = parsed.netloc.lower()
        # Strip default ports
        if netloc.endswith(":80") and parsed.scheme == "http":
            netloc = netloc[:-3]
        elif netloc.endswith(":443") and parsed.scheme == "https":
            netloc = netloc[:-4]
        # Normalize path: trailing slash + collapse /./ and //
        path = parsed.path.rstrip("/")
        while "//" in path:
            path = path.replace("//", "/")
        path = path.replace("/./", "/")
        if not path:
            path = "/"
        # Sort query params
        query = ""
        if parsed.query:
            qs_pairs = sorted(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
            query = urllib.parse.urlencode(qs_pairs)
        return urllib.parse.urlunparse((parsed.scheme, netloc, path, "", query, ""))

    def _join_url(self, base: str, path: str) -> str:
        if not path:
            return base
        if path.startswith("data:") or path.startswith("mailto:") or path.startswith("tel:"):
            return base
        try:
            return urllib.parse.urljoin(base, path)
        except Exception:
            return base

    def _url_key(self, url: str) -> str:
        parsed = urllib.parse.urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}"
        if parsed.query:
            important: List[str] = []
            for k, vals in urllib.parse.parse_qs(parsed.query).items():
                v = vals[0] if vals else ""
                ext = os.path.splitext(v.split("?")[0])[1].lower()
                if ext in CRAWLABLE_EXTENSIONS and ext:
                    important.append(f"{k}={v}")
                elif k.lower() in PAGE_IDENT_PARAMS:
                    important.append(f"{k}={v}")
            if important:
                base += "?" + "&".join(sorted(important))
        return base

    def _is_visited(self, url: str) -> bool:
        return self._url_key(url) in self._visited

    def _is_crawlable(self, url: str) -> bool:
        if not url or not url.startswith("http"):
            return False
        if self._allowed_host:
            parsed = urllib.parse.urlparse(url)
            allowed_parsed = urllib.parse.urlparse(f"http://{self._allowed_host}")
            host_no_port = parsed.hostname or parsed.netloc.split(":")[0]
            allowed_host = allowed_parsed.hostname or self._allowed_host.split(":")[0]
            if host_no_port != allowed_host:
                return False
        parsed = urllib.parse.urlparse(url)
        ext = os.path.splitext(parsed.path)[1].lower()
        if ext in SKIP_EXTENSIONS:
            return False
        return True

    def _is_api_url(self, url: str) -> bool:
        url_lower = url.lower()
        return any(ind in url_lower for ind in API_PATH_PATTERNS)

    def get_stats(self) -> Dict[str, Any]:
        return {**self._stats, "endpoints_found": len(self._endpoints)}
