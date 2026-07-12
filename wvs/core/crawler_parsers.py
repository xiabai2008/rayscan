"""
WebCrawler parsers mixin — robots.txt, sitemap, OpenAPI, and JS URL extraction.
"""

import asyncio
import logging
import re
import urllib.parse
from typing import TYPE_CHECKING, List

from bs4 import BeautifulSoup

if TYPE_CHECKING:
    from .crawler import DiscoveredEndpoint, HTTPPool, WebCrawler

logger = logging.getLogger(__name__)

# Regex to extract URLs from JavaScript files
# Enhanced with LinkFinder patterns (https://github.com/GerbenJavado/LinkFinder)
_JS_URL_RE = re.compile(
    r"""(?:
        # LinkFinder: full URLs with scheme
        ["'`]((?:https?://)[^"'`\s]{5,})["'`]|
        # LinkFinder: relative paths starting with / ../ ./
        ["'`]((?:/|\.\./|\./)[^"'`><,;|*()\s\[\]]{1,})["'`]|
        # LinkFinder: file paths with extensions
        ["'`]([a-zA-Z0-9_\-/.]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml|do)[^"'`\s]{0,})["'`]|
        # RayScan: explicit HTTP call patterns
        fetch\s*\(\s*["'`]([^"'`\s]+)["'`]|
        axios\.[a-z]+\s*\(\s*["'`]([^"'`\s]+)["'`]|
        \.get\s*\(\s*["'`]([^"'`\s]+)["'`]|
        \.post\s*\(\s*["'`]([^"'`\s]+)["'`]|
        (?:window|document|location)\.(?:href|src|action)\s*=\s*["'`]([^"'`\s]+)["'`]|
        (?:href|src|action|formAction)\s*=\s*["'`]([^"'`\s]+)["']
    )""",
    re.VERBOSE | re.IGNORECASE,
)


class CrawlerParsersMixin:
    """Sitemap, robots.txt, OpenAPI spec, and JS URL parsers."""

    async def _parse_robots_txt(self: "WebCrawler", target_url: str, session: "HTTPPool") -> None:
        """Parse robots.txt to discover hidden paths."""
        parsed = urllib.parse.urlparse(target_url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        try:
            resp = await session.get(robots_url, timeout=8)
            if resp.status_code != 200:
                return
            text = resp.text
            for line in text.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                    path_part = line.split(":", 1)[1].strip()
                    if path_part and path_part != "/" and not path_part.startswith("#"):
                        full_url = f"{parsed.scheme}://{parsed.netloc}{path_part}"
                        full_url = self._normalize_url(full_url)
                        if self._is_crawlable(full_url) and not self._is_visited(full_url):
                            self._urls_to_visit.append((full_url, 1))
            logger.debug(f"[Crawler] robots.txt parsed: {len(self._urls_to_visit)} URLs queued")
        except (OSError, asyncio.TimeoutError) as e:
            logger.debug(f"[Crawler] robots.txt parse failed: {e}")
        except Exception as e:
            logger.debug(f"[Crawler] robots.txt parse failed: {e}")

    async def _parse_sitemap(
        self: "WebCrawler", url: str, session: "HTTPPool", depth: int
    ) -> "List[DiscoveredEndpoint]":
        """Parse an XML sitemap to extract URLs."""
        from .crawler import DiscoveredEndpoint

        endpoints: List[DiscoveredEndpoint] = []
        try:
            resp = await session.get(url, timeout=10)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "xml")
                for loc in soup.find_all("loc"):
                    loc_url = loc.text.strip()
                    if loc_url and self._is_crawlable(loc_url):
                        endpoints.append(
                            DiscoveredEndpoint(
                                url=loc_url,
                                method="GET",
                                source_url=url,
                                source_depth=depth,
                            )
                        )
        except (OSError, asyncio.TimeoutError) as e:
            logger.debug(f"[Crawler] sitemap parse failed {url}: {e}")
        except Exception as e:
            logger.debug(f"[Crawler] sitemap parse failed {url}: {e}")
        return endpoints

    def _parse_openapi_spec(
        self: "WebCrawler", spec: dict, spec_url: str, source_url: str
    ) -> "List[DiscoveredEndpoint]":
        """Parse an OpenAPI/Swagger spec to extract API endpoints."""
        from .crawler import DiscoveredEndpoint

        endpoints: List[DiscoveredEndpoint] = []
        parsed_spec = urllib.parse.urlparse(spec_url)
        base = f"{parsed_spec.scheme}://{parsed_spec.netloc}"

        if "paths" in spec:
            for path, methods in spec["paths"].items():
                if isinstance(methods, dict):
                    for method in methods:
                        if method.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                            full_url = base + path
                            params: dict = {}
                            param_types: dict = {}
                            params_spec = methods[method].get("parameters", [])
                            if isinstance(params_spec, list):
                                for p in params_spec:
                                    if isinstance(p, dict):
                                        pname = p.get("name", "")
                                        pin = p.get("in", "query")
                                        if pname:
                                            params[pname] = p.get("example", "") or ""
                                            param_types[pname] = pin
                            endpoints.append(
                                DiscoveredEndpoint(
                                    url=full_url,
                                    method=method.upper(),
                                    parameters=params,
                                    param_types=param_types,
                                    source_url=source_url,
                                    source_depth=1,
                                    is_api=True,
                                )
                            )
        return endpoints

    async def _extract_urls_from_js_file(
        self: "WebCrawler", js_url: str, session: "HTTPPool", referer: str, depth: int
    ) -> "List[DiscoveredEndpoint]":
        """Extract URL references from JavaScript file content."""
        from .crawler import DiscoveredEndpoint

        endpoints: List[DiscoveredEndpoint] = []
        try:
            resp = await session.get(js_url, timeout=10)
            if resp.status_code != 200:
                return endpoints
            js_text = resp.text
        except Exception:
            return endpoints

        for match in _JS_URL_RE.finditer(js_text):
            found_url = next((g for g in match.groups() if g), None)
            if found_url:
                full_url = self._join_url(referer, found_url)
                if self._is_crawlable(full_url):
                    endpoints.append(
                        DiscoveredEndpoint(
                            url=full_url,
                            method="GET",
                            source_url=js_url,
                            source_depth=depth,
                        )
                    )
        return endpoints
