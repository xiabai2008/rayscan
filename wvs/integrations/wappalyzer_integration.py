"""
Wappalyzer Integration Module
v19.2 New: Technology Stack Fingerprinting

Strategy:
1. Prefer python-Wappalyzer (pip package)
2. Fallback to built-in lightweight fingerprint matching
3. Results used to optimize scan strategy (skip irrelevant modules)

Supports:
- Server technology stack identification (language/framework/CMS/CDN)
- JavaScript library detection
- Security tool identification (WAF/IDS)
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from ..config import ConfigManager


logger = logging.getLogger("wvs.integrations.wappalyzer")


@dataclass
class Technology:
    """Identified technology information"""

    name: str
    category: str = "unknown"
    version: Optional[str] = None
    confidence: int = 50  # 0-100
    evidence: Dict[str, List[str]] = field(default_factory=dict)


@dataclass
class TechFingerprint:
    """
    Technology stack fingerprint result

    Contains the complete technology stack information of the target website,
    can be passed to scan modules to optimize scan strategies.
    """

    url: str
    technologies: List[Technology] = field(default_factory=list)
    server: Optional[str] = None
    powered_by: Optional[str] = None
    cms: Optional[str] = None
    language: Optional[str] = None
    framework: Optional[str] = None
    cdn: Optional[str] = None
    analytics: Optional[str] = None
    has_waf: bool = False
    waf_name: Optional[str] = None

    def has_tech(self, name: str) -> bool:
        """Check whether a specific technology is used"""
        name_lower = name.lower()
        return any(t.name.lower() == name_lower for t in self.technologies)

    def get_category(self, category: str) -> List[Technology]:
        """Get all technologies of a specific category"""
        return [t for t in self.technologies if t.category == category]

    def summary(self) -> str:
        """Technology stack summary"""
        parts = []
        if self.language:
            parts.append(self.language)
        if self.framework:
            parts.append(self.framework)
        if self.cms:
            parts.append(self.cms)
        if self.server:
            parts.append(self.server)
        if self.has_waf:
            parts.append(f"WAF: {self.waf_name or 'Yes'}")
        return " | ".join(parts) if parts else "Unknown"


class WappalyzerIntegration:
    """
    Wappalyzer Integration — Technology Stack Fingerprinting

    Identifies the technology stack of the target website,
    guides subsequent scan module selection.
    """

    # ── Built-in lightweight fingerprint database (fallback when Wappalyzer is unavailable) ──
    _BUILTIN_FINGERPRINTS = [
        # CMS
        ("WordPress", "cms", [r"wp-content", r"wp-includes", r"/wp-json/"], ["meta", "header", "html"]),
        ("Drupal", "cms", [r"Drupal", r"/sites/default/", r"/misc/drupal\.js"], ["html"]),
        ("Joomla", "cms", [r"Joomla", r"/components/com_", r"/templates/ja_"], ["html"]),
        ("Magento", "cms", [r"Magento", r"/skin/frontend/"], ["html"]),
        # Frameworks
        ("Laravel", "framework", [r"laravel_session", r"XSRF-TOKEN"], ["cookie", "header"]),
        ("Django", "framework", [r"csrftoken", r"django\.", r"__debug__"], ["cookie", "html"]),
        ("Ruby on Rails", "framework", [r"_session_id.*rails", r"rails/"], ["cookie", "header"]),
        ("Spring", "framework", [r"JSESSIONID", r"springframework"], ["cookie", "html"]),
        ("ASP.NET", "framework", [r"__VIEWSTATE", r"ASP\.NET", r"ASPXANONYMOUS"], ["html", "cookie", "header"]),
        ("Express", "framework", [r"x-powered-by:.*express", r"connect\.sid"], ["header", "cookie"]),
        ("Flask", "framework", [r"werkzeug", r"flask/"], ["header", "html"]),
        # Languages
        ("PHP", "language", [r"\.php", r"PHPSESSID", r"x-powered-by:.*PHP"], ["url", "cookie", "header"]),
        ("Python", "language", [r"\.py(?:$|\?)", r"python/"], ["url", "header"]),
        ("Java", "language", [r"\.jsp", r"\.do", r"JSESSIONID", r"x-powered-by:.*JSP"], ["url", "cookie", "header"]),
        ("Node.js", "language", [r"node\.js", r"express"], ["header", "html"]),
        ("Ruby", "language", [r"\.rb(?:$|\?)", r"phusion passenger"], ["url", "header"]),
        ("Go", "language", [r"go/", r"x-powered-by:.*go"], ["header"]),
        # Web Servers
        ("Nginx", "server", [r"server:.*nginx", r"x-powered-by:.*nginx"], ["header"]),
        ("Apache", "server", [r"server:.*apache", r"x-powered-by:.*apache"], ["header"]),
        ("IIS", "server", [r"server:.*IIS", r"x-powered-by:.*ASP\.NET"], ["header"]),
        ("Tomcat", "server", [r"server:.*tomcat", r"Apache-Coyote"], ["header"]),
        # CDN
        ("Cloudflare", "cdn", [r"cloudflare", r"__cfduid", r"cf-ray"], ["header", "cookie"]),
        ("AWS CloudFront", "cdn", [r"cloudfront", r"x-amz-cf-"], ["header"]),
        # Analytics
        ("Google Analytics", "analytics", [r"google-analytics", r"ga\.js", r"gtag"], ["html"]),
        ("Baidu Tongji", "analytics", [r"hm\.baidu\.com", r"baidu\.com/hm\.js"], ["html"]),
        # WAF
        ("ModSecurity", "waf", [r"mod_security", r"modsecurity"], ["header", "html"]),
        ("Cloudflare WAF", "waf", [r"cloudflare-nginx", r"cf-chl-"], ["header"]),
        ("AWS WAF", "waf", [r"x-amz-waf", r"awselb"], ["header"]),
    ]

    def __init__(
        self,
        config: Optional[ConfigManager] = None,
    ):
        self.config = config or ConfigManager()
        self._wappalyzer = None
        self._try_init_wappalyzer()

    def _try_init_wappalyzer(self):
        """Try to initialize python-Wappalyzer"""
        try:
            from Wappalyzer import Wappalyzer, WebPage

            self._wappalyzer = Wappalyzer.latest()
            self._WebPage = WebPage
            logger.info("[Wappalyzer] python-Wappalyzer loaded")
        except ImportError:
            logger.info("[Wappalyzer] python-Wappalyzer not installed, using built-in fingerprint database")
            self._wappalyzer = None

    @property
    def is_available(self) -> bool:
        return True  # Always available (built-in fallback)

    async def fingerprint(
        self,
        url: str,
        html: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> TechFingerprint:
        """
        Perform technology stack fingerprinting on the target URL

        Args:
            url: Target URL
            html: HTML content (optional, auto-fetched if not provided)
            headers: HTTP response headers
            cookies: Cookie dictionary

        Returns:
            Technology stack fingerprint result
        """
        fingerprint = TechFingerprint(url=url)

        if self._wappalyzer is not None:
            return await self._fingerprint_wappalyzer(url, html, headers, fingerprint)
        else:
            return await self._fingerprint_builtin(url, html, headers, cookies, fingerprint)

    async def _fingerprint_wappalyzer(
        self,
        url: str,
        html: Optional[str],
        headers: Optional[Dict[str, str]],
        fingerprint: TechFingerprint,
    ) -> TechFingerprint:
        """Identify using python-Wappalyzer"""
        try:
            if html is None:
                html, resp_headers = await self._fetch_url(url)
                if headers is None:
                    headers = resp_headers

            webpage = self._WebPage(url, html, headers or {})
            analysis = self._wappalyzer.analyze(webpage)

            for tech_name, tech_info in analysis.items():
                tech = Technology(
                    name=tech_name,
                    category=self._guess_category(tech_name),
                    version=tech_info.get("version"),
                    confidence=tech_info.get("confidence", 80),
                )
                fingerprint.technologies.append(tech)

            logger.info(f"[Wappalyzer] Identified {len(analysis)} technologies")

        except Exception as e:
            logger.warning(f"[Wappalyzer] python-Wappalyzer failed: {e}, falling back to built-in")
            return await self._fingerprint_builtin(url, html, headers, {}, fingerprint)

        self._enrich_fingerprint(fingerprint)
        return fingerprint

    async def _fingerprint_builtin(
        self,
        url: str,
        html: Optional[str],
        headers: Optional[Dict[str, str]],
        cookies: Optional[Dict[str, str]],
        fingerprint: TechFingerprint,
    ) -> TechFingerprint:
        """Identify using the built-in fingerprint database"""
        if html is None and headers is None:
            html, headers = await self._fetch_url(url)

        html_lower = html.lower() if html else ""
        headers_lower = {k.lower(): v.lower() for k, v in (headers or {}).items()}
        cookie_keys = " ".join((cookies or {}).keys()).lower()

        # Extract key response header fields
        fingerprint.server = headers.get("Server") or headers_lower.get("server")
        fingerprint.powered_by = headers.get("X-Powered-By") or headers_lower.get("x-powered-by")

        for name, category, patterns, sources in self._BUILTIN_FINGERPRINTS:
            for pattern in patterns:
                matched = False
                for source in sources:
                    if source == "html" and re.search(pattern, html_lower, re.IGNORECASE):
                        matched = True
                    elif source == "header":
                        for h_key, h_val in headers_lower.items():
                            if re.search(pattern, f"{h_key}: {h_val}", re.IGNORECASE):
                                matched = True
                                break
                    elif source == "cookie" and re.search(pattern, cookie_keys, re.IGNORECASE):
                        matched = True
                    elif source == "url" and re.search(pattern, url.lower(), re.IGNORECASE):
                        matched = True
                    if matched:
                        break
                if matched:
                    tech = Technology(name=name, category=category, confidence=60)
                    fingerprint.technologies.append(tech)
                    break

        self._enrich_fingerprint(fingerprint)
        logger.info(f"[Wappalyzer:Builtin] Identified {len(fingerprint.technologies)} technologies: {fingerprint.summary()}")
        return fingerprint

    def _enrich_fingerprint(self, fp: TechFingerprint):
        """Extract summary information from identified technologies"""
        for tech in fp.technologies:
            cat = tech.category
            if cat == "cms" and fp.cms is None:
                fp.cms = tech.name
            elif cat == "language" and fp.language is None:
                fp.language = tech.name
            elif cat == "framework" and fp.framework is None:
                fp.framework = tech.name
            elif cat in ("server", "web-server") and fp.server is None:
                fp.server = tech.name
            elif cat in ("cdn", "cdn-cache") and fp.cdn is None:
                fp.cdn = tech.name
            elif cat in ("analytics", "tracking") and fp.analytics is None:
                fp.analytics = tech.name
            elif cat == "waf":
                fp.has_waf = True
                fp.waf_name = tech.name

    async def _fetch_url(self, url: str) -> Tuple[Optional[str], Dict[str, str]]:
        """Fetch HTML content and response headers for a URL"""
        try:
            import aiohttp
        except ImportError:
            return None, {}

        try:
            timeout = aiohttp.ClientTimeout(total=15)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, allow_redirects=True, ssl=False) as resp:
                    html = await resp.text()
                    headers = dict(resp.headers)
                    return html, headers
        except Exception as e:
            logger.warning(f"[Wappalyzer] Failed to fetch {url}: {e}")
            return None, {}

    def get_scan_recommendations(self, fp: TechFingerprint) -> Dict[str, List[str]]:
        """
        Generate scan recommendations based on technology stack fingerprinting

        Returns:
            {"enable": [...], "disable": [...], "focus": [...]}
        """
        rec = {"enable": [], "disable": [], "focus": []}

        # Recommendations based on language
        if fp.language == "PHP":
            rec["focus"].extend(["sqli", "lfi", "cmdi"])
            rec["enable"].append("php_specific")
        elif fp.language == "Java":
            rec["focus"].extend(["sqli", "rce", "xxe"])
            rec["enable"].append("java_deserialization")
        elif fp.language == "Node.js":
            rec["focus"].extend(["ssrf", "api"])
            rec["disable"].append("php_specific")
        elif fp.language == "Python":
            rec["focus"].extend(["ssti", "sqli"])

        # Recommendations based on CMS
        if fp.cms == "WordPress":
            rec["focus"].extend(["sqli", "xss", "lfi"])
            rec["enable"].append("wordpress_specific")
        elif fp.cms == "Drupal":
            rec["focus"].append("rce")

        # WAF detection
        if fp.has_waf:
            rec["enable"].append("waf_bypass")

        return rec

    @staticmethod
    def _guess_category(tech_name: str) -> str:
        """Guess the category based on the technology name"""
        name_lower = tech_name.lower()
        if any(k in name_lower for k in ["wordpress", "drupal", "joomla", "cms"]):
            return "cms"
        if any(k in name_lower for k in ["nginx", "apache", "iis", "tomcat"]):
            return "server"
        if any(k in name_lower for k in ["cloudflare", "cloudfront", "cdn"]):
            return "cdn"
        if any(k in name_lower for k in ["analytics", "gtag", "tongji"]):
            return "analytics"
        if any(k in name_lower for k in ["waf", "modsecurity", "mod_security"]):
            return "waf"
        if any(k in name_lower for k in ["php", "python", "ruby", "node"]):
            return "language"
        return "other"
