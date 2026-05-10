"""
Wappalyzer 集成模块
v19.2 新增：技术栈指纹识别

策略：
1. 优先使用 python-Wappalyzer（pip 包）
2. Fallback 到内置轻量指纹匹配
3. 识别结果用于优化扫描策略（跳过不相关模块）

支持：
- 服务端技术栈识别（语言/框架/CMS/CDN）
- JavaScript 库检测
- 安全工具识别（WAF/IDS）
"""
import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from ..config import ConfigManager
from ..models import Vulnerability, VulnerabilityType, Severity, Confidence


logger = logging.getLogger("wvs.integrations.wappalyzer")


@dataclass
class Technology:
    """识别到的技术信息"""
    name: str
    category: str = "unknown"
    version: Optional[str] = None
    confidence: int = 50  # 0-100
    evidence: Dict[str, List[str]] = field(default_factory=dict)


@dataclass
class TechFingerprint:
    """
    技术栈指纹结果

    包含目标网站使用的完整技术栈信息，
    可传递给扫描模块以优化扫描策略。
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
        """检查是否使用了特定技术"""
        name_lower = name.lower()
        return any(t.name.lower() == name_lower for t in self.technologies)

    def get_category(self, category: str) -> List[Technology]:
        """获取特定类别的所有技术"""
        return [t for t in self.technologies if t.category == category]

    def summary(self) -> str:
        """技术栈摘要"""
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
    Wappalyzer 集成 — 技术栈指纹识别

    识别目标网站的技术栈，指导后续扫描模块选择。
    """

    # ── 内置轻量指纹库（无 Wappalyzer 时的 fallback）──
    _BUILTIN_FINGERPRINTS = [
        # CMS
        ("WordPress", "cms", [r"wp-content", r"wp-includes", r"/wp-json/"], ["meta", "header", "html"]),
        ("Drupal", "cms", [r"Drupal", r"/sites/default/", r"/misc/drupal\.js"], ["html"]),
        ("Joomla", "cms", [r"Joomla", r"/components/com_", r"/templates/ja_"], ["html"]),
        ("Magento", "cms", [r"Magento", r"/skin/frontend/"], ["html"]),
        # 框架
        ("Laravel", "framework", [r"laravel_session", r"XSRF-TOKEN"], ["cookie", "header"]),
        ("Django", "framework", [r"csrftoken", r"django\.", r"__debug__"], ["cookie", "html"]),
        ("Ruby on Rails", "framework", [r"_session_id.*rails", r"rails/"], ["cookie", "header"]),
        ("Spring", "framework", [r"JSESSIONID", r"springframework"], ["cookie", "html"]),
        ("ASP.NET", "framework", [r"__VIEWSTATE", r"ASP\.NET", r"ASPXANONYMOUS"], ["html", "cookie", "header"]),
        ("Express", "framework", [r"x-powered-by:.*express", r"connect\.sid"], ["header", "cookie"]),
        ("Flask", "framework", [r"werkzeug", r"flask/"], ["header", "html"]),
        # 语言
        ("PHP", "language", [r"\.php", r"PHPSESSID", r"x-powered-by:.*PHP"], ["url", "cookie", "header"]),
        ("Python", "language", [r"\.py(?:$|\?)", r"python/"], ["url", "header"]),
        ("Java", "language", [r"\.jsp", r"\.do", r"JSESSIONID", r"x-powered-by:.*JSP"], ["url", "cookie", "header"]),
        ("Node.js", "language", [r"node\.js", r"express"], ["header", "html"]),
        ("Ruby", "language", [r"\.rb(?:$|\?)", r"phusion passenger"], ["url", "header"]),
        ("Go", "language", [r"go/", r"x-powered-by:.*go"], ["header"]),
        # Web 服务器
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
        """尝试初始化 python-Wappalyzer"""
        try:
            from Wappalyzer import Wappalyzer, WebPage
            self._wappalyzer = Wappalyzer.latest()
            self._WebPage = WebPage
            logger.info("[Wappalyzer] python-Wappalyzer 已加载")
        except ImportError:
            logger.info("[Wappalyzer] python-Wappalyzer 未安装，使用内置指纹库")
            self._wappalyzer = None

    @property
    def is_available(self) -> bool:
        return True  # 始终可用（内置 fallback）

    async def fingerprint(
        self,
        url: str,
        html: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> TechFingerprint:
        """
        对目标 URL 进行技术栈指纹识别

        Args:
            url: 目标 URL
            html: HTML 内容（可选，如不传则自动获取）
            headers: HTTP 响应头
            cookies: Cookie 字典

        Returns:
            技术栈指纹结果
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
        """使用 python-Wappalyzer 进行识别"""
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

            logger.info(f"[Wappalyzer] 识别到 {len(analysis)} 项技术")

        except Exception as e:
            logger.warning(f"[Wappalyzer] python-Wappalyzer 失败: {e}，回退内置")
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
        """使用内置指纹库进行识别"""
        if html is None and headers is None:
            html, headers = await self._fetch_url(url)

        html_lower = html.lower() if html else ""
        headers_lower = {k.lower(): v.lower() for k, v in (headers or {}).items()}
        cookie_keys = " ".join((cookies or {}).keys()).lower()

        # 提取响应头关键字段
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
        logger.info(f"[Wappalyzer:Builtin] 识别到 {len(fingerprint.technologies)} 项技术: {fingerprint.summary()}")
        return fingerprint

    def _enrich_fingerprint(self, fp: TechFingerprint):
        """从识别到的技术中提取摘要信息"""
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
        """获取 URL 的 HTML 和响应头"""
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
            logger.warning(f"[Wappalyzer] 获取 {url} 失败: {e}")
            return None, {}

    def get_scan_recommendations(self, fp: TechFingerprint) -> Dict[str, List[str]]:
        """
        根据技术栈指纹生成扫描建议

        Returns:
            {"enable": [...], "disable": [...], "focus": [...]}
        """
        rec = {"enable": [], "disable": [], "focus": []}

        # 根据语言推荐
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

        # 根据 CMS 推荐
        if fp.cms == "WordPress":
            rec["focus"].extend(["sqli", "xss", "lfi"])
            rec["enable"].append("wordpress_specific")
        elif fp.cms == "Drupal":
            rec["focus"].append("rce")

        # WAF 检测
        if fp.has_waf:
            rec["enable"].append("waf_bypass")

        return rec

    @staticmethod
    def _guess_category(tech_name: str) -> str:
        """根据技术名称猜测类别"""
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
