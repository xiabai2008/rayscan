"""
Subdomain Enumeration Module — 子域名枚举与资产发现

通过 DNS 解析、证书透明度、搜索引擎等方式发现目标子域名。
"""

import asyncio
import logging
import socket
from typing import List, Optional, Set
from urllib.parse import urlparse

from ...models import Confidence, ScanTarget, Severity, Vulnerability
from ..base import DetectionModule, ModuleInfo, register_module

logger = logging.getLogger("wvs.module.subdomain")

# 常见子域名字典（Top 100）
COMMON_SUBDOMAINS = [
    "www",
    "mail",
    "admin",
    "api",
    "blog",
    "dev",
    "test",
    "cdn",
    "static",
    "app",
    "m",
    "mobile",
    "wap",
    "oa",
    "portal",
    "vpn",
    "web",
    "smtp",
    "pop3",
    "imap",
    "ns1",
    "ns2",
    "ns3",
    "mx",
    "mail2",
    "mail1",
    "cloud",
    "git",
    "svn",
    "jenkins",
    "jira",
    "confluence",
    "wiki",
    "download",
    "upload",
    "files",
    "img",
    "image",
    "img1",
    "img2",
    "video",
    "tv",
    "live",
    "stream",
    "chat",
    "support",
    "help",
    "forum",
    "news",
    "status",
    "monitor",
    "report",
    "analytics",
    "track",
    "tracking",
    "pay",
    "payment",
    "order",
    "shop",
    "store",
    "cart",
    "checkout",
    "sso",
    "login",
    "auth",
    "oauth",
    "openid",
    "api2",
    "api3",
    "api-v1",
    "api-v2",
    "graphql",
    "backup",
    "backup1",
    "backup2",
    "db",
    "database",
    "sql",
    "redis",
    "mq",
    "rabbitmq",
    "kafka",
    "es",
    "elasticsearch",
    "stage",
    "staging",
    "pre",
    "preprod",
    "beta",
    "alpha",
    "demo",
    "prod",
    "production",
    "release",
    "new",
    "old",
    "v1",
    "v2",
    "erp",
    "crm",
    "scm",
    "bi",
    "hrm",
    "hr",
    "boss",
    "static1",
    "static2",
    "static3",
    "res",
    "resource",
    "assets",
    "s1",
    "s2",
    "s3",
    "a",
    "b",
    "c",
    "d",
    "e",
    "f",
    "g",
    "h",
]

# 证书透明度查询端点
CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"


@register_module
class SubdomainDetector(DetectionModule):
    """子域名枚举模块"""

    @classmethod
    def get_info(cls) -> ModuleInfo:
        return ModuleInfo(
            name="subdomain",
            description="子域名枚举 — DNS爆破/证书透明度",
            author="RayScan Team",
            version="1.0.0",
            enabled_by_default=False,
            tags=["recon", "subdomain", "asset-discovery"],
        )

    async def _scan_impl(self, target: ScanTarget) -> List[Vulnerability]:
        url = target.url.rstrip("/")
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split("/")[0]

        # 提取纯域名
        domain = domain.split(":")[0]
        if domain.startswith("www."):
            domain = domain[4:]

        if not domain or "." not in domain:
            return []

        vulnerabilities: List[Vulnerability] = []
        found_subdomains: Set[str] = set()

        self.logger.info(f"[Subdomain] 开始枚举: {domain}")

        # 1. 证书透明度查询
        crt_subdomains = await self._crt_sh_enum(domain)
        found_subdomains.update(crt_subdomains)

        # 2. DNS 爆破
        dns_subdomains = await self._dns_bruteforce(domain)
        found_subdomains.update(dns_subdomains)

        if found_subdomains:
            vuln = self._create_vuln(
                url=url,
                param=None,
                param_type="query",
                method="GET",
                payload="",
                vuln_type="info_disclosure",
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                evidence=f"发现 {len(found_subdomains)} 个子域名",
                description=f"目标 {domain} 发现 {len(found_subdomains)} 个子域名: {', '.join(sorted(found_subdomains)[:20])}",
                recommendation="子域名可能扩大攻击面，建议统一管理",
                context={"subdomains": sorted(found_subdomains), "domain": domain, "total": len(found_subdomains)},
            )
            vulnerabilities.append(vuln)

        return vulnerabilities

    async def _crt_sh_enum(self, domain: str) -> Set[str]:
        """通过 crt.sh 证书透明度查询子域名"""
        subdomains: Set[str] = set()
        try:
            import httpx

            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            async with httpx.AsyncClient(timeout=15, verify=False) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    for entry in data[:100]:
                        name = entry.get("name_value", "")
                        if name:
                            for sub in name.split("\n"):
                                sub = sub.strip().lower()
                                if sub.endswith("." + domain) or sub == domain:
                                    if sub != domain and "*" not in sub:
                                        subdomains.add(sub)
        except Exception as e:
            logger.debug(f"[Subdomain] crt.sh 查询失败: {e}")
        return subdomains

    async def _dns_bruteforce(self, domain: str) -> Set[str]:
        """DNS 爆破子域名"""
        found: Set[str] = set()
        sem = asyncio.Semaphore(20)  # 并发限制

        async def check_sub(sub: str) -> Optional[str]:
            async with sem:
                try:
                    full = f"{sub}.{domain}"
                    addr = await asyncio.wait_for(
                        asyncio.get_event_loop().getaddrinfo(full, 80),
                        timeout=3,
                    )
                    if addr:
                        return full
                except (socket.gaierror, asyncio.TimeoutError, OSError):
                    pass
            return None

        tasks = [check_sub(sub) for sub in COMMON_SUBDOMAINS]
        results = await asyncio.gather(*tasks)
        found = {r for r in results if r}
        logger.info(f"[Subdomain] DNS爆破: 发现 {len(found)} 个")
        return found
