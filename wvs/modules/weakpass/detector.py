"""
Weak Password Detection Module — 弱口令检测

检测常见服务的默认密码/弱口令。
根据本地 08-破解字典/ 的资源生成检测字典。
"""

import logging
from typing import List, Optional
from urllib.parse import urljoin

from ...models import Confidence, ScanTarget, Severity, Vulnerability
from ..base import DetectionModule, ModuleInfo, register_module

logger = logging.getLogger("wvs.module.weakpass")

# 常见弱口令组合
COMMON_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "123456"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "root"),
    ("admin", "1234"),
    ("admin", "12345"),
    ("admin", "123"),
    ("admin", "pass"),
    ("root", "root"),
    ("root", "admin"),
    ("root", "123456"),
    ("root", "toor"),
    ("root", "password"),
    ("test", "test"),
    ("test", "123456"),
    ("user", "user"),
    ("user", "123456"),
    ("user", "password"),
    ("guest", "guest"),
    ("guest", ""),
    ("demo", "demo"),
    ("demo", "123456"),
    ("manager", "manager"),
    ("manager", "123456"),
    ("administrator", "administrator"),
    ("administrator", "admin"),
    ("tomcat", "tomcat"),
    ("tomcat", "s3cret"),
    ("jenkins", "jenkins"),
    ("jenkins", "admin"),
    ("weblogic", "weblogic"),
    ("weblogic", "Oracle@123"),
    ("oracle", "oracle"),
    ("oracle", "admin"),
    ("sa", "sa"),
    ("sa", "123456"),
    ("sa", "password"),
    ("postgres", "postgres"),
    ("mysql", "mysql"),
    ("root", ""),
]

# 常见登录路径
LOGIN_PATHS = [
    "/login",
    "/admin",
    "/admin/login",
    "/admin/login.php",
    "/wp-login.php",
    "/administrator",
    "/manager",
    "/user/login",
    "/api/login",
    "/auth/login",
    "/admin/admin.php",
    "/login.jsp",
    "/login.aspx",
    "/phpmyadmin/",
    "/phpmyadmin/index.php",
]


@register_module
class WeakPasswordDetector(DetectionModule):
    """弱口令检测模块"""

    @classmethod
    def get_info(cls) -> ModuleInfo:
        return ModuleInfo(
            name="weakpass",
            description="弱口令检测 — 常见服务默认口令/Web登录弱口令",
            author="RayScan Team",
            version="1.0.0",
            enabled_by_default=False,
            tags=["bruteforce", "weak-password", "auth"],
        )

    async def _scan_impl(self, target: ScanTarget) -> List[Vulnerability]:
        url = target.url.rstrip("/")
        vulnerabilities: List[Vulnerability] = []

        parsed = url.split("://")[-1] if "://" in url else url
        base = f"{url.split('://')[0]}://{parsed.split('/')[0]}" if "://" in url else f"http://{parsed.split('/')[0]}"

        # 检查常见登录路径
        for path in LOGIN_PATHS:
            login_url = urljoin(base, path)
            vuln = await self._try_login_form(login_url)
            if vuln:
                vulnerabilities.append(vuln)

        # 检查 phpMyAdmin
        phpmyadmin_url = urljoin(base, "/phpmyadmin/")
        vuln = await self._try_phpmyadmin(phpmyadmin_url)
        if vuln:
            vulnerabilities.append(vuln)

        # 检查 Tomcat Manager
        tomcat_url = urljoin(base, "/manager/html")
        vuln = await self._try_tomcat_mgr(tomcat_url)
        if vuln:
            vulnerabilities.append(vuln)

        return vulnerabilities

    async def _try_login_form(self, login_url: str) -> Optional[Vulnerability]:
        """尝试表单登录弱口令"""
        for username, password in COMMON_CREDENTIALS[:10]:
            try:
                resp = await self._send_request(
                    "POST",
                    login_url,
                    {
                        "username": username,
                        "password": password,
                        "log": username,
                        "pwd": password,
                        "user_login": username,
                        "user_pass": password,
                    },
                )
                if resp:
                    body = resp.get("text", "").lower()
                    status = resp.get("status_code", 0)
                    success_markers = ["welcome", "dashboard", "logout", "admin", "profile"]
                    fail_markers = ["invalid", "failed", "error", "incorrect", "wrong"]

                    if status == 200 and any(m in body for m in success_markers):
                        if not any(m in body for m in fail_markers):
                            return self._create_vuln(
                                url=login_url,
                                param=None,
                                param_type="body",
                                method="POST",
                                payload=f"{username}:{password}",
                                vuln_type="weak_password",
                                severity=Severity.CRITICAL,
                                confidence=Confidence.HIGH,
                                evidence=f"弱口令: {username}/{password}",
                                description=f"登录页面 {login_url} 存在弱口令: {username}/{password}",
                                recommendation="更换强密码，启用多因素认证",
                            )
            except Exception:
                continue
        return None

    async def _try_phpmyadmin(self, url: str) -> Optional[Vulnerability]:
        """尝试 phpMyAdmin 默认口令"""
        for username, password in COMMON_CREDENTIALS[:15]:
            try:
                resp = await self._send_request(
                    "POST",
                    url,
                    {
                        "pma_username": username,
                        "pma_password": password,
                        "server": "1",
                        "lang": "en",
                    },
                )
                if resp:
                    body = resp.get("text", "").lower()
                    if "phpmyadmin" in body and ("navigation" in body or "server" in body):
                        if "cannot" not in body and "denied" not in body:
                            return self._create_vuln(
                                url=url,
                                param=None,
                                param_type="body",
                                method="POST",
                                payload=f"{username}:{password}",
                                vuln_type="weak_password",
                                severity=Severity.CRITICAL,
                                confidence=Confidence.HIGH,
                                evidence=f"phpMyAdmin 弱口令: {username}/{password}",
                                description="phpMyAdmin 使用弱口令",
                                recommendation="更换强密码或限制访问",
                            )
            except Exception:
                continue
        return None

    async def _try_tomcat_mgr(self, url: str) -> Optional[Vulnerability]:
        """尝试 Tomcat Manager 默认口令"""
        import base64

        for username, password in COMMON_CREDENTIALS[:10]:
            try:
                auth = base64.b64encode(f"{username}:{password}".encode()).decode()
                resp = await self._send_request("GET", url, {}, headers={"Authorization": f"Basic {auth}"})
                if resp and resp.get("status_code") == 200:
                    body = resp.get("text", "").lower()
                    if "tomcat" in body and ("manager" in body or "applications" in body):
                        return self._create_vuln(
                            url=url,
                            param=None,
                            param_type="header",
                            method="GET",
                            payload=f"{username}:{password}",
                            vuln_type="weak_password",
                            severity=Severity.CRITICAL,
                            confidence=Confidence.HIGH,
                            evidence=f"Tomcat Manager 弱口令: {username}/{password}",
                            description="Tomcat Manager 使用弱口令",
                            recommendation="更换强密码或限制访问",
                        )
            except Exception:
                continue
        return None
