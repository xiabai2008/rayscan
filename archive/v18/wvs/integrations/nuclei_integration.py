"""WVS v18.0 - Nuclei 集成模块 v4.0

修复:
- URL 构造 bug (lstrip 破坏 URL)
- 同步 urllib 改为异步 aiohttp
- 新增 Cookie/认证支持
- 新增 Metasploitable2 专属模板
- 支持扫描已发现的 URL
- v4.0: 优先使用真实 Nuclei CLI (C:/Tools/nuclei/nuclei.exe)，fallback 到内置模板
"""
import os
import asyncio
import re
import time
import json
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse
import aiohttp


# Nuclei CLI 路径（使用原始字符串避免转义问题）
NUCLEI_CLI_PATH = Path("C:/Tools/nuclei/nuclei.exe")


@dataclass
class NucleiVulnerability:
    """Nuclei 发现的漏洞"""
    template_id: str
    name: str
    severity: str
    matched_at: str
    description: str
    cve_ids: List[str]
    cvss_score: Optional[float]


class NucleiIntegration:
    """Nuclei 集成器 - v4.0 支持 CLI + 内置模板 fallback"""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.output_dir = Path(self.config.get("output_dir", "reports/nuclei"))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = self.config.get("timeout", 8)
        self.session: Optional[aiohttp.ClientSession] = None
        self.templates = self._get_builtin_templates()
        
        # 检测 Nuclei CLI 是否可用
        self.use_cli = self._check_cli_available()
        if self.use_cli:
            print(f"[Nuclei] Using real CLI: {NUCLEI_CLI_PATH}")
        else:
            print(f"[Nuclei] CLI not found, using built-in templates ({len(self.templates)} templates)")

    def _check_cli_available(self) -> bool:
        """检查 Nuclei CLI 是否可用"""
        cli_path = str(NUCLEI_CLI_PATH)
        if os.path.exists(cli_path):
            # 验证可执行
            try:
                import subprocess
                result = subprocess.run(
                    [cli_path, "-version"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                return result.returncode == 0
            except Exception:
                pass
        return False

    # ───────────────────────────────────────────────────────────
    # 模板库（111 个，分 8 类）
    # ───────────────────────────────────────────────────────────
    def _get_builtin_templates(self) -> Dict:
        templates = {}

        # ── 1. 信息泄露 ──────────────────────────────────────
        self._add_templates(templates, "info-phpinfo", {
            "name": "PHP Info Disclosure",
            "severity": "high",
            "category": "info-disclosure",
            "paths": ["/phpinfo.php", "/info.php", "/phpversion.php",
                      "/pinfo.php", "/?a=phpinfo"],
            "keywords": ["phpinfo()", "Zend Optimizer"],
            "exclude": [],  # 必须包含的关键词
            "description": "PHP configuration information exposed",
            "cvss": 7.5
        })

        self._add_templates(templates, "info-env-file", {
            "name": "Environment File Exposure",
            "severity": "critical",
            "category": "info-disclosure",
            "paths": ["/.env", "/.env.local", "/.env.production", "/config/.env",
                      "/.env.bak", "/config.env", "/settings.env"],
            "keywords": ["APP_KEY", "DB_PASSWORD", "SECRET_KEY", "AWS_SECRET",
                         "password", "mysql", "database"],
            "description": "Environment variables with secrets exposed",
            "cvss": 9.8
        })

        self._add_templates(templates, "info-git-config", {
            "name": "Git Configuration Exposure",
            "severity": "high",
            "category": "info-disclosure",
            "paths": ["/.git/config", "/.git/HEAD", "/.git/index",
                      "/.git/refs/heads/main", "/.git/refs/heads/master"],
            "keywords": ["repositoryformatversion", "remote \"origin\""],
            "description": "Git repository configuration exposed",
            "cvss": 7.5
        })

        self._add_templates(templates, "info-git-expose", {
            "name": "Git Directory Exposure",
            "severity": "high",
            "category": "info-disclosure",
            "paths": ["/.git/", "/.git/logs/", "/.git/objects/"],
            "keywords": ["HEAD", "refs", "commit"],
            "description": ".git directory is accessible - source code may leak",
            "cvss": 7.5
        })

        self._add_templates(templates, "info-svn-config", {
            "name": "SVN Configuration Exposure",
            "severity": "high",
            "category": "info-disclosure",
            "paths": ["/.svn/entries", "/.svn/wc.db", "/.svn/format"],
            "keywords": ["dir", "svn"],
            "description": "Subversion repository exposed",
            "cvss": 7.5
        })

        self._add_templates(templates, "info-database-dump", {
            "name": "Database Dump Exposure",
            "severity": "critical",
            "category": "info-disclosure",
            "paths": ["/backup.sql", "/database.sql", "/dump.sql", "/db.sql",
                      "/data.sql", "/backup/database.sql", "/sql/backup.sql",
                      "/db_backup.sql", "/mysql.sql", "/postgres.sql"],
            "keywords": ["CREATE TABLE", "INSERT INTO", "mysqldump"],
            "description": "SQL database backup/dump file exposed",
            "cvss": 9.8
        })

        self._add_templates(templates, "info-config-backup", {
            "name": "Configuration Backup Exposed",
            "severity": "high",
            "category": "info-disclosure",
            "paths": ["/config.php.bak", "/config.bak", "/settings.php.old",
                      "/.htaccess.bak", "/wp-config.php.bak", "/database.php.old",
                      "/backup.zip", "/backup.tar.gz", "/site.tar.gz", "/www.zip",
                      "/config.php~", "/settings.php~"],
            "keywords": ["<?php", "<configuration", "<settings"],
            "description": "Configuration file backup exposed",
            "cvss": 7.5
        })

        self._add_templates(templates, "info-readme", {
            "name": "README File Exposure",
            "severity": "low",
            "category": "info-disclosure",
            "paths": ["/README.md", "/README.txt", "/readme.md", "/readme.txt",
                      "/CHANGELOG.md", "/INSTALL", "/LICENSE"],
            "keywords": [],
            "description": "README or documentation file exposed",
            "cvss": 3.0
        })

        self._add_templates(templates, "info-index-of", {
            "name": "Directory Listing Enabled",
            "severity": "medium",
            "category": "info-disclosure",
            "paths": [],  # 动态检测，不走路径
            "keywords": ["Index of /", "<title>Index of", "[To Parent Directory]"],
            "description": "Directory listing is enabled - files may be exposed",
            "cvss": 5.0
        })

        self._add_templates(templates, "info-xss-config", {
            "name": "XML External Entity (XXE)",
            "severity": "high",
            "category": "info-disclosure",
            "paths": ["/api/feed", "/data/feed.xml", "/rss", "/xmlrpc.php"],
            "keywords": [],
            "description": "XML endpoint may be vulnerable to XXE",
            "cvss": 7.5
        })

        # ── 2. 管理面板 ──────────────────────────────────────
        self._add_templates(templates, "admin-phpmyadmin", {
            "name": "phpMyAdmin Accessible",
            "severity": "high",
            "category": "admin-panel",
            "paths": ["/phpmyadmin/", "/phpMyAdmin/", "/pma/", "/dbadmin/",
                      "/mysql/", "/phpmyadmin/index.php", "/admin/sql/",
                      "/phpmyadmin/setup/"],
            "keywords": ["phpmyadmin", "phpMyAdmin", "Welcome to phpMyAdmin"],
            "description": "phpMyAdmin database management interface accessible",
            "cvss": 8.0
        })

        self._add_templates(templates, "admin-phpmyadmin-setup", {
            "name": "phpMyAdmin Setup Accessible",
            "severity": "critical",
            "category": "admin-panel",
            "paths": ["/phpmyadmin/setup/", "/phpMyAdmin/setup/",
                      "/phpmyadmin/scripts/setup.php"],
            "keywords": ["phpmyadmin", "setup"],
            "description": "phpMyAdmin setup wizard accessible - possible RCE",
            "cvss": 9.8
        })

        self._add_templates(templates, "admin-tomcat-manager", {
            "name": "Tomcat Manager Accessible",
            "severity": "critical",
            "category": "admin-panel",
            "paths": ["/manager/html", "/manager/status", "/host-manager/html",
                      "/host-manager/status", "/manager/", "/admin/"],
            "keywords": ["tomcat", "manager", "Tomcat"],
            "description": "Apache Tomcat manager interface accessible",
            "cvss": 9.8
        })

        self._add_templates(templates, "admin-webdav", {
            "name": "WebDAV Enabled",
            "severity": "medium",
            "category": "admin-panel",
            "paths": ["/webdav/", "/webdav/index.html", "/dav/", "/dav/sabre/"],
            "keywords": ["webdav", "WebDAV", "PROPFIND"],
            "description": "WebDAV enabled - may allow unauthorized file operations",
            "cvss": 5.3
        })

        self._add_templates(templates, "admin-wordpress-login", {
            "name": "WordPress Login Page",
            "severity": "info",
            "category": "cms-detect",
            "paths": ["/wp-login.php", "/wp-admin/", "/wordpress/wp-login.php",
                      "/wp/wp-login.php"],
            "keywords": ["wordpress", "wp-admin", "log-in"],
            "description": "WordPress CMS detected - login page accessible",
            "cvss": None
        })

        self._add_templates(templates, "admin-joomla", {
            "name": "Joomla CMS Detected",
            "severity": "info",
            "category": "cms-detect",
            "paths": ["/administrator/", "/joomla/administrator/",
                      "/cms/administrator/"],
            "keywords": ["joomla", "com_login"],
            "description": "Joomla CMS detected",
            "cvss": None
        })

        self._add_templates(templates, "admin-panel-generic", {
            "name": "Admin Panel Detected",
            "severity": "high",
            "category": "admin-panel",
            "paths": ["/admin/", "/admin/index.php", "/admin/login.php",
                      "/administrator/", "/backend/", "/control/", "/manage/",
                      "/admin-console/", "/cp/", "/cpanel/"],
            "keywords": ["admin", "login", "password", "username", "dashboard"],
            "description": "Administrative login panel detected",
            "cvss": 5.3
        })

        # ── 3. API 文档 ──────────────────────────────────────
        self._add_templates(templates, "api-swagger", {
            "name": "Swagger UI Exposed",
            "severity": "medium",
            "category": "api-docs",
            "paths": ["/swagger-ui.html", "/swagger-ui/", "/swagger/",
                      "/api/swagger.json", "/api-docs/", "/docs/",
                      "/api/documentation"],
            "keywords": ["swagger", "openapi", "api-documentation"],
            "description": "Swagger/OpenAPI documentation exposed",
            "cvss": 5.3
        })

        self._add_templates(templates, "api-actuator", {
            "name": "Spring Boot Actuator Exposed",
            "severity": "high",
            "category": "api-docs",
            "paths": ["/actuator/", "/actuator/env", "/actuator/health",
                      "/actuator/configprops", "/actuator/heapdump",
                      "/health", "/env", "/metrics"],
            "keywords": ["spring", "actuator", "env", "heapdump"],
            "description": "Spring Boot Actuator endpoints exposed (may leak secrets)",
            "cvss": 7.5
        })

        self._add_templates(templates, "api-graphql", {
            "name": "GraphQL Introspection Enabled",
            "severity": "medium",
            "category": "api-docs",
            "paths": ["/graphql", "/graphiql", "/graphql.php", "/playground",
                      "/api/graphql"],
            "keywords": ["schema", "introspection", "__type", "graphql"],
            "description": "GraphQL introspection enabled (schema exposed)",
            "cvss": 5.3
        })

        self._add_templates(templates, "api-redoc", {
            "name": "ReDoc API Documentation",
            "severity": "low",
            "category": "api-docs",
            "paths": ["/redoc/", "/api-reference/", "/documentation/"],
            "keywords": ["redoc", "openapi"],
            "description": "ReDoc API documentation exposed",
            "cvss": 3.7
        })

        # ── 4. Web 应用指纹 ──────────────────────────────────
        # DVWA 系列
        self._add_templates(templates, "tech-dvwa-login", {
            "name": "DVWA Login Page",
            "severity": "info",
            "category": "tech-fingerprint",
            "paths": ["/dvwa/login.php", "/dvwa/", "/DVWA/"],
            "keywords": ["dvwa", "damn vulnerable", "security level"],
            "description": "DVWA vulnerable web application detected",
            "cvss": None
        })

        self._add_templates(templates, "tech-dvwa-vulns", {
            "name": "DVWA Vulnerable Paths",
            "severity": "info",
            "category": "tech-fingerprint",
            "paths": ["/dvwa/vulnerabilities/", "/dvwa/vulnerabilities/sqli/",
                      "/dvwa/vulnerabilities/xss_r/", "/dvwa/vulnerabilities/csrf/",
                      "/dvwa/vulnerabilities/brute/", "/dvwa/vulnerabilities/fi/",
                      "/dvwa/vulnerabilities/upload/", "/dvwa/vulnerabilities/cmdi/"],
            "keywords": ["dvwa", "vulnerability", "id="],
            "description": "DVWA vulnerability modules accessible",
            "cvss": None
        })

        self._add_templates(templates, "tech-dvwa-phpinfo", {
            "name": "DVWA phpinfo",
            "severity": "high",
            "category": "info-disclosure",
            "paths": ["/dvwa/phpinfo.php"],
            "keywords": ["phpinfo"],
            "description": "DVWA phpinfo page exposed",
            "cvss": 7.5
        })

        self._add_templates(templates, "tech-dvwa-setup", {
            "name": "DVWA Setup Page",
            "severity": "high",
            "category": "info-disclosure",
            "paths": ["/dvwa/setup.php"],
            "keywords": ["dvwa", "setup"],
            "description": "DVWA setup page accessible",
            "cvss": 7.5
        })

        # Mutillidae
        self._add_templates(templates, "tech-mutillidae", {
            "name": "Mutillidae Vulnerable App",
            "severity": "info",
            "category": "tech-fingerprint",
            "paths": ["/mutillidae/", "/mutillidae/index.php",
                      "/mutillidae/login.php"],
            "keywords": ["mutillidae", "owasp", "Niklas van #"],
            "description": "Mutillidae vulnerable application detected",
            "cvss": None
        })

        self._add_templates(templates, "tech-mutillidae-pages", {
            "name": "Mutillidae Vulnerability Pages",
            "severity": "info",
            "category": "tech-fingerprint",
            "paths": ["/mutillidae/dns-lookup.php", "/mutillidae/user-info.php",
                      "/mutillidae/password-licious.php", "/mutillidae/captured-data.php",
                      "/mutillidae/registration.php", "/mutillidae/set-stealthy-sid.php",
                      "/mutillidae/html5-storage.php"],
            "keywords": ["mutillidae", "page"],
            "description": "Mutillidae specific vulnerability pages accessible",
            "cvss": None
        })

        # TWiki
        self._add_templates(templates, "tech-twiki", {
            "name": "TWiki Detected",
            "severity": "info",
            "category": "tech-fingerprint",
            "paths": ["/twiki/", "/twiki/bin/view/Main/",
                      "/twiki/bin/view/TWiki/"],
            "keywords": ["twiki", "twikiweb"],
            "description": "TWiki wiki platform detected",
            "cvss": None
        })

        # Tomcat
        self._add_templates(templates, "tech-tomcat", {
            "name": "Apache Tomcat Detected",
            "severity": "info",
            "category": "tech-fingerprint",
            "paths": ["/", "/index.jsp", "/tomcat/", "/docs/"],
            "keywords": ["apache", "tomcat"],
            "description": "Apache Tomcat web server detected",
            "cvss": None
        })

        self._add_templates(templates, "tech-tomcat-examples", {
            "name": "Tomcat Example Pages",
            "severity": "medium",
            "category": "tech-fingerprint",
            "paths": ["/examples/", "/examples/servlets/", "/examples/jsp/",
                      "/examples/servlets/servlet/SessionExample",
                      "/examples/jsp/sessions/carts.jsp"],
            "keywords": ["apache", "examples", "servlet"],
            "description": "Apache Tomcat example servlets accessible",
            "cvss": 5.0
        })

        # phpLiteAdmin
        self._add_templates(templates, "tech-phpliteadmin", {
            "name": "phpLiteAdmin Accessible",
            "severity": "high",
            "category": "admin-panel",
            "paths": ["/phpliteadmin.php", "/dbadmin/test_db.php",
                      "/admin/phpliteadmin.php", "/databases/",
                      "/db.php", "/database.php"],
            "keywords": ["phpliteadmin", "phpLiteAdmin", "Create new database"],
            "description": "phpLiteAdmin database interface accessible",
            "cvss": 8.0
        })

        # ── 5. 安全配置问题 ──────────────────────────────────
        self._add_templates(templates, "cfg-apache-status", {
            "name": "Apache Server Status Exposed",
            "severity": "medium",
            "category": "security-misconfig",
            "paths": ["/server-status", "/server-info", "/server-status?auto"],
            "keywords": ["apache", "requests", "scoreboard"],
            "description": "Apache server-status page exposed",
            "cvss": 5.3
        })

        self._add_templates(templates, "cfg-cors-misconfig", {
            "name": "CORS Misconfiguration",
            "severity": "medium",
            "category": "security-misconfig",
            "paths": [],  # 通过响应头检测
            "keywords": [],
            "header_check": True,
            "description": "CORS allows arbitrary origins",
            "cvss": 6.5
        })

        self._add_templates(templates, "cfg-printers", {
            "name": "CUPS Printer Interface",
            "severity": "low",
            "category": "security-misconfig",
            "paths": ["/printers/", "/printers/ipp"],
            "keywords": ["cups", "printer"],
            "description": "CUPS printer web interface accessible",
            "cvss": 3.7
        })

        self._add_templates(templates, "cfg-apache-examples", {
            "name": "Apache Examples Page",
            "severity": "low",
            "category": "security-misconfig",
            "paths": ["/examples/", "/examples/jsp/", "/examples/servlets/"],
            "keywords": ["apache", "examples"],
            "description": "Apache example servlets/JSP pages accessible",
            "cvss": 3.7
        })

        # ── 6. CVE ────────────────────────────────────────────
        self._add_templates(templates, "cve-php-cgi", {
            "name": "PHP CGI RCE (CVE-2012-1823)",
            "severity": "critical",
            "category": "cve",
            "paths": ["/index.php", "/cgi-bin/php", "/cgi-bin/php-cgi"],
            "keywords": [],
            "description": "PHP CGI argument injection - RCE if exposing PHP as CGI",
            "cvss": 9.8,
            "cve": ["CVE-2012-1823"]
        })

        self._add_templates(templates, "cve-tomcat-examples", {
            "name": "Tomcat Example Pages RCE (CVE-2009-3843)",
            "severity": "high",
            "category": "cve",
            "paths": ["/examples/servlets/servlet/SessionExample",
                      "/examples/jsp/sessions/carts.jsp",
                      "/examples/servlets/servlet/RequestHeaderExample"],
            "keywords": [],
            "description": "Apache Tomcat example servlets may allow session hijacking",
            "cvss": 7.5,
            "cve": ["CVE-2009-3843"]
        })

        self._add_templates(templates, "cve-drupalgeddon", {
            "name": "Drupalgeddon (CVE-2014-3704)",
            "severity": "critical",
            "category": "cve",
            "paths": ["/?q=node&destination=node", "/?q=node/1"],
            "keywords": ["drupal"],
            "description": "Drupal SQL injection (Drupageddon) - pre-auth RCE",
            "cvss": 9.3,
            "cve": ["CVE-2014-3704"]
        })

        self._add_templates(templates, "cve-wordpress-xmlrpc", {
            "name": "WordPress XMLRPC Pingback (CVE-2013-0235)",
            "severity": "medium",
            "category": "cve",
            "paths": ["/xmlrpc.php"],
            "keywords": ["xmlrpc", "pingback"],
            "description": "WordPress XMLRPC pingback may allow SSRF",
            "cvss": 6.0,
            "cve": ["CVE-2013-0235"]
        })

        self._add_templates(templates, "cve-openssh", {
            "name": "OpenSSH Security Advisory",
            "severity": "low",
            "category": "cve",
            "paths": ["/"],
            "keywords": [],
            "version_check": True,  # 需检测版本
            "description": "OpenSSH version detection",
            "cvss": None
        })

        # ── 7. 认证/会话问题 ──────────────────────────────────
        self._add_templates(templates, "auth-basic-http", {
            "name": "HTTP Basic Auth Detected",
            "severity": "low",
            "category": "auth-issue",
            "paths": [],
            "keywords": [],
            "header_check": True,
            "description": "HTTP Basic Authentication in use",
            "cvss": None
        })

        self._add_templates(templates, "auth-debug-endpoint", {
            "name": "Debug/Testing Endpoint Exposed",
            "severity": "high",
            "category": "security-misconfig",
            "paths": ["/debug/", "/debug", "/test/", "/test.php",
                      "/api/test/", "/api/debug/", "/debug.jsp",
                      "/api/v1/debug/", "/dev/"],
            "keywords": ["debug", "stack trace", "exception", "error", "traceback"],
            "description": "Debug or testing endpoint exposed",
            "cvss": 7.5
        })

        # ── 8. 数据存储服务检测 ────────────────────────────────
        self._add_templates(templates, "data-redis", {
            "name": "Redis Unauthenticated Access",
            "severity": "critical",
            "category": "service-detect",
            "paths": [],
            "keywords": [],
            "port_check": [6379],
            "description": "Redis server may be accessible without authentication",
            "cvss": 10.0
        })

        self._add_templates(templates, "data-memcached", {
            "name": "Memcached Unauthenticated Access",
            "severity": "high",
            "category": "service-detect",
            "paths": [],
            "keywords": [],
            "port_check": [11211],
            "description": "Memcached server may be accessible without authentication",
            "cvss": 7.5
        })

        self._add_templates(templates, "data-mongo", {
            "name": "MongoDB Unauthenticated Access",
            "severity": "critical",
            "category": "service-detect",
            "paths": [],
            "keywords": [],
            "port_check": [27017],
            "description": "MongoDB may be accessible without authentication",
            "cvss": 9.8
        })

        # ── 9. zico2 靶机特定 ────────────────────────────────
        self._add_templates(templates, "zico2-view-lfi", {
            "name": "zico2 LFI (Local File Inclusion)",
            "severity": "critical",
            "category": "lfi",
            "paths": ["/view.php?page=/etc/passwd", "/view.php?page=../../etc/passwd"],
            "keywords": ["root:", "daemon:"],
            "description": "Local File Inclusion in view.php - can read system files",
            "cvss": 8.1
        })

        self._add_templates(templates, "zico2-wood-www", {
            "name": "zico2 /wood/ Directory",
            "severity": "medium",
            "category": "info-disclosure",
            "paths": ["/wood/", "/wood/index.php"],
            "keywords": [],
            "description": "zico2 /wood/ directory accessible",
            "cvss": 5.0
        })

        return templates

    def _add_templates(self, templates: Dict, tid: str, spec: Dict):
        """将模板添加到库（支持一个模板多个路径）"""
        paths = spec.get("paths", [])
        keywords = spec.get("keywords", [])
        header_check = spec.get("header_check", False)
        version_check = spec.get("version_check", False)
        port_check = spec.get("port_check", [])

        if not paths and not header_check and not version_check and not port_check:
            return

        for path in paths:
            key = f"{tid}-{len(templates)}"
            templates[key] = {
                "id": tid,
                "name": spec["name"],
                "severity": spec["severity"],
                "category": spec.get("category", "info-disclosure"),
                "path": path,
                "keywords": keywords,
                "header_check": header_check,
                "version_check": version_check,
                "port_check": port_check,
                "description": spec["description"],
                "cvss": spec.get("cvss"),
                "cve": spec.get("cve", [])
            }

    # ───────────────────────────────────────────────────────────
    # 异步扫描入口
    # ───────────────────────────────────────────────────────────
    async def scan_async(
        self,
        base_url: str,
        discovered_urls: List[str] = None,
        cookies: Dict = None,
        headers: Dict = None,
        severity: List[str] = None,
        concurrency: int = 20
    ) -> List[NucleiVulnerability]:
        """
        异步扫描

        Args:
            base_url: 目标根 URL（模板路径拼接基点）
            discovered_urls: 已发现的 URL 列表（逐个检测关键词指纹）
            cookies: 会话 Cookie
            headers: 自定义请求头
            severity: 过滤严重度
            concurrency: 并发数
        """
        # 优先使用真实 CLI
        if self.use_cli:
            return await self._cli_scan_async(base_url, discovered_urls, cookies, headers, severity)
        
        # Fallback 到内置模板
        return await self._builtin_scan_async(base_url, discovered_urls, cookies, headers, severity, concurrency)

    async def _cli_scan_async(
        self,
        base_url: str,
        discovered_urls: List[str] = None,
        cookies: Dict = None,
        headers: Dict = None,
        severity: List[str] = None
    ) -> List[NucleiVulnerability]:
        """使用真实 Nuclei CLI 扫描"""
        print(f"[*] Nuclei CLI scan: {base_url}")
        
        import subprocess
        import tempfile
        
        vulns = []
        
        # 创建目标文件
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            # 写入根 URL
            f.write(base_url + "\n")
            # 写入发现的 URL
            if discovered_urls:
                for url in discovered_urls[:100]:  # 限制 100 个
                    if url.startswith("http"):
                        f.write(url + "\n")
            target_file = f.name
        
        try:
            # 构建 CLI 命令
            cmd = [
                str(NUCLEI_CLI_PATH),
                "-l", target_file,
                "-json",
                "-silent",
                "-no-color",
            ]
            
            # 严重度过滤
            if severity:
                cmd.extend(["-severity", ",".join(severity)])
            
            # Cookie
            if cookies:
                cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
                cmd.extend(["-header", f"Cookie: {cookie_str}"])
            
            # 自定义 headers
            if headers:
                for k, v in headers.items():
                    cmd.extend(["-header", f"{k}: {v}"])
            
            # 运行 CLI
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=120  # 2 分钟超时
            )
            
            # 解析 JSON 输出
            for line in stdout.decode('utf-8', errors='ignore').strip().split('\n'):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    vulns.append(NucleiVulnerability(
                        template_id=data.get("template-id", data.get("templateID", "")),
                        name=data.get("info", {}).get("name", data.get("template-id", "")),
                        severity=data.get("info", {}).get("severity", "medium"),
                        matched_at=data.get("matched-at", data.get("matched", base_url)),
                        description=data.get("info", {}).get("description", ""),
                        cve_ids=data.get("info", {}).get("cve", []) or [],
                        cvss_score=data.get("info", {}).get("cvss-score")
                    ))
                except json.JSONDecodeError:
                    continue
            
            print(f"    [Nuclei CLI] Found {len(vulns)} vulnerabilities")
            
        except asyncio.TimeoutError:
            print(f"    [Nuclei CLI] Timeout after 120s")
        except Exception as e:
            print(f"    [Nuclei CLI] Error: {e}")
        finally:
            # 清理临时文件
            try:
                os.unlink(target_file)
            except:
                pass
        
        return vulns

    async def _builtin_scan_async(
        self,
        base_url: str,
        discovered_urls: List[str] = None,
        cookies: Dict = None,
        headers: Dict = None,
        severity: List[str] = None,
        concurrency: int = 20
    ) -> List[NucleiVulnerability]:
        """使用内置模板扫描（fallback）"""
        print(f"[*] Nuclei async scan: {base_url}")

        # 修复 URL
        base_url = base_url.rstrip("/")
        if not base_url.startswith("http"):
            base_url = "http://" + base_url

        base_parsed = urlparse(base_url)
        base_root = f"{base_parsed.scheme}://{base_parsed.netloc}"

        connector = aiohttp.TCPConnector(limit=concurrency, limit_per_host=5)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        headers = headers or {}

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            self.session = session
            vulns = []

            # 1) CORS 头检测（仅一次）
            await self._check_cors(session, base_url, vulns, headers)

            # 2) 准备 URL 列表
            unique_urls = [base_url]
            if discovered_urls:
                seen = {base_url}
                for u in discovered_urls[:50]:
                    if u.startswith("http"):
                        norm = u.split("#")[0].split("?")[0].rstrip("/")
                    else:
                        norm = (base_url + "/" + u.lstrip("/")).split("#")[0].split("?")[0].rstrip("/")
                    if norm not in seen and norm.startswith(base_root):
                        seen.add(norm)
                        unique_urls.append(norm)

            # 3) 按 severity 过滤模板
            filtered = {
                k: v for k, v in self.templates.items()
                if (not severity or v["severity"] in severity)
                and not v.get("header_check")
                and not v.get("version_check")
                and not v.get("port_check")
            }

            print(f"    Scanning {len(unique_urls)} URLs × {len(filtered)} path templates")

            # 4) 构建任务
            tasks = []
            for url in unique_urls:
                for tk, tv in filtered.items():
                    # 核心修复：模板路径只拼在 base_root（根域名）上
                    # discovered_urls 只做页面内容关键词匹配，不做路径拼接
                    if url == base_url or url == base_root:
                        # 根 URL：正常拼接模板路径
                        task = self._check_template(session, base_root, tk, tv, headers, cookies)
                    else:
                        # 子 URL：只检测该页面内容是否匹配关键词（不拼接路径）
                        task = self._check_url_content(session, url, tk, tv, headers, cookies)
                    tasks.append(task)

            # 5) 并发执行
            for i in range(0, len(tasks), concurrency):
                batch = tasks[i:i + concurrency]
                results = await asyncio.gather(*batch, return_exceptions=True)
                for r in results:
                    if isinstance(r, NucleiVulnerability):
                        vulns.append(r)

        self.session = None
        print(f"[*] Nuclei found: {len(vulns)} vulnerabilities")
        return vulns

    async def _check_template(
        self,
        session: aiohttp.ClientSession,
        base: str,
        tk: str,
        tv: Dict,
        headers: Dict,
        cookies: Dict = None
    ) -> Optional[NucleiVulnerability]:
        """检查单个模板（路径拼接模式 — 仅用于根 URL）"""
        path = tv["path"]
        check_url = base + path if path.startswith("/") else base + "/" + path

        try:
            req_headers = dict(headers)
            req_headers["User-Agent"] = "Mozilla/5.0 (compatible; WVS/18.0)"
            if cookies:
                req_headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())

            async with session.get(check_url, headers=req_headers,
                                   allow_redirects=True) as resp:
                status = resp.status
                body = await resp.text(errors="ignore")

                if status == 200 and body and len(body) > 50:
                    keywords = tv.get("keywords", [])
                    matched = True
                    if keywords:
                        matched = any(kw.lower() in body.lower() for kw in keywords)

                    if matched:
                        return NucleiVulnerability(
                            template_id=tk,
                            name=tv["name"],
                            severity=tv["severity"],
                            matched_at=check_url,
                            description=tv["description"],
                            cve_ids=tv.get("cve", []),
                            cvss_score=tv.get("cvss")
                        )
        except Exception:
            pass

        return None

    async def _check_url_content(
        self,
        session: aiohttp.ClientSession,
        url: str,
        tk: str,
        tv: Dict,
        headers: Dict,
        cookies: Dict = None
    ) -> Optional[NucleiVulnerability]:
        """
        检查已发现 URL 是否匹配模板 — 页面级精确匹配
        
        只在 URL 路径本身就与模板路径匹配时才做内容检测，
        避免用泛关键词在所有子页面产生误报。
        """
        url_parsed = urlparse(url)
        url_path = url_parsed.path.rstrip("/") + "/"

        # 模板路径列表
        template_paths = tv.get("path", "")
        # 取模板 ID 的第一部分作为路径族
        template_id = tv.get("id", tk)

        # 检查 URL 路径是否与模板路径相关
        # 只在 URL 路径明确匹配模板路径时才检测
        path_list = self._get_template_paths(tv)
        is_path_match = False
        for tp in path_list:
            tp_clean = tp.rstrip("/") + "/"
            # 精确匹配或子路径匹配
            if url_path == tp_clean or url_path.startswith(tp_clean):
                is_path_match = True
                break

        if not is_path_match:
            return None

        # URL 路径匹配 — 做关键词验证
        keywords = tv.get("keywords", [])
        try:
            req_headers = dict(headers)
            req_headers["User-Agent"] = "Mozilla/5.0 (compatible; WVS/18.0)"
            if cookies:
                req_headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())

            async with session.get(url, headers=req_headers,
                                   allow_redirects=True) as resp:
                if resp.status != 200:
                    return None
                body = await resp.text(errors="ignore")
                if not body or len(body) < 50:
                    return None

                # 关键词验证
                if keywords:
                    matched = any(kw.lower() in body.lower() for kw in keywords)
                    if not matched:
                        return None

                return NucleiVulnerability(
                    template_id=tk,
                    name=tv["name"],
                    severity=tv["severity"],
                    matched_at=url,
                    description=tv["description"],
                    cve_ids=tv.get("cve", []),
                    cvss_score=tv.get("cvss")
                )
        except Exception:
            pass

        return None

    def _get_template_paths(self, tv: Dict) -> List[str]:
        """从模板 spec 提取路径列表"""
        # 原始模板 spec 中存储的是单路径，需要从模板 ID 推断
        path = tv.get("path", "")
        if path:
            return [path]
        return []

    async def _check_cors(
        self,
        session: aiohttp.ClientSession,
        url: str,
        vulns: List[NucleiVulnerability],
        headers: Dict
    ) -> None:
        """检查 CORS 配置"""
        try:
            req_headers = dict(headers)
            req_headers["User-Agent"] = "Mozilla/5.0 (compatible; WVS/18.0)"
            req_headers["Origin"] = "https://evil.com"
            async with session.get(url, headers=req_headers) as resp:
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                if acao == "*" or acao == "https://evil.com":
                    vulns.append(NucleiVulnerability(
                        template_id="cfg-cors-misconfig",
                        name="CORS Misconfiguration",
                        severity="medium",
                        matched_at=url,
                        description=f"Access-Control-Allow-Origin: {acao}",
                        cve_ids=[],
                        cvss_score=6.5
                    ))
        except Exception:
            pass

    def scan(
        self,
        url: str,
        discovered_urls: List[str] = None,
        cookies: Dict = None,
        headers: Dict = None,
        severity: List[str] = None
    ) -> List[NucleiVulnerability]:
        """同步包装"""
        return asyncio.run(self.scan_async(url, discovered_urls, cookies, headers, severity))

    # ───────────────────────────────────────────────────────────
    # CLI 兼容
    # ───────────────────────────────────────────────────────────
    async def _cli_scan(self, url: str, severity: List[str] = None) -> List[NucleiVulnerability]:
        return await self.scan_async(url, severity=severity)


def quick_scan(url: str, severity: List[str] = None, cookies: Dict = None) -> Dict:
    """快速扫描（同步入口）"""
    integration = NucleiIntegration()
    results = integration.scan(url, severity=severity, cookies=cookies)
    return {
        "url": url,
        "vulnerabilities": [
            {"template_id": v.template_id, "name": v.name, "severity": v.severity,
             "matched_at": v.matched_at, "description": v.description,
             "cve_ids": v.cve_ids, "cvss": v.cvss_score}
            for v in results
        ],
        "summary": {
            "total": len(results),
            "critical": sum(1 for v in results if v.severity == "critical"),
            "high": sum(1 for v in results if v.severity == "high"),
            "medium": sum(1 for v in results if v.severity == "medium"),
            "low": sum(1 for v in results if v.severity == "low"),
            "info": sum(1 for v in results if v.severity == "info"),
        }
    }
