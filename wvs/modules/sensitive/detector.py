"""
Sensitive Information Disclosure Detection Module
Detects: source code leaks, configuration file leaks, backup files, sensitive directories, Git/SVN leaks
"""

import logging
import re
from typing import List
from urllib.parse import urlparse

from ...models import Confidence, ScanTarget, Severity, Vulnerability, VulnerabilityType
from ..base import DetectionModule, ModuleInfo, register_module

logger = logging.getLogger("wvs.module.sensitive")


@register_module
class SensitiveDetector(DetectionModule):
    """
    Sensitive Information Disclosure Detection Module

    Detection strategies:
    1. Backup files (.bak, .old, .zip, etc.)
    2. Configuration files (.env, config.php, web.config, etc.)
    3. Source code leaks (.git, .svn, .DS_Store)
    4. Sensitive directories (admin, backup, test, etc.)
    5. Sensitive information patterns (API keys, passwords, etc.)
    """

    # High priority paths (tested first)
    HIGH_PRIORITY_PATHS = [
        # Git leaks (common and high risk)
        "/.git/config",
        "/.git/HEAD",
        # Configuration files (common sensitive information)
        "/.env",
        "/.env.local",
        "/.env.production",
        "/wp-config.php",
        "/config.php",
        "/database.yml",
        "/settings.py",
        # Backup files
        "/backup.sql",
        "/database.sql",
        "/backup.zip",
        # Install directories (should not be accessible after installation)
        "/install/",
        "/install/index.php",
        "/setup/",
        "/setup/index.php",
        "/upgrade/",
        "/update/",
    ]

    # P11: Default credential targets for Metasploitable2 common services
    DEFAULT_CREDENTIAL_TARGETS = [
        # URL pattern, login method, credential pairs, success marker
        (
            "/phpMyAdmin/index.php",
            "POST",
            [
                {"pma_username": "root", "pma_password": ""},
                {"pma_username": "root", "pma_password": "root"},
                {"pma_username": "admin", "pma_password": ""},
            ],
            ["phpMyAdmin", "Server:", "Database", "localhost"],
        ),
        (
            "/dvwa/login.php",
            "POST",
            [
                {"username": "admin", "password": "password", "Login": "Login"},
            ],
            ["Welcome", "Damn Vulnerable", "logout"],
        ),
        (
            "/mutillidae/index.php?page=login.php",
            "POST",
            [
                {"username": "admin", "password": "adminpass"},
                {"username": "admin", "password": "password"},
            ],
            ["logged-in", "Welcome", "logout"],
        ),
    ]

    # Sensitive file paths (deduplicated compact version)
    SENSITIVE_PATHS = list(
        set(
            [
                # === Backup files ===
                "/backup.zip",
                "/backup.tar.gz",
                "/backup.sql",
                "/backup.tar",
                "/db_backup.sql",
                "/database.sql",
                "/dump.sql",
                "/data.sql",
                "/www.zip",
                "/www.tar.gz",
                "/web.zip",
                "/site.zip",
                "/html.zip",
                "/backup/",
                "/backups/",
                "/backup.bak",
                "/database.bak",
                "/.bak",
                "/.old",
                "/.swp",
                "/.tmp",
                # === Configuration files ===
                "/.env",
                "/.env.local",
                "/.env.production",
                "/.env.backup",
                "/config.php",
                "/config.php.bak",
                "/config.inc.php",
                "/configuration.php",
                "/wp-config.php",
                "/wp-config.php.bak",
                "/web.config",
                "/app.config",
                "/settings.py",
                "/local_settings.py",
                "/database.php",
                "/db.php",
                "/db_config.php",
                "/config.ini",
                "/config.xml",
                "/config.txt",
                "/.htpasswd",
                "/.htaccess",
                "/httpd.conf",
                "/nginx.conf",
                "/apache2.conf",
                "/php.ini",
                "/my.cnf",
                "/my.ini",
                "/application.yml",
                "/application.properties",
                "/config/database.yml",
                "/settings.yml",
                "/database.yml",
                "/package.json",
                "/composer.json",
                "/requirements.txt",
                # === Source code/VCS leaks ===
                "/.git/config",
                "/.git/HEAD",
                "/.git/objects/",
                "/.git/",
                "/.gitignore",
                "/.gitattributes",
                "/.svn/",
                "/.svn/entries",
                "/.svn/wc.db",
                "/.hg/",
                "/.bzr/",
                "/.DS_Store",
                "/.idea/",
                "/.idea/workspace.xml",
                "/.vscode/",
                "/.vscode/settings.json",
                "/__pycache__/",
                "/node_modules/",
                "/vendor/",
                # === Sensitive directories ===
                "/admin/",
                "/administrator/",
                "/admin/login",
                "/wp-admin/",
                "/wp-login.php",
                "/login.php",
                "/login/",
                "/login.html",
                "/signin",
                "/auth/",
                "/auth/login",
                "/manager/",
                "/management/",
                "/cpanel/",
                "/phpmyadmin/",
                "/phpMyAdmin/",
                "/pma/",
                "/adminer.php",
                "/api/",
                "/api/v1/",
                "/api/v2/",
                "/swagger/",
                "/swagger-ui/",
                "/swagger-ui.html",
                "/api-docs/",
                "/graphql/",
                "/graphiql/",
                "/test/",
                "/tests/",
                "/debug/",
                "/tmp/",
                "/temp/",
                "/logs/",
                "/old/",
                "/archive/",
                "/.well-known/",
                "/.jenkins/",
                "/jenkins/",
                "/console/",
                "/backend/",
                "/actuator/",
                "/actuator/health",
                "/actuator/env",
                # === Log files ===
                "/error.log",
                "/access.log",
                "/debug.log",
                "/app.log",
                "/server.log",
                # === CMS/Framework ===
                "/wp-content/",
                "/wp-includes/",
                "/uploads/",
                "/upload/",
                "/media/",
                "/images/",
                # === Other sensitive files ===
                "/robots.txt",
                "/sitemap.xml",
                "/security.txt",
                "/.well-known/security.txt",
                "/crossdomain.xml",
                "/clientaccesspolicy.xml",
                "/WEB-INF/",
                "/WEB-INF/web.xml",
                "/META-INF/",
                "/META-INF/context.xml",
                "/server-status",
                "/server-info",
                "/server-info/",
            ]
        )
    )

    # Sensitive information regex patterns (extended version)
    SENSITIVE_PATTERNS = {
        # Keys
        "aws_access_key": (r"AKIA[0-9A-Z]{16}", Severity.HIGH),
        "aws_secret_key": (r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+=]{40}['\"]", Severity.HIGH),
        "github_token": (r"ghp_[0-9a-zA-Z]{36}", Severity.HIGH),
        "ghp_token_v2": (r"ghp_[0-9a-zA-Z]{36}|gho_[0-9a-zA-Z]{36}", Severity.HIGH),
        "slack_token": (r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}", Severity.HIGH),
        "google_api_key": (r"AIza[0-9A-Za-z-_]{35}", Severity.HIGH),
        "stripe_key": (r"sk_live_[0-9a-zA-Z]{24,}", Severity.CRITICAL),
        "stripe_pub_key": (r"pk_live_[0-9a-zA-Z]{24,}", Severity.HIGH),
        "mailgun_key": (r"key-[0-9a-zA-Z]{32}", Severity.HIGH),
        "twilio_key": (r"SK[0-9a-fA-F]{32}", Severity.HIGH),
        "sendgrid_key": (r"SG\.[0-9a-zA-Z_-]{22}\.[0-9a-zA-Z_-]{43}", Severity.HIGH),
        "private_key": (r"-----BEGIN (RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----", Severity.CRITICAL),
        "facebook_token": (r"EAACEdEose0cBA[0-9A-Za-z]+", Severity.HIGH),
        # Credentials — P10: exclude HTML attribute context (type="password", name="passwd")
        "password_plain": (
            r"(?i)(?:^\s*|[^{])(password|passwd|pwd|pass)\s*[:=]\s*['\"]([^'\"]{6,})['\"]",
            Severity.MEDIUM,
        ),
        "connection_string": (r"(?i)(connection|conn|string)[\s:=]+['\"][^'\"]{10,}['\"]", Severity.MEDIUM),
        "jwt_token": (r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*", Severity.MEDIUM),
        "bearer_token": (r"Bearer\s+[a-zA-Z0-9_-]{20,}", Severity.MEDIUM),
        "basic_auth": (r"Basic\s+[A-Za-z0-9+/]+=*", Severity.MEDIUM),
        # Database connections
        "mysql_conn": (r"mysql://[^:]+:[^@]+@[^/]+/\w+", Severity.HIGH),
        "postgres_conn": (r"postgresql://[^:]+:[^@]+@[^/]+/\w+", Severity.HIGH),
        "mongodb_conn": (r"mongodb://[^:]+:[^@]+@[^/]+/\w+", Severity.HIGH),
        "redis_conn": (r"redis://[^:]*:[^@]+@[^:]+:\d+", Severity.HIGH),
        "mssql_conn": (r"Server=[^;]+;.*Password=[^;]+", Severity.HIGH),
        "oracle_conn": (r"\/\/[^\/]+\/[^\s\"']+", Severity.MEDIUM),
        # Certificates/CA
        "client_cert": (r"-----BEGIN CERTIFICATE-----", Severity.HIGH),
        # AWS
        "aws_session": (r"aws_session_token", Severity.HIGH),
        # IP whitelist/SECRET
        "secret_key": (r"(?i)(secret|token|api)[_-]?key[\s:=]+['\"][0-9a-zA-Z_-]{16,}['\"]", Severity.MEDIUM),
        # Cloud metadata
        "cloud_meta": (r"169\.254\.169\.254", Severity.HIGH),
    }

    @classmethod
    def get_info(cls) -> ModuleInfo:
        return ModuleInfo(
            name="sensitive",
            description="Sensitive Information Disclosure detection (backup files, configs, source code leaks)",
            author="WVS Team",
            version="1.0.0",
            enabled_by_default=True,
            tags=["info-disclosure", "backup", "config", "git", "sensitive"],
        )

    async def _scan_impl(self, target: ScanTarget) -> List[Vulnerability]:
        """
        Sensitive information detection main logic
        """
        parsed = urlparse(target.url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # P12: Host-level cache — sensitive paths only depend on base_url,
        # not individual endpoint params. Re-scanning from every endpoint
        # produces duplicate findings that the scanner must re-dedup.
        if not hasattr(self, "_scanned_hosts"):
            self._scanned_hosts: set = set()
        if base_url in self._scanned_hosts:
            return []
        self._scanned_hosts.add(base_url)

        vulns: List[Vulnerability] = []

        # 1. Detect sensitive paths
        path_vulns = await self._detect_sensitive_paths(base_url)
        vulns.extend(path_vulns)

        # 2. Detect sensitive information in response
        content_vulns = await self._detect_sensitive_content(target)
        vulns.extend(content_vulns)

        # P11: 3. Detect default credentials (phpMyAdmin, DVWA, Mutillidae, etc.)
        cred_vulns = await self._detect_default_credentials(base_url)
        vulns.extend(cred_vulns)

        # P8: Post-dedup — merge same-type findings on same host to reduce flood
        vulns = self._dedup_sensitive_vulns(vulns)

        return vulns

    @staticmethod
    def _dedup_sensitive_vulns(vulns: List[Vulnerability]) -> List[Vulnerability]:
        """P9: Aggressively dedup info disclosure on same host.
        Collapse same path + different parameter into one finding.
        Same base URL + same severity + same evidence type -> keep the most specific."""
        if len(vulns) <= 1:
            return vulns

        # Group by (normalized_url, severity, evidence_category)
        groups: dict = {}
        for v in vulns:
            # P9: Normalize URL — strip query params, fragment, and dynamic path segments
            norm_url = SensitiveDetector._normalize_sensitive_url(v.url or "")
            evidence_cat = ""
            if v.evidence:
                ev = v.evidence[:120]
                if "Path accessible" in ev:
                    evidence_cat = "path_accessible:" + norm_url
                elif "Pattern matched:" in ev:
                    evidence_cat = "pattern:" + ev.split("Pattern matched:")[-1].split("(")[0].strip()[:40]
                elif "Server header" in ev:
                    evidence_cat = "server_header:" + norm_url
                elif "Sensitive file exposed" in ev:
                    evidence_cat = "file:" + ev.split("Sensitive file exposed:")[-1][:40]
                else:
                    evidence_cat = ev[:50]
            key = (norm_url, v.severity.value, evidence_cat)
            if key not in groups:
                groups[key] = v
            else:
                existing = groups[key]
                # Keep the more specific (longer evidence) + higher confidence
                if len(v.evidence or "") > len(existing.evidence or "") or Confidence._member_map_.get(
                    v.confidence.value, 0
                ) > Confidence._member_map_.get(existing.confidence.value, 0):
                    groups[key] = v
        return list(groups.values())

    @staticmethod
    def _normalize_sensitive_url(url: str) -> str:
        """P9: Normalize URL for dedup — strip params, fragments, trailing slashes."""
        u = url.split("?")[0].split("#")[0].rstrip("/")
        return u

    async def _detect_sensitive_paths(self, base_url: str) -> List[Vulnerability]:
        """Detect if sensitive paths exist (prioritize high-value paths, limit probe count, stop after 3 hits)"""
        vulns: List[Vulnerability] = []

        # Prioritize high-priority paths + first 30 from deduplicated SENSITIVE_PATHS
        hp_set = set(self.HIGH_PRIORITY_PATHS)
        extra_paths = [p for p in self.SENSITIVE_PATHS if p not in hp_set][:30]
        test_paths = self.HIGH_PRIORITY_PATHS + extra_paths

        for path in test_paths:
            try:
                url = base_url + path
                resp = await self._active_session.get(url, timeout=5, follow_redirects=False)

                if resp.status_code != 200:
                    continue
                if len(resp.text) < 50:
                    continue

                # P5: Require content evidence — not just "path returned 200"
                if not self._has_sensitive_content(path, resp.text):
                    continue

                severity = self._get_path_severity(path)

                vulns.append(
                    Vulnerability(
                        type=VulnerabilityType.INFO_DISCLOSURE,
                        title=f"Sensitive Path Exposed: {path}",
                        url=url,
                        severity=severity,
                        confidence=Confidence.HIGH,
                        evidence=f"Path accessible with sensitive content (status: {resp.status_code}, size: {len(resp.text)} bytes)",
                        description=f"Sensitive path '{path}' is publicly accessible and contains recognizable sensitive content.",
                        impact="Information disclosure, potential credential/source code exposure.",
                        recommendation=f"Restrict access to '{path}' or remove it from public access.",
                        module="sensitive",
                    )
                )

                # Stop after 5 hits to avoid excessive scanning
                if len(vulns) >= 5:
                    break

            except Exception as e:
                logger.debug(f"Path test failed for {path}: {e}")

        return vulns

    async def _detect_sensitive_content(self, target: ScanTarget) -> List[Vulnerability]:
        """Detect sensitive information in response content — P7: report each pattern type only once"""
        vulns: List[Vulnerability] = []
        reported_types: set = set()  # P7: Track already reported info types to avoid duplicates

        try:
            resp = await self._active_session.get(
                target.url,
                params=target.params,
                timeout=10,
            )

            content = resp.text

            # Detect sensitive patterns
            for info_type, (pattern, severity) in self.SENSITIVE_PATTERNS.items():
                if info_type in reported_types:
                    continue  # P7: Same type already reported, skip
                matches = re.findall(pattern, content)
                if matches:
                    reported_types.add(info_type)
                    vulns.append(
                        Vulnerability(
                            type=VulnerabilityType.INFO_DISCLOSURE,
                            title=f"Sensitive Data: {info_type}",
                            url=target.url,
                            severity=severity,
                            confidence=Confidence.HIGH,
                            evidence=f"Pattern matched: {pattern[:50]}... ({len(matches)} occurrences)",
                            description=f"Sensitive information ({info_type}) detected in response.",
                            impact="Credential leakage, potential account compromise.",
                            recommendation="Remove sensitive data from responses. Use environment variables.",
                            module="sensitive",
                        )
                    )

        except Exception as e:
            logger.debug(f"Content scan failed: {e}")

        return vulns

    async def _detect_default_credentials(self, base_url: str) -> List[Vulnerability]:
        """
        P11: Detect default credential vulnerabilities on common services

        Targets common admin panels on Metasploitable2 (phpMyAdmin, DVWA, Mutillidae)
        Tests known default username/password combinations.
        """
        vulns: List[Vulnerability] = []
        tested_paths: set = set()

        for path_pattern, method, creds_list, success_markers in self.DEFAULT_CREDENTIAL_TARGETS:
            # Extract base path for deduplication
            base_path = path_pattern.split("?")[0]
            if base_path in tested_paths:
                continue

            # First probe if path exists
            test_url = base_url + base_path
            try:
                probe_resp = await self._active_session.get(test_url, timeout=5, follow_redirects=False)
                if probe_resp.status_code >= 400:
                    continue
            except Exception:
                continue

            tested_paths.add(base_path)
            login_url = base_url + path_pattern

            for creds in creds_list:
                try:
                    if method.upper() == "POST":
                        resp = await self._active_session.post(
                            login_url,
                            data=creds,
                            timeout=10,
                            follow_redirects=False,
                        )
                    else:
                        resp = await self._active_session.get(
                            login_url,
                            params=creds,
                            timeout=10,
                            follow_redirects=False,
                        )
                except Exception:
                    continue

                if resp.status_code >= 400:
                    continue

                resp_text = resp.text[:5000]
                # Check login success markers
                hits = [m for m in success_markers if m in resp_text]
                if len(hits) >= 2:
                    username = creds.get("username") or creds.get("pma_username", "unknown")
                    password = creds.get("password") or creds.get("pma_password", "empty")
                    cred_str = f"{username}/{password if password else '(no password)'}"
                    vulns.append(
                        Vulnerability(
                            type=VulnerabilityType.INSECURE_CONFIG,
                            title=f"Default Credentials: {cred_str}",
                            url=login_url,
                            severity=Severity.CRITICAL,
                            confidence=Confidence.HIGH,
                            evidence=f"Login successful with default credentials ({cred_str}): matched markers {hits[:2]}",
                            description=f"Default credentials ({cred_str}) grant access to admin panel at {path_pattern}.",
                            impact="Full administrative access to the service, leading to complete system compromise.",
                            recommendation="Change default password immediately. Disable remote root login if not needed.",
                            module="sensitive",
                        )
                    )
                    # One default credential finding is enough
                    break

        return vulns

    def _has_sensitive_content(self, path: str, content: str) -> bool:
        """
        P5: Verify response actually contains sensitive data, not just a 200 OK.
        Returns False for error pages, empty dir listings, HTML defaults.
        """
        content_lower = content.lower()

        # Git objects must contain git-specific content
        if ".git/" in path or path.endswith("/.git"):
            return "refs/heads" in content or "refs/tags" in content or "[core]" in content

        # Config files must contain recognizable config patterns
        if any(
            x in path
            for x in [".env", "config.php", "wp-config", "web.config", "database.yml", "settings.py", "application.yml"]
        ):
            config_indicators = [
                "db_host",
                "database",
                "password",
                "secret",
                "api_key",
                "connection",
                "mysql",
                "postgres",
                "sqlite",
                "mongodb",
                "define(",
                "jdbc:",
                "driver",
                "hostname",
                "username",
            ]
            return any(ind in content_lower for ind in config_indicators)

        # Backup files must not be HTML error pages
        if any(x in path for x in [".sql", ".zip", ".tar", ".bak", "backup", "dump"]):
            # Exclude HTML pages pretending to be backups
            if content_lower.strip().startswith("<!doctype") or content_lower.strip().startswith("<html"):
                return False
            # SQL dumps contain SQL statements
            if ".sql" in path or "dump" in path:
                return any(kw in content_lower for kw in ["create table", "insert into", "drop table"])
            return True  # binary files passed content-type check

        # Log files
        if any(x in path for x in [".log", "error.log", "access.log"]):
            log_indicators = [
                "error",
                "warn",
                "info",
                "debug",
                "trace",
                "exception",
                "stack trace",
                "thread",
                "timestamp",
            ]
            return any(ind in content_lower for ind in log_indicators)

        # Source code leaks (.gitignore, .htaccess, etc.)
        if any(
            x in path
            for x in [
                ".gitignore",
                ".htaccess",
                "robots.txt",
                "composer.json",
                "package.json",
                "requirements.txt",
                "Dockerfile",
            ]
        ):
            return True

        # API/docs endpoints — check for JSON/Swagger content
        if "swagger" in path or "api-docs" in path:
            return "swagger" in content_lower or "openapi" in content_lower or '"paths"' in content_lower

        # Admin / login / management paths — check for recognizable admin UI
        admin_paths = [
            "/admin",
            "/administrator",
            "/manager",
            "/management",
            "/login",
            "/signin",
            "/auth",
            "/console",
            "/cpanel",
            "/actuator",
            "/phpmyadmin",
            "/pma",
            "/adminer",
            "/wp-admin",
            "/wp-login",
            "/jenkins",
        ]
        if any(x in path for x in admin_paths):
            admin_indicators = [
                "login",
                "password",
                "username",
                "sign in",
                "dashboard",
                "control panel",
                "administration",
                "管理",
            ]
            if any(ind in content_lower for ind in admin_indicators):
                return True
            # P10: admin/login path but content looks like an error/redirect, not an admin panel
            if len(content) < 500:
                return False
            # P10: require admin-specific indicators beyond just a login form
            admin_specific = [
                "dashboard",
                "control panel",
                "administration",
                "管理",
                "user management",
                "site administration",
                "admin panel",
                "cpanel",
                "webadmin",
                "server management",
            ]
            if not any(ind in content_lower for ind in admin_specific):
                # Must at least have login form + 2 other admin-specific indicators
                secondary_indicators = [
                    "remember me",
                    "forgot password",
                    "sign in to",
                    "authorized",
                    "privileges",
                    "permissions",
                ]
                form_match = "<form" in content_lower and any(x in content_lower for x in ["password", "login"])
                if not form_match:
                    return False
                secondary_count = sum(1 for ind in secondary_indicators if ind in content_lower)
                if secondary_count < 2:
                    return False
            return True

        # Test/debug paths — verify content isn't just a placeholder
        if any(x in path for x in ["/test/", "/debug/", "/tmp/", "/temp/"]):
            if len(content) < 100:
                return False
            return any(ind in content_lower for ind in ["test", "debug", "php", "info"])

        # Fallback: require specific content evidence, not just 200 status
        html_indicators = ["<!doctype html>", "<html", "<head>", "<body"]
        is_html = all(ind in content_lower[:500] for ind in html_indicators)

        if is_html:
            error_indicators = [
                "404",
                "not found",
                "page not found",
                "error",
                "access denied",
                "forbidden",
                "unauthorized",
            ]
            if any(ind in content_lower[:1000] for ind in error_indicators):
                return False
            return "index of" in content_lower or "directory listing" in content_lower

        # Non-HTML content: must contain identifiable sensitive data patterns
        sensitive_content_markers = [
            "<?php",
            "<?=",  # PHP source
            "sql",
            "mysql",
            "postgresql",
            "mssql",  # DB related
            "password",
            "secret",
            "api_key",
            "token",  # Credentials
            "jdbc:",
            "Driver:",
            "Server=",  # Connection strings
            "-----BEGIN",
            "PRIVATE KEY",  # Crypto keys
            "stack trace",
            "exception",
            "at line",  # Stack traces
        ]
        return any(m in content_lower for m in sensitive_content_markers)

    def _get_path_severity(self, path: str) -> Severity:
        """Determine severity based on path type"""
        # CRITICAL: Directly accessible source code, keys, databases
        critical = (
            ".git/",
            ".git/config",
            ".git/HEAD",
            ".svn/",
            ".hg/",
            ".env",
            ".env.bak",
            "wp-config.php",
            "wp-config.php.bak",
            ".idea/",
            ".vscode/",
            ".ssh/",
            ".aws/",
            "private_key",
            "id_rsa",
            "id_ed25519",
            "WEB-INF/web.xml",
            "WEB-INF/",
            "META-INF/context.xml",
            ".jenkins/",
            "jenkins/",
            "Hudson/",
            "phpmyadmin/",
            "phpMyAdmin/",
            "sqlmanager/",
            "mysql/",
        )
        # HIGH: Backup files, configuration files, sensitive directories
        high = (
            "backup.sql",
            "db_backup",
            "dump.sql",
            "database.sql",
            "backup.zip",
            "backup.tar.gz",
            "www.zip",
            "web.zip",
            "config.php",
            "web.config",
            "httpd.conf",
            "nginx.conf",
            "php.ini",
            "my.cnf",
            "apache2.conf",
            "wp-content/",
            "wp-admin/",
            "wp-login.php",
            ".htpasswd",
            ".htaccess",
            "server-status",
            "server-info",
            "actuator/env",
            "actuator/",
            "jmx-console/",
            "web-console/",
            "backup/",
            "backups/",
            ".old",
        )
        # MEDIUM: Admin panels, debug endpoints, Swagger
        medium = (
            "/admin/",
            "/administrator/",
            "/manager/",
            "/management/",
            "/login.php",
            "/login/",
            "/auth/",
            "/console/",
            "/test/",
            "/testing/",
            "/debug/",
            "/tmp/",
            "/sqlmanager/",
            "/sql/",
            "/api/admin",
            "/swagger-ui/",
            "/swagger-ui.html",
            "/api-docs/",
            "/graphiql/",
            "/graphql/",
            "/phpmyadmin/",
            "/adminer.php",
            "/pma/",
            "/error.log",
            "/access.log",
            "/debug.log",
            "/server.log",
            "/.env.local",
            "/.env.production",
            "/.env.backup",
        )
        # LOW: Other information disclosure
        for p in critical:
            if p in path:
                return Severity.CRITICAL
        for p in high:
            if p in path:
                return Severity.HIGH
        for p in medium:
            if p in path:
                return Severity.MEDIUM
        return Severity.LOW


# Register module
register_module(SensitiveDetector)
