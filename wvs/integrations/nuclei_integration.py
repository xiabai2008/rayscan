"""
Nuclei Integration Module

Strategy:
1. Find nuclei CLI via PATH or well-known install locations
2. When CLI is unavailable, fallback to built-in templates (not fake output)
3. Auto-parse JSON output
4. Support custom template directories
"""

import asyncio
import json
import logging
import os
import shutil
import sys
from typing import Any, Dict, List, Optional

from ..config import ConfigManager
from ..constants import DEFAULT_VERIFY_SSL
from ..models import Vulnerability, VulnerabilityType, Severity, Confidence


logger = logging.getLogger("wvs.integrations.nuclei")

# Nuclei CLI search paths (OS-agnostic; PATH search via shutil.which() comes first)
NUCLEI_EXE_PATHS = [
    "nuclei",  # From PATH (primary)
]
# Additional platform-specific fallback paths
if sys.platform == "win32":
    NUCLEI_EXE_PATHS.extend(
        [
            "C:/Tools/nuclei/nuclei.exe",
            os.path.expandvars("%LOCALAPPDATA%/nuclei/nuclei.exe"),
        ]
    )
else:
    NUCLEI_EXE_PATHS.extend(
        [
            "/usr/local/bin/nuclei",
            "/usr/bin/nuclei",
            os.path.expanduser("~/.nuclei/nuclei"),
        ]
    )

# Default severity levels used for nuclei scanning
DEFAULT_SEVERITIES = ["critical", "high", "medium", "low"]


class NucleiIntegration:
    """
    Nuclei Integration

    Uses real nuclei CLI to perform batch vulnerability scanning,
    results parsed into Vulnerability objects.

    Supports:
    - JSON output parsing
    - Custom template directories
    - HTTP headers / cookies passing
    - Timeout control
    - Automatic fallback
    """

    def __init__(
        self,
        config: Optional[ConfigManager] = None,
        templates_dir: Optional[str] = None,
        nuclei_exe: Optional[str] = None,
    ):
        self.config = config or ConfigManager()
        self.templates_dir = templates_dir
        self.nuclei_exe = nuclei_exe or self._find_nuclei_exe()
        self.timeout = self.config.get("timeout", 60)
        self._stats = {
            "total_scanned": 0,
            "vulnerabilities_found": 0,
            "cli_used": False,
            "fallback_used": False,
        }

    def _find_nuclei_exe(self) -> Optional[str]:
        """Find the nuclei CLI binary, checking PATH first, then known install locations."""
        # 1. Try PATH via shutil.which (most portable)
        exe = shutil.which("nuclei")
        if exe:
            logger.info(f"[Nuclei] Found nuclei in PATH: {exe}")
            return exe

        # 2. Try known install locations (skip "nuclei" which is just the PATH lookup)
        for path in NUCLEI_EXE_PATHS:
            if path != "nuclei" and os.path.exists(path):
                logger.info(f"[Nuclei] Found nuclei: {path}")
                return path

        logger.warning("[Nuclei] nuclei binary not found; using built-in templates")
        return None

    @property
    def is_available(self) -> bool:
        """Whether Nuclei CLI is available"""
        return self.nuclei_exe is not None

    async def scan(
        self,
        url: str,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        severities: Optional[List[str]] = None,
    ) -> List[Vulnerability]:
        """
        Scan the target URL using Nuclei

        Args:
            url: Target URL
            cookies: Cookie dictionary
            headers: HTTP headers
            severities: Severity levels to check (default all)

        Returns:
            List of discovered security issues (converted to Vulnerability objects)
        """
        if severities is None:
            severities = DEFAULT_SEVERITIES

        if self.is_available:
            return await self._cli_scan_async(url, cookies, headers, severities)
        else:
            return await self._fallback_scan(url, severities)

    # ─────────────────────────────────────────────────────────────
    # Real CLI invocation
    # ─────────────────────────────────────────────────────────────

    async def _cli_scan_async(
        self,
        url: str,
        cookies: Optional[Dict[str, str]],
        headers: Optional[Dict[str, str]],
        severities: List[str],
    ) -> List[Vulnerability]:
        """
        Actually invoke nuclei.exe
        """
        cmd = [
            self.nuclei_exe,
            "-u",
            url,
            "-json",  # JSON output
            "-no-color",  # No color output (easier to parse)
            "-silent",  # Silent mode (output results only)
        ]

        # Severity level filtering
        for sev in severities:
            cmd.extend(["-severity", sev])

        # Template directory
        if self.templates_dir and os.path.exists(self.templates_dir):
            cmd.extend(["-t", self.templates_dir])

        # Timeout
        cmd.extend(["-timeout", str(self.timeout)])

        # Headers
        all_headers = {}
        if headers:
            all_headers.update(headers)
        if cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
            all_headers["Cookie"] = cookie_str

        for key, value in all_headers.items():
            cmd.extend(["-H", f"{key}: {value}"])

        logger.info(f"[Nuclei] Executing command: {' '.join(cmd[:6])}...")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self.timeout + 10,
                )
            except asyncio.TimeoutError:
                proc.kill()
                logger.warning(f"[Nuclei] Execution timeout (>{self.timeout + 10}s)")
                return []

            if proc.returncode != 0:
                stderr_text = stderr.decode("utf-8", errors="ignore")[:500]
                if stderr_text and "error" in stderr_text.lower():
                    logger.warning(f"[Nuclei] CLI error: {stderr_text}")

            return self._parse_nuclei_output(stdout.decode("utf-8", errors="ignore"))

        except FileNotFoundError:
            logger.error(f"[Nuclei] nuclei.exe not found: {self.nuclei_exe}")
            self._stats["fallback_used"] = True
            return await self._fallback_scan(url, severities)

        except Exception as e:
            logger.error(f"[Nuclei] Execution failed: {e}")
            self._stats["fallback_used"] = True
            return await self._fallback_scan(url, severities)

    def _parse_nuclei_output(self, raw_output: str) -> List[Vulnerability]:
        """
        Parse Nuclei JSON output

        Nuclei JSON format example:
        {"template":"cves/2021/cve-2021-44228.yaml","template-id":"cve-2021-44228",...}
        """
        vulnerabilities = []

        for line in raw_output.strip().split("\n"):
            if not line.strip():
                continue

            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Map Nuclei fields to Vulnerability
            vuln = self._nuclei_entry_to_vulnerability(entry)
            if vuln:
                vulnerabilities.append(vuln)
                self._stats["vulnerabilities_found"] += 1

        self._stats["total_scanned"] += 1
        self._stats["cli_used"] = True
        return vulnerabilities

    def _nuclei_entry_to_vulnerability(self, entry: Dict[str, Any]) -> Optional[Vulnerability]:
        """Convert a Nuclei entry to a Vulnerability object"""
        info = entry.get("info", {})
        matched_at = entry.get("matched-at", "")
        matched_line = entry.get("matched-line", "")
        curl_command = entry.get("curl", "")
        host = entry.get("host", "")

        severity_str = info.get("severity", "info").lower()
        severity = self._map_severity(severity_str)

        title = info.get("name", "") or info.get("title", "Nuclei Finding")
        description = info.get("description", "")
        recommendation = info.get("remediation", "")

        cwe_ids = info.get("classification", {}).get("cwe-id", [])
        if isinstance(cwe_ids, list) and cwe_ids:
            cwe_id = int(cwe_ids[0].replace("CWE-", "")) if cwe_ids else None
        else:
            cwe_id = None

        refs = info.get("reference", []) or []
        if isinstance(refs, str):
            refs = [refs]

        tags = info.get("tags", []) or []

        # Extract URL (from matched-at)
        vuln_url = matched_at.split("?")[0] if matched_at else host

        return Vulnerability(
            type=VulnerabilityType.ZERO_DAY,  # Nuclei templates are counted as zero-day library
            title=f"[Nuclei] {title}",
            url=vuln_url,
            payload=matched_line or curl_command,
            evidence=f"{severity_str.upper()}: {title}",
            severity=severity,
            confidence=Confidence.HIGH,  # Nuclei has explicit templates, high confidence
            description=description[:500] if description else "",
            recommendation=recommendation[:500] if recommendation else "",
            references=refs[:5],
            cwe_id=cwe_id,
            module="nuclei",
            tags=["nuclei"] + tags,
            context={
                "source": "nuclei",
                "template_id": entry.get("template-id", ""),
                "template": entry.get("template", ""),
                "matched_at": matched_at,
                "nuclei_type": entry.get("type", ""),
                "matched_line": matched_line,
            },
        )

    def _map_severity(self, nuclei_severity: str) -> Severity:
        """Map nuclei severity to our Severity enum"""
        mapping = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
            "unknown": Severity.INFO,
        }
        return mapping.get(nuclei_severity.lower(), Severity.INFO)

    # ─────────────────────────────────────────────────────────────
    # Fallback: Built-in templates (not fake output)
    # ─────────────────────────────────────────────────────────────

    async def _fallback_scan(
        self,
        url: str,
        severities: List[str],
    ) -> List[Vulnerability]:
        """
        Fallback: Use built-in basic templates when nuclei.exe is unavailable

        This is not a simulation! It is simple detection logic based on known CVE/CWE.
        """
        logger.info(f"[Nuclei] Scanning with built-in fallback templates: {url}")
        self._stats["fallback_used"] = True

        vulnerabilities = []
        base_url = url.rstrip("/")

        # Built-in simple detection rules (quick fingerprints for known vulnerabilities)
        builtin_checks = [
            {
                "path": "/.git/config",
                "type": VulnerabilityType.INFO_DISCLOSURE,
                "title": "Git Repository Exposed",
                "severity": Severity.LOW,
                "evidence_pattern": "remote origin",
            },
            {
                "path": "/.env",
                "type": VulnerabilityType.INFO_DISCLOSURE,
                "title": ".env File Exposed",
                "severity": Severity.HIGH,
                "evidence_pattern": "APP_KEY",
            },
            {
                "path": "/.htaccess",
                "type": VulnerabilityType.INFO_DISCLOSURE,
                "title": ".htaccess File Exposed",
                "severity": Severity.LOW,
                "evidence_pattern": "RewriteEngine",
            },
            {
                "path": "/backup.zip",
                "type": VulnerabilityType.INFO_DISCLOSURE,
                "title": "Backup File Exposed",
                "severity": Severity.HIGH,
                "evidence_pattern": None,  # Any non-404 response counts
            },
            {
                "path": "/wp-admin",
                "type": VulnerabilityType.INFO_DISCLOSURE,
                "title": "WordPress Admin Panel",
                "severity": Severity.LOW,
                "evidence_pattern": None,
            },
            {
                "path": "/phpmyadmin",
                "type": VulnerabilityType.INFO_DISCLOSURE,
                "title": "phpMyAdmin Exposed",
                "severity": Severity.HIGH,
                "evidence_pattern": "phpMyAdmin",
            },
            {
                "path": "/.git/HEAD",
                "type": VulnerabilityType.INFO_DISCLOSURE,
                "title": "Git HEAD Exposed",
                "severity": Severity.LOW,
                "evidence_pattern": "ref: refs/heads/",
            },
            {
                "path": "/debug=true",
                "type": VulnerabilityType.INFO_DISCLOSURE,
                "title": "Debug Mode Enabled",
                "severity": Severity.MEDIUM,
                "evidence_pattern": "debug",
            },
        ]

        # Simple HTTP request (uses httpx)
        async def check_path(path: str) -> Optional[Dict]:
            try:
                import httpx

                async with httpx.AsyncClient(
                    timeout=httpx.Timeout(10),
                    follow_redirects=True,
                    verify=DEFAULT_VERIFY_SSL,  # Use default SSL verification setting
                ) as client:
                    resp = await client.get(base_url + path)
                    if resp.status_code not in (404, 400, 403):
                        return {"status": resp.status_code, "body": resp.text[:200]}
            except Exception:
                pass
            return None

        tasks = [check_path(c["path"]) for c in builtin_checks]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for check, result in zip(builtin_checks, results):
            if isinstance(result, dict):
                body = result.get("body", "")
                pattern = check.get("evidence_pattern")
                if pattern is None or pattern in body:
                    vuln = Vulnerability(
                        type=check["type"],
                        title=f"[Builtin] {check['title']}",
                        url=base_url + check["path"],
                        severity=check["severity"],
                        confidence=Confidence.MEDIUM,
                        description=check["title"],
                        recommendation="移除敏感文件或配置访问权限",
                        module="nuclei-fallback",
                        tags=["builtin", "info-disclosure"],
                        context={"source": "builtin-fallback"},
                    )
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics"""
        return self._stats.copy()
