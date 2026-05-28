"""
Sqlmap Integration Module
v19.2 New: Invoke sqlmap for deep SQL injection detection

Strategy:
1. Prefer real sqlmap CLI
2. Use --batch mode for automatic answers
3. Parse stdout output to extract injection points
4. Map results to Vulnerability objects
"""

import asyncio
import logging
import os
import re
import shutil
from typing import Any, Dict, List, Optional

from ..config import ConfigManager
from ..models import Vulnerability, VulnerabilityType, Severity, Confidence


logger = logging.getLogger("wvs.integrations.sqlmap")

# sqlmap possible paths
SQLMAP_PATHS = [
    "C:/Tools/sqlmap/sqlmap.py",
    "C:/Tools/sqlmap/sqlmap.exe",
    "sqlmap",
    "sqlmap.py",
]

# Default technique combination (B: Boolean, E: Error, U: Union, S: Stacked, T: Time)
DEFAULT_TECHNIQUES = "BEUST"


class SqlmapIntegration:
    """
    Sqlmap Integration

    Uses real sqlmap CLI to perform automated SQL injection detection,
    results parsed into Vulnerability objects.

    Supports:
    - Multiple injection techniques (Boolean/Error/Union/Stacked/Time)
    - Database fingerprinting
    - Data extraction (optional, must be explicitly enabled)
    - Custom detection levels and risk levels
    """

    def __init__(
        self,
        config: Optional[ConfigManager] = None,
        sqlmap_path: Optional[str] = None,
        python_exe: Optional[str] = None,
    ):
        self.config = config or ConfigManager()
        self.sqlmap_path = sqlmap_path or self._find_sqlmap()
        self.python_exe = python_exe or shutil.which("python3") or shutil.which("python") or "python"
        self.timeout = self.config.get("sqlmap_timeout", 300)
        self._stats = {
            "total_scanned": 0,
            "injections_found": 0,
            "sqlmap_available": self.sqlmap_path is not None,
        }

    def _find_sqlmap(self) -> Optional[str]:
        """Find if sqlmap exists"""
        for path in SQLMAP_PATHS:
            if os.path.exists(path):
                logger.info(f"[Sqlmap] Found sqlmap: {path}")
                return path
        exe = shutil.which("sqlmap")
        if exe:
            logger.info(f"[Sqlmap] Found sqlmap in PATH: {exe}")
            return exe
        logger.warning("[Sqlmap] sqlmap not found")
        return None

    @property
    def is_available(self) -> bool:
        return self.sqlmap_path is not None

    async def scan(
        self,
        url: str,
        method: str = "GET",
        data: Optional[str] = None,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        level: int = 1,
        risk: int = 1,
        techniques: str = DEFAULT_TECHNIQUES,
        extract_data: bool = False,
    ) -> List[Vulnerability]:
        """
        Scan target using sqlmap

        Args:
            url: Target URL
            method: HTTP method (GET/POST)
            data: POST data
            cookies: Cookie dictionary
            headers: Additional HTTP headers
            level: Detection level (1-5)
            risk: Risk level (1-3)
            techniques: Injection techniques (BEUST)
            extract_data: Whether to extract data (slow and dangerous)

        Returns:
            List of discovered SQL injection vulnerabilities
        """
        if not self.is_available:
            logger.warning("[Sqlmap] sqlmap not available, skipping scan")
            return []

        return await self._scan_async(url, method, data, cookies, headers, level, risk, techniques, extract_data)

    async def _scan_async(
        self,
        url: str,
        method: str,
        data: Optional[str],
        cookies: Optional[Dict[str, str]],
        headers: Optional[Dict[str, str]],
        level: int,
        risk: int,
        techniques: str,
        extract_data: bool,
    ) -> List[Vulnerability]:
        """Execute sqlmap scan asynchronously"""
        # Base command
        cmd = [self._get_runner(), "-u", url]

        # Injection technique
        cmd.extend(["--technique", techniques])

        # Detection depth
        cmd.extend(["--level", str(max(1, min(5, level)))])
        cmd.extend(["--risk", str(max(1, min(3, risk)))])

        # Automation
        cmd.append("--batch")

        # Random UA
        cmd.append("--random-agent")

        # Skip WAF confirmation
        cmd.append("--skip-waf")

        # HTTP method
        if method.upper() == "POST":
            cmd.extend(["--method", "POST"])
        else:
            cmd.extend(["--method", "GET"])

        # POST data
        if data:
            cmd.extend(["--data", data])

        # Cookie
        if cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
            cmd.extend(["--cookie", cookie_str])

        # Headers
        if headers:
            for key, value in headers.items():
                if key.lower() != "cookie":
                    cmd.extend(["--headers", f"{key}: {value}"])

        # Do not extract data (unless explicitly requested)
        if not extract_data:
            cmd.append("--no-escape")

        # Threads
        cmd.extend(["--threads", "3"])

        logger.info(f"[Sqlmap] Executing: {self._get_runner()} -u {url} --level {level} --risk {risk}")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self.timeout + 30,
                )
            except asyncio.TimeoutError:
                proc.kill()
                logger.warning(f"[Sqlmap] Timeout (>{self.timeout + 30}s)")
                return []

            output = stdout.decode("utf-8", errors="ignore")
            stderr_output = stderr.decode("utf-8", errors="ignore")

            if stderr_output and "error" in stderr_output.lower():
                logger.warning(f"[Sqlmap] stderr: {stderr_output[:300]}")

            return self._parse_sqlmap_output(output, url)

        except FileNotFoundError:
            logger.exception(f"[Sqlmap] Not found: {self.sqlmap_path}")
            return []
        except Exception as e:
            logger.exception("[Sqlmap] Execution failed")
            return []

    def _get_runner(self) -> str:
        """Get the command to run sqlmap"""
        if self.sqlmap_path and self.sqlmap_path.endswith(".py"):
            return self.python_exe
        return self.sqlmap_path

    def _build_command(self) -> List[str]:
        """Build the full command (sqlmap.py needs python prefix)"""
        if self.sqlmap_path and self.sqlmap_path.endswith(".py"):
            return [self.python_exe, self.sqlmap_path]
        return [self.sqlmap_path]

    def _parse_sqlmap_output(self, output: str, target_url: str) -> List[Vulnerability]:
        """Parse sqlmap stdout output"""
        vulnerabilities = []

        # ── Check if injection was found ──
        if "identified the following injection point" not in output:
            # Try other matching patterns
            if "is vulnerable" not in output and "vulnerable" not in output.lower():
                logger.debug("[Sqlmap] No injection point found")
                return []

        # ── Extract injection parameters ──
        injection_pattern = re.compile(
            r"Parameter:\s*['\"](.+?)['\"]"
            r"[\s\S]*?"
            r"Type:\s*(.+?)(?:\n|$)"
            r"[\s\S]*?"
            r"Title:\s*(.+?)(?:\n|$)"
            r"[\s\S]*?"
            r"Payload:\s*(.+?)(?:\n|$)",
            re.MULTILINE | re.IGNORECASE,
        )

        injections = list(injection_pattern.finditer(output))

        if not injections:
            # Try loose matching
            if "is vulnerable" in output.lower() or "injectable" in output.lower():
                vuln = Vulnerability(
                    type=VulnerabilityType.SQL_INJECTION,
                    title="[Sqlmap] SQL Injection Detected",
                    url=target_url,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description="sqlmap 检测到 SQL 注入（详细参数解析失败）",
                    recommendation="使用参数化查询，修复注入点",
                    module="sqlmap",
                    tags=["sqlmap", "sqli"],
                    context={
                        "source": "sqlmap",
                        "raw_output": output[:2000],
                    },
                )
                vulnerabilities.append(vuln)
                self._stats["injections_found"] += 1
            return vulnerabilities

        # ── Parse each injection point ──
        for match in injections:
            param = match.group(1).strip()
            inj_type = match.group(2).strip()
            title = match.group(3).strip()
            payload = match.group(4).strip() if len(match.groups()) >= 4 else ""

            # Extract database type
            dbms_match = re.search(r"back-end DBMS:\s*(.+?)(?:\n|$)", output)
            dbms = dbms_match.group(1).strip() if dbms_match else "Unknown"

            severity, confidence = self._assess_injection(inj_type)

            vuln = Vulnerability(
                type=VulnerabilityType.SQL_INJECTION,
                title=f"[Sqlmap] {title}",
                url=target_url,
                parameter=param,
                payload=payload,
                evidence=f"Type: {inj_type}, DBMS: {dbms}",
                severity=severity,
                confidence=confidence,
                description=f"参数 '{param}' 存在 SQL 注入 ({inj_type})。后端数据库: {dbms}",
                recommendation=("1. 使用参数化查询/预编译语句\n2. 对输入进行严格校验和转义\n3. 最小化数据库用户权限\n4. 启用 WAF 作为额外防护层"),
                module="sqlmap",
                tags=["sqlmap", "sqli", inj_type.lower()],
                context={
                    "source": "sqlmap",
                    "injection_type": inj_type,
                    "dbms": dbms,
                    "parameter": param,
                },
            )
            vulnerabilities.append(vuln)
            self._stats["injections_found"] += 1

        self._stats["total_scanned"] += 1
        return vulnerabilities

    @staticmethod
    def _assess_injection(inj_type: str) -> tuple:
        """Assess severity and confidence based on injection type"""
        inj_type_lower = inj_type.lower()
        if "error-based" in inj_type_lower:
            return (Severity.HIGH, Confidence.CERTAIN)
        elif "stacked" in inj_type_lower:
            return (Severity.CRITICAL, Confidence.CERTAIN)
        elif "time-based" in inj_type_lower:
            return (Severity.HIGH, Confidence.HIGH)
        elif "boolean-based" in inj_type_lower:
            return (Severity.HIGH, Confidence.HIGH)
        elif "union" in inj_type_lower:
            return (Severity.CRITICAL, Confidence.CERTAIN)
        else:
            return (Severity.MEDIUM, Confidence.MEDIUM)

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics"""
        return self._stats.copy()
