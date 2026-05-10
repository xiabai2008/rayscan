"""
Nuclei 集成模块
v18 痛点彻底解决：必须真实调用 nuclei.exe，不允许模拟

策略：
1. 优先使用真实 CLI：C:\Tools\nuclei\nuclei.exe
2. CLI 不可用时 fallback 到内置模板（不是假输出）
3. 自动解析 JSON 输出
4. 支持自定义模板目录
"""
import asyncio
import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config import ConfigManager
from ..constants import DEFAULT_VERIFY_SSL
from ..models import Vulnerability, VulnerabilityType, Severity, Confidence


logger = logging.getLogger("wvs.integrations.nuclei")

# Nuclei CLI 路径（用正斜杠避免 Windows 路径的 escape sequence warning）
NUCLEI_EXE_PATHS = [
    "C:/Tools/nuclei/nuclei.exe",
    "C:/Tools/nuclei/nuclei",
    "nuclei",  # PATH 中
]

# 默认 nuclei 扫描使用的 severity 级别
DEFAULT_SEVERITIES = ["critical", "high", "medium", "low"]


class NucleiIntegration:
    """
    Nuclei 集成

    使用真实 nuclei CLI 执行批量漏洞扫描，
    结果解析为 Vulnerability 对象。

    支持：
    - JSON 输出解析
    - 自定义模板目录
    - HTTP headers / cookies 传递
    - 超时控制
    - 自动 fallback
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
        """查找 nuclei.exe 是否存在"""
        for path in NUCLEI_EXE_PATHS:
            if os.path.exists(path):
                logger.info(f"[Nuclei] 找到 nuclei.exe: {path}")
                return path

        # 尝试从 PATH 查找
        exe = shutil.which("nuclei")
        if exe:
            logger.info(f"[Nuclei] 从 PATH 找到 nuclei: {exe}")
            return exe

        logger.warning("[Nuclei] 未找到 nuclei.exe，将使用内置模板")
        return None

    @property
    def is_available(self) -> bool:
        """Nuclei CLI 是否可用"""
        return self.nuclei_exe is not None

    async def scan(
        self,
        url: str,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        severities: Optional[List[str]] = None,
    ) -> List[Vulnerability]:
        """
        使用 Nuclei 扫描目标 URL

        Args:
            url: 目标 URL
            cookies: Cookie 字典
            headers: HTTP headers
            severities: 要检测的严重级别（默认全部）

        Returns:
            发现的安全问题列表（转为 Vulnerability 对象）
        """
        if severities is None:
            severities = DEFAULT_SEVERITIES

        if self.is_available:
            return await self._cli_scan_async(
                url, cookies, headers, severities
            )
        else:
            return await self._fallback_scan(url, severities)

    # ─────────────────────────────────────────────────────────────
    # 真实 CLI 调用
    # ─────────────────────────────────────────────────────────────

    async def _cli_scan_async(
        self,
        url: str,
        cookies: Optional[Dict[str, str]],
        headers: Optional[Dict[str, str]],
        severities: List[str],
    ) -> List[Vulnerability]:
        """
        真实调用 nuclei.exe
        """
        cmd = [
            self.nuclei_exe,
            "-u", url,
            "-json",          # JSON 输出
            "-no-color",      # 无颜色输出（方便解析）
            "-silent",         # 静默模式（只输出结果）
        ]

        # 严重级别过滤
        for sev in severities:
            cmd.extend(["-severity", sev])

        # 模板目录
        if self.templates_dir and os.path.exists(self.templates_dir):
            cmd.extend(["-t", self.templates_dir])

        # 超时
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

        logger.info(f"[Nuclei] 执行命令: {' '.join(cmd[:6])}...")

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
                logger.warning(f"[Nuclei] 执行超时（>{self.timeout + 10}s）")
                return []

            if proc.returncode != 0:
                stderr_text = stderr.decode("utf-8", errors="ignore")[:500]
                if stderr_text and "error" in stderr_text.lower():
                    logger.warning(f"[Nuclei] CLI 报错: {stderr_text}")

            return self._parse_nuclei_output(stdout.decode("utf-8", errors="ignore"))

        except FileNotFoundError:
            logger.error(f"[Nuclei] nuclei.exe 未找到: {self.nuclei_exe}")
            self._stats["fallback_used"] = True
            return await self._fallback_scan(url, severities)

        except Exception as e:
            logger.error(f"[Nuclei] 执行失败: {e}")
            self._stats["fallback_used"] = True
            return await self._fallback_scan(url, severities)

    def _parse_nuclei_output(self, raw_output: str) -> List[Vulnerability]:
        """
        解析 Nuclei JSON 输出

        Nuclei JSON 格式示例：
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

            # 映射 Nuclei 字段到 Vulnerability
            vuln = self._nuclei_entry_to_vulnerability(entry)
            if vuln:
                vulnerabilities.append(vuln)
                self._stats["vulnerabilities_found"] += 1

        self._stats["total_scanned"] += 1
        self._stats["cli_used"] = True
        return vulnerabilities

    def _nuclei_entry_to_vulnerability(self, entry: Dict[str, Any]) -> Optional[Vulnerability]:
        """将 Nuclei 条目转为 Vulnerability 对象"""
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

        # 提取 URL（从 matched-at）
        vuln_url = matched_at.split("?")[0] if matched_at else host

        return Vulnerability(
            type=VulnerabilityType.ZERO_DAY,  # Nuclei 的 template 本身算 zero-day 库
            title=f"[Nuclei] {title}",
            url=vuln_url,
            payload=matched_line or curl_command,
            evidence=f"{severity_str.upper()}: {title}",
            severity=severity,
            confidence=Confidence.HIGH,  # Nuclei 有明确 template，置信度高
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
        """映射 Nuclei severity 到我们的 Severity 枚举"""
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
    # Fallback：内置模板（不是假输出）
    # ─────────────────────────────────────────────────────────────

    async def _fallback_scan(
        self,
        url: str,
        severities: List[str],
    ) -> List[Vulnerability]:
        """
        Fallback：当 nuclei.exe 不可用时，使用内置基础模板

        这不是模拟！是基于已知 CVE/CWE 的简单检测逻辑。
        """
        logger.info(f"[Nuclei] 使用内置 fallback 模板扫描: {url}")
        self._stats["fallback_used"] = True

        vulnerabilities = []
        base_url = url.rstrip("/")

        # 内置简单检测规则（已知漏洞的快速指纹）
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
                "evidence_pattern": None,  # 任何非404响应都算
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

        # 简单的 HTTP HEAD 请求（不依赖 httpx，直接用 asyncio）
        async def check_path(path: str) -> Optional[Dict]:
            try:
                import httpx
                async with httpx.AsyncClient(
                    timeout=httpx.Timeout(10),
                    follow_redirects=True,
                    verify=DEFAULT_VERIFY_SSL,  # 使用默认 SSL 验证设置
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
        """获取统计信息"""
        return self._stats.copy()
