"""
ffuf 集成模块
v19.2 新增：目录/文件爆破与模糊测试

策略：
1. 调用 ffuf CLI 执行批量路径发现
2. 使用 -json 输出模式解析结果
3. 发现的敏感路径映射为 Vulnerability (INFO_DISCLOSURE)

支持：
- 自定义字典
- 递归发现
- 状态码/行数/字数过滤
- 扩展名爆破
"""
import asyncio
import json
import logging
import os
import shutil
from typing import Any, Dict, List, Optional

from ..config import ConfigManager
from ..models import Vulnerability, VulnerabilityType, Severity, Confidence


logger = logging.getLogger("wvs.integrations.ffuf")

FFUF_PATHS = [
    "C:/Tools/ffuf/ffuf.exe",
    "C:/Tools/ffuf/ffuf",
    "ffuf.exe",
    "ffuf",
]

# 默认扩展名列表
DEFAULT_EXTENSIONS = [".php", ".asp", ".aspx", ".jsp", ".html", ".txt", ".bak", ".zip", ".sql", ".git"]


class FfufIntegration:
    """
    ffuf 集成 — 目录/文件发现

    使用 ffuf (Fuzz Faster U Fool) 进行高速路径爆破，
    结果解析为信息泄露漏洞。
    """

    def __init__(
        self,
        config: Optional[ConfigManager] = None,
        ffuf_path: Optional[str] = None,
        wordlist_dir: Optional[str] = None,
    ):
        self.config = config or ConfigManager()
        self.ffuf_path = ffuf_path or self._find_ffuf()
        self.wordlist_dir = wordlist_dir or "C:/Tools/wordlists"
        self.timeout = self.config.get("ffuf_timeout", 120)
        self._stats = {
            "total_scanned": 0,
            "paths_found": 0,
            "ffuf_available": self.ffuf_path is not None,
        }

    def _find_ffuf(self) -> Optional[str]:
        for path in FFUF_PATHS:
            if os.path.exists(path):
                logger.info(f"[ffuf] 找到 ffuf: {path}")
                return path
        exe = shutil.which("ffuf")
        if exe:
            logger.info(f"[ffuf] 从 PATH 找到: {exe}")
            return exe
        logger.warning("[ffuf] 未找到 ffuf.exe")
        return None

    @property
    def is_available(self) -> bool:
        return self.ffuf_path is not None

    async def discover(
        self,
        url: str,
        wordlist: Optional[str] = None,
        extensions: Optional[List[str]] = None,
        match_codes: Optional[str] = "200,204,301,302,307,401,403",
        filter_codes: Optional[str] = "404",
        recursion: bool = False,
        rate: int = 50,
        timeout: int = 10,
    ) -> List[Vulnerability]:
        """
        使用 ffuf 爆破目录/文件

        Args:
            url: 目标基 URL（必须包含 FUZZ 占位符，如 http://test.com/FUZZ）
            wordlist: 字典路径（默认使用内置小字典）
            extensions: 扩展名列表
            match_codes: 匹配的状态码
            filter_codes: 过滤的状态码
            recursion: 是否递归
            rate: 每秒请求数
            timeout: 单个请求超时秒数

        Returns:
            发现的路径列表（Vulnerability）
        """
        if not self.is_available:
            logger.warning("[ffuf] ffuf 不可用")
            return []

        return await self._scan_async(
            url, wordlist, extensions, match_codes,
            filter_codes, recursion, rate, timeout,
        )

    async def _scan_async(
        self,
        url: str,
        wordlist: Optional[str],
        extensions: Optional[List[str]],
        match_codes: str,
        filter_codes: str,
        recursion: bool,
        rate: int,
        timeout: int,
    ) -> List[Vulnerability]:
        cmd = [
            self.ffuf_path,
            "-u", url,
            "-json",
            "-mc", match_codes,
            "-fc", filter_codes,
            "-rate", str(rate),
            "-timeout", str(timeout),
            "-t", "30",
        ]

        # 字典
        if wordlist and os.path.exists(wordlist):
            cmd.extend(["-w", wordlist])
        else:
            cmd.extend(["-w", "FUZZ"])  # fallback

        # 扩展名
        if extensions:
            ext_str = ",".join(extensions)
            cmd.extend(["-e", ext_str])

        # 递归
        if recursion:
            cmd.append("-recursion")
            cmd.extend(["-recursion-depth", "2"])

        # 静默
        cmd.append("-s")

        logger.info(f"[ffuf] 扫描: {url}")

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
                logger.warning(f"[ffuf] 超时")
                return []

            output = stdout.decode("utf-8", errors="ignore")
            return self._parse_ffuf_output(output, url)

        except FileNotFoundError:
            logger.error(f"[ffuf] 未找到: {self.ffuf_path}")
            return []
        except Exception as e:
            logger.error(f"[ffuf] 执行失败: {e}")
            return []

    def _parse_ffuf_output(
        self,
        output: str,
        base_url: str,
    ) -> List[Vulnerability]:
        """解析 ffuf JSON 输出"""
        vulnerabilities = []

        for line in output.strip().split("\n"):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            result_url = entry.get("url", "")
            status = entry.get("status", 0)
            length = entry.get("length", 0)
            words = entry.get("words", 0)
            lines_count = entry.get("lines", 0)

            # 分类路径
            path_info = self._classify_path(result_url, status)

            vuln = Vulnerability(
                type=path_info["type"],
                title=f"[ffuf] {path_info['title']}",
                url=result_url,
                severity=path_info["severity"],
                confidence=Confidence.MEDIUM if status != 200 else Confidence.HIGH,
                description=(
                    f"发现路径: {result_url}\n"
                    f"状态码: {status}, 大小: {length}B, 行数: {lines_count}"
                ),
                recommendation=path_info["recommendation"],
                module="ffuf",
                tags=["ffuf", "path-discovery", path_info.get("tag", "info")],
                context={
                    "source": "ffuf",
                    "status": status,
                    "length": length,
                    "words": words,
                    "lines": lines_count,
                },
            )
            vulnerabilities.append(vuln)
            self._stats["paths_found"] += 1

        self._stats["total_scanned"] += 1
        return vulnerabilities

    def _classify_path(self, url: str, status: int) -> Dict[str, Any]:
        """根据 HTTP 状态码和路径特征分类"""
        url_lower = url.lower()

        # 关键敏感路径
        sensitive_patterns = [
            (".git/", "Git 仓库暴露", Severity.HIGH, VulnerabilityType.INFO_DISCLOSURE, "git"),
            (".env", "环境配置文件暴露", Severity.CRITICAL, VulnerabilityType.INFO_DISCLOSURE, "config"),
            ("backup", "备份文件暴露", Severity.HIGH, VulnerabilityType.INFO_DISCLOSURE, "backup"),
            ("wp-config", "WordPress 配置暴露", Severity.CRITICAL, VulnerabilityType.INFO_DISCLOSURE, "config"),
            ("phpmyadmin", "phpMyAdmin 暴露", Severity.HIGH, VulnerabilityType.INFO_DISCLOSURE, "admin"),
            ("phpinfo", "phpinfo 暴露", Severity.MEDIUM, VulnerabilityType.INFO_DISCLOSURE, "info"),
            ("admin", "管理后台", Severity.MEDIUM, VulnerabilityType.INFO_DISCLOSURE, "admin"),
            ("login", "登录页面", Severity.LOW, VulnerabilityType.INFO_DISCLOSURE, "auth"),
            ("upload", "文件上传", Severity.MEDIUM, VulnerabilityType.INFO_DISCLOSURE, "upload"),
            ("api", "API 端点", Severity.LOW, VulnerabilityType.API_SECURITY, "api"),
            ("debug", "调试页面", Severity.MEDIUM, VulnerabilityType.INFO_DISCLOSURE, "debug"),
            ("config", "配置文件", Severity.HIGH, VulnerabilityType.INSECURE_CONFIG, "config"),
        ]

        for pattern, title, severity, vuln_type, tag in sensitive_patterns:
            if pattern in url_lower:
                return {
                    "type": vuln_type,
                    "title": title,
                    "severity": severity,
                    "recommendation": "限制敏感路径的外部访问，配置正确的访问控制",
                    "tag": tag,
                }

        # 默认分类
        if status in (200, 204):
            return {
                "type": VulnerabilityType.INFO_DISCLOSURE,
                "title": f"可访问路径 (HTTP {status})",
                "severity": Severity.INFO,
                "recommendation": "检查路径是否应限制访问",
                "tag": "info",
            }
        elif status in (301, 302, 307):
            return {
                "type": VulnerabilityType.INFO_DISCLOSURE,
                "title": f"重定向路径 (HTTP {status})",
                "severity": Severity.INFO,
                "recommendation": "检查重定向逻辑是否合理",
                "tag": "redirect",
            }
        elif status == 401:
            return {
                "type": VulnerabilityType.BROKEN_AUTH,
                "title": "需要认证的路径",
                "severity": Severity.LOW,
                "recommendation": "确认认证机制无漏洞",
                "tag": "auth",
            }
        elif status == 403:
            return {
                "type": VulnerabilityType.BROKEN_ACCESS,
                "title": "禁止访问的路径",
                "severity": Severity.INFO,
                "recommendation": "确认访问控制规则正确",
                "tag": "forbidden",
            }
        else:
            return {
                "type": VulnerabilityType.INFO_DISCLOSURE,
                "title": f"已发现路径 (HTTP {status})",
                "severity": Severity.INFO,
                "recommendation": "评估路径是否需要额外保护",
                "tag": "info",
            }

    def get_stats(self) -> Dict[str, Any]:
        return self._stats.copy()
