"""
Sqlmap 集成模块
v19.2 新增：调用 sqlmap 进行深度 SQL 注入检测

策略：
1. 优先使用真实 sqlmap CLI
2. 使用 --batch 模式自动应答
3. 解析 stdout 输出提取注入点
4. 结果映射为 Vulnerability 对象
"""
import asyncio
import json
import logging
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config import ConfigManager
from ..models import Vulnerability, VulnerabilityType, Severity, Confidence


logger = logging.getLogger("wvs.integrations.sqlmap")

# sqlmap 可能的路径
SQLMAP_PATHS = [
    "C:/Tools/sqlmap/sqlmap.py",
    "C:/Tools/sqlmap/sqlmap.exe",
    "sqlmap",
    "sqlmap.py",
]

# 默认技术组合（B: Boolean, E: Error, U: Union, S: Stacked, T: Time）
DEFAULT_TECHNIQUES = "BEUST"


class SqlmapIntegration:
    """
    Sqlmap 集成

    使用真实 sqlmap CLI 执行自动化 SQL 注入检测，
    结果解析为 Vulnerability 对象。

    支持：
    - 多种注入技术（Boolean/Error/Union/Stacked/Time）
    - 数据库指纹识别
    - 数据提取（可选，需显式开启）
    - 自定义检测级别和风险等级
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
        """查找 sqlmap 是否存在"""
        for path in SQLMAP_PATHS:
            if os.path.exists(path):
                logger.info(f"[Sqlmap] 找到 sqlmap: {path}")
                return path
        exe = shutil.which("sqlmap")
        if exe:
            logger.info(f"[Sqlmap] 从 PATH 找到 sqlmap: {exe}")
            return exe
        logger.warning("[Sqlmap] 未找到 sqlmap")
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
        使用 sqlmap 扫描目标

        Args:
            url: 目标 URL
            method: HTTP 方法 (GET/POST)
            data: POST 数据
            cookies: Cookie 字典
            headers: 额外的 HTTP headers
            level: 检测级别 (1-5)
            risk: 风险级别 (1-3)
            techniques: 注入技术 (BEUST)
            extract_data: 是否提取数据（慢且危险）

        Returns:
            发现的 SQL 注入漏洞列表
        """
        if not self.is_available:
            logger.warning("[Sqlmap] sqlmap 不可用，跳过扫描")
            return []

        return await self._scan_async(
            url, method, data, cookies, headers,
            level, risk, techniques, extract_data
        )

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
        """异步执行 sqlmap 扫描"""
        # 基础命令
        cmd = [self._get_runner(), "-u", url]

        # 注入技术
        cmd.extend(["--technique", techniques])

        # 检测深度
        cmd.extend(["--level", str(max(1, min(5, level)))])
        cmd.extend(["--risk", str(max(1, min(3, risk)))])

        # 自动化
        cmd.append("--batch")

        # 随机 UA
        cmd.append("--random-agent")

        # 跳过确认
        cmd.append("--skip-waf")

        # HTTP 方法
        if method.upper() == "POST":
            cmd.extend(["--method", "POST"])
        else:
            cmd.extend(["--method", "GET"])

        # POST 数据
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

        # 不提取数据（除非显式要求）
        if not extract_data:
            cmd.append("--no-escape")

        # 线程
        cmd.extend(["--threads", "3"])

        logger.info(f"[Sqlmap] 执行: {self._get_runner()} -u {url} --level {level} --risk {risk}")

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
                logger.warning(f"[Sqlmap] 超时（>{self.timeout + 30}s）")
                return []

            output = stdout.decode("utf-8", errors="ignore")
            stderr_output = stderr.decode("utf-8", errors="ignore")

            if stderr_output and "error" in stderr_output.lower():
                logger.warning(f"[Sqlmap] stderr: {stderr_output[:300]}")

            return self._parse_sqlmap_output(output, url)

        except FileNotFoundError:
            logger.error(f"[Sqlmap] 未找到: {self.sqlmap_path}")
            return []
        except Exception as e:
            logger.error(f"[Sqlmap] 执行失败: {e}")
            return []

    def _get_runner(self) -> str:
        """获取运行 sqlmap 的命令"""
        if self.sqlmap_path and self.sqlmap_path.endswith(".py"):
            return self.python_exe
        return self.sqlmap_path

    def _build_command(self) -> List[str]:
        """构建完整命令（sqlmap.py 需要 python 前缀）"""
        if self.sqlmap_path and self.sqlmap_path.endswith(".py"):
            return [self.python_exe, self.sqlmap_path]
        return [self.sqlmap_path]

    def _parse_sqlmap_output(self, output: str, target_url: str) -> List[Vulnerability]:
        """解析 sqlmap stdout 输出"""
        vulnerabilities = []

        # ── 检查是否发现注入 ──
        if "identified the following injection point" not in output:
            # 尝试其他匹配模式
            if "is vulnerable" not in output and "vulnerable" not in output.lower():
                logger.debug("[Sqlmap] 未发现注入点")
                return []

        # ── 提取注入参数 ──
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
            # 尝试宽松匹配
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

        # ── 解析每个注入点 ──
        for match in injections:
            param = match.group(1).strip()
            inj_type = match.group(2).strip()
            title = match.group(3).strip()
            payload = match.group(4).strip() if len(match.groups()) >= 4 else ""

            # 提取数据库类型
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
                recommendation=(
                    "1. 使用参数化查询/预编译语句\n"
                    "2. 对输入进行严格校验和转义\n"
                    "3. 最小化数据库用户权限\n"
                    "4. 启用 WAF 作为额外防护层"
                ),
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
        """根据注入类型评估严重程度和置信度"""
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
        """获取统计信息"""
        return self._stats.copy()
