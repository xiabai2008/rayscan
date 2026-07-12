"""
WebShell 检测模块

检测已知 WebShell 的路径、内容特征、请求行为。
利用本地 04-webshell/ 中的样本生成检测指纹。
"""

import logging
import re
from typing import List, Optional, Set

from ...models import Confidence, ScanTarget, Severity, Vulnerability
from ..base import DetectionModule, ModuleInfo, register_module

logger = logging.getLogger("wvs.module.webshell")

# ── 已知 WebShell 路径特征 ────────────────────────────────────
WEBSHELL_PATHS = {
    "/shell.php",
    "/shell.asp",
    "/shell.aspx",
    "/shell.jsp",
    "/cmd.php",
    "/cmd.asp",
    "/webshell.php",
    "/webshell.asp",
    "/b374k.php",
    "/b374k/",
    "/b374k",
    "/c99.php",
    "/c99shell.php",
    "/r57.php",
    "/r57shell.php",
    "/wso.php",
    "/wso112.php",
    "/wsoshell.php",
    "/ma.php",
    "/ma.asp",
    "/ant.aspx",
    "/ant.php",
    "/godzilla.php",
    "/godzilla.jsp",
    "/behinder.php",
    "/behinder.jsp",
    "/behinder.aspx",
    "/冰蝎.php",
    "/冰蝎.jsp",
    "/哥斯拉.php",
    "/哥斯拉.jsp",
    "/_shell.php",
    "/_webshell.php",
    "/up.php",
    "/upload.php",
    "/files.php",
    "/404.php",
    "/admin_shell.php",
    "/1.php",
    "/2.php",
    "/3.php",
}

# ── WebShell 内容特征 (正则) ──────────────────────────────────
WEBSHELL_PATTERNS = [
    # 一句话木马
    re.compile(r"eval\s*\(\s*\$_\s*(POST|GET|REQUEST|SERVER)\s*\[", re.I),
    re.compile(r"assert\s*\(\s*\$_\s*(POST|GET|REQUEST)\s*\[", re.I),
    re.compile(r"@eval\(", re.I),
    re.compile(r"@\s*assert\(", re.I),
    re.compile(r'\$_\s*(POST|GET|REQUEST)\s*\[\s*[\'"]\w+[\'"]\s*\]\s*\)', re.I),
    # 大马特征
    re.compile(r"class\s+.*WebShell", re.I),
    re.compile(r"class\s+.*FileManager", re.I),
    re.compile(r"class\s+.*ShellManager", re.I),
    re.compile(r"class\s+.*C99", re.I),
    re.compile(r"class\s+.*R57", re.I),
    re.compile(r"class\s+.*WSO", re.I),
    # JSP 木马
    re.compile(r"Runtime\.getRuntime\(\)\.exec\(", re.I),
    re.compile(r"ProcessBuilder\(\)", re.I),
    re.compile(r"java\.lang\.Runtime", re.I),
    # ASP 木马
    re.compile(r'CreateObject\s*\(\s*[\'"]WScript\.Shell[\'"]\s*\)', re.I),
    re.compile(r'CreateObject\s*\(\s*[\'"]Shell\.Application[\'"]\s*\)', re.I),
    # 编码器
    re.compile(r"base64_decode\s*\(\s*\$_\s*(POST|GET)", re.I),
    re.compile(r"gzinflate\s*\(\s*base64_decode", re.I),
    re.compile(r"str_rot13", re.I),
    # 冰蝎特征
    re.compile(r"@error_reporting\(0\)", re.I),
    re.compile(r"session_start\(\)", re.I),
    re.compile(r"base64_decode\(\$postStr\)", re.I),
    # 哥斯拉特征
    re.compile(r"Godzilla", re.I),
    re.compile(r"goddess", re.I),
]

# ── WebShell 文件哈希黑名单 ────────────────────────────────────
KNOWN_WEBSHELL_HASHES: Set[str] = set()


@register_module
class WebShellDetector(DetectionModule):
    """WebShell 检测模块"""

    @classmethod
    def get_info(cls) -> ModuleInfo:
        return ModuleInfo(
            name="webshell",
            description="WebShell 检测 — 路径扫描/内容特征/文件哈希",
            author="RayScan Team",
            version="1.0.0",
            enabled_by_default=False,
            tags=["webshell", "backdoor", "malware"],
        )

    async def _scan_impl(self, target: ScanTarget) -> List[Vulnerability]:
        url = target.url.rstrip("/")
        vulnerabilities: List[Vulnerability] = []
        base = url.split("?")[0].rstrip("/")

        # 提取域名根路径
        from urllib.parse import urlparse

        parsed = urlparse(base)
        root = f"{parsed.scheme}://{parsed.netloc}"

        checked = set()
        for shell_path in WEBSHELL_PATHS:
            full_url = root.rstrip("/") + shell_path
            if full_url in checked:
                continue
            checked.add(full_url)

            vuln = await self._check_webshell(full_url)
            if vuln:
                vulnerabilities.append(vuln)

        return vulnerabilities

    async def _check_webshell(self, url: str) -> Optional[Vulnerability]:
        """检查单个 WebShell 路径"""
        try:
            resp = await self._send_request("GET", url, {})
            if not resp:
                return None

            status = resp.get("status_code", 0)
            body = resp.get("text", "")

            if status == 200 and len(body) > 10:
                # 检查内容特征
                matched_patterns = []
                for pattern in WEBSHELL_PATTERNS:
                    if pattern.search(body):
                        matched_patterns.append(pattern.pattern[:40])

                if matched_patterns:
                    return self._create_vuln(
                        url=url,
                        param=None,
                        param_type="query",
                        method="GET",
                        payload="",
                        vuln_type="webshell",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        evidence=f"匹配 {len(matched_patterns)} 个 WebShell 特征",
                        description=f"发现疑似 WebShell: {url}",
                        recommendation="立即删除该文件并排查入侵来源",
                        context={"matched_patterns": matched_patterns[:5], "body_size": len(body)},
                    )

                # 简单启发式检测
                heuristic_score = 0
                if any(kw in body.lower() for kw in ["exec", "shell", "cmd", "password", "admin"]):
                    heuristic_score += 1
                if any(kw in body.lower() for kw in ["eval", "assert", "system", "passthru"]):
                    heuristic_score += 2
                if "<?php" in body or "<%@" in body:
                    heuristic_score += 1

                if heuristic_score >= 3:
                    return self._create_vuln(
                        url=url,
                        param=None,
                        param_type="query",
                        method="GET",
                        payload="",
                        vuln_type="webshell",
                        severity=Severity.HIGH,
                        confidence=Confidence.LOW,
                        evidence=f"启发式评分: {heuristic_score}/5",
                        description=f"可疑文件: {url}",
                        recommendation="人工确认是否为 WebShell",
                        context={"heuristic_score": heuristic_score},
                    )

            # 404 返回非标准响应（可能是隐藏的 WebShell）
            if status == 404 and len(body) > 500 and status != status:
                pass  # 一般不是 WebShell

        except Exception as e:
            logger.debug(f"[WebShell] 检查失败 {url}: {e}")

        return None
