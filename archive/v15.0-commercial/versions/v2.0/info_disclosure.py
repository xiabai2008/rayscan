"""敏感信息泄露检测模块"""
import re
from typing import List, Dict
from urllib.parse import urljoin

from .base import BaseVulnerabilityChecker, Vulnerability, Severity
from ..core.payloads_v3 import SENSITIVE_PATHS_V3


# 敏感信息正则模式
SENSITIVE_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"[0-9a-zA-Z/+]{40}",
    "GitHub Token": r"gh[pousr]_[A-Za-z0-9_]{35,}",
    "GitLab Token": r"glpat-[0-9a-zA-Z\-]{20}",
    "OpenAI API Key": r"sk-[0-9A-Za-z]{48}",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "Private Key": r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
    "Password Pattern": r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{4,}['\"]",
    "Email Pattern": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "IP Address": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
}

# 使用扩展的敏感路径列表
SENSITIVE_PATHS = SENSITIVE_PATHS_V3


class InfoDisclosureScanner(BaseVulnerabilityChecker):
    """敏感信息泄露扫描器"""
    
    async def check(self, target: str, context: Dict) -> List[Vulnerability]:
        """执行敏感信息检测"""
        vulns = []
        session = context.get("session")
        urls = context.get("urls", [])
        
        if session is None:
            return vulns
        
        base_url = target.rstrip("/")
        
        # 1. 检测敏感路径
        for path in SENSITIVE_PATHS[:20]:  # 限制数量避免太慢
            result = await self._check_path(base_url, path, session)
            if result:
                vulns.append(result)
        
        # 2. 检测已爬取页面中的敏感信息
        for url in urls[:10]:
            result = await self._check_content(url, session)
            vulns.extend(result)
        
        return vulns
    
    async def _check_path(self, base_url: str, path: str, session) -> Vulnerability:
        """检测敏感路径是否可访问"""
        url = f"{base_url}/{path}"
        try:
            async with session.get(url, timeout=5, ssl=False) as resp:
                if resp.status == 200:
                    content = await resp.text()
                    if self._is_sensitive_content(content, path):
                        return Vulnerability(
                            name=f"敏感路径泄露: {path}",
                            severity=Severity.HIGH,
                            url=url,
                            payload=path,
                            description=f"发现敏感路径 {path} 可被直接访问",
                            remediation="禁止敏感路径的外部访问",
                            confidence=0.9,
                        )
        except Exception:
            pass
        return None
    
    async def _check_content(self, url: str, session) -> List[Vulnerability]:
        """检测页面内容中的敏感信息"""
        vulns = []
        try:
            async with session.get(url, timeout=5, ssl=False) as resp:
                if resp.status == 200:
                    content = await resp.text()
                    
                    for pattern_name, pattern in SENSITIVE_PATTERNS.items():
                        matches = re.findall(pattern, content)
                        if matches:
                            unique_matches = list(set(matches))[:2]
                            for match in unique_matches:
                                masked = self._mask_sensitive(match)
                                vulns.append(Vulnerability(
                                    name=f"敏感信息: {pattern_name}",
                                    severity=Severity.CRITICAL if "Key" in pattern_name or "Token" in pattern_name else Severity.HIGH,
                                    url=url,
                                    payload=masked,
                                    description=f"发现 {pattern_name}: {masked}",
                                    remediation="移除敏感信息，使用环境变量",
                                    confidence=0.85,
                                ))
        except Exception:
            pass
        return vulns
    
    def _is_sensitive_content(self, content: str, path: str) -> bool:
        """判断内容是否敏感"""
        if path.endswith(".git/config"):
            return "[core]" in content or "remote" in content
        if ".env" in path:
            return "=" in content and len(content) > 10
        if path.endswith((".sql", ".bak")):
            return len(content) > 100
        if "phpinfo" in path.lower():
            return "phpinfo()" in content or "PHP Version" in content
        return len(content) > 0
    
    def _mask_sensitive(self, text: str) -> str:
        """隐藏敏感信息"""
        text_str = str(text)
        if len(text_str) <= 8:
            return "*" * len(text_str)
        return text_str[:4] + "****" + text_str[-4:]
