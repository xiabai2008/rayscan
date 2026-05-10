"""漏洞去重和过滤模块"""
from typing import List
from dataclasses import dataclass
import hashlib

from ..vuln.base import Vulnerability


@dataclass
class VulnFingerprint:
    """漏洞指纹"""
    url: str
    param: str
    vuln_type: str
    
    def get_hash(self) -> str:
        """生成指纹哈希"""
        content = f"{self.url}:{self.param}:{self.vuln_type}"
        return hashlib.md5(content.encode()).hexdigest()


class VulnDeduplicator:
    """漏洞去重器"""
    
    def __init__(self):
        self.seen_hashes: set = set()
    
    def deduplicate(self, vulns: List[Vulnerability]) -> List[Vulnerability]:
        """对漏洞列表进行去重"""
        unique_vulns = []
        
        for vuln in vulns:
            fingerprint = self._extract_fingerprint(vuln)
            vuln_hash = fingerprint.get_hash()
            
            if vuln_hash not in self.seen_hashes:
                self.seen_hashes.add(vuln_hash)
                unique_vulns.append(vuln)
        
        return unique_vulns
    
    def _extract_fingerprint(self, vuln: Vulnerability) -> VulnFingerprint:
        """从漏洞中提取指纹"""
        # 提取 URL（去除查询参数）
        url = vuln.url.split("?")[0].split("#")[0]
        
        # 提取参数名（从 payload 或 URL 中）
        param = self._extract_param(vuln.url, vuln.payload)
        
        # 提取漏洞类型
        vuln_type = self._extract_vuln_type(vuln.name)
        
        return VulnFingerprint(url=url, param=param, vuln_type=vuln_type)
    
    def _extract_param(self, url: str, payload: str) -> str:
        """从 URL 中提取参数名"""
        # 尝试从 URL 查询参数中提取
        if "?" in url:
            query = url.split("?")[1]
            if "=" in query:
                return query.split("=")[0]
        
        # 从 payload 特征判断
        if payload.startswith("<script>"):
            return "xss_script"
        elif payload.startswith("<img"):
            return "xss_img"
        elif payload.startswith("'"):
            return "sqli"
        
        return "unknown"
    
    def _extract_vuln_type(self, name: str) -> str:
        """从漏洞名称中提取类型"""
        name_lower = name.lower()
        
        if "xss" in name_lower:
            return "xss"
        elif "sql" in name_lower or "注入" in name_lower:
            return "sqli"
        elif "敏感" in name_lower or "信息" in name_lower:
            return "info_disclosure"
        elif "目录" in name_lower or "遍历" in name_lower:
            return "dir_traversal"
        elif "csrf" in name_lower:
            return "csrf"
        
        return "other"


class VulnFilter:
    """漏洞过滤器"""
    
    def __init__(self, min_confidence: float = 0.5, 
                 exclude_severities: List[str] = None):
        self.min_confidence = min_confidence
        self.exclude_severities = set(exclude_severities or [])
    
    def filter(self, vulns: List[Vulnerability]) -> List[Vulnerability]:
        """过滤漏洞列表"""
        filtered = []
        
        for vuln in vulns:
            # 置信度过滤
            if vuln.confidence < self.min_confidence:
                continue
            
            # 严重等级过滤
            if vuln.severity.name in self.exclude_severities:
                continue
            
            filtered.append(vuln)
        
        return filtered
    
    def sort_by_severity(self, vulns: List[Vulnerability]) -> List[Vulnerability]:
        """按严重等级排序"""
        severity_order = {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3,
            "INFO": 4,
        }
        return sorted(vulns, key=lambda v: severity_order.get(v.severity.name, 99))
