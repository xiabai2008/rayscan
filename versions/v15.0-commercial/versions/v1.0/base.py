"""漏洞扫描器基类"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from enum import Enum


class Severity(Enum):
    """漏洞严重等级"""
    CRITICAL = ("严重", 9.0, 10.0, "#C0392B")
    HIGH = ("高危", 7.0, 8.9, "#E74C3C")
    MEDIUM = ("中危", 4.0, 6.9, "#E67E22")
    LOW = ("低危", 0.1, 3.9, "#F1C40F")
    INFO = ("信息", 0.0, 0.0, "#7F8C8D")
    
    def __init__(self, label_cn, cvss_min, cvss_max, color):
        self.label_cn = label_cn
        self.cvss_min = cvss_min
        self.cvss_max = cvss_max
        self.color = color


@dataclass
class Vulnerability:
    """漏洞数据类"""
    name: str
    severity: Severity
    url: str
    payload: str
    description: str
    remediation: str = ""
    confidence: float = 0.0
    cve_ids: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "severity": self.severity.name,
            "severity_cn": self.severity.label_cn,
            "color": self.severity.color,
            "url": self.url,
            "payload": self.payload,
            "description": self.description,
            "remediation": self.remediation,
            "confidence": self.confidence,
            "cve_ids": self.cve_ids,
        }


class BaseVulnerabilityChecker(ABC):
    """漏洞检测器基类"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.name = self.__class__.__name__
        self.false_positive_markers = [
            "Access Denied", "Forbidden", "401 Unauthorized",
            "403 Forbidden", "BLOCKED BY", "WAF",
        ]
    
    @abstractmethod
    async def check(self, target: str, context: Dict) -> List[Vulnerability]:
        """执行漏洞检测"""
        pass
    
    def is_false_positive(self, response_text: str) -> bool:
        """检查是否为误报"""
        text = response_text.lower()
        return any(marker.lower() in text for marker in self.false_positive_markers)
