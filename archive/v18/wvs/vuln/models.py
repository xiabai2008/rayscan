"""WVS v18 - 统一数据模型

避免循环导入，所有模块共享的数据类定义。
"""
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass(eq=False)
class Vulnerability:
    """统一漏洞格式"""
    type: str
    url: str
    parameter: str = ""
    payload: str = ""
    severity: str = "medium"  # critical, high, medium, low, info
    confidence: float = 0.7
    evidence: str = ""
    source: str = "scanner"  # scanner, sqlmap, nuclei, playwright
    cve_id: str = ""
    cvss_score: float = 0.0

    def __hash__(self):
        """基于 type + url + parameter 去重"""
        return hash((self.type, self.url, self.parameter))

    async def exploit(self, attacker_ip: str = "127.0.0.1", attacker_port: int = 4444):
        """自动利用此漏洞"""
        # 延迟导入避免循环依赖
        from ..modules.exploit import exploit_vulnerability

        vuln_info = {
            'type': self.type,
            'url': self.url,
            'parameter': self.parameter,
            'payload': self.payload,
            'evidence': self.evidence,
            'severity': self.severity,
            'attacker_ip': attacker_ip,
            'attacker_port': attacker_port
        }

        return await exploit_vulnerability(vuln_info)


@dataclass
class ScanResult:
    """统一扫描结果"""
    target: str
    urls: List[str] = field(default_factory=list)
    forms: List[Dict] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    sensitive_paths: List[Dict] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    duration: float = 0.0
    sources: List[str] = field(default_factory=list)
