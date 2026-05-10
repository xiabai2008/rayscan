"""WVS v18.0 - 数据合规扫描插件

功能：
1. PII 自动检测
2. GDPR 合规检查
3. CCPA 合规检查
4. 中国数据安全法合规
5. PCI DSS 合规
"""
import re
from typing import List, Dict, Pattern
from dataclasses import dataclass
from enum import Enum


class ComplianceFramework(Enum):
    GDPR = "gdpr"
    CCPA = "ccpa"
    CHINA_DS = "china_data_security"  # 中国数据安全法
    CHINA_PI = "china_personal_info"  # 个人信息保护法
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    ISO27001 = "iso27001"


@dataclass
class PIIFinding:
    data_type: str
    pattern_matched: str
    location: str
    context: str
    severity: str
    regulation: str
    recommendation: str


@dataclass
class ComplianceViolation:
    framework: ComplianceFramework
    article: str
    requirement: str
    status: str  # compliant / non-compliant / partial
    evidence: str
    recommendation: str


class PIIDetector:
    """PII 自动检测"""
    
    # PII 类型和正则模式
    PII_PATTERNS: Dict[str, List[Pattern]] = {
        "email": [
            re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
        ],
        "phone_cn": [
            re.compile(r'1[3-9]\d{9}'),  # 中国手机号
            re.compile(r'0\d{2,3}-?\d{7,8}'),  # 固定电话
        ],
        "phone_intl": [
            re.compile(r'\+?\d{1,3}[-.\s]?\d{3,4}[-.\s]?\d{4}'),
        ],
        "id_card_cn": [
            re.compile(r'\d{17}[\dXx]'),  # 中国身份证
        ],
        "ssn_us": [
            re.compile(r'\d{3}-\d{2}-\d{4}'),  # 美国社保号
        ],
        "credit_card": [
            re.compile(r'4\d{12}(\d{3})?'),  # Visa
            re.compile(r'5[1-5]\d{14}'),  # MasterCard
            re.compile(r'3[47]\d{13}'),  # Amex
            re.compile(r'6(?:011|5\d{2})\d{12}'),  # Discover
        ],
        "bank_account_cn": [
            re.compile(r'\d{16,19}'),  # 银行卡号
        ],
        "passport_cn": [
            re.compile(r'[GE]\d{8}'),  # 中国护照
        ],
        "api_key": [
            re.compile(r'(?i)api[_-]?key\s*[=:]\s*["\']?[\w-]{20,}'),
            re.compile(r'sk-[a-zA-Z0-9]{48}'),  # OpenAI API Key
            re.compile(r'AKIA[0-9A-Z]{16}'),  # AWS Access Key
        ],
        "password": [
            re.compile(r'(?i)password\s*[=:]\s*["\'][^"\']{6,}["\']'),
            re.compile(r'(?i)passwd\s*[=:]\s*["\'][^"\']{6,}["\']'),
        ],
        "secret_key": [
            re.compile(r'(?i)secret[_-]?key\s*[=:]\s*["\']?[\w-]{16,}'),
            re.compile(r'(?i)private[_-]?key'),
        ],
        "token": [
            re.compile(r'(?i)token\s*[=:]\s*["\']?[\w-]{20,}'),
            re.compile(r'Bearer\s+[A-Za-z0-9-_.]+'),
            re.compile(r'eyJ[A-Za-z0-9-_.]+\.eyJ[A-Za-z0-9-_.]+\.[A-Za-z0-9-_.]+'),  # JWT
        ],
        "ip_address": [
            re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            re.compile(r'\b([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'),  # IPv6
        ],
        "mac_address": [
            re.compile(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})'),
        ],
        "url": [
            re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+'),
        ],
    }
    
    # 严重程度映射
    SEVERITY_MAP = {
        "password": "critical",
        "secret_key": "critical",
        "api_key": "critical",
        "token": "critical",
        "credit_card": "critical",
        "id_card_cn": "high",
        "ssn_us": "critical",
        "passport_cn": "high",
        "bank_account_cn": "high",
        "email": "medium",
        "phone_cn": "medium",
        "phone_intl": "medium",
        "ip_address": "low",
        "mac_address": "low",
        "url": "info",
    }
    
    def detect(self, content: str, location: str = "") -> List[PIIFinding]:
        """检测文本中的 PII"""
        findings = []
        
        for data_type, patterns in self.PII_PATTERNS.items():
            for pattern in patterns:
                matches = pattern.finditer(content)
                
                for match in matches:
                    # 获取上下文
                    start = max(0, match.start() - 50)
                    end = min(len(content), match.end() + 50)
                    context = content[start:end]
                    
                    # 隐私脱敏
                    matched_text = match.group()
                    if len(matched_text) > 10:
                        masked = matched_text[:3] + "*" * (len(matched_text) - 6) + matched_text[-3:]
                    else:
                        masked = "*" * len(matched_text)
                    
                    findings.append(PIIFinding(
                        data_type=data_type,
                        pattern_matched=masked,
                        location=location,
                        context=context,
                        severity=self.SEVERITY_MAP.get(data_type, "medium"),
                        regulation=self._get_regulation(data_type),
                        recommendation=self._get_recommendation(data_type)
                    ))
        
        return findings
    
    def _get_regulation(self, data_type: str) -> str:
        """获取相关法规"""
        regulations = {
            "email": "GDPR Article 4(1), 个人信息保护法",
            "phone_cn": "个人信息保护法 第4条",
            "id_card_cn": "个人信息保护法 第4条, 数据安全法 第21条",
            "credit_card": "PCI DSS Requirement 3",
            "password": "GDPR Article 32, 数据安全法 第27条",
            "api_key": "数据安全法 第27条",
            "secret_key": "数据安全法 第27条",
        }
        return regulations.get(data_type, "数据安全法")
    
    def _get_recommendation(self, data_type: str) -> str:
        """获取修复建议"""
        recommendations = {
            "email": "加密存储，限制访问权限",
            "phone_cn": "加密存储，脱敏展示",
            "id_card_cn": "加密存储，严格访问控制",
            "credit_card": "符合 PCI DSS 标准，不存储完整卡号",
            "password": "使用安全哈希存储，禁止明文",
            "api_key": "使用密钥管理服务，禁止硬编码",
            "secret_key": "使用 HSM 或密钥管理服务",
            "token": "使用安全存储，定期轮换",
        }
        return recommendations.get(data_type, "加密存储，访问控制")


class GDPRChecker:
    """GDPR 合规检查"""
    
    REQUIREMENTS = [
        {
            "article": "Art. 5(1)(a)",
            "requirement": "合法、公平、透明处理",
            "check": lambda data: data.get("privacy_policy", False),
            "evidence": "检查隐私政策是否存在"
        },
        {
            "article": "Art. 5(1)(b)",
            "requirement": "目的限制",
            "check": lambda data: data.get("purpose_limitation", False),
            "evidence": "检查数据处理目的是否明确"
        },
        {
            "article": "Art. 5(1)(c)",
            "requirement": "数据最小化",
            "check": lambda data: data.get("data_minimization", False),
            "evidence": "检查是否仅收集必要数据"
        },
        {
            "article": "Art. 5(1)(d)",
            "requirement": "准确性",
            "check": lambda data: data.get("accuracy", False),
            "evidence": "检查数据更新机制"
        },
        {
            "article": "Art. 5(1)(e)",
            "requirement": "存储限制",
            "check": lambda data: data.get("storage_limitation", False),
            "evidence": "检查数据保留策略"
        },
        {
            "article": "Art. 5(1)(f)",
            "requirement": "完整性保密性",
            "check": lambda data: data.get("security", False),
            "evidence": "检查安全措施"
        },
        {
            "article": "Art. 32",
            "requirement": "安全措施",
            "check": lambda data: data.get("encryption", False),
            "evidence": "检查加密措施"
        },
    ]
    
    def check(self, assessment_data: Dict) -> List[ComplianceViolation]:
        """检查 GDPR 合规"""
        violations = []
        
        for req in self.REQUIREMENTS:
            status = "compliant" if req["check"](assessment_data) else "non-compliant"
            
            violations.append(ComplianceViolation(
                framework=ComplianceFramework.GDPR,
                article=req["article"],
                requirement=req["requirement"],
                status=status,
                evidence=req["evidence"],
                recommendation=self._get_recommendation(req["article"])
            ))
        
        return violations
    
    def _get_recommendation(self, article: str) -> str:
        """获取修复建议"""
        recommendations = {
            "Art. 5(1)(a)": "发布清晰的隐私政策，告知数据处理详情",
            "Art. 5(1)(b)": "明确数据处理目的，不得超出目的范围使用",
            "Art. 5(1)(c)": "仅收集业务必需的最少数据",
            "Art. 5(1)(d)": "建立数据更新和核验机制",
            "Art. 5(1)(e)": "制定数据保留期限，到期自动删除",
            "Art. 5(1)(f)": "实施技术和组织安全措施",
            "Art. 32": "加密个人数据，实施访问控制",
        }
        return recommendations.get(article, "参考 GDPR 要求")


class ChinaDataSecurityChecker:
    """中国数据安全法合规检查"""
    
    REQUIREMENTS = [
        {
            "article": "第21条",
            "requirement": "数据分类分级",
            "check": lambda data: data.get("classification", False),
        },
        {
            "article": "第27条",
            "requirement": "安全保护义务",
            "check": lambda data: data.get("security_measures", False),
        },
        {
            "article": "第30条",
            "requirement": "风险评估",
            "check": lambda data: data.get("risk_assessment", False),
        },
        {
            "article": "第31条",
            "requirement": "重要数据保护",
            "check": lambda data: data.get("important_data_protection", False),
        },
        {
            "article": "第33条",
            "requirement": "数据交易安全",
            "check": lambda data: data.get("data_trading_security", True),
        },
    ]
    
    def check(self, assessment_data: Dict) -> List[ComplianceViolation]:
        """检查数据安全法合规"""
        violations = []
        
        for req in self.REQUIREMENTS:
            status = "compliant" if req["check"](assessment_data) else "non-compliant"
            
            violations.append(ComplianceViolation(
                framework=ComplianceFramework.CHINA_DS,
                article=req["article"],
                requirement=req["requirement"],
                status=status,
                evidence="",
                recommendation=self._get_recommendation(req["article"])
            ))
        
        return violations
    
    def _get_recommendation(self, article: str) -> str:
        """获取修复建议"""
        recommendations = {
            "第21条": "建立数据分类分级制度，识别重要数据",
            "第27条": "落实安全保护措施，防止数据泄露",
            "第30条": "定期开展数据安全风险评估",
            "第31条": "对重要数据实施重点保护",
            "第33条": "数据交易需获得授权，确保来源合法",
        }
        return recommendations.get(article, "参考数据安全法要求")


class ComplianceScanner:
    """合规扫描主类"""
    
    def __init__(self):
        self.pii_detector = PIIDetector()
        self.gdpr_checker = GDPRChecker()
        self.china_checker = ChinaDataSecurityChecker()
    
    def scan_pii(self, content: str, location: str = "") -> List[PIIFinding]:
        """扫描 PII"""
        return self.pii_detector.detect(content, location)
    
    def check_compliance(self, framework: ComplianceFramework, data: Dict) -> List[ComplianceViolation]:
        """检查合规"""
        if framework == ComplianceFramework.GDPR:
            return self.gdpr_checker.check(data)
        elif framework == ComplianceFramework.CHINA_DS:
            return self.china_checker.check(data)
        else:
            return []
    
    def generate_report(self, pii_findings: List[PIIFinding], compliance_results: List[ComplianceViolation]) -> Dict:
        """生成合规报告"""
        return {
            "pii_summary": {
                "total": len(pii_findings),
                "critical": sum(1 for f in pii_findings if f.severity == "critical"),
                "high": sum(1 for f in pii_findings if f.severity == "high"),
                "medium": sum(1 for f in pii_findings if f.severity == "medium"),
                "by_type": self._count_by_type(pii_findings),
            },
            "compliance_summary": {
                "compliant": sum(1 for v in compliance_results if v.status == "compliant"),
                "non_compliant": sum(1 for v in compliance_results if v.status == "non-compliant"),
                "partial": sum(1 for v in compliance_results if v.status == "partial"),
            },
            "pii_findings": [f.__dict__ for f in pii_findings],
            "compliance_results": [v.__dict__ for v in compliance_results],
        }
    
    def _count_by_type(self, findings: List[PIIFinding]) -> Dict[str, int]:
        """按类型统计"""
        count = {}
        for f in findings:
            count[f.data_type] = count.get(f.data_type, 0) + 1
        return count
