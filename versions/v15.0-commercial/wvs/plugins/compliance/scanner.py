"""数据合规扫描器 - v13.0"""
import re
import json
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass
from enum import Enum


class ComplianceFramework(Enum):
    """合规框架枚举"""
    GDPR = "gdpr"
    CCPA = "ccpa"
    CHINA_DS = "china_ds"  # 数据安全法
    PCI_DSS = "pci_dss"


@dataclass
class PIIFinding:
    """PII发现"""
    pii_type: str
    location: str
    confidence: float
    sample: str
    data_flow: Optional[Dict] = None


class PIIPatterns:
    """PII检测模式"""
    
    PATTERNS = {
        # 个人身份信息
        'email': {
            'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'severity': 'medium',
            'category': 'contact',
        },
        'phone': {
            'pattern': r'\b1[3-9]\d{9}\b|\+86\s*1[3-9]\d{9}',  # 中国手机号
            'severity': 'high',
            'category': 'contact',
        },
        'id_card': {
            'pattern': r'\b\d{17}[\dXx]|\d{15}\b',  # 身份证号
            'severity': 'critical',
            'category': 'identity',
        },
        'credit_card': {
            'pattern': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b',
            'severity': 'critical',
            'category': 'financial',
        },
        'ssn': {
            'pattern': r'\b\d{3}-\d{2}-\d{4}\b',  # 美国SSN
            'severity': 'critical',
            'category': 'identity',
        },
        'bank_account': {
            'pattern': r'\b\d{16,19}\b',  # 银行卡号
            'severity': 'high',
            'category': 'financial',
        },
        'ip_address': {
            'pattern': r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            'severity': 'low',
            'category': 'technical',
        },
        'api_key': {
            'pattern': r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']?[a-zA-Z0-9]{16,}["\']?',
            'severity': 'high',
            'category': 'credential',
        },
        'password': {
            'pattern': r'(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\']{4,}["\']',
            'severity': 'high',
            'category': 'credential',
        },
        'jwt_token': {
            'pattern': r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
            'severity': 'high',
            'category': 'credential',
        },
        'address': {
            'pattern': r'(?:省|市|区|县|街道|路|号|单元|室)[\u4e00-\u9fa5]{2,30}',  # 中文地址
            'severity': 'medium',
            'category': 'location',
        },
        'name': {
            'pattern': r'["\']name["\']\s*[:=]\s*["\'][\u4e00-\u9fa5]{2,4}["\']',  # 中文姓名
            'severity': 'medium',
            'category': 'identity',
        },
    }
    
    @classmethod
    def detect_all(cls, text: str) -> List[PIIFinding]:
        """检测所有PII类型"""
        findings = []
        
        for pii_type, config in cls.PATTERNS.items():
            matches = re.finditer(config['pattern'], text, re.IGNORECASE)
            for match in matches:
                sample = match.group()
                # 脱敏处理
                masked = cls._mask_sample(sample)
                
                findings.append(PIIFinding(
                    pii_type=pii_type,
                    location=f'offset:{match.start()}',
                    confidence=0.85,
                    sample=masked,
                ))
        
        return findings
    
    @staticmethod
    def _mask_sample(sample: str) -> str:
        """脱敏样本"""
        if len(sample) <= 4:
            return '*' * len(sample)
        return sample[:2] + '*' * (len(sample) - 4) + sample[-2:]


class GDPRFramework:
    """GDPR合规框架"""
    
    CHECKS = {
        'data_minimization': {
            'description': '数据最小化原则',
            'check': '检查是否收集不必要的个人数据',
        },
        'purpose_limitation': {
            'description': '目的限制原则',
            'check': '检查数据使用是否超出声明目的',
        },
        'storage_limitation': {
            'description': '存储限制原则',
            'check': '检查数据保留期限是否合理',
        },
        'accuracy': {
            'description': '准确性原则',
            'check': '检查是否有数据更新机制',
        },
        'integrity_confidentiality': {
            'description': '完整性和保密性',
            'check': '检查数据安全措施',
        },
        'lawful_basis': {
            'description': '合法处理依据',
            'check': '检查是否有用户同意机制',
        },
        'data_subject_rights': {
            'description': '数据主体权利',
            'check': '检查访问/删除/更正功能',
        },
    }
    
    def assess_compliance(self, scan_results: Dict) -> Dict:
        """评估GDPR合规性"""
        violations = []
        score = 100
        
        # 检查PII收集
        pii_findings = scan_results.get('pii_findings', [])
        if pii_findings:
            # 检查是否有同意机制
            if not scan_results.get('consent_mechanism_found', False):
                violations.append({
                    'principle': 'lawful_basis',
                    'severity': 'high',
                    'description': '发现PII数据但未检测到用户同意机制',
                    'remediation': '实现明确的用户同意收集流程',
                })
                score -= 20
            
            # 检查数据加密
            if not scan_results.get('encryption_enabled', False):
                violations.append({
                    'principle': 'integrity_confidentiality',
                    'severity': 'high',
                    'description': 'PII数据传输未加密',
                    'remediation': '启用HTTPS/TLS加密',
                })
                score -= 15
        
        # 检查数据保留政策
        if not scan_results.get('retention_policy_found', False):
            violations.append({
                'principle': 'storage_limitation',
                'severity': 'medium',
                'description': '未检测到数据保留期限政策',
                'remediation': '制定并实施数据保留期限政策',
            })
            score -= 10
        
        return {
            'framework': 'GDPR',
            'score': max(0, score),
            'compliant': score >= 80,
            'violations': violations,
            'total_checks': len(self.CHECKS),
            'passed_checks': len(self.CHECKS) - len(violations),
        }
    
    def generate_remediation_steps(self, violations: List[Dict]) -> List[str]:
        """生成修复步骤"""
        steps = []
        for v in violations:
            steps.append(f"[{v['severity'].upper()}] {v['principle']}: {v['remediation']}")
        return steps


class ChinaDSFramework:
    """中国数据安全法合规框架"""
    
    CHECKS = {
        'data_classification': {
            'description': '数据分类分级',
            'check': '检查是否对数据进行分类分级',
        },
        'important_data_protection': {
            'description': '重要数据保护',
            'check': '检查重要数据的安全措施',
        },
        'cross_border_transfer': {
            'description': '跨境数据传输',
            'check': '检查数据出境合规性',
        },
        'data_security_management': {
            'description': '数据安全管理',
            'check': '检查安全管理制度',
        },
        'personal_info_protection': {
            'description': '个人信息保护',
            'check': '检查个保法合规性',
        },
    }
    
    def assess_compliance(self, scan_results: Dict) -> Dict:
        """评估数据安全法合规性"""
        violations = []
        score = 100
        
        # 检查重要数据
        important_data_types = ['id_card', 'bank_account', 'credit_card']
        findings = scan_results.get('pii_findings', [])
        # 支持 dict 或 PIIFinding 对象
        found_important = any(
            (f['pii_type'] if isinstance(f, dict) else f.pii_type) in important_data_types
            for f in findings
        )
        
        if found_important:
            if not scan_results.get('important_data_protection', False):
                violations.append({
                    'principle': 'important_data_protection',
                    'severity': 'high',
                    'description': '发现重要数据但未实施专门保护措施',
                    'remediation': '对重要数据实施加密存储、访问控制等保护措施',
                })
                score -= 25
        
        # 检查跨境传输
        if scan_results.get('third_party_domains', []):
            foreign_domains = [d for d in scan_results['third_party_domains'] 
                             if not d.endswith('.cn')]
            if foreign_domains:
                violations.append({
                    'principle': 'cross_border_transfer',
                    'severity': 'high',
                    'description': f'检测到数据流向境外: {foreign_domains}',
                    'remediation': '实施数据出境安全评估，确保符合跨境传输要求',
                })
                score -= 20
        
        return {
            'framework': 'China Data Security Law',
            'score': max(0, score),
            'compliant': score >= 80,
            'violations': violations,
            'total_checks': len(self.CHECKS),
            'passed_checks': len(self.CHECKS) - len(violations),
        }
    
    def generate_remediation_steps(self, violations: List[Dict]) -> List[str]:
        """生成修复步骤"""
        steps = []
        for v in violations:
            steps.append(f"[{v['severity'].upper()}] {v['principle']}: {v['remediation']}")
        return steps


class DataComplianceScanner:
    """数据合规扫描器主类"""
    
    def __init__(self):
        self.pii_patterns = PIIPatterns()
        self.frameworks = {
            'gdpr': GDPRFramework(),
            'china_ds': ChinaDSFramework(),
            'ccpa': GDPRFramework(),  # CCPA与GDPR类似，复用
            'pci_dss': GDPRFramework(),  # PCI DSS简化实现
        }
    
    def scan_for_pii(self, target_urls: List[str], scan_depth: str = 'deep',
                     crawler=None) -> Dict[str, Any]:
        """扫描PII数据"""
        results = {
            'scan_depth': scan_depth,
            'urls_scanned': len(target_urls),
            'pii_findings': [],
            'pii_summary': {},
            'data_flows': [],
        }
        
        all_findings = []
        
        for url in target_urls:
            try:
                # 获取响应
                if crawler:
                    response = crawler.get_response(url)
                    text = response.text
                else:
                    import requests
                    response = requests.get(url, timeout=10)
                    text = response.text
                
                # 检测PII
                findings = self.pii_patterns.detect_all(text)
                
                for finding in findings:
                    finding.data_flow = self._trace_data_flow(url, finding)
                
                all_findings.extend(findings)
                
            except Exception as e:
                results['error'] = str(e)
        
        # 去重和汇总
        results['pii_findings'] = self._deduplicate_findings(all_findings)
        results['pii_summary'] = self._summarize_pii(results['pii_findings'])
        
        return results
    
    def _trace_data_flow(self, source: str, finding: PIIFinding) -> Dict:
        """追踪数据流向"""
        return {
            'source': source,
            'pii_type': finding.pii_type,
            'destination': 'unknown',  # 简化实现
            'transmission_method': 'https',  # 假设
        }
    
    def _deduplicate_findings(self, findings: List[PIIFinding]) -> List[Dict]:
        """去重"""
        seen = set()
        unique = []
        
        for f in findings:
            key = (f.pii_type, f.location)
            if key not in seen:
                seen.add(key)
                unique.append({
                    'pii_type': f.pii_type,
                    'location': f.location,
                    'confidence': f.confidence,
                    'sample': f.sample,
                    'data_flow': f.data_flow,
                })
        
        return unique
    
    def _summarize_pii(self, findings: List[Dict]) -> Dict:
        """汇总PII统计"""
        summary = {}
        
        for f in findings:
            pii_type = f['pii_type']
            summary[pii_type] = summary.get(pii_type, 0) + 1
        
        return {
            'total_findings': len(findings),
            'by_type': summary,
            'unique_types': len(summary),
        }
    
    def generate_compliance_report(self, scan_results: Dict, 
                                   framework: str = 'gdpr') -> Dict[str, Any]:
        """生成合规报告"""
        if framework not in self.frameworks:
            return {'error': f'不支持的合规框架: {framework}'}
        
        framework_engine = self.frameworks[framework]
        compliance_status = framework_engine.assess_compliance(scan_results)
        
        return {
            'framework': framework,
            'compliance_score': compliance_status['score'],
            'is_compliant': compliance_status['compliant'],
            'violations': compliance_status['violations'],
            'remediation_steps': framework_engine.generate_remediation_steps(
                compliance_status['violations']
            ),
            'executive_summary': self._generate_executive_summary(compliance_status),
            'total_checks': compliance_status['total_checks'],
            'passed_checks': compliance_status['passed_checks'],
        }
    
    def _generate_executive_summary(self, compliance_status: Dict) -> str:
        """生成执行摘要"""
        score = compliance_status['score']
        violations = compliance_status['violations']
        
        if score >= 90:
            level = '优秀'
            status = '高度合规'
        elif score >= 80:
            level = '良好'
            status = '基本合规'
        elif score >= 60:
            level = '一般'
            status = '部分合规'
        else:
            level = '较差'
            status = '不合规'
        
        return f"""
合规评估结果: {status}
合规评分: {score}/100 ({level})
发现问题: {len(violations)} 项

关键建议:
{chr(10).join(f"- {v['description']}" for v in violations[:3]) if violations else "- 暂无重大问题"}

下一步行动:
{chr(10).join(f"- {v['remediation']}" for v in violations[:3]) if violations else "- 继续保持合规实践"}
        """.strip()
    
    def scan_all_frameworks(self, scan_results: Dict) -> Dict[str, Any]:
        """扫描所有合规框架"""
        results = {}
        
        for framework_name in self.frameworks.keys():
            results[framework_name] = self.generate_compliance_report(
                scan_results, framework_name
            )
        
        return results
