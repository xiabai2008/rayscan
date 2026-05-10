"""自动化修复模块 - 漏洞自动修复建议"""
import re
from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class FixSuggestion:
    """修复建议"""
    vuln_type: str
    description: str
    code_before: str
    code_after: str
    file_pattern: str
    confidence: float
    automated: bool = False


class AutoFixer:
    """自动修复器"""
    
    def __init__(self):
        self.fix_patterns = self._load_fix_patterns()
    
    def _load_fix_patterns(self) -> Dict:
        """加载修复模式"""
        return {
            "xss": {
                "php": {
                    "pattern": r'echo\s+\$_(GET|POST|REQUEST)\[.*\]',
                    "fix": "echo htmlspecialchars($_$1[$2], ENT_QUOTES, 'UTF-8');",
                    "description": "使用htmlspecialchars转义输出",
                },
                "python": {
                    "pattern": r'render_template\(.*user_input',
                    "fix": "使用Jinja2 autoescape",
                    "description": "启用模板自动转义",
                },
            },
            "sqli": {
                "php": {
                    "pattern": r'mysql_query\s*\(\s*["\'].*\$',
                    "fix": "使用PDO预处理语句",
                    "description": "使用参数化查询",
                },
                "python": {
                    "pattern": r'execute\s*\(\s*["\'].*%s',
                    "fix": "cursor.execute(query, params)",
                    "description": "使用参数化查询",
                },
            },
            "hardcoded_password": {
                "generic": {
                    "pattern": r'(password|passwd|pwd)\s*=\s*["\'][^"\']+["\']',
                    "fix": "使用环境变量或密钥管理服务",
                    "description": "移除硬编码密码",
                },
            },
        }
    
    def generate_fix(self, vuln: Dict, code: str = "") -> Optional[FixSuggestion]:
        """生成修复建议"""
        vuln_type = vuln.get("type", "").lower()
        
        if vuln_type not in self.fix_patterns:
            return None
        
        patterns = self.fix_patterns[vuln_type]
        
        # 根据语言选择修复模式
        for lang, pattern_info in patterns.items():
            if code and self._matches_language(code, lang):
                return FixSuggestion(
                    vuln_type=vuln_type,
                    description=pattern_info["description"],
                    code_before=pattern_info["pattern"],
                    code_after=pattern_info["fix"],
                    file_pattern=f"*.{lang}",
                    confidence=0.8,
                    automated=True,
                )
        
        # 通用修复建议
        if "generic" in patterns:
            pattern_info = patterns["generic"]
            return FixSuggestion(
                vuln_type=vuln_type,
                description=pattern_info["description"],
                code_before=pattern_info["pattern"],
                code_after=pattern_info["fix"],
                file_pattern="*",
                confidence=0.6,
                automated=False,
            )
        
        return None
    
    def _matches_language(self, code: str, lang: str) -> bool:
        """检测代码语言"""
        lang_signatures = {
            "php": ["<?php", "<?", "$", "echo"],
            "python": ["def ", "import ", "class ", ":"],
            "javascript": ["function", "const", "let", "var"],
            "java": ["public class", "private", "System.out"],
        }
        
        signatures = lang_signatures.get(lang, [])
        return any(sig in code for sig in signatures)
    
    def generate_patch(self, file_path: str, fix: FixSuggestion) -> str:
        """生成补丁文件"""
        patch = f"""--- a/{file_path}
+++ b/{file_path}
@@ -1,5 +1,5 @@
 # 修复: {fix.description}
-{fix.code_before}
+{fix.code_after}
"""
        return patch


class DevSecOpsIntegration:
    """DevSecOps集成"""
    
    def __init__(self):
        self.ci_templates = self._load_ci_templates()
    
    def _load_ci_templates(self) -> Dict:
        """加载CI模板"""
        return {
            "github": """
name: Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Run WVS Scan
      uses: wvs/action@v1
      with:
        target: http://localhost:8080
        profile: standard
        fail-on-high: true
    
    - name: Upload Report
      uses: actions/upload-artifact@v3
      with:
        name: security-report
        path: reports/
""",
            "gitlab": """
stages:
  - security

wvs_scan:
  stage: security
  image: wvs/scanner:latest
  script:
    - wvs scan -t $CI_ENVIRONMENT_URL --profile standard
  artifacts:
    reports:
      sast: reports/gl-sast-report.json
  only:
    - main
    - develop
""",
            "jenkins": """
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'wvs scan -t http://target.com --profile standard'
            }
        }
    }
    post {
        always {
            publishHTML([
                allowMissing: false,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: 'reports',
                reportFiles: '*.html',
                reportName: 'Security Report'
            ])
        }
    }
}
""",
        }
    
    def generate_ci_config(self, platform: str, target: str) -> str:
        """生成CI配置"""
        template = self.ci_templates.get(platform, "")
        return template.replace("http://localhost:8080", target)
    
    def check_compliance(self, vulns: List[Dict], standard: str = "owasp") -> Dict:
        """合规检查"""
        compliance_rules = {
            "owasp": {
                "injection": ["sqli", "nosql", "ldap", "xpath"],
                "broken_auth": ["weak_password", "session_fixation"],
                "sensitive_data": ["info_disclosure", "hardcoded_password"],
                "xxe": ["xxe"],
                "broken_access": ["dir_traversal", "idor"],
                "security_misconfig": ["default_config", "verbose_error"],
                "xss": ["xss", "dom_xss"],
                "insecure_deserialization": ["deserialization"],
                "known_vulns": ["outdated_component"],
                "insufficient_logging": ["missing_logging"],
            },
            "pci_dss": {
                "sql_injection": ["sqli"],
                "xss": ["xss"],
                "insecure_communication": ["no_https", "weak_ssl"],
                "access_control": ["broken_auth", "privilege_escalation"],
            },
        }
        
        rules = compliance_rules.get(standard, {})
        findings = {category: [] for category in rules}
        
        for vuln in vulns:
            vuln_type = vuln.get("type", "").lower()
            for category, types in rules.items():
                if vuln_type in types:
                    findings[category].append(vuln)
        
        # 计算合规分数
        total_categories = len(rules)
        passed_categories = sum(1 for v in findings.values() if not v)
        score = (passed_categories / total_categories) * 100 if total_categories else 100
        
        return {
            "standard": standard,
            "score": score,
            "findings": findings,
            "passed": score >= 80,
        }
    
    def generate_sbom(self, dependencies: List[Dict]) -> Dict:
        """生成SBOM (软件物料清单)"""
        sbom = {
            "specVersion": "1.4",
            "serialNumber": f"urn:uuid:{__import__('uuid').uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": __import__('datetime').datetime.now().isoformat(),
                "tools": [{"vendor": "WVS", "name": "scanner", "version": "11.0"}],
            },
            "components": [],
        }
        
        for dep in dependencies:
            component = {
                "type": "library",
                "name": dep.get("name"),
                "version": dep.get("version"),
                "purl": f"pkg:{dep.get('type', 'generic')}/{dep.get('name')}@{dep.get('version')}",
            }
            if dep.get("license"):
                component["licenses"] = [{"license": {"id": dep["license"]}}]
            sbom["components"].append(component)
        
        return sbom


class SecurityGate:
    """安全门禁"""
    
    def __init__(self):
        self.policies = []
    
    def add_policy(self, name: str, condition: Dict):
        """添加策略"""
        self.policies.append({
            "name": name,
            "condition": condition,
        })
    
    def evaluate(self, scan_result: Dict) -> Dict:
        """评估扫描结果"""
        violations = []
        
        for policy in self.policies:
            condition = policy["condition"]
            
            # 检查严重漏洞数量
            if "max_critical" in condition:
                critical_count = sum(
                    1 for v in scan_result.get("vulnerabilities", [])
                    if v.get("severity") == "CRITICAL"
                )
                if critical_count > condition["max_critical"]:
                    violations.append({
                        "policy": policy["name"],
                        "message": f"严重漏洞数量 {critical_count} 超过阈值 {condition['max_critical']}",
                    })
            
            # 检查高危漏洞数量
            if "max_high" in condition:
                high_count = sum(
                    1 for v in scan_result.get("vulnerabilities", [])
                    if v.get("severity") == "HIGH"
                )
                if high_count > condition["max_high"]:
                    violations.append({
                        "policy": policy["name"],
                        "message": f"高危漏洞数量 {high_count} 超过阈值 {condition['max_high']}",
                    })
            
            # 检查合规分数
            if "min_compliance_score" in condition:
                score = scan_result.get("compliance_score", 0)
                if score < condition["min_compliance_score"]:
                    violations.append({
                        "policy": policy["name"],
                        "message": f"合规分数 {score} 低于阈值 {condition['min_compliance_score']}",
                    })
        
        return {
            "passed": len(violations) == 0,
            "violations": violations,
        }
