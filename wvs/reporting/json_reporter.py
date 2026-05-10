"""
JSON 报告生成器
支持标准 JSON 和 SARIF 格式
"""
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..models import ScanResult, Vulnerability, Severity, VulnerabilityType


class JSONReporter:
    """
    JSON 报告生成器
    
    支持格式：
    - standard: 标准 JSON 格式
    - sarif: GitHub Code Scanning SARIF 格式
    """
    
    def __init__(self, indent: int = 2, ensure_ascii: bool = False):
        """
        Args:
            indent: JSON 缩进
            ensure_ascii: 是否转义非 ASCII 字符
        """
        self.indent = indent
        self.ensure_ascii = ensure_ascii
    
    def generate(self, result: ScanResult, output_path: Path) -> None:
        """生成标准 JSON 报告"""
        data = self._build_standard(result)
        self._write_json(output_path, data)
    
    def generate_sarif(self, result: ScanResult, output_path: Path) -> None:
        """生成 SARIF 格式报告（GitHub Code Scanning）"""
        data = self._build_sarif(result)
        self._write_json(output_path, data)
    
    def _write_json(self, path: Path, data: Dict[str, Any]) -> None:
        """写入 JSON 文件"""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(data, indent=self.indent, ensure_ascii=self.ensure_ascii),
            encoding="utf-8"
        )
    
    # ─────────────────────────────────────────────────────────────
    # 标准 JSON 格式
    # ─────────────────────────────────────────────────────────────
    
    def _build_standard(self, result: ScanResult) -> Dict[str, Any]:
        """构建标准 JSON 格式"""
        return {
            "schema": "wvs-report-v1",
            "generated_at": datetime.now().isoformat(),
            "scanner": {
                "name": "WVS",
                "version": "19.0.0",
                "vendor": "OpenClaw"
            },
            "target": result.target.to_dict(),
            "scan_info": {
                "url": result.target.url,
                "start_time": result.scan_time.isoformat(),
                "duration_seconds": round(result.duration, 2),
                "requests_made": result.requests_made,
                "endpoints_found": result.endpoints_found,
                "modules_run": result.modules_run,
            },
            "statistics": {
                "total_vulnerabilities": len(result.vulnerabilities),
                "by_severity": result.severity_count,
                "by_type": result.vulnerability_count,
            },
            "vulnerabilities": [self._vuln_to_dict(v) for v in result.vulnerabilities],
            "errors": result.errors if result.errors else [],
        }
    
    def _vuln_to_dict(self, v: Vulnerability) -> Dict[str, Any]:
        """漏洞转字典"""
        data = {
            "id": v.id,
            "type": v.type.value,
            "title": v.title,
            "severity": v.severity.value,
            "confidence": v.confidence.value,
            "url": v.url,
            "method": v.method,
        }
        
        # 可选字段
        optional = [
            ("parameter", v.parameter),
            ("parameter_type", v.parameter_type),
            ("payload", v.payload),
            ("evidence", v.evidence),
            ("description", v.description),
            ("recommendation", v.recommendation),
            ("cwe_id", v.cwe_id),
            ("cvss_score", v.cvss_score),
            ("references", v.references),
            ("tags", v.tags),
            ("module", v.module),
        ]
        
        for key, value in optional:
            if value is not None:
                data[key] = value
        
        return data
    
    # ─────────────────────────────────────────────────────────────
    # SARIF 格式（GitHub Code Scanning）
    # ─────────────────────────────────────────────────────────────
    
    def _build_sarif(self, result: ScanResult) -> Dict[str, Any]:
        """构建 SARIF 格式"""
        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "WVS",
                        "version": "19.0.0",
                        "informationUri": "https://github.com/openclaw/wvs",
                        "rules": self._build_sarif_rules(result.vulnerabilities),
                    }
                },
                "results": [self._vuln_to_sarif(v) for v in result.vulnerabilities],
                "invocations": [{
                    "startTimeUtc": result.scan_time.isoformat() + "Z",
                    "endTimeUtc": datetime.now().isoformat() + "Z",
                    "executionSuccessful": True,
                }],
            }]
        }
    
    def _build_sarif_rules(self, vulns: List[Vulnerability]) -> List[Dict[str, Any]]:
        """构建 SARIF 规则（去重）"""
        seen = set()
        rules = []
        
        for v in vulns:
            rule_id = v.type.value
            if rule_id in seen:
                continue
            seen.add(rule_id)
            
            rule = {
                "id": rule_id,
                "name": v.type.name,
                "shortDescription": {
                    "text": self._get_rule_description(v.type)
                },
                "defaultConfiguration": {
                    "level": self._severity_to_sarif_level(v.severity)
                }
            }
            
            if v.cwe_id:
                rule["relationships"] = [{
                    "target": {
                        "id": f"CWE-{v.cwe_id}",
                        "toolComponent": {
                            "name": "CWE"
                        }
                    },
                    "kinds": ["superset"]
                }]
            
            rules.append(rule)
        
        return rules
    
    def _vuln_to_sarif(self, v: Vulnerability) -> Dict[str, Any]:
        """漏洞转 SARIF 格式"""
        result = {
            "ruleId": v.type.value,
            "level": self._severity_to_sarif_level(v.severity),
            "message": {
                "text": v.title or f"{v.type.name} vulnerability detected"
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": v.url
                    }
                }
            }],
            "properties": {
                "confidence": v.confidence.value,
                "severity": v.severity.value,
            }
        }
        
        # 添加可选字段
        if v.parameter:
            result["locations"][0]["physicalLocation"]["region"] = {
                "startLine": 1,
                "snippet": {
                    "text": f"Parameter: {v.parameter}"
                }
            }
        
        if v.payload:
            result["properties"]["payload"] = v.payload
        
        if v.evidence:
            result["properties"]["evidence"] = v.evidence
        
        if v.cwe_id:
            result["properties"]["cwe"] = f"CWE-{v.cwe_id}"
        
        return result
    
    def _severity_to_sarif_level(self, severity: Severity) -> str:
        """严重程度转 SARIF level"""
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "none",
        }
        return mapping.get(severity, "note")
    
    def _get_rule_description(self, vuln_type: VulnerabilityType) -> str:
        """获取规则描述"""
        descriptions = {
            VulnerabilityType.SQL_INJECTION: "SQL Injection vulnerability allows attackers to execute arbitrary SQL commands",
            VulnerabilityType.XSS: "Cross-Site Scripting allows attackers to inject malicious scripts",
            VulnerabilityType.COMMAND_INJECTION: "Command Injection allows attackers to execute system commands",
            VulnerabilityType.LFI: "Local File Inclusion allows reading arbitrary files on the server",
            VulnerabilityType.RFI: "Remote File Inclusion allows including remote files",
            VulnerabilityType.XXE: "XML External Entity injection allows reading files or SSRF",
            VulnerabilityType.SSRF: "Server-Side Request Forgery allows making requests from the server",
            VulnerabilityType.IDOR: "Insecure Direct Object Reference allows accessing unauthorized resources",
            VulnerabilityType.BROKEN_AUTH: "Broken Authentication allows bypassing authentication",
            VulnerabilityType.BROKEN_ACCESS: "Broken Access Control allows unauthorized actions",
            VulnerabilityType.INSECURE_CONFIG: "Insecure Configuration exposes sensitive information",
            VulnerabilityType.INFO_DISCLOSURE: "Information Disclosure exposes sensitive data",
            VulnerabilityType.API_SECURITY: "API Security issues allow unauthorized access",
            VulnerabilityType.LOGIC_VULNERABILITY: "Logic vulnerabilities allow unintended behavior",
            VulnerabilityType.ZERO_DAY: "Zero-day vulnerability with no known patch",
            VulnerabilityType.OTHER: "Other vulnerability type",
        }
        return descriptions.get(vuln_type, "Vulnerability detected")
