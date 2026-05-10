"""多格式报告生成器"""
import json
import csv
from typing import List
from pathlib import Path
from datetime import datetime

from ..vuln.base import Vulnerability


class JSONReportGenerator:
    """JSON 报告生成器"""
    
    def generate(self, scan_id: str, target: str, vulns: List[Vulnerability]) -> str:
        """生成 JSON 报告"""
        report = {
            "scan_info": {
                "scan_id": scan_id,
                "target": target,
                "scan_time": datetime.now().isoformat(),
                "vulnerability_count": len(vulns),
            },
            "summary": self._generate_summary(vulns),
            "vulnerabilities": [v.to_dict() for v in vulns],
        }
        return json.dumps(report, indent=2, ensure_ascii=False)
    
    def save(self, scan_id: str, target: str, vulns: List[Vulnerability], output_dir: Path) -> Path:
        """保存 JSON 报告"""
        json_content = self.generate(scan_id, target, vulns)
        output_path = output_dir / f"{scan_id}.json"
        output_path.write_text(json_content, encoding="utf-8")
        return output_path
    
    def _generate_summary(self, vulns: List[Vulnerability]) -> dict:
        """生成统计摘要"""
        severity_count = {}
        for v in vulns:
            severity_count[v.severity.name] = severity_count.get(v.severity.name, 0) + 1
        
        return {
            "total": len(vulns),
            "critical": severity_count.get("CRITICAL", 0),
            "high": severity_count.get("HIGH", 0),
            "medium": severity_count.get("MEDIUM", 0),
            "low": severity_count.get("LOW", 0),
            "info": severity_count.get("INFO", 0),
        }


class CSVReportGenerator:
    """CSV 报告生成器"""
    
    def save(self, scan_id: str, target: str, vulns: List[Vulnerability], output_dir: Path) -> Path:
        """保存 CSV 报告"""
        output_path = output_dir / f"{scan_id}.csv"
        
        with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            # 写入表头
            writer.writerow([
                "序号", "漏洞名称", "严重等级", "URL", 
                "Payload", "描述", "修复建议", "置信度"
            ])
            
            # 写入数据
            for i, v in enumerate(vulns, 1):
                writer.writerow([
                    i,
                    v.name,
                    v.severity.label_cn,
                    v.url,
                    v.payload,
                    v.description,
                    v.remediation,
                    f"{v.confidence * 100:.0f}%",
                ])
        
        return output_path
