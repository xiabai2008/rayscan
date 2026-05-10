"""
CSV 报告生成器
导出漏洞数据为 CSV 格式
"""
import csv
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from ..models import ScanResult, Vulnerability


class CSVReporter:
    """
    CSV 报告生成器
    
    导出漏洞数据为 CSV 格式，便于：
    - Excel / Google Sheets 导入
    - 数据分析和统计
    - 与其他工具集成
    """
    
    # CSV 列定义
    COLUMNS = [
        "ID",
        "Type",
        "Title",
        "Severity",
        "Confidence",
        "URL",
        "Method",
        "Parameter",
        "Parameter Type",
        "Payload",
        "Evidence",
        "Description",
        "Recommendation",
        "CWE ID",
        "CVSS Score",
        "Module",
        "Tags",
        "Timestamp",
    ]
    
    def __init__(self, delimiter: str = ",", include_bom: bool = True):
        """
        Args:
            delimiter: CSV 分隔符（默认逗号）
            include_bom: 是否包含 BOM（解决 Excel 中文乱码）
        """
        self.delimiter = delimiter
        self.include_bom = include_bom
    
    def generate(self, result: ScanResult, output_path: Path) -> None:
        """生成 CSV 报告"""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, "w", encoding="utf-8-sig" if self.include_bom else "utf-8", newline="") as f:
            writer = csv.writer(f, delimiter=self.delimiter)
            
            # 写入表头
            writer.writerow(self.COLUMNS)
            
            # 写入漏洞数据
            for vuln in result.vulnerabilities:
                row = self._vuln_to_row(vuln)
                writer.writerow(row)
    
    def generate_summary(self, result: ScanResult, output_path: Path) -> None:
        """生成汇总 CSV（统计报告）"""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.writer(f, delimiter=self.delimiter)
            
            # 扫描信息
            writer.writerow(["Scan Summary"])
            writer.writerow([])
            writer.writerow(["Target URL", result.target.url])
            writer.writerow(["Scan Time", result.scan_time.strftime("%Y-%m-%d %H:%M:%S")])
            writer.writerow(["Duration (seconds)", f"{result.duration:.2f}"])
            writer.writerow(["Requests Made", result.requests_made])
            writer.writerow(["Endpoints Found", result.endpoints_found])
            writer.writerow(["Modules Run", result.modules_run])
            writer.writerow(["Total Vulnerabilities", len(result.vulnerabilities)])
            writer.writerow([])
            
            # 按严重程度统计
            writer.writerow(["By Severity"])
            writer.writerow(["Severity", "Count"])
            for sev, count in sorted(result.severity_count.items(), key=lambda x: self._severity_order(x[0])):
                writer.writerow([sev.upper(), count])
            writer.writerow([])
            
            # 按类型统计
            writer.writerow(["By Type"])
            writer.writerow(["Type", "Count"])
            for vuln_type, count in sorted(result.vulnerability_count.items()):
                writer.writerow([vuln_type, count])
    
    def _vuln_to_row(self, v: Vulnerability) -> List[str]:
        """漏洞转 CSV 行"""
        return [
            v.id,
            v.type.value,
            v.title or "",
            v.severity.value.upper(),
            v.confidence.value.upper(),
            v.url,
            v.method,
            v.parameter or "",
            v.parameter_type or "",
            self._truncate(v.payload, 500),
            self._truncate(v.evidence, 500),
            self._truncate(v.description, 500),
            self._truncate(v.recommendation, 500),
            f"CWE-{v.cwe_id}" if v.cwe_id else "",
            f"{v.cvss_score:.1f}" if v.cvss_score else "",
            v.module or "",
            "|".join(v.tags) if v.tags else "",
            v.timestamp.strftime("%Y-%m-%d %H:%M:%S") if v.timestamp else "",
        ]
    
    def _truncate(self, text: Any, max_len: int) -> str:
        """截断文本"""
        if not text:
            return ""
        text = str(text)
        return text[:max_len] + "..." if len(text) > max_len else text
    
    def _severity_order(self, severity: str) -> int:
        """严重程度排序"""
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return order.get(severity.lower(), 5)
