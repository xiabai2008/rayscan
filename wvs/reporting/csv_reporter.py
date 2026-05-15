"""
CSV Report Generator
Export vulnerability data in CSV format
"""

import csv
from pathlib import Path
from typing import Any, List

from ..models import ScanResult, Vulnerability


class CSVReporter:
    """
    CSV Report Generator

    Exports vulnerability data in CSV format, suitable for:
    - Excel / Google Sheets import
    - Data analysis and statistics
    - Integration with other tools
    """

    # CSV column definitions
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
            delimiter: CSV delimiter (default comma)
            include_bom: Whether to include BOM (fix Excel encoding issues)
        """
        self.delimiter = delimiter
        self.include_bom = include_bom

    def generate(self, result: ScanResult, output_path: Path) -> None:
        """Generate CSV report"""
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", encoding="utf-8-sig" if self.include_bom else "utf-8", newline="") as f:
            writer = csv.writer(f, delimiter=self.delimiter)

            # Write header
            writer.writerow(self.COLUMNS)

            # Write vulnerability data
            for vuln in result.vulnerabilities:
                row = self._vuln_to_row(vuln)
                writer.writerow(row)

    def generate_summary(self, result: ScanResult, output_path: Path) -> None:
        """Generate summary CSV (statistics report)"""
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.writer(f, delimiter=self.delimiter)

            # Scan information
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

            # By severity
            writer.writerow(["By Severity"])
            writer.writerow(["Severity", "Count"])
            for sev, count in sorted(result.severity_count.items(), key=lambda x: self._severity_order(x[0])):
                writer.writerow([sev.upper(), count])
            writer.writerow([])

            # By type
            writer.writerow(["By Type"])
            writer.writerow(["Type", "Count"])
            for vuln_type, count in sorted(result.vulnerability_count.items()):
                writer.writerow([vuln_type, count])

    def _vuln_to_row(self, v: Vulnerability) -> List[str]:
        """Convert vulnerability to CSV row"""
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
        """Truncate text"""
        if not text:
            return ""
        text = str(text)
        return text[:max_len] + "..." if len(text) > max_len else text

    def _severity_order(self, severity: str) -> int:
        """Severity sort order"""
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return order.get(severity.lower(), 5)
