"""WVS v18.2 - Report Generator
生成 HTML 和 JSON 格式的漏洞扫描报告
"""
import json
import time
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class Vulnerability:
    type: str
    url: str
    parameter: str
    payload: str
    severity: str
    confidence: float
    evidence: str = ""
    poc: str = ""


@dataclass
class ScanReport:
    """扫描报告数据结构"""
    target: str
    scan_time: str
    duration: float
    total_requests: int
    urls_count: int
    forms_count: int
    js_files_count: int
    sensitive_paths_count: int
    vulnerabilities: List[Vulnerability]
    severity_stats: Dict[str, int]
    
    def to_dict(self) -> Dict:
        return {
            "target": self.target,
            "scan_time": self.scan_time,
            "duration": self.duration,
            "total_requests": self.total_requests,
            "urls_count": self.urls_count,
            "forms_count": self.forms_count,
            "js_files_count": self.js_files_count,
            "sensitive_paths_count": self.sensitive_paths_count,
            "vulnerabilities": [asdict(v) for v in self.vulnerabilities],
            "severity_stats": self.severity_stats
        }


class ReportGenerator:
    """报告生成器"""
    
    SEVERITY_COLORS = {
        "critical": "#dc3545",
        "high": "#fd7e14",
        "medium": "#ffc107",
        "low": "#20c997",
        "info": "#17a2b8"
    }
    
    SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
    
    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate(self, scan_result, target: str) -> ScanReport:
        """从扫描结果生成报告"""
        # 统计漏洞等级
        severity_stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for vuln in scan_result.vulnerabilities:
            sev = vuln.severity.lower()
            if sev in severity_stats:
                severity_stats[sev] += 1
        
        # 安全获取各字段（兼容不同 ScanResult 版本）
        js_files = getattr(scan_result, 'js_files', [])
        total_requests = getattr(scan_result, 'total_requests', len(scan_result.urls) + len(scan_result.forms))
        
        return ScanReport(
            target=target,
            scan_time=datetime.now().isoformat(),
            duration=getattr(scan_result, 'duration', 0.0),
            total_requests=total_requests,
            urls_count=len(scan_result.urls),
            forms_count=len(scan_result.forms),
            js_files_count=len(js_files),
            sensitive_paths_count=len(scan_result.sensitive_paths),
            vulnerabilities=scan_result.vulnerabilities,
            severity_stats=severity_stats
        )
    
    def to_json(self, report: ScanReport, filename: Optional[str] = None) -> str:
        """生成 JSON 报告"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_target = report.target.replace("://", "_").replace("/", "_")[:50]
            filename = f"wvs_report_{safe_target}_{timestamp}.json"
        
        filepath = self.output_dir / filename
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)
        
        return str(filepath)
    
    def to_html(self, report: ScanReport, filename: Optional[str] = None) -> str:
        """生成 HTML 报告"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_target = report.target.replace("://", "_").replace("/", "_")[:50]
            filename = f"wvs_report_{safe_target}_{timestamp}.html"
        
        filepath = self.output_dir / filename
        html_content = self._generate_html(report)
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        return str(filepath)
    
    def _generate_html(self, report: ScanReport) -> str:
        """生成 HTML 内容"""
        # 按 severity 排序漏洞
        sorted_vulns = sorted(
            report.vulnerabilities,
            key=lambda v: self.SEVERITY_ORDER.index(v.severity.lower()) if v.severity.lower() in self.SEVERITY_ORDER else 5
        )
        
        # 统计卡片
        stats_html = self._generate_stats_cards(report)
        
        # 漏洞表格
        vulns_html = self._generate_vulns_table(sorted_vulns)
        
        # 敏感路径表格
        sensitive_html = self._generate_sensitive_table(report)
        
        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WVS v18.2 扫描报告 - {report.target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f7fa; color: #333; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }}
        .header h1 {{ font-size: 24px; margin-bottom: 10px; }}
        .header .meta {{ font-size: 14px; opacity: 0.9; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }}
        .stat-card {{ background: white; border-radius: 10px; padding: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .stat-card h3 {{ font-size: 14px; color: #666; margin-bottom: 5px; }}
        .stat-card .value {{ font-size: 32px; font-weight: bold; }}
        .stat-card.critical .value {{ color: {self.SEVERITY_COLORS['critical']}; }}
        .stat-card.high .value {{ color: {self.SEVERITY_COLORS['high']}; }}
        .stat-card.medium .value {{ color: {self.SEVERITY_COLORS['medium']}; }}
        .stat-card.low .value {{ color: {self.SEVERITY_COLORS['low']}; }}
        .stat-card.info .value {{ color: {self.SEVERITY_COLORS['info']}; }}
        .section {{ background: white; border-radius: 10px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .section h2 {{ font-size: 18px; margin-bottom: 15px; padding-bottom: 10px; border-bottom: 2px solid #eee; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #eee; }}
        th {{ background: #f8f9fa; font-weight: 600; }}
        .severity {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; color: white; }}
        .severity.critical {{ background: {self.SEVERITY_COLORS['critical']}; }}
        .severity.high {{ background: {self.SEVERITY_COLORS['high']}; }}
        .severity.medium {{ background: {self.SEVERITY_COLORS['medium']}; }}
        .severity.low {{ background: {self.SEVERITY_COLORS['low']}; }}
        .severity.info {{ background: {self.SEVERITY_COLORS['info']}; }}
        .confidence {{ font-size: 12px; color: #666; }}
        .payload {{ font-family: 'Courier New', monospace; font-size: 12px; background: #f8f9fa; padding: 2px 6px; border-radius: 4px; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
        .evidence {{ font-size: 12px; color: #666; max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
        .no-data {{ text-align: center; color: #999; padding: 40px; }}
        .footer {{ text-align: center; color: #999; font-size: 12px; margin-top: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>WVS v18.2 扫描报告</h1>
            <div class="meta">
                <div>目标: {report.target}</div>
                <div>扫描时间: {report.scan_time} | 耗时: {report.duration:.2f}s | 请求数: {report.total_requests}</div>
            </div>
        </div>
        
        {stats_html}
        
        <div class="section">
            <h2>发现漏洞 ({len(report.vulnerabilities)})</h2>
            {vulns_html}
        </div>
        
        {sensitive_html}
        
        <div class="footer">
            Generated by WVS v18.2 | {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        </div>
    </div>
</body>
</html>"""
    
    def _generate_stats_cards(self, report: ScanReport) -> str:
        """生成统计卡片"""
        cards = []
        
        # 漏洞统计
        for sev in self.SEVERITY_ORDER:
            count = report.severity_stats.get(sev, 0)
            cards.append(f"""
            <div class="stat-card {sev}">
                <h3>{sev.upper()}</h3>
                <div class="value">{count}</div>
            </div>""")
        
        # 其他统计
        cards.append(f"""
        <div class="stat-card">
            <h3>扫描 URL</h3>
            <div class="value">{report.urls_count}</div>
        </div>""")
        
        cards.append(f"""
        <div class="stat-card">
            <h3>表单</h3>
            <div class="value">{report.forms_count}</div>
        </div>""")
        
        cards.append(f"""
        <div class="stat-card">
            <h3>敏感路径</h3>
            <div class="value">{report.sensitive_paths_count}</div>
        </div>""")
        
        return f'<div class="stats-grid">{"".join(cards)}</div>'
    
    def _generate_vulns_table(self, vulns: List) -> str:
        """生成漏洞表格"""
        if not vulns:
            return '<div class="no-data">无漏洞发现</div>'
        
        rows = []
        for i, v in enumerate(vulns, 1):
            sev = v.severity.lower()
            rows.append(f"""
            <tr>
                <td>{i}</td>
                <td><span class="severity {sev}">{sev.upper()}</span></td>
                <td>{v.type}</td>
                <td><a href="{v.url}" target="_blank">{v.url[:60]}{'...' if len(v.url) > 60 else ''}</a></td>
                <td>{v.parameter}</td>
                <td><span class="payload" title="{v.payload}">{v.payload[:50]}{'...' if len(v.payload) > 50 else ''}</span></td>
                <td class="confidence">{v.confidence * 100:.0f}%</td>
                <td class="evidence" title="{v.evidence}">{v.evidence[:60]}{'...' if len(v.evidence) > 60 else ''}</td>
            </tr>""")
        
        return f"""
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>严重度</th>
                    <th>类型</th>
                    <th>URL</th>
                    <th>参数</th>
                    <th>Payload</th>
                    <th>置信度</th>
                    <th>证据</th>
                </tr>
            </thead>
            <tbody>
                {"".join(rows)}
            </tbody>
        </table>"""
    
    def _generate_sensitive_table(self, report: ScanReport) -> str:
        """生成敏感路径表格"""
        if not hasattr(report, 'sensitive_paths') or not report.sensitive_paths:
            return ""
        
        # 从原始扫描结果获取敏感路径（这里需要外部传入）
        rows = []
        for i, sp in enumerate(report.sensitive_paths, 1):
            sev = sp.get("severity", "info").lower()
            rows.append(f"""
            <tr>
                <td>{i}</td>
                <td><span class="severity {sev}">{sev.upper()}</span></td>
                <td>{sp.get('type', 'Unknown')}</td>
                <td><a href="{sp.get('url', '')}" target="_blank">{sp.get('url', '')[:70]}{'...' if len(sp.get('url', '')) > 70 else ''}</a></td>
            </tr>""")
        
        return f"""
        <div class="section">
            <h2>敏感路径 ({len(report.sensitive_paths)})</h2>
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>严重度</th>
                        <th>类型</th>
                        <th>URL</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(rows)}
                </tbody>
            </table>
        </div>"""
