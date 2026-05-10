"""WVS v18 - 报告生成模块：HTML/JSON 报告，漏洞等级统计"""
import json
import html
from datetime import datetime
from typing import Dict, List, Any
from dataclasses import dataclass, field, asdict
from pathlib import Path


@dataclass
class ReportSummary:
    """扫描摘要"""
    target: str
    start_time: str
    end_time: str
    duration: float
    total_requests: int
    urls_crawled: int
    forms_found: int


@dataclass
class VulnerabilityStats:
    """漏洞统计"""
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    
    def by_severity(self) -> Dict[str, int]:
        return {
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "info": self.info
        }


class ReportGenerator:
    """报告生成器 - 支持 HTML/JSON 格式"""
    
    SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
    SEVERITY_COLORS = {
        "critical": "#dc3545",
        "high": "#fd7e14", 
        "medium": "#ffc107",
        "low": "#17a2b8",
        "info": "#6c757d"
    }
    
    def __init__(self, scan_result: Any, target: str = ""):
        self.scan_result = scan_result
        self.target = target
        self.timestamp = datetime.now().isoformat()
        self.stats = self._calculate_stats()
    
    def _calculate_stats(self) -> VulnerabilityStats:
        """计算漏洞统计"""
        stats = VulnerabilityStats()
        vulns = getattr(self.scan_result, 'vulnerabilities', [])
        
        stats.total = len(vulns)
        for v in vulns:
            severity = getattr(v, 'severity', 'info').lower()
            if severity == 'critical':
                stats.critical += 1
            elif severity == 'high':
                stats.high += 1
            elif severity == 'medium':
                stats.medium += 1
            elif severity == 'low':
                stats.low += 1
            else:
                stats.info += 1
        
        return stats
    
    def generate_json(self) -> str:
        """生成 JSON 报告"""
        report = {
            "report_info": {
                "version": "WVS v18.0",
                "generated_at": self.timestamp,
                "target": self.target
            },
            "summary": {
                "total_vulnerabilities": self.stats.total,
                "severity_distribution": self.stats.by_severity(),
                "urls_crawled": len(getattr(self.scan_result, 'urls', [])),
                "forms_found": len(getattr(self.scan_result, 'forms', [])),
                "scan_duration": getattr(self.scan_result, 'duration', 0)
            },
            "vulnerabilities": self._vulns_to_dict()
        }
        return json.dumps(report, indent=2, ensure_ascii=False)
    
    def _vulns_to_dict(self) -> List[Dict]:
        """转换漏洞为字典列表"""
        vulns = getattr(self.scan_result, 'vulnerabilities', [])
        result = []
        for v in vulns:
            result.append({
                "type": getattr(v, 'type', 'Unknown'),
                "url": getattr(v, 'url', ''),
                "parameter": getattr(v, 'parameter', ''),
                "payload": getattr(v, 'payload', ''),
                "severity": getattr(v, 'severity', 'info'),
                "confidence": getattr(v, 'confidence', 0.0),
                "evidence": getattr(v, 'evidence', ''),
                "poc": getattr(v, 'poc', '')
            })
        return result
    
    def generate_html(self) -> str:
        """生成 HTML 报告"""
        vulns = getattr(self.scan_result, 'vulnerabilities', [])
        urls = getattr(self.scan_result, 'urls', [])
        forms = getattr(self.scan_result, 'forms', [])
        duration = getattr(self.scan_result, 'duration', 0)
        
        # 按严重度排序
        sorted_vulns = sorted(vulns, 
            key=lambda x: self.SEVERITY_ORDER.index(getattr(x, 'severity', 'info').lower()) 
            if getattr(x, 'severity', 'info').lower() in self.SEVERITY_ORDER else 99)
        
        html_template = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WVS v18 扫描报告 - {html.escape(self.target)}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
               background: #f5f5f5; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                   color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }}
        .header h1 {{ font-size: 28px; margin-bottom: 10px; }}
        .header .meta {{ opacity: 0.9; font-size: 14px; }}
        
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); 
                      gap: 15px; margin-bottom: 20px; }}
        .stat-card {{ background: white; padding: 20px; border-radius: 8px; 
                     box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }}
        .stat-card .number {{ font-size: 32px; font-weight: bold; margin-bottom: 5px; }}
        .stat-card .label {{ color: #666; font-size: 14px; }}
        
        .severity-critical {{ color: #dc3545; }}
        .severity-high {{ color: #fd7e14; }}
        .severity-medium {{ color: #ffc107; }}
        .severity-low {{ color: #17a2b8; }}
        .severity-info {{ color: #6c757d; }}
        
        .section {{ background: white; border-radius: 8px; padding: 20px; 
                   margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .section h2 {{ font-size: 20px; margin-bottom: 15px; color: #333; 
                      border-bottom: 2px solid #667eea; padding-bottom: 10px; }}
        
        .vuln-table {{ width: 100%; border-collapse: collapse; }}
        .vuln-table th {{ background: #f8f9fa; padding: 12px; text-align: left; 
                         font-weight: 600; color: #555; border-bottom: 2px solid #dee2e6; }}
        .vuln-table td {{ padding: 12px; border-bottom: 1px solid #dee2e6; }}
        .vuln-table tr:hover {{ background: #f8f9fa; }}
        
        .severity-badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; 
                         font-size: 12px; font-weight: 600; text-transform: uppercase; }}
        .severity-badge.critical {{ background: #dc3545; color: white; }}
        .severity-badge.high {{ background: #fd7e14; color: white; }}
        .severity-badge.medium {{ background: #ffc107; color: #333; }}
        .severity-badge.low {{ background: #17a2b8; color: white; }}
        .severity-badge.info {{ background: #6c757d; color: white; }}
        
        .confidence-bar {{ display: inline-block; width: 60px; height: 8px; 
                         background: #e9ecef; border-radius: 4px; overflow: hidden; }}
        .confidence-fill {{ height: 100%; background: #28a745; border-radius: 4px; }}
        
        .vuln-details {{ background: #f8f9fa; padding: 15px; border-radius: 6px; 
                       margin-top: 10px; font-family: monospace; font-size: 13px; }}
        .vuln-details .label {{ color: #666; margin-right: 10px; }}
        .vuln-details .value {{ color: #333; word-break: break-all; }}
        
        .empty-state {{ text-align: center; padding: 40px; color: #666; }}
        .empty-state svg {{ width: 64px; height: 64px; margin-bottom: 15px; opacity: 0.5; }}
        
        .footer {{ text-align: center; padding: 20px; color: #999; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 WVS v18 漏洞扫描报告</h1>
            <div class="meta">
                目标: {html.escape(self.target)} | 
                生成时间: {self.timestamp[:19]} | 
                扫描耗时: {duration:.2f}s
            </div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="number severity-critical">{self.stats.critical}</div>
                <div class="label">严重 (Critical)</div>
            </div>
            <div class="stat-card">
                <div class="number severity-high">{self.stats.high}</div>
                <div class="label">高危 (High)</div>
            </div>
            <div class="stat-card">
                <div class="number severity-medium">{self.stats.medium}</div>
                <div class="label">中危 (Medium)</div>
            </div>
            <div class="stat-card">
                <div class="number severity-low">{self.stats.low}</div>
                <div class="label">低危 (Low)</div>
            </div>
            <div class="stat-card">
                <div class="number severity-info">{self.stats.info}</div>
                <div class="label">信息 (Info)</div>
            </div>
            <div class="stat-card">
                <div class="number" style="color: #667eea;">{self.stats.total}</div>
                <div class="label">总计</div>
            </div>
        </div>
        
        <div class="section">
            <h2>📊 扫描摘要</h2>
            <table class="vuln-table">
                <tr><td width="200">爬取 URL 数</td><td>{len(urls)}</td></tr>
                <tr><td>发现表单数</td><td>{len(forms)}</td></tr>
                <tr><td>敏感路径</td><td>{len(getattr(self.scan_result, 'sensitive_paths', []))}</td></tr>
                <tr><td>JS 文件</td><td>{len(getattr(self.scan_result, 'js_files', []))}</td></tr>
            </table>
        </div>
        
        <div class="section">
            <h2>🐛 漏洞详情 ({self.stats.total})</h2>
            {self._generate_vuln_table(sorted_vulns) if vulns else '<div class="empty-state">未发现漏洞</div>'}
        </div>
        
        <div class="footer">
            Generated by WVS v18.0 | Web Vulnerability Scanner
        </div>
    </div>
</body>
</html>"""
        return html_template
    
    def _generate_vuln_table(self, vulns: List[Any]) -> str:
        """生成漏洞表格"""
        if not vulns:
            return ""
        
        rows = []
        for i, v in enumerate(vulns, 1):
            severity = getattr(v, 'severity', 'info').lower()
            confidence = getattr(v, 'confidence', 0.0)
            
            rows.append(f"""
            <tr>
                <td>#{i}</td>
                <td><span class="severity-badge {severity}">{severity.upper()}</span></td>
                <td>{html.escape(getattr(v, 'type', 'Unknown'))}</td>
                <td>{html.escape(getattr(v, 'url', ''))}</td>
                <td><code>{html.escape(getattr(v, 'parameter', ''))}</code></td>
                <td>
                    <div class="confidence-bar">
                        <div class="confidence-fill" style="width: {confidence*100:.0f}%"></div>
                    </div>
                    {confidence*100:.0f}%
                </td>
            </tr>
            <tr>
                <td colspan="6">
                    <div class="vuln-details">
                        <div><span class="label">Payload:</span> <span class="value">{html.escape(getattr(v, 'payload', ''))}</span></div>
                        <div><span class="label">Evidence:</span> <span class="value">{html.escape(str(getattr(v, 'evidence', ''))[:200])}</span></div>
                        <div><span class="label">PoC:</span> <span class="value">{html.escape(getattr(v, 'poc', ''))}</span></div>
                    </div>
                </td>
            </tr>
            """)
        
        return f"""
        <table class="vuln-table">
            <thead>
                <tr>
                    <th>#</th>
                    <th>严重度</th>
                    <th>类型</th>
                    <th>URL</th>
                    <th>参数</th>
                    <th>置信度</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>
        """
    
    def save(self, output_path: str, format: str = "html") -> str:
        """保存报告到文件"""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        if format.lower() == "json":
            content = self.generate_json()
        else:
            content = self.generate_html()
        
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return str(path.absolute())


class ScanReporter:
    """扫描报告器 - 简化接口"""
    
    @staticmethod
    def from_result(scan_result: Any, target: str = "", output_dir: str = "./reports") -> Dict[str, str]:
        """从扫描结果生成报告"""
        generator = ReportGenerator(scan_result, target)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_slug = target.replace('://', '_').replace('/', '_').replace(':', '_')[:50]
        
        # 生成两种格式
        html_path = f"{output_dir}/wvs_report_{target_slug}_{timestamp}.html"
        json_path = f"{output_dir}/wvs_report_{target_slug}_{timestamp}.json"
        
        html_file = generator.save(html_path, "html")
        json_file = generator.save(json_path, "json")
        
        return {
            "html": html_file,
            "json": json_file,
            "stats": generator.stats.by_severity()
        }
