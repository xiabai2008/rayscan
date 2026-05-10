"""WVS v16.0 - 可视化报告生成器

改进点：
1. HTML 交互式报告（可折叠、可筛选）
2. 漏洞分布图表（饼图、柱状图）
3. 扫描进度可视化
4. 漏洞详情卡片
5. 导出 PDF/JSON/CSV
"""
import json
import csv
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass
from pathlib import Path
import base64


@dataclass
class Vulnerability:
    name: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    url: str
    parameter: str
    payload: str
    description: str
    remediation: str
    confidence: float
    evidence: str
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None
    references: List[str] = None


class ReportGeneratorV16:
    """可视化报告生成器 v16.0"""
    
    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.vulnerabilities: List[Vulnerability] = []
        self.scan_info: Dict = {}
        self.statistics: Dict = {}
    
    def add_vulnerability(self, vuln: Vulnerability):
        """添加漏洞"""
        self.vulnerabilities.append(vuln)
    
    def set_scan_info(self, target: str, start_time: datetime, end_time: datetime,
                      urls_scanned: int, forms_tested: int):
        """设置扫描信息"""
        self.scan_info = {
            "target": target,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration_seconds": (end_time - start_time).total_seconds(),
            "urls_scanned": urls_scanned,
            "forms_tested": forms_tested,
        }
    
    def calculate_statistics(self):
        """计算统计数据"""
        severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        
        for vuln in self.vulnerabilities:
            sev = vuln.severity.upper()
            if sev in severity_count:
                severity_count[sev] += 1
        
        self.statistics = {
            "total": len(self.vulnerabilities),
            "by_severity": severity_count,
            "by_type": self._group_by_type(),
            "risk_score": self._calculate_risk_score(severity_count),
        }
    
    def _group_by_type(self) -> Dict[str, int]:
        """按漏洞类型分组"""
        type_count = {}
        for vuln in self.vulnerabilities:
            vuln_type = vuln.name.split("(")[0].strip()
            type_count[vuln_type] = type_count.get(vuln_type, 0) + 1
        return type_count
    
    def _calculate_risk_score(self, severity_count: Dict) -> float:
        """计算风险评分（0-100）"""
        weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2, "INFO": 0.5}
        score = sum(severity_count.get(k, 0) * v for k, v in weights.items())
        return min(score, 100)
    
    def generate_html_report(self, filename: str = "report.html") -> str:
        """生成 HTML 交互式报告"""
        self.calculate_statistics()
        
        html = self._build_html_template()
        
        output_path = self.output_dir / filename
        output_path.write_text(html, encoding="utf-8")
        
        return str(output_path)
    
    def _build_html_template(self) -> str:
        """构建 HTML 模板"""
        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WVS v16.0 漏洞扫描报告</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f5f5f5; color: #333; }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
        
        /* 头部 */
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }}
        .header h1 {{ font-size: 28px; margin-bottom: 10px; }}
        .header .meta {{ opacity: 0.9; font-size: 14px; }}
        
        /* 统计卡片 */
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }}
        .stat-card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .stat-card.critical {{ border-left: 4px solid #d32f2f; }}
        .stat-card.high {{ border-left: 4px solid #f57c00; }}
        .stat-card.medium {{ border-left: 4px solid #fbc02d; }}
        .stat-card.low {{ border-left: 4px solid #388e3c; }}
        .stat-card .label {{ font-size: 14px; color: #666; margin-bottom: 5px; }}
        .stat-card .value {{ font-size: 32px; font-weight: bold; }}
        
        /* 图表区域 */
        .charts-section {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }}
        .chart-container {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .chart-container h3 {{ margin-bottom: 15px; color: #333; }}
        
        /* 筛选栏 */
        .filter-bar {{ background: white; padding: 15px; border-radius: 8px; margin-bottom: 20px; display: flex; gap: 15px; align-items: center; }}
        .filter-bar select, .filter-bar input {{ padding: 8px 12px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; }}
        .filter-bar button {{ padding: 8px 20px; background: #667eea; color: white; border: none; border-radius: 4px; cursor: pointer; }}
        .filter-bar button:hover {{ background: #5a6fd6; }}
        
        /* 漏洞列表 */
        .vuln-list {{ background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .vuln-item {{ border-bottom: 1px solid #eee; padding: 20px; cursor: pointer; }}
        .vuln-item:hover {{ background: #f9f9f9; }}
        .vuln-item:last-child {{ border-bottom: none; }}
        .vuln-item .header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }}
        .vuln-item .severity-badge {{ padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: bold; text-transform: uppercase; }}
        .severity-badge.critical {{ background: #ffebee; color: #d32f2f; }}
        .severity-badge.high {{ background: #fff3e0; color: #f57c00; }}
        .severity-badge.medium {{ background: #fffde7; color: #fbc02d; }}
        .severity-badge.low {{ background: #e8f5e9; color: #388e3c; }}
        .vuln-item .details {{ display: none; margin-top: 15px; padding-top: 15px; border-top: 1px dashed #ddd; }}
        .vuln-item.expanded .details {{ display: block; }}
        .vuln-item .url {{ color: #667eea; font-size: 14px; word-break: break-all; }}
        .vuln-item .payload {{ background: #f5f5f5; padding: 10px; border-radius: 4px; font-family: monospace; margin-top: 10px; overflow-x: auto; }}
        
        /* 进度条 */
        .progress-bar {{ height: 8px; background: #e0e0e0; border-radius: 4px; overflow: hidden; margin-top: 10px; }}
        .progress-bar .fill {{ height: 100%; background: linear-gradient(90deg, #667eea, #764ba2); transition: width 0.3s; }}
        
        /* 导出按钮 */
        .export-bar {{ display: flex; gap: 10px; margin-bottom: 20px; }}
        .export-btn {{ padding: 10px 20px; background: white; border: 1px solid #ddd; border-radius: 4px; cursor: pointer; text-decoration: none; color: #333; }}
        .export-btn:hover {{ background: #f5f5f5; }}
    </style>
</head>
<body>
    <div class="container">
        <!-- 头部 -->
        <div class="header">
            <h1>🛡️ WVS v16.0 漏洞扫描报告</h1>
            <div class="meta">
                <strong>目标:</strong> {self.scan_info.get('target', 'N/A')} | 
                <strong>扫描时间:</strong> {self.scan_info.get('start_time', 'N/A')} | 
                <strong>耗时:</strong> {self.scan_info.get('duration_seconds', 0):.1f}秒 | 
                <strong>URL数:</strong> {self.scan_info.get('urls_scanned', 0)}
            </div>
        </div>
        
        <!-- 统计卡片 -->
        <div class="stats-grid">
            <div class="stat-card critical">
                <div class="label">严重漏洞</div>
                <div class="value">{self.statistics['by_severity']['CRITICAL']}</div>
            </div>
            <div class="stat-card high">
                <div class="label">高危漏洞</div>
                <div class="value">{self.statistics['by_severity']['HIGH']}</div>
            </div>
            <div class="stat-card medium">
                <div class="label">中危漏洞</div>
                <div class="value">{self.statistics['by_severity']['MEDIUM']}</div>
            </div>
            <div class="stat-card low">
                <div class="label">低危漏洞</div>
                <div class="value">{self.statistics['by_severity']['LOW']}</div>
            </div>
            <div class="stat-card">
                <div class="label">风险评分</div>
                <div class="value">{self.statistics['risk_score']:.1f}</div>
            </div>
        </div>
        
        <!-- 图表 -->
        <div class="charts-section">
            <div class="chart-container">
                <h3>漏洞严重程度分布</h3>
                <canvas id="severityChart"></canvas>
            </div>
            <div class="chart-container">
                <h3>漏洞类型分布</h3>
                <canvas id="typeChart"></canvas>
            </div>
        </div>
        
        <!-- 导出按钮 -->
        <div class="export-bar">
            <a href="report.json" class="export-btn" download>📥 导出 JSON</a>
            <a href="report.csv" class="export-btn" download>📥 导出 CSV</a>
            <button class="export-btn" onclick="window.print()">🖨️ 打印报告</button>
        </div>
        
        <!-- 筛选栏 -->
        <div class="filter-bar">
            <select id="severityFilter">
                <option value="all">所有严重程度</option>
                <option value="CRITICAL">严重</option>
                <option value="HIGH">高危</option>
                <option value="MEDIUM">中危</option>
                <option value="LOW">低危</option>
            </select>
            <input type="text" id="searchInput" placeholder="搜索漏洞名称或 URL...">
            <button onclick="applyFilters()">筛选</button>
        </div>
        
        <!-- 漏洞列表 -->
        <div class="vuln-list" id="vulnList">
            {self._render_vuln_items()}
        </div>
    </div>
    
    <script>
        // 严重程度图表
        const severityCtx = document.getElementById('severityChart').getContext('2d');
        new Chart(severityCtx, {{
            type: 'doughnut',
            data: {{
                labels: ['严重', '高危', '中危', '低危'],
                datasets: [{{
                    data: [{self.statistics['by_severity']['CRITICAL']}, {self.statistics['by_severity']['HIGH']}, {self.statistics['by_severity']['MEDIUM']}, {self.statistics['by_severity']['LOW']}],
                    backgroundColor: ['#d32f2f', '#f57c00', '#fbc02d', '#388e3c']
                }}]
            }},
            options: {{ plugins: {{ legend: {{ position: 'bottom' }} }} }}
        }});
        
        // 类型图表
        const typeCtx = document.getElementById('typeChart').getContext('2d');
        new Chart(typeCtx, {{
            type: 'bar',
            data: {{
                labels: {json.dumps(list(self.statistics['by_type'].keys()))},
                datasets: [{{
                    label: '漏洞数量',
                    data: {json.dumps(list(self.statistics['by_type'].values()))},
                    backgroundColor: '#667eea'
                }}]
            }},
            options: {{ plugins: {{ legend: {{ display: false }} }} }}
        }});
        
        // 展开/折叠详情
        document.querySelectorAll('.vuln-item').forEach(item => {{
            item.addEventListener('click', () => item.classList.toggle('expanded'));
        }});
        
        // 筛选
        function applyFilters() {{
            const severity = document.getElementById('severityFilter').value;
            const search = document.getElementById('searchInput').value.toLowerCase();
            document.querySelectorAll('.vuln-item').forEach(item => {{
                const sev = item.dataset.severity;
                const text = item.textContent.toLowerCase();
                const matchSev = severity === 'all' || sev === severity;
                const matchSearch = !search || text.includes(search);
                item.style.display = matchSev && matchSearch ? 'block' : 'none';
            }});
        }}
    </script>
</body>
</html>"""
    
    def _render_vuln_items(self) -> str:
        """渲染漏洞项"""
        items = []
        for i, vuln in enumerate(self.vulnerabilities):
            severity_class = vuln.severity.lower()
            items.append(f"""
            <div class="vuln-item" data-severity="{vuln.severity}">
                <div class="header">
                    <div>
                        <span class="severity-badge {severity_class}">{vuln.severity}</span>
                        <strong style="margin-left: 10px;">{vuln.name}</strong>
                    </div>
                    <div style="color: #666; font-size: 14px;">
                        置信度: {vuln.confidence:.0%}
                    </div>
                </div>
                <div class="url">{vuln.url}</div>
                <div class="details">
                    <p><strong>参数:</strong> {vuln.parameter}</p>
                    <p><strong>描述:</strong> {vuln.description}</p>
                    <p><strong>Payload:</strong></p>
                    <div class="payload">{self._escape_html(vuln.payload)}</div>
                    <p><strong>证据:</strong> {vuln.evidence}</p>
                    <p><strong>修复建议:</strong> {vuln.remediation}</p>
                    {f'<p><strong>CWE:</strong> <a href="https://cwe.mitre.org/data/definitions/{vuln.cwe_id}.html">{vuln.cwe_id}</a></p>' if vuln.cwe_id else ''}
                </div>
            </div>
            """)
        return "\n".join(items)
    
    def _escape_html(self, text: str) -> str:
        """转义 HTML"""
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    
    def generate_json_report(self, filename: str = "report.json") -> str:
        """生成 JSON 报告"""
        self.calculate_statistics()
        
        data = {
            "scan_info": self.scan_info,
            "statistics": self.statistics,
            "vulnerabilities": [
                {
                    "name": v.name,
                    "severity": v.severity,
                    "url": v.url,
                    "parameter": v.parameter,
                    "payload": v.payload,
                    "description": v.description,
                    "remediation": v.remediation,
                    "confidence": v.confidence,
                    "evidence": v.evidence,
                    "cvss_score": v.cvss_score,
                    "cwe_id": v.cwe_id,
                }
                for v in self.vulnerabilities
            ]
        }
        
        output_path = self.output_dir / filename
        output_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        
        return str(output_path)
    
    def generate_csv_report(self, filename: str = "report.csv") -> str:
        """生成 CSV 报告"""
        output_path = self.output_dir / filename
        
        with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow([
                "名称", "严重程度", "URL", "参数", "Payload",
                "描述", "修复建议", "置信度", "证据"
            ])
            
            for v in self.vulnerabilities:
                writer.writerow([
                    v.name, v.severity, v.url, v.parameter, v.payload,
                    v.description, v.remediation, f"{v.confidence:.2f}", v.evidence
                ])
        
        return str(output_path)


# 扫描进度可视化
class ScanProgressUI:
    """扫描进度 UI（终端）"""
    
    def __init__(self):
        self.total_urls = 0
        self.scanned_urls = 0
        self.vulns_found = 0
        self.current_url = ""
    
    def update(self, scanned: int, total: int, vulns: int, current: str):
        """更新进度"""
        self.scanned_urls = scanned
        self.total_urls = total
        self.vulns_found = vulns
        self.current_url = current
        
        self._render()
    
    def _render(self):
        """渲染进度条"""
        import sys
        
        if self.total_urls == 0:
            return
        
        percent = self.scanned_urls / self.total_urls * 100
        bar_len = 50
        filled = int(bar_len * self.scanned_urls / self.total_urls)
        bar = "█" * filled + "░" * (bar_len - filled)
        
        # 清除当前行
        sys.stdout.write("\r")
        sys.stdout.write(f"[{bar}] {percent:.1f}% | {self.scanned_urls}/{self.total_urls} URLs | {self.vulns_found} 漏洞")
        sys.stdout.flush()
    
    def finish(self):
        """完成"""
        import sys
        sys.stdout.write("\n")
