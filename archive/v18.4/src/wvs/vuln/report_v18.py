"""WVS v18.0 - 完整版报告生成器

修复：
1. PDF 报告支持 (fpdf2)
2. HTML 报告优化
3. JSON/CSV 导出
4. Markdown 报告
"""
import json
import csv
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
from dataclasses import asdict

try:
    from fpdf import FPDF
    FPDF_AVAILABLE = True
except ImportError:
    FPDF_AVAILABLE = False


class ReportGeneratorV18:
    """报告生成器 v18.0"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.output_dir = Path(self.config.get("output_dir", "./reports"))
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate(self, results: List[Any], format: str = "html") -> str:
        """生成报告"""
        if format == "html":
            return self._generate_html(results)
        elif format == "json":
            return self._generate_json(results)
        elif format == "csv":
            return self._generate_csv(results)
        elif format == "pdf":
            return self._generate_pdf(results)
        elif format == "md":
            return self._generate_markdown(results)
        else:
            return self._generate_html(results)
    
    def _generate_html(self, results: List[Any]) -> str:
        """生成 HTML 报告"""
        # 统计
        severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        type_count = {}
        
        for r in results:
            if hasattr(r, '__dict__'):
                data = asdict(r)
            else:
                data = r
            
            sev = data.get("severity", "medium").lower()
            if sev in severity_count:
                severity_count[sev] += 1
            
            vtype = data.get("type", data.get("vuln_type", "Unknown"))
            type_count[vtype] = type_count.get(vtype, 0) + 1
        
        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WVS v18.0 漏洞扫描报告</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #1e293b 0%, #334155 100%); padding: 30px; border-radius: 12px; margin-bottom: 20px; }}
        .header h1 {{ font-size: 2em; margin-bottom: 10px; }}
        .header .meta {{ color: #94a3b8; font-size: 0.9em; }}
        .stats {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin-bottom: 20px; }}
        .stat-card {{ background: #1e293b; padding: 20px; border-radius: 8px; text-align: center; }}
        .stat-card.critical {{ border-left: 4px solid #ef4444; }}
        .stat-card.high {{ border-left: 4px solid #f97316; }}
        .stat-card.medium {{ border-left: 4px solid #eab308; }}
        .stat-card.low {{ border-left: 4px solid #3b82f6; }}
        .stat-card.info {{ border-left: 4px solid #6b7280; }}
        .stat-value {{ font-size: 2em; font-weight: bold; margin-bottom: 5px; }}
        .stat-label {{ color: #94a3b8; font-size: 0.85em; }}
        .vuln-list {{ background: #1e293b; border-radius: 12px; overflow: hidden; }}
        .vuln-item {{ padding: 15px 20px; border-bottom: 1px solid #334155; }}
        .vuln-item:hover {{ background: #334155; }}
        .vuln-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }}
        .vuln-title {{ font-weight: 600; font-size: 1.1em; }}
        .vuln-severity {{ padding: 4px 12px; border-radius: 20px; font-size: 0.75em; font-weight: 600; text-transform: uppercase; }}
        .severity-critical {{ background: #7f1d1d; color: #fecaca; }}
        .severity-high {{ background: #7c2d12; color: #fed7aa; }}
        .severity-medium {{ background: #713f12; color: #fef08a; }}
        .severity-low {{ background: #1e3a5f; color: #bfdbfe; }}
        .severity-info {{ background: #374151; color: #d1d5db; }}
        .vuln-meta {{ color: #94a3b8; font-size: 0.85em; margin-bottom: 8px; }}
        .vuln-payload {{ background: #0f172a; padding: 10px; border-radius: 6px; font-family: 'Fira Code', monospace; font-size: 0.85em; overflow-x: auto; }}
        .chart-container {{ background: #1e293b; padding: 20px; border-radius: 12px; margin-bottom: 20px; }}
        .chart-title {{ font-size: 1.2em; margin-bottom: 15px; }}
        .bar-chart {{ display: flex; align-items: flex-end; height: 200px; gap: 20px; padding: 20px 0; }}
        .bar {{ flex: 1; display: flex; flex-direction: column; align-items: center; }}
        .bar-fill {{ width: 100%; border-radius: 4px 4px 0 0; transition: height 0.3s; }}
        .bar-label {{ margin-top: 10px; color: #94a3b8; font-size: 0.8em; }}
        .bar-value {{ margin-top: 5px; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 WVS v18.0 扫描报告</h1>
            <div class="meta">
                生成时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | 
                漏洞总数: {len(results)} |
                风险等级: Critical={severity_count['critical']} High={severity_count['high']} Medium={severity_count['medium']} Low={severity_count['low']}
            </div>
        </div>
        
        <div class="stats">
            <div class="stat-card critical">
                <div class="stat-value" style="color: #ef4444;">{severity_count['critical']}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="stat-value" style="color: #f97316;">{severity_count['high']}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-value" style="color: #eab308;">{severity_count['medium']}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card low">
                <div class="stat-value" style="color: #3b82f6;">{severity_count['low']}</div>
                <div class="stat-label">Low</div>
            </div>
            <div class="stat-card info">
                <div class="stat-value" style="color: #6b7280;">{severity_count['info']}</div>
                <div class="stat-label">Info</div>
            </div>
        </div>
        
        <div class="chart-container">
            <div class="chart-title">📊 漏洞类型分布</div>
            <div class="bar-chart">
"""
        
        # 添加柱状图
        max_count = max(type_count.values()) if type_count else 1
        colors = ["#ef4444", "#f97316", "#eab308", "#22c55e", "#3b82f6", "#8b5cf6", "#ec4899"]
        for i, (vtype, count) in enumerate(type_count.items()):
            height = int((count / max_count) * 150)
            color = colors[i % len(colors)]
            html += f"""
                <div class="bar">
                    <div class="bar-fill" style="height: {height}px; background: {color};"></div>
                    <div class="bar-value">{count}</div>
                    <div class="bar-label">{vtype}</div>
                </div>
"""
        
        html += """
            </div>
        </div>
        
        <div class="vuln-list">
            <h2 style="padding: 15px 20px; border-bottom: 1px solid #334155;">📋 漏洞详情</h2>
"""
        
        # 添加漏洞详情
        for i, r in enumerate(results, 1):
            if hasattr(r, '__dict__'):
                data = asdict(r)
            else:
                data = r
            
            vtype = data.get("type", data.get("vuln_type", "Unknown"))
            severity = data.get("severity", "medium").lower()
            param = data.get("parameter", data.get("param", "N/A"))
            url = data.get("url", data.get("endpoint", "N/A"))
            payload = data.get("payload", "N/A")
            confidence = data.get("confidence", 0)
            evidence = data.get("evidence", "N/A")
            
            html += f"""
            <div class="vuln-item">
                <div class="vuln-header">
                    <div class="vuln-title">#{i} {vtype}</div>
                    <span class="vuln-severity severity-{severity}">{severity}</span>
                </div>
                <div class="vuln-meta">
                    📍 URL: {url} | 📌 参数: {param} | 🎯 置信度: {confidence:.0%}
                </div>
                <div class="vuln-payload">{str(payload)[:200]}</div>
            </div>
"""
        
        html += """
        </div>
    </div>
</body>
</html>
"""
        
        return html
    
    def _generate_json(self, results: List[Any]) -> str:
        """生成 JSON 报告"""
        data = []
        for r in results:
            if hasattr(r, '__dict__'):
                data.append(asdict(r))
            else:
                data.append(r)
        return json.dumps(data, ensure_ascii=False, indent=2)
    
    def _generate_csv(self, results: List[Any]) -> str:
        """生成 CSV 报告"""
        import io
        output = io.StringIO()
        
        if not results:
            return ""
        
        # 获取字段
        if hasattr(results[0], '__dict__'):
            fieldnames = list(asdict(results[0]).keys())
        else:
            fieldnames = list(results[0].keys())
        
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        
        for r in results:
            if hasattr(r, '__dict__'):
                writer.writerow(asdict(r))
            else:
                writer.writerow(r)
        
        return output.getvalue()
    
    def _generate_pdf(self, results: List[Any]) -> str:
        """生成 PDF 报告"""
        if not FPDF_AVAILABLE:
            return "ERROR: fpdf2 not installed. Run: pip install fpdf2"
        
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", size=12)
        
        # 标题
        pdf.set_font_size(20)
        pdf.cell(0, 10, "WVS v18.0 Scan Report", ln=True, align="C")
        pdf.ln(10)
        
        # 统计
        pdf.set_font_size(14)
        pdf.cell(0, 10, f"Total Vulnerabilities: {len(results)}", ln=True)
        pdf.ln(5)
        
        # 漏洞列表
        pdf.set_font_size(10)
        for i, r in enumerate(results, 1):
            if hasattr(r, '__dict__'):
                data = asdict(r)
            else:
                data = r
            
            vtype = data.get("type", data.get("vuln_type", "Unknown"))
            severity = data.get("severity", "medium")
            url = data.get("url", data.get("endpoint", "N/A"))
            
            pdf.cell(0, 8, f"#{i} [{severity.upper()}] {vtype} - {url}", ln=True)
        
        # 保存
        output_path = self.output_dir / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        pdf.output(str(output_path))
        
        return str(output_path)
    
    def _generate_markdown(self, results: List[Any]) -> str:
        """生成 Markdown 报告"""
        md = f"""# WVS v18.0 扫描报告

**生成时间**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## 统计

| 严重程度 | 数量 |
|---------|------|
"""
        
        severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for r in results:
            if hasattr(r, '__dict__'):
                data = asdict(r)
            else:
                data = r
            sev = data.get("severity", "medium").lower()
            if sev in severity_count:
                severity_count[sev] += 1
        
        for sev, count in severity_count.items():
            md += f"| {sev.upper()} | {count} |\n"
        
        md += "\n## 漏洞列表\n\n"
        
        for i, r in enumerate(results, 1):
            if hasattr(r, '__dict__'):
                data = asdict(r)
            else:
                data = r
            
            vtype = data.get("type", data.get("vuln_type", "Unknown"))
            severity = data.get("severity", "medium")
            url = data.get("url", data.get("endpoint", "N/A"))
            param = data.get("parameter", data.get("param", "N/A"))
            payload = data.get("payload", "N/A")
            
            md += f"""### #{i} {vtype}

- **严重程度**: {severity}
- **URL**: {url}
- **参数**: {param}
- **Payload**: `{payload}`

"""
        
        return md
    
    def save_report(self, results: List[Any], format: str = "html", filename: str = None) -> str:
        """保存报告到文件"""
        content = self.generate(results, format)
        
        if filename is None:
            filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format}"
        
        output_path = self.output_dir / filename
        
        if format == "pdf":
            return content  # PDF 已经保存
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
        
        return str(output_path)
