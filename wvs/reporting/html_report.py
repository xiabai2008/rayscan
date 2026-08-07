"""
HTML Report Generator
Generates a self-contained single-file HTML report (no external network required)
"""

import html
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from ..models import Confidence, ScanResult, Severity, Vulnerability

SEV_COLORS_HTML = {
    Severity.CRITICAL: ("#d32f2f", "#ffcdd2", "CRITICAL"),
    Severity.HIGH: ("#c62828", "#ef9a9a", "HIGH"),
    Severity.MEDIUM: ("#f9a825", "#fff59d", "MEDIUM"),
    Severity.LOW: ("#1565c0", "#90caf9", "LOW"),
    Severity.INFO: ("#616161", "#e0e0e0", "INFO"),
}

SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


class HTMLReporter:
    """
    HTML Report Generator

    Generates a fully self-contained single-file HTML report:
    - Responsive design, suitable for mobile and desktop
    - All CSS/JS inline, no external dependencies
    - Vulnerabilities grouped by severity
    - Click to expand vulnerability details
    - Export to JSON
    """

    def __init__(self):
        self._counter = 0

    def generate(self, result: ScanResult, output_path: Path):
        """Generate HTML report"""
        html_content = self._build_html(result)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html_content, encoding="utf-8")

    def _build_html(self, result: ScanResult) -> str:
        """Build complete HTML"""
        has_vulns = bool(result.vulnerabilities)
        vuln_stats = result.severity_count

        groups = self._group_by_severity(result.vulnerabilities)

        stats_html = self._build_stats_html(result, vuln_stats)

        # JSON data (for JS use)
        vuln_json = json.dumps(
            [self._vuln_to_json(v) for v in result.vulnerabilities],
            ensure_ascii=False,
            indent=2,
        )

        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RayScan 1.0.2 扫描报告 - {html.escape(result.target.url)}</title>
<style>
:root {{
    --bg: #0f1419;
    --card-bg: #1a2332;
    --card-border: #2a3a50;
    --text: #e6edf3;
    --text-dim: #7d8590;
    --accent: #58a6ff;
    --accent-dim: #1f6feb;
    --critical: #d32f2f;
    --high: #c62828;
    --medium: #f9a825;
    --low: #1565c0;
    --info: #616161;
    --font: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
}}

* {{ box-sizing: border-box; margin: 0; padding: 0; }}

body {{
    background: var(--bg);
    color: var(--text);
    font-family: var(--font);
    font-size: 14px;
    line-height: 1.6;
    padding: 20px;
}}

.container {{ max-width: 1200px; margin: 0 auto; }}

.header {{
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: 8px;
    padding: 24px;
    margin-bottom: 20px;
}}

.header h1 {{
    font-size: 24px;
    color: var(--accent);
    margin-bottom: 8px;
}}

.header .meta {{
    display: flex;
    gap: 24px;
    flex-wrap: wrap;
    color: var(--text-dim);
    font-size: 13px;
}}

.stats-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 12px;
    margin-bottom: 20px;
}}

.stat-card {{
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: 8px;
    padding: 16px;
    text-align: center;
}}

.stat-card .value {{
    font-size: 28px;
    font-weight: bold;
    margin-bottom: 4px;
}}

.stat-card .label {{ color: var(--text-dim); font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }}

.stat-card.critical .value {{ color: var(--critical); }}
.stat-card.high .value {{ color: var(--high); }}
.stat-card.medium .value {{ color: var(--medium); }}
.stat-card.low .value {{ color: var(--low); }}
.stat-card.total .value {{ color: var(--accent); }}

.severity-section {{
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: 8px;
    margin-bottom: 16px;
    overflow: hidden;
}}

.section-header {{
    padding: 14px 20px;
    cursor: pointer;
    display: flex;
    justify-content: space-between;
    align-items: center;
    user-select: none;
    border-bottom: 1px solid var(--card-border);
}}

.section-header:hover {{ background: rgba(255,255,255,0.03); }}
.section-header .chevron {{ transition: transform 0.2s; font-size: 12px; color: var(--text-dim); }}
.section-header.open .chevron {{ transform: rotate(90deg); }}
.section-header .title {{ font-size: 15px; font-weight: 600; }}
.section-header .count {{ background: var(--card-border); border-radius: 20px; padding: 2px 10px; font-size: 12px; font-weight: bold; }}

.section-body {{ display: none; padding: 16px; }}
.section-body.open {{ display: block; }}

table {{ width: 100%; border-collapse: collapse; }}
th {{ text-align: left; padding: 8px 12px; color: var(--text-dim); font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid var(--card-border); }}  # noqa: E501
td {{ padding: 10px 12px; border-bottom: 1px solid rgba(255,255,255,0.05); }}
tr:last-child td {{ border-bottom: none; }}
tr:hover td {{ background: rgba(255,255,255,0.02); }}

.badge {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: bold;
    text-transform: uppercase;
}}

.badge-critical {{ background: var(--critical); color: white; }}
.badge-high {{ background: var(--high); color: white; }}
.badge-medium {{ background: var(--medium); color: #1a1a1a; }}
.badge-low {{ background: var(--low); color: white; }}
.badge-info {{ background: var(--info); color: white; }}
.badge-high-confidence {{ background: #2e7d32; color: white; }}
.badge-medium-confidence {{ background: #f57c00; color: white; }}

.vuln-url {{ font-family: 'Courier New', monospace; font-size: 12px; color: var(--accent); word-break: break-all; }}
.vuln-param {{ font-family: monospace; font-size: 12px; color: var(--text-dim); }}
.payload-block {{
    font-family: 'Courier New', monospace;
    font-size: 12px;
    background: rgba(0,0,0,0.3);
    border: 1px solid var(--card-border);
    border-radius: 4px;
    padding: 8px;
    color: #e57373;
    word-break: break-all;
    margin-top: 8px;
}}

.detail-panel {{
    background: rgba(0,0,0,0.2);
    border-radius: 6px;
    padding: 16px;
    margin-top: 10px;
    font-size: 13px;
}}

.detail-row {{ display: flex; gap: 12px; margin-bottom: 8px; }}
.detail-label {{ color: var(--text-dim); min-width: 80px; }}
.detail-value {{ color: var(--text); }}

.footer {{
    text-align: center;
    color: var(--text-dim);
    font-size: 12px;
    margin-top: 32px;
    padding-top: 16px;
    border-top: 1px solid var(--card-border);
}}

.no-vuln {{
    background: var(--card-bg);
    border: 1px solid #2e7d32;
    border-radius: 8px;
    padding: 40px;
    text-align: center;
    color: #4caf50;
    font-size: 18px;
}}

.actions {{
    display: flex;
    gap: 12px;
    margin-bottom: 16px;
}}

.btn {{
    background: var(--accent-dim);
    color: white;
    border: none;
    border-radius: 6px;
    padding: 8px 16px;
    font-size: 13px;
    cursor: pointer;
}}

.btn:hover {{ background: var(--accent); }}
</style>
</head>
<body>
<div class="container">

<div class="header">
  <h1>🔍 RayScan 1.0.2 扫描报告</h1>
  <div class="meta">
    <span>📍 {html.escape(result.target.url)}</span>
    <span>⏱ {result.duration:.1f}s</span>
    <span>🌐 {result.requests_made} 请求</span>
    <span>📅 {result.scan_time.strftime("%Y-%m-%d %H:%M:%S") if result.scan_time else datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</span>
  </div>
</div>

{stats_html}

<div class="actions">
  <button class="btn" onclick="exportJSON()">📥 导出 JSON</button>
  <button class="btn" onclick="expandAll()">🔓 展开全部</button>
  <button class="btn" onclick="collapseAll()">🔒 收起全部</button>
</div>

{self._build_vuln_sections(groups) if has_vulns else '<div class="no-vuln">✅ 扫描完成，未发现漏洞</div>'}

<div class="footer">
  RayScan 1.0.2 | Generated by xiabai2004
</div>
</div>

<script>
const vulns = {vuln_json};

function toggle(id) {{
    const body = document.getElementById(id);
    const header = body.previousElementSibling;
    body.classList.toggle('open');
    header.classList.toggle('open');
}}

function expandAll() {{
    document.querySelectorAll('.section-body').forEach(b => b.classList.add('open'));
    document.querySelectorAll('.section-header').forEach(h => h.classList.add('open'));
}}

function collapseAll() {{
    document.querySelectorAll('.section-body').forEach(b => b.classList.remove('open'));
    document.querySelectorAll('.section-header').forEach(h => h.classList.remove('open'));
}}

function exportJSON() {{
    const blob = new Blob([JSON.stringify(vulns, null, 2)], {{type: 'application/json'}});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'wvs-report.json';
    a.click();
}}

// Auto-expand critical/high vulns
document.querySelectorAll('.section-header').forEach(h => {{
    const badge = h.querySelector('.badge');
    if (badge && (badge.classList.contains('badge-critical') || badge.classList.contains('badge-high'))) {{
        h.classList.add('open');
        h.nextElementSibling.classList.add('open');
    }}
}});
</script>
</body>
</html>"""

    def _build_stats_html(self, result: ScanResult, stats: Dict[str, int]) -> str:
        total = len(result.vulnerabilities)
        parts = []
        for sev, cls in [
            ("critical", "critical"),
            ("high", "high"),
            ("medium", "medium"),
            ("low", "low"),
            ("info", "info"),
        ]:
            count = stats.get(sev, 0)
            if count:
                parts.append(
                    f'<div class="stat-card {cls}"><div class="value">{count}</div><div class="label">{sev.upper()}</div></div>'
                )

        parts.append(
            f'<div class="stat-card total"><div class="value">{total}</div><div class="label">TOTAL</div></div>'
        )

        return f'<div class="stats-grid">{"".join(parts)}</div>'

    def _group_by_severity(self, vulns: List[Vulnerability]) -> Dict[Severity, List[Vulnerability]]:
        groups: Dict[Severity, List[Vulnerability]] = {s: [] for s in SEV_ORDER}
        for v in vulns:
            groups[v.severity].append(v)
        return {k: v for k, v in groups.items() if v}

    def _build_vuln_sections(self, groups: Dict[Severity, List[Vulnerability]]) -> str:
        html_parts = []
        for sev in SEV_ORDER:
            vulns = groups.get(sev, [])
            if not vulns:
                continue
            color_cls = sev.value.lower()
            badge_cls = f"badge-{color_cls}"
            section_id = f"sec-{color_cls}"
            rows = "\n".join(self._build_vuln_row(v, i) for i, v in enumerate(vulns))

            html_parts.append(f"""
<div class="severity-section">
  <div class="section-header" onclick="toggle('{section_id}')">
    <span class="title"><span class="badge {badge_cls}">{sev.value.upper()}</span> {sev.value.capitalize()} 级别漏洞</span>
    <span><span class="count">{len(vulns)}</span> <span class="chevron">▶</span></span>
  </div>
  <div class="section-body" id="{section_id}">
    <table>
      <thead><tr>
        <th>#</th><th>类型</th><th>URL</th><th>参数</th><th>置信度</th><th>Payload</th>
      </tr></thead>
      <tbody>
        {rows}
      </tbody>
    </table>
  </div>
</div>""")

        return "\n".join(html_parts)

    def _build_vuln_row(self, v: Vulnerability, i: int) -> str:
        vuln_id = f"vuln-{v.type.value}-{i}"
        color_cls = v.severity.value.lower()
        badge_cls = f"badge-{color_cls}"
        conf_cls = (
            "badge-high-confidence"
            if v.confidence in (Confidence.HIGH, Confidence.CERTAIN)
            else "badge-medium-confidence"
        )
        detail_rows = []
        if v.description:
            detail_rows.append(
                f'<div class="detail-row"><span class="detail-label">描述</span><span class="detail-value">{html.escape(v.description[:300])}</span></div>'
            )
        if v.recommendation:
            detail_rows.append(
                f'<div class="detail-row"><span class="detail-label">修复建议</span><span class="detail-value">{html.escape(v.recommendation[:300])}</span></div>'
            )
        if v.references:
            refs = " | ".join(
                f'<a href="{html.escape(r)}" target="_blank" style="color:#58a6ff">{html.escape(r[:50])}</a>'
                for r in v.references[:3]
            )
            detail_rows.append(
                f'<div class="detail-row"><span class="detail-label">参考</span><span class="detail-value">{refs}</span></div>'
            )

        return f"""
<tr>
  <td>{i + 1}</td>
  <td><span class="badge {badge_cls}">{v.type.value.upper()}</span></td>
  <td class="vuln-url">{html.escape(v.url)}</td>
  <td class="vuln-param">{html.escape(v.parameter or "-")}</td>
  <td><span class="badge {conf_cls}">{v.confidence.value.upper()}</span></td>
  <td>
    <div style="cursor:pointer;color:#e57373" onclick="
      const d = document.getElementById('{vuln_id}');
      d.style.display = d.style.display === 'none' ? 'block' : 'none';
    ">查看 Payload ▼</div>
    <div class="payload-block" id="{vuln_id}" style="display:none">{html.escape(v.payload or "N/A")}</div>
    <div class="detail-panel" style="display:none">{"".join(detail_rows)}</div>
  </td>
</tr>"""

    def _build_vuln_rows(self, vulns: List[Vulnerability]) -> str:
        return "\n".join(self._build_vuln_row(v, i) for i, v in enumerate(vulns))

    def _vuln_to_json(self, v: Vulnerability) -> Dict[str, Any]:
        return {
            "type": v.type.value,
            "title": v.title,
            "severity": v.severity.value,
            "confidence": v.confidence.value,
            "url": v.url,
            "parameter": v.parameter,
            "parameter_type": v.parameter_type,
            "method": v.method,
            "payload": v.payload,
            "evidence": v.evidence,
            "description": v.description,
            "recommendation": v.recommendation,
            "references": v.references,
            "tags": v.tags,
            "module": v.module,
        }
