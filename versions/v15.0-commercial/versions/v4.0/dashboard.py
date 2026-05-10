"""扫描统计面板 - 数据分析和可视化"""
import json
from typing import Dict, List
from datetime import datetime, timedelta
from pathlib import Path

from .database import db


class ScanDashboard:
    """扫描统计面板"""
    
    def __init__(self):
        self.db = db
    
    def get_summary(self) -> Dict:
        """获取扫描摘要"""
        stats = self.db.get_statistics(days=30)
        
        return {
            "overview": {
                "total_scans": stats["total_scans"],
                "total_vulnerabilities": stats["total_vulnerabilities"],
                "average_vulns_per_scan": round(stats["average_vulns_per_scan"], 2),
            },
            "severity_distribution": stats["severity_distribution"],
            "recent_activity": stats["daily_stats"][:7],
        }
    
    def get_trend_analysis(self, days: int = 30) -> Dict:
        """获取趋势分析"""
        stats = self.db.get_statistics(days=days)
        daily = stats["daily_stats"]
        
        if not daily or len(daily) < 2:
            return {"trend": "insufficient_data"}
        
        # 计算趋势
        recent = daily[:7]
        older = daily[7:14] if len(daily) >= 14 else []
        
        recent_avg = sum(d["vulns"] for d in recent) / len(recent) if recent else 0
        older_avg = sum(d["vulns"] for d in older) / len(older) if older else 0
        
        if older_avg == 0:
            trend = "increasing" if recent_avg > 0 else "stable"
        else:
            change = (recent_avg - older_avg) / older_avg
            if change > 0.2:
                trend = "increasing"
            elif change < -0.2:
                trend = "decreasing"
            else:
                trend = "stable"
        
        return {
            "trend": trend,
            "recent_average": round(recent_avg, 2),
            "older_average": round(older_avg, 2) if older else 0,
            "change_percent": round((recent_avg - older_avg) / older_avg * 100, 2) if older_avg else 0,
            "daily_data": daily,
        }
    
    def get_top_vulnerabilities(self, limit: int = 10) -> List[Dict]:
        """获取最常见的漏洞"""
        scans = self.db.list_scans(limit=100)
        
        vuln_counter = {}
        
        for scan in scans:
            try:
                vulns = json.loads(scan.get("vulnerabilities", "[]"))
                for vuln in vulns:
                    name = vuln.get("name", "Unknown")
                    if name not in vuln_counter:
                        vuln_counter[name] = {
                            "name": name,
                            "severity": vuln.get("severity", "UNKNOWN"),
                            "count": 0,
                        }
                    vuln_counter[name]["count"] += 1
            except:
                pass
        
        # 排序
        sorted_vulns = sorted(vuln_counter.values(), key=lambda x: x["count"], reverse=True)
        return sorted_vulns[:limit]
    
    def get_target_stats(self) -> List[Dict]:
        """获取目标统计"""
        scans = self.db.list_scans(limit=1000)
        
        target_stats = {}
        
        for scan in scans:
            target = scan.get("target", "")
            if target not in target_stats:
                target_stats[target] = {
                    "target": target,
                    "scan_count": 0,
                    "total_vulns": 0,
                    "last_scan": scan.get("timestamp"),
                }
            
            target_stats[target]["scan_count"] += 1
            target_stats[target]["total_vulns"] += scan.get("vulnerability_count", 0)
        
        # 排序
        sorted_targets = sorted(target_stats.values(), key=lambda x: x["total_vulns"], reverse=True)
        return sorted_targets[:20]
    
    def generate_html_dashboard(self, output_path: str = "dashboard.html"):
        """生成 HTML 统计面板"""
        summary = self.get_summary()
        trend = self.get_trend_analysis()
        top_vulns = self.get_top_vulnerabilities()
        target_stats = self.get_target_stats()
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>WVS Scan Dashboard</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        h1 {{
            color: #333;
            margin-bottom: 30px;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .stat-card h3 {{
            margin: 0 0 10px 0;
            color: #666;
            font-size: 14px;
            text-transform: uppercase;
        }}
        .stat-card .value {{
            font-size: 32px;
            font-weight: bold;
            color: #333;
        }}
        .severity-bar {{
            display: flex;
            height: 30px;
            border-radius: 4px;
            overflow: hidden;
            margin-top: 10px;
        }}
        .severity-segment {{
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 12px;
            font-weight: bold;
        }}
        .critical {{ background: #e74c3c; }}
        .high {{ background: #e67e22; }}
        .medium {{ background: #f39c12; }}
        .low {{ background: #27ae60; }}
        table {{
            width: 100%;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-collapse: collapse;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #eee;
        }}
        th {{
            background: #f8f9fa;
            font-weight: 600;
            color: #666;
        }}
        .section {{
            margin-bottom: 30px;
        }}
        .section h2 {{
            color: #333;
            margin-bottom: 15px;
        }}
        .trend-{{trend['trend']}} {{
            color: {'#e74c3c' if trend['trend'] == 'increasing' else '#27ae60' if trend['trend'] == 'decreasing' else '#f39c12'};
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>📊 WVS Scan Dashboard</h1>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Scans</h3>
                <div class="value">{summary['overview']['total_scans']}</div>
            </div>
            <div class="stat-card">
                <h3>Total Vulnerabilities</h3>
                <div class="value">{summary['overview']['total_vulnerabilities']}</div>
            </div>
            <div class="stat-card">
                <h3>Avg Vulns/Scan</h3>
                <div class="value">{summary['overview']['average_vulns_per_scan']}</div>
            </div>
            <div class="stat-card">
                <h3>Trend</h3>
                <div class="value trend-{trend['trend']}">{trend['trend'].title()}</div>
            </div>
        </div>
        
        <div class="section">
            <h2>Severity Distribution</h2>
            <div class="severity-bar">
                {self._generate_severity_bar(summary['severity_distribution'])}
            </div>
        </div>
        
        <div class="section">
            <h2>Top Vulnerabilities</h2>
            <table>
                <thead>
                    <tr>
                        <th>Vulnerability</th>
                        <th>Severity</th>
                        <th>Occurrences</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(f"<tr><td>{v['name']}</td><td>{v['severity']}</td><td>{v['count']}</td></tr>" for v in top_vulns)}
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>Target Statistics</h2>
            <table>
                <thead>
                    <tr>
                        <th>Target</th>
                        <th>Scan Count</th>
                        <th>Total Vulns</th>
                        <th>Last Scan</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(f"<tr><td>{t['target'][:50]}...</td><td>{t['scan_count']}</td><td>{t['total_vulns']}</td><td>{t['last_scan'][:10]}</td></tr>" for t in target_stats[:10])}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
"""
        
        Path(output_path).write_text(html, encoding="utf-8")
        return output_path
    
    def _generate_severity_bar(self, distribution: Dict) -> str:
        """生成严重等级条形图"""
        total = sum(distribution.values())
        if total == 0:
            return '<div class="severity-segment" style="width:100%;background:#95a5a6;">No Data</div>'
        
        segments = []
        colors = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
        
        for sev, count in distribution.items():
            if count > 0:
                pct = count / total * 100
                segments.append(
                    f'<div class="severity-segment {colors.get(sev, "")}" '
                    f'style="width:{pct}%">{sev[:1]}: {count}</div>'
                )
        
        return ''.join(segments)


# 全局面板实例
dashboard = ScanDashboard()
