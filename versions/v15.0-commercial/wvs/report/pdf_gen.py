"""PDF 报告生成模块"""
from pathlib import Path
from typing import Dict, List
from datetime import datetime

try:
    from fpdf import FPDF
    FPDF_AVAILABLE = True
except ImportError:
    FPDF_AVAILABLE = False
    FPDF = None


class PDFReportGenerator:
    """PDF 报告生成器"""
    
    def __init__(self):
        self.font_family = "Arial"
    
    def generate(self, scan_id: str, target: str, vulnerabilities: List[Dict],
                 output_path: str) -> Path:
        """生成 PDF 报告"""
        if not FPDF_AVAILABLE:
            raise ImportError("需要安装 fpdf2: pip install fpdf2")
        
        pdf = FPDF()
        pdf.add_page()
        
        # 封面
        self._add_cover(pdf, scan_id, target)
        
        # 执行摘要
        pdf.add_page()
        self._add_summary(pdf, vulnerabilities)
        
        # 漏洞详情
        if vulnerabilities:
            pdf.add_page()
            self._add_vulnerabilities(pdf, vulnerabilities)
        
        # 修复建议
        pdf.add_page()
        self._add_remediation(pdf, vulnerabilities)
        
        # 保存
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        pdf.output(str(output))
        
        return output
    
    def _add_cover(self, pdf: FPDF, scan_id: str, target: str):
        """添加封面"""
        # 标题
        pdf.set_font(self.font_family, "B", 24)
        pdf.cell(0, 20, "Web Vulnerability Scanner", 0, 1, "C")
        pdf.cell(0, 10, "Security Assessment Report", 0, 1, "C")
        
        pdf.ln(30)
        
        # 报告信息
        pdf.set_font(self.font_family, "", 12)
        pdf.cell(0, 10, f"Scan ID: {scan_id}", 0, 1, "C")
        pdf.cell(0, 10, f"Target: {target}", 0, 1, "C")
        pdf.cell(0, 10, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1, "C")
        
        pdf.ln(20)
        
        # 声明
        pdf.set_font(self.font_family, "I", 10)
        pdf.multi_cell(0, 5, "CONFIDENTIAL: This report contains security assessment results and should be handled with care.")
    
    def _add_summary(self, pdf: FPDF, vulnerabilities: List[Dict]):
        """添加执行摘要"""
        pdf.set_font(self.font_family, "B", 16)
        pdf.cell(0, 10, "Executive Summary", 0, 1)
        pdf.ln(5)
        
        # 统计
        severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for vuln in vulnerabilities:
            sev = vuln.get("severity", "UNKNOWN")
            severity_count[sev] = severity_count.get(sev, 0) + 1
        
        pdf.set_font(self.font_family, "", 12)
        pdf.cell(0, 8, f"Total Vulnerabilities: {len(vulnerabilities)}", 0, 1)
        pdf.cell(0, 8, f"  Critical: {severity_count['CRITICAL']}", 0, 1)
        pdf.cell(0, 8, f"  High: {severity_count['HIGH']}", 0, 1)
        pdf.cell(0, 8, f"  Medium: {severity_count['MEDIUM']}", 0, 1)
        pdf.cell(0, 8, f"  Low: {severity_count['LOW']}", 0, 1)
        
        pdf.ln(10)
        
        # 风险评级
        pdf.set_font(self.font_family, "B", 14)
        pdf.cell(0, 10, "Risk Rating", 0, 1)
        pdf.ln(5)
        
        risk_score = self._calculate_risk_score(severity_count)
        risk_level = self._get_risk_level(risk_score)
        
        pdf.set_font(self.font_family, "", 12)
        pdf.cell(0, 8, f"Overall Risk Score: {risk_score}/100", 0, 1)
        pdf.cell(0, 8, f"Risk Level: {risk_level}", 0, 1)
    
    def _add_vulnerabilities(self, pdf: FPDF, vulnerabilities: List[Dict]):
        """添加漏洞详情"""
        pdf.set_font(self.font_family, "B", 16)
        pdf.cell(0, 10, "Vulnerability Details", 0, 1)
        pdf.ln(5)
        
        for i, vuln in enumerate(vulnerabilities, 1):
            # 漏洞标题
            pdf.set_font(self.font_family, "B", 12)
            severity = vuln.get("severity", "UNKNOWN")
            pdf.set_text_color(*self._get_severity_color(severity))
            pdf.cell(0, 8, f"{i}. [{severity}] {vuln.get('name', 'Unknown')}", 0, 1)
            pdf.set_text_color(0, 0, 0)
            
            # 详情
            pdf.set_font(self.font_family, "", 10)
            pdf.cell(0, 6, f"URL: {vuln.get('url', 'N/A')}", 0, 1)
            pdf.cell(0, 6, f"Payload: {vuln.get('payload', 'N/A')[:80]}", 0, 1)
            pdf.cell(0, 6, f"Confidence: {vuln.get('confidence', 0) * 100:.0f}%", 0, 1)
            
            # 描述
            if vuln.get("description"):
                pdf.set_font(self.font_family, "I", 9)
                pdf.multi_cell(0, 5, f"Description: {vuln.get('description')}")
            
            pdf.ln(5)
    
    def _add_remediation(self, pdf: FPDF, vulnerabilities: List[Dict]):
        """添加修复建议"""
        pdf.set_font(self.font_family, "B", 16)
        pdf.cell(0, 10, "Remediation Recommendations", 0, 1)
        pdf.ln(5)
        
        # 按严重等级分组
        critical_high = [v for v in vulnerabilities 
                        if v.get("severity") in ["CRITICAL", "HIGH"]]
        
        if critical_high:
            pdf.set_font(self.font_family, "B", 12)
            pdf.cell(0, 8, "Priority 1 - Critical/High Severity:", 0, 1)
            pdf.set_font(self.font_family, "", 10)
            
            for vuln in critical_high:
                name = vuln.get("name", "Unknown")
                remediation = vuln.get("remediation", "No specific guidance available.")
                pdf.multi_cell(0, 5, f"• {name}: {remediation}")
                pdf.ln(2)
        
        pdf.ln(10)
        
        # 通用建议
        pdf.set_font(self.font_family, "B", 12)
        pdf.cell(0, 8, "General Security Recommendations:", 0, 1)
        pdf.set_font(self.font_family, "", 10)
        
        recommendations = [
            "Keep all software and frameworks up to date",
            "Implement proper input validation and sanitization",
            "Use parameterized queries for database access",
            "Implement Content Security Policy (CSP)",
            "Enable security headers (HSTS, X-Frame-Options, etc.)",
            "Regularly review and update access controls",
        ]
        
        for rec in recommendations:
            pdf.cell(0, 6, f"• {rec}", 0, 1)
    
    def _calculate_risk_score(self, severity_count: Dict) -> int:
        """计算风险评分"""
        score = 100
        score -= severity_count.get("CRITICAL", 0) * 20
        score -= severity_count.get("HIGH", 0) * 10
        score -= severity_count.get("MEDIUM", 0) * 5
        score -= severity_count.get("LOW", 0) * 2
        return max(0, score)
    
    def _get_risk_level(self, score: int) -> str:
        """获取风险等级"""
        if score >= 80:
            return "Low"
        elif score >= 60:
            return "Medium"
        elif score >= 40:
            return "High"
        else:
            return "Critical"
    
    def _get_severity_color(self, severity: str) -> tuple:
        """获取严重等级颜色"""
        colors = {
            "CRITICAL": (192, 57, 43),  # 深红
            "HIGH": (231, 76, 60),      # 红
            "MEDIUM": (243, 156, 18),   # 橙
            "LOW": (46, 204, 113),      # 绿
        }
        return colors.get(severity, (127, 140, 141))
