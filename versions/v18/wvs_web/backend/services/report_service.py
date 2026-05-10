import os
import uuid
import json
import asyncio
from datetime import datetime
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import desc

from core.database import get_db, ScanTask, Vulnerability, ScanLog
from core.config import settings
from schemas.reports import ReportGenerateRequest, ReportFormat, ReportType, ReportStatus

# 临时报告模型（实际项目中应该有数据库模型）
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text, JSON
from core.database import Base

class Report(Base):
    """报告模型"""
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text)
    report_type = Column(String(50), default="scan_summary")
    format = Column(String(20), default="pdf")
    template = Column(String(100))
    parameters = Column(JSON, default={})
    file_path = Column(String(500), nullable=False)
    file_size = Column(Integer, default=0)
    status = Column(String(20), default="generating")
    generated_at = Column(DateTime, default=datetime.now)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    scan_task_ids = Column(JSON, default=[])

class ReportService:
    """报告服务"""

    def get_reports(self, db: Session, skip: int = 0, limit: int = 100) -> List[Report]:
        """获取报告列表"""
        query = db.query(Report)
        query = query.order_by(desc(Report.generated_at))
        reports = query.offset(skip).limit(limit).all()
        return reports

    def get_user_reports(self, db: Session, user_id: int, skip: int = 0, limit: int = 100) -> List[Report]:
        """获取用户报告列表"""
        query = db.query(Report).filter(Report.user_id == user_id)
        query = query.order_by(desc(Report.generated_at))
        reports = query.offset(skip).limit(limit).all()
        return reports

    def get_scan_reports(self, db: Session, scan_task_id: int) -> List[Report]:
        """获取扫描任务报告"""
        query = db.query(Report).filter(Report.scan_task_ids.contains([scan_task_id]))
        query = query.order_by(desc(Report.generated_at))
        reports = query.all()
        return reports

    def get_report_by_id(self, db: Session, report_id: int) -> Optional[Report]:
        """通过ID获取报告"""
        return db.query(Report).filter(Report.id == report_id).first()

    def get_report_by_filename(self, db: Session, filename: str) -> Optional[Report]:
        """通过文件名获取报告"""
        # 查找文件路径包含文件名的报告
        reports = db.query(Report).filter(Report.file_path.contains(filename)).all()
        if reports:
            return reports[0]
        return None

    async def generate_report(
        self,
        db: Session,
        report_request: ReportGenerateRequest,
        user_id: int
    ) -> Optional[str]:
        """生成报告"""
        try:
            # 创建报告记录
            report_id = f"report_{uuid.uuid4().hex[:8]}"
            filename = f"{report_id}.{report_request.format}"
            file_path = os.path.join(settings.REPORT_DIR, filename)

            # 创建报告目录
            os.makedirs(settings.REPORT_DIR, exist_ok=True)

            # 生成报告内容
            report_data = await self._generate_report_content(db, report_request)

            # 根据格式保存报告
            if report_request.format == ReportFormat.JSON:
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(report_data, f, ensure_ascii=False, indent=2)
            elif report_request.format == ReportFormat.HTML:
                html_content = self._generate_html_report(report_data)
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
            elif report_request.format == ReportFormat.PDF:
                # PDF生成需要额外库，这里先保存为HTML
                html_content = self._generate_html_report(report_data)
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
            else:
                # 默认保存为JSON
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(report_data, f, ensure_ascii=False, indent=2)

            # 获取文件大小
            file_size = os.path.getsize(file_path)

            # 保存报告记录到数据库
            db_report = Report(
                name=report_request.name,
                description=report_request.description,
                report_type=report_request.report_type,
                format=report_request.format,
                template=report_request.template,
                parameters=report_request.parameters,
                file_path=file_path,
                file_size=file_size,
                status=ReportStatus.COMPLETED,
                generated_at=datetime.now(),
                user_id=user_id,
                scan_task_ids=report_request.scan_task_ids
            )

            db.add(db_report)
            db.commit()
            db.refresh(db_report)

            return file_path

        except Exception as e:
            print(f"生成报告失败: {e}")
            return None

    async def _generate_report_content(
        self,
        db: Session,
        report_request: ReportGenerateRequest
    ) -> Dict[str, Any]:
        """生成报告内容"""
        # 获取扫描任务数据
        from services.scan_service import ScanService
        scan_service = ScanService()

        scan_tasks = []
        vulnerabilities = []
        statistics = {}

        for task_id in report_request.scan_task_ids:
            # 获取扫描任务
            task = scan_service.get_scan_task_by_id(db, task_id)
            if task:
                scan_tasks.append({
                    "id": task.id,
                    "task_id": task.task_id,
                    "name": task.name,
                    "target_url": task.target_url,
                    "status": task.status,
                    "progress": task.progress,
                    "started_at": task.started_at.isoformat() if task.started_at else None,
                    "completed_at": task.completed_at.isoformat() if task.completed_at else None,
                    "vulnerabilities_found": task.vulnerabilities_found,
                    "critical_count": task.critical_count,
                    "high_count": task.high_count,
                    "medium_count": task.medium_count,
                    "low_count": task.low_count,
                    "info_count": task.info_count
                })

                # 获取漏洞数据
                if report_request.include_vulnerabilities:
                    from services.vulnerability_service import VulnerabilityService
                    vuln_service = VulnerabilityService()
                    task_vulns = vuln_service.get_vulnerabilities_by_scan(db, task_id)
                    for vuln in task_vulns:
                        vulnerabilities.append({
                            "id": vuln.id,
                            "title": vuln.title,
                            "severity": vuln.severity,
                            "cvss_score": vuln.cvss_score,
                            "affected_url": vuln.affected_url,
                            "status": vuln.status,
                            "discovered_at": vuln.discovered_at.isoformat() if vuln.discovered_at else None
                        })

                # 获取统计信息
                if report_request.include_statistics:
                    task_stats = scan_service.get_scan_statistics(db, task_id)
                    statistics[task_id] = task_stats

        # 生成报告元数据
        report_data = {
            "metadata": {
                "report_id": f"report_{uuid.uuid4().hex[:8]}",
                "name": report_request.name,
                "description": report_request.description,
                "type": report_request.report_type,
                "format": report_request.format,
                "generated_at": datetime.now().isoformat(),
                "scan_task_ids": report_request.scan_task_ids,
                "options": {
                    "include_vulnerabilities": report_request.include_vulnerabilities,
                    "include_logs": report_request.include_logs,
                    "include_statistics": report_request.include_statistics,
                    "include_recommendations": report_request.include_recommendations
                }
            },
            "scan_tasks": scan_tasks,
            "vulnerabilities": vulnerabilities if report_request.include_vulnerabilities else [],
            "statistics": statistics if report_request.include_statistics else {},
            "summary": self._generate_summary(scan_tasks, vulnerabilities),
            "recommendations": self._generate_recommendations(vulnerabilities) if report_request.include_recommendations else []
        }

        return report_data

    def _generate_html_report(self, report_data: Dict[str, Any]) -> str:
        """生成HTML报告"""
        # 简化的HTML报告生成
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>{report_name}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background-color: #f5f5f5; padding: 20px; border-radius: 5px; }}
                .section {{ margin-top: 30px; }}
                .vulnerability {{ border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }}
                .critical {{ border-left: 5px solid #dc3545; }}
                .high {{ border-left: 5px solid #fd7e14; }}
                .medium {{ border-left: 5px solid #ffc107; }}
                .low {{ border-left: 5px solid #28a745; }}
                .info {{ border-left: 5px solid #17a2b8; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>{report_name}</h1>
                <p>{report_description}</p>
                <p>生成时间: {generated_at}</p>
            </div>

            <div class="section">
                <h2>扫描任务概览</h2>
                <table>
                    <tr>
                        <th>任务名称</th>
                        <th>目标URL</th>
                        <th>状态</th>
                        <th>漏洞数量</th>
                        <th>开始时间</th>
                        <th>完成时间</th>
                    </tr>
                    {scan_tasks_rows}
                </table>
            </div>

            {vulnerabilities_section}

            <div class="section">
                <h2>报告摘要</h2>
                <pre>{summary}</pre>
            </div>

            {recommendations_section}
        </body>
        </html>
        """

        # 生成扫描任务行
        scan_tasks_rows = ""
        for task in report_data.get("scan_tasks", []):
            scan_tasks_rows += f"""
            <tr>
                <td>{task.get('name', 'N/A')}</td>
                <td>{task.get('target_url', 'N/A')}</td>
                <td>{task.get('status', 'N/A')}</td>
                <td>{task.get('vulnerabilities_found', 0)}</td>
                <td>{task.get('started_at', 'N/A')}</td>
                <td>{task.get('completed_at', 'N/A')}</td>
            </tr>
            """

        # 生成漏洞部分
        vulnerabilities_section = ""
        vulnerabilities = report_data.get("vulnerabilities", [])
        if vulnerabilities:
            vulnerabilities_section = '<div class="section"><h2>漏洞详情</h2>'
            for vuln in vulnerabilities:
                severity_class = vuln.get("severity", "info").lower()
                vulnerabilities_section += f"""
                <div class="vulnerability {severity_class}">
                    <h3>{vuln.get('title', '未命名漏洞')}</h3>
                    <p><strong>严重程度:</strong> {vuln.get('severity', 'N/A')}</p>
                    <p><strong>CVSS分数:</strong> {vuln.get('cvss_score', 'N/A')}</p>
                    <p><strong>影响URL:</strong> {vuln.get('affected_url', 'N/A')}</p>
                    <p><strong>发现时间:</strong> {vuln.get('discovered_at', 'N/A')}</p>
                </div>
                """
            vulnerabilities_section += '</div>'

        # 生成建议部分
        recommendations_section = ""
        recommendations = report_data.get("recommendations", [])
        if recommendations:
            recommendations_section = '<div class="section"><h2>安全建议</h2><ul>'
            for rec in recommendations:
                recommendations_section += f'<li>{rec}</li>'
            recommendations_section += '</ul></div>'

        # 格式化报告数据
        summary_json = json.dumps(report_data.get("summary", {}), ensure_ascii=False, indent=2)

        html_content = html_template.format(
            report_name=report_data["metadata"]["name"],
            report_description=report_data["metadata"]["description"],
            generated_at=report_data["metadata"]["generated_at"],
            scan_tasks_rows=scan_tasks_rows,
            vulnerabilities_section=vulnerabilities_section,
            summary=summary_json,
            recommendations_section=recommendations_section
        )

        return html_content

    def _generate_summary(self, scan_tasks: List[Dict], vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """生成报告摘要"""
        total_vulnerabilities = len(vulnerabilities)
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for vuln in vulnerabilities:
            severity = vuln.get("severity", "info").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        total_scans = len(scan_tasks)
        completed_scans = sum(1 for task in scan_tasks if task.get("status") == "completed")
        failed_scans = sum(1 for task in scan_tasks if task.get("status") == "failed")

        return {
            "total_scan_tasks": total_scans,
            "completed_scans": completed_scans,
            "failed_scans": failed_scans,
            "total_vulnerabilities": total_vulnerabilities,
            "vulnerabilities_by_severity": severity_counts,
            "generated_at": datetime.now().isoformat()
        }

    def _generate_recommendations(self, vulnerabilities: List[Dict]) -> List[str]:
        """生成安全建议"""
        recommendations = []

        # 根据漏洞类型生成建议
        vuln_types = set(vuln.get("title", "").lower() for vuln in vulnerabilities)

        if any("sql" in vuln_type for vuln_type in vuln_types):
            recommendations.append("实施参数化查询或使用ORM框架来防止SQL注入攻击")
        if any("xss" in vuln_type for vuln_type in vuln_types):
            recommendations.append("对用户输入进行适当的编码和验证，使用Content Security Policy (CSP)")
        if any("csrf" in vuln_type for vuln_type in vuln_types):
            recommendations.append("为敏感操作实施CSRF令牌保护")
        if any("injection" in vuln_type for vuln_type in vuln_types):
            recommendations.append("对所有用户输入进行严格的验证和清理")

        # 通用建议
        recommendations.append("定期更新系统和应用程序到最新版本")
        recommendations.append("实施Web应用防火墙(WAF)保护")
        recommendations.append("定期进行安全扫描和渗透测试")
        recommendations.append("对开发团队进行安全编码培训")

        return recommendations

    def delete_report(self, db: Session, report_id: int):
        """删除报告"""
        report = self.get_report_by_id(db, report_id)
        if not report:
            return

        # 删除文件
        try:
            if os.path.exists(report.file_path):
                os.remove(report.file_path)
        except Exception as e:
            print(f"删除报告文件失败: {e}")

        # 删除数据库记录
        db.delete(report)
        db.commit()

    def get_report_templates(self) -> List[Dict[str, Any]]:
        """获取报告模板列表"""
        templates = [
            {
                "name": "standard",
                "description": "标准报告模板",
                "format": "pdf",
                "type": "scan_summary",
                "preview_url": None,
                "parameters_schema": {},
                "is_default": True
            },
            {
                "name": "detailed",
                "description": "详细报告模板",
                "format": "html",
                "type": "technical",
                "preview_url": None,
                "parameters_schema": {
                    "include_screenshots": {"type": "boolean", "default": False},
                    "include_code": {"type": "boolean", "default": True}
                },
                "is_default": False
            },
            {
                "name": "executive",
                "description": "管理层报告模板",
                "format": "pdf",
                "type": "executive",
                "preview_url": None,
                "parameters_schema": {
                    "include_charts": {"type": "boolean", "default": True},
                    "language": {"type": "string", "default": "zh"}
                },
                "is_default": False
            }
        ]

        return templates

    def preview_template(self, template_name: str) -> Optional[Dict[str, Any]]:
        """预览报告模板"""
        templates = self.get_report_templates()
        for template in templates:
            if template["name"] == template_name:
                return template
        return None