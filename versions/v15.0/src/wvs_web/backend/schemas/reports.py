from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

class ReportFormat(str, Enum):
    """报告格式枚举"""
    PDF = "pdf"
    HTML = "html"
    JSON = "json"
    CSV = "csv"
    XML = "xml"
    EXCEL = "excel"

class ReportType(str, Enum):
    """报告类型枚举"""
    SCAN_SUMMARY = "scan_summary"
    VULNERABILITY_DETAIL = "vulnerability_detail"
    COMPLIANCE = "compliance"
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    CUSTOM = "custom"

class ReportStatus(str, Enum):
    """报告状态枚举"""
    GENERATING = "generating"
    COMPLETED = "completed"
    FAILED = "failed"
    DELETED = "deleted"

class ReportBase(BaseModel):
    """报告基础模型"""
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    report_type: ReportType = ReportType.SCAN_SUMMARY
    format: ReportFormat = ReportFormat.PDF
    template: Optional[str] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)

class ReportGenerateRequest(ReportBase):
    """报告生成请求模型"""
    scan_task_ids: List[int] = Field(..., min_items=1)
    include_vulnerabilities: bool = True
    include_logs: bool = False
    include_statistics: bool = True
    include_recommendations: bool = True

class ReportCreate(ReportBase):
    """报告创建模型"""
    file_path: str
    file_size: int
    scan_task_ids: List[int]
    user_id: int

class ReportUpdate(BaseModel):
    """报告更新模型"""
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = None
    status: Optional[ReportStatus] = None

class ReportResponse(ReportBase):
    """报告响应模型"""
    id: int
    file_path: str
    file_size: int
    status: ReportStatus
    download_url: str
    generated_at: datetime
    user_id: int
    scan_task_ids: List[int]

    class Config:
        from_attributes = True

class ReportTemplate(BaseModel):
    """报告模板模型"""
    name: str
    description: str
    format: ReportFormat
    type: ReportType
    preview_url: Optional[str]
    parameters_schema: Dict[str, Any]
    is_default: bool = False

class ReportStatistics(BaseModel):
    """报告统计模型"""
    total_reports: int
    reports_by_format: Dict[str, int]
    reports_by_type: Dict[str, int]
    total_file_size: int
    average_file_size: int
    reports_by_day: List[Dict[str, Any]]

class ExportOptions(BaseModel):
    """导出选项模型"""
    include_charts: bool = True
    include_screenshots: bool = False
    include_code_snippets: bool = True
    include_http_requests: bool = False
    include_remediation_steps: bool = True
    include_references: bool = True
    include_appendix: bool = False
    language: str = "zh"
    timezone: str = "Asia/Shanghai"