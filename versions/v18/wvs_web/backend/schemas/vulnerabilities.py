from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

class VulnerabilityStatus(str, Enum):
    """漏洞状态枚举"""
    NEW = "new"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    FIXED = "fixed"

class VulnerabilitySeverity(str, Enum):
    """漏洞严重程度枚举"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class VulnerabilityBase(BaseModel):
    """漏洞基础模型"""
    title: str = Field(..., min_length=1, max_length=500)
    description: Optional[str] = None
    severity: VulnerabilitySeverity = VulnerabilitySeverity.MEDIUM
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    cvss_vector: Optional[str] = None
    affected_url: Optional[str] = None
    parameter: Optional[str] = None
    http_method: Optional[str] = None
    request_data: Optional[str] = None
    response_data: Optional[str] = None
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = Field(default_factory=list)

class VulnerabilityCreate(VulnerabilityBase):
    """漏洞创建模型"""
    vulnerability_id: Optional[str] = None
    scan_task_id: int

class VulnerabilityUpdate(BaseModel):
    """漏洞更新模型"""
    title: Optional[str] = Field(None, min_length=1, max_length=500)
    description: Optional[str] = None
    severity: Optional[VulnerabilitySeverity] = None
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    cvss_vector: Optional[str] = None
    status: Optional[VulnerabilityStatus] = None
    remediation: Optional[str] = None
    references: Optional[List[str]] = None

class VulnerabilitySummary(BaseModel):
    """漏洞摘要模型"""
    id: int
    vulnerability_id: str
    title: str
    severity: VulnerabilitySeverity
    cvss_score: Optional[float]
    affected_url: Optional[str]
    status: VulnerabilityStatus
    discovered_at: datetime
    scan_task_id: int
    scan_task_name: str

    class Config:
        from_attributes = True

class VulnerabilityResponse(VulnerabilityBase):
    """漏洞响应模型"""
    id: int
    vulnerability_id: str
    status: VulnerabilityStatus
    discovered_at: datetime
    confirmed_at: Optional[datetime]
    fixed_at: Optional[datetime]
    scan_task_id: int
    scan_task_name: str

    class Config:
        from_attributes = True

class VulnerabilityStatistics(BaseModel):
    """漏洞统计模型"""
    total_vulnerabilities: int
    vulnerabilities_by_severity: Dict[str, int]
    vulnerabilities_by_status: Dict[str, int]
    vulnerabilities_by_day: List[Dict[str, Any]]
    average_cvss_score: float
    top_vulnerability_types: List[Dict[str, Any]]

class ExportFormat(str, Enum):
    """导出格式枚举"""
    JSON = "json"
    CSV = "csv"
    PDF = "pdf"
    HTML = "html"
    XML = "xml"

class VulnerabilityExportRequest(BaseModel):
    """漏洞导出请求模型"""
    vulnerability_ids: Optional[List[int]] = None
    scan_task_ids: Optional[List[int]] = None
    severity: Optional[List[VulnerabilitySeverity]] = None
    status: Optional[List[VulnerabilityStatus]] = None
    format: ExportFormat = ExportFormat.JSON
    include_details: bool = True