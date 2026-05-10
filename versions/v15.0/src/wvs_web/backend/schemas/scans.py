from pydantic import BaseModel, Field, HttpUrl
from typing import Optional, Dict, Any, List
from datetime import datetime
from enum import Enum

class ScanStatus(str, Enum):
    """扫描状态枚举"""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class ScanSeverity(str, Enum):
    """漏洞严重程度枚举"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ScanTaskBase(BaseModel):
    """扫描任务基础模型"""
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    target_url: HttpUrl
    scan_config: Dict[str, Any] = Field(default_factory=dict)

class ScanTaskCreate(ScanTaskBase):
    """扫描任务创建模型"""
    pass

class ScanTaskUpdate(BaseModel):
    """扫描任务更新模型"""
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = None
    scan_config: Optional[Dict[str, Any]] = None
    status: Optional[ScanStatus] = None
    progress: Optional[float] = Field(None, ge=0, le=100)

class ScanTaskSummary(BaseModel):
    """扫描任务摘要模型"""
    id: int
    task_id: str
    name: str
    target_url: str
    status: ScanStatus
    progress: float
    vulnerabilities_found: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime
    user_id: int

    class Config:
        from_attributes = True

class ScanTaskResponse(ScanTaskSummary):
    """扫描任务响应模型"""
    description: Optional[str]
    scan_config: Dict[str, Any]
    current_stage: Optional[str]
    result_summary: Dict[str, Any]

    class Config:
        from_attributes = True

class ScanProgress(BaseModel):
    """扫描进度模型"""
    task_id: str
    progress: float
    stage: Optional[str]
    timestamp: datetime

class ScanLog(BaseModel):
    """扫描日志模型"""
    id: int
    log_level: str
    message: str
    details: Dict[str, Any]
    timestamp: datetime
    scan_task_id: int

    class Config:
        from_attributes = True

class ScanStatistics(BaseModel):
    """扫描统计模型"""
    task_id: str
    total_requests: int
    total_vulnerabilities: int
    vulnerabilities_by_severity: Dict[str, int]
    scan_duration: Optional[float]  # 秒
    average_response_time: Optional[float]  # 毫秒
    requests_per_second: Optional[float]

class ScanConfig(BaseModel):
    """扫描配置模型"""
    # 基本配置
    scan_type: str = Field("full", description="扫描类型: full, quick, custom")
    max_depth: int = Field(5, ge=1, le=10, description="最大爬取深度")
    max_pages: int = Field(1000, ge=1, le=10000, description="最大页面数")

    # 漏洞检测配置
    check_sql_injection: bool = True
    check_xss: bool = True
    check_csrf: bool = True
    check_file_inclusion: bool = True
    check_command_injection: bool = True
    check_xxe: bool = True
    check_ssrf: bool = True

    # 性能配置
    max_concurrent_requests: int = Field(10, ge=1, le=100)
    request_timeout: int = Field(30, ge=1, le=300)
    delay_between_requests: float = Field(0.1, ge=0, le=5)

    # 认证配置
    use_authentication: bool = False
    auth_type: Optional[str] = Field(None, description="认证类型: basic, form, token")
    auth_credentials: Optional[Dict[str, str]] = None

    # 高级配置
    enable_brute_force: bool = False
    enable_fuzzing: bool = False
    enable_crawl: bool = True
    enable_ajax_crawl: bool = False

class ScanResult(BaseModel):
    """扫描结果模型"""
    task_id: str
    status: ScanStatus
    vulnerabilities: List[Dict[str, Any]]
    statistics: ScanStatistics
    scan_config: ScanConfig
    start_time: datetime
    end_time: Optional[datetime]
    report_path: Optional[str]