from pydantic import BaseModel, Field
from typing import Optional, Any, Dict
from datetime import datetime

class SystemConfigBase(BaseModel):
    """系统配置基础模型"""
    config_key: str = Field(..., min_length=1, max_length=100)
    config_value: Dict[str, Any] = Field(...)
    description: Optional[str] = None
    is_public: bool = False

class SystemConfigCreate(SystemConfigBase):
    """系统配置创建模型"""
    pass

class SystemConfigUpdate(BaseModel):
    """系统配置更新模型"""
    config_value: Optional[Dict[str, Any]] = None
    description: Optional[str] = None
    is_public: Optional[bool] = None

class SystemConfigResponse(SystemConfigBase):
    """系统配置响应模型"""
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class WVSConfig(BaseModel):
    """WVS扫描器配置模型"""
    scanner_path: str = "/usr/local/bin/wvs"
    config_path: str = "./config/wvs_config.json"
    report_dir: str = "./wvs_reports"
    max_concurrent_scans: int = Field(5, ge=1, le=20)
    scan_timeout: int = Field(3600, ge=60, le=86400)
    default_scan_type: str = "full"
    enable_advanced_modules: bool = True
    enable_caching: bool = True
    enable_rate_limiting: bool = True

class PerformanceConfig(BaseModel):
    """性能优化配置模型"""
    concurrent_workers: int = Field(3, ge=1, le=10)
    cache_enabled: bool = True
    cache_ttl: int = Field(300, ge=60, le=3600)
    rate_limiting_enabled: bool = True
    rate_limit: int = Field(100, ge=10, le=1000)
    rate_limit_period: int = Field(60, ge=1, le=3600)
    scan_priority_levels: list = ["high", "medium", "low"]
    max_memory_mb: int = Field(2048, ge=512, le=16384)
    max_cpu_percent: int = Field(80, ge=10, le=100)
    max_disk_gb: int = Field(10, ge=1, le=100)

class SecurityConfig(BaseModel):
    """安全配置模型"""
    enable_https: bool = True
    session_timeout: int = Field(1800, ge=300, le=86400)
    max_login_attempts: int = Field(5, ge=1, le=10)
    password_min_length: int = Field(8, ge=6, le=32)
    password_require_special: bool = True
    password_require_numbers: bool = True
    password_require_uppercase: bool = True
    enable_two_factor_auth: bool = False
    allowed_ip_ranges: list = ["0.0.0.0/0"]
    blocked_ip_ranges: list = []

class NotificationConfig(BaseModel):
    """通知配置模型"""
    email_enabled: bool = False
    email_server: Optional[str] = None
    email_port: Optional[int] = None
    email_username: Optional[str] = None
    email_password: Optional[str] = None
    email_from: Optional[str] = None
    slack_enabled: bool = False
    slack_webhook_url: Optional[str] = None
    webhook_enabled: bool = False
    webhook_url: Optional[str] = None
    notify_on_scan_complete: bool = True
    notify_on_critical_vuln: bool = True
    notify_on_scan_error: bool = True