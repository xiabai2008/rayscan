from pydantic_settings import BaseSettings
from typing import List, Optional
import os

class Settings(BaseSettings):
    # 应用配置
    APP_NAME: str = "WVS Web Management"
    DEBUG: bool = True
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    LOG_LEVEL: str = "info"

    # 数据库配置
    DATABASE_URL: str = "sqlite:///./wvs.db"
    DATABASE_POOL_SIZE: int = 5
    DATABASE_MAX_OVERFLOW: int = 10

    # Redis配置
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_POOL_SIZE: int = 10

    # JWT配置
    SECRET_KEY: str = "your-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # CORS配置
    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:8080",
        "http://localhost:3000",
        "http://127.0.0.1:8080",
        "http://127.0.0.1:3000",
    ]

    # 文件存储配置
    UPLOAD_DIR: str = "./uploads"
    REPORT_DIR: str = "./reports"
    MAX_UPLOAD_SIZE: int = 100 * 1024 * 1024  # 100MB

    # WVS扫描器配置
    WVS_SCANNER_PATH: str = "/usr/local/bin/wvs"
    WVS_CONFIG_PATH: str = "./config/wvs_config.json"
    WVS_REPORT_DIR: str = "./wvs_reports"
    WVS_MAX_CONCURRENT_SCANS: int = 5
    WVS_SCAN_TIMEOUT: int = 3600  # 1小时

    # Celery配置
    CELERY_BROKER_URL: str = "redis://localhost:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/2"

    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()

# 创建必要的目录
os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
os.makedirs(settings.REPORT_DIR, exist_ok=True)
os.makedirs(settings.WVS_REPORT_DIR, exist_ok=True)