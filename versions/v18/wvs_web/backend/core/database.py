from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, ForeignKey, Text, JSON, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from sqlalchemy.sql import func
from typing import Optional, Generator
import datetime

from core.config import settings

engine = create_engine(
    settings.DATABASE_URL,
    pool_size=settings.DATABASE_POOL_SIZE,
    max_overflow=settings.DATABASE_MAX_OVERFLOW,
    connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db() -> Generator[Session, None, None]:
    """数据库会话依赖注入"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# 用户模型
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(200), nullable=False)
    full_name = Column(String(100))
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    # 关系
    scan_tasks = relationship("ScanTask", back_populates="user")

# 扫描任务模型
class ScanTask(Base):
    __tablename__ = "scan_tasks"

    id = Column(Integer, primary_key=True, index=True)
    task_id = Column(String(50), unique=True, index=True, nullable=False)
    name = Column(String(200), nullable=False)
    description = Column(Text)
    target_url = Column(String(500), nullable=False)
    scan_config = Column(JSON, default={})

    # 状态: pending, running, paused, completed, failed, cancelled
    status = Column(String(20), default="pending", index=True)
    progress = Column(Float, default=0.0)  # 0-100
    current_stage = Column(String(100))

    # 结果
    result_summary = Column(JSON, default={})
    vulnerabilities_found = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)

    # 时间
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    # 外键
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    # 关系
    user = relationship("User", back_populates="scan_tasks")
    vulnerabilities = relationship("Vulnerability", back_populates="scan_task", cascade="all, delete-orphan")
    scan_logs = relationship("ScanLog", back_populates="scan_task", cascade="all, delete-orphan")

# 漏洞模型
class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    vulnerability_id = Column(String(50), index=True, nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(String(20), index=True)  # critical, high, medium, low, info
    cvss_score = Column(Float)
    cvss_vector = Column(String(100))
    affected_url = Column(String(500))
    parameter = Column(String(200))
    http_method = Column(String(10))
    request_data = Column(Text)
    response_data = Column(Text)
    evidence = Column(Text)
    remediation = Column(Text)
    references = Column(JSON, default=[])

    # 状态: new, confirmed, false_positive, fixed
    status = Column(String(20), default="new", index=True)

    # 时间
    discovered_at = Column(DateTime, default=func.now())
    confirmed_at = Column(DateTime)
    fixed_at = Column(DateTime)

    # 外键
    scan_task_id = Column(Integer, ForeignKey("scan_tasks.id"), nullable=False)

    # 关系
    scan_task = relationship("ScanTask", back_populates="vulnerabilities")

# 扫描日志模型
class ScanLog(Base):
    __tablename__ = "scan_logs"

    id = Column(Integer, primary_key=True, index=True)
    log_level = Column(String(20), index=True)  # info, warning, error, debug
    message = Column(Text, nullable=False)
    details = Column(JSON, default={})
    timestamp = Column(DateTime, default=func.now(), index=True)

    # 外键
    scan_task_id = Column(Integer, ForeignKey("scan_tasks.id"), nullable=False)

    # 关系
    scan_task = relationship("ScanTask", back_populates="scan_logs")

# 系统配置模型
class SystemConfig(Base):
    __tablename__ = "system_configs"

    id = Column(Integer, primary_key=True, index=True)
    config_key = Column(String(100), unique=True, index=True, nullable=False)
    config_value = Column(JSON, nullable=False)
    description = Column(Text)
    is_public = Column(Boolean, default=False)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())