from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import desc

from core.database import SystemConfig
from schemas.config import SystemConfigCreate, SystemConfigUpdate

class ConfigService:
    """配置服务"""

    def get_configs(
        self,
        db: Session,
        is_public: Optional[bool] = None,
        skip: int = 0,
        limit: int = 100
    ) -> List[SystemConfig]:
        """获取配置列表"""
        query = db.query(SystemConfig)

        if is_public is not None:
            query = query.filter(SystemConfig.is_public == is_public)

        query = query.order_by(desc(SystemConfig.created_at))
        configs = query.offset(skip).limit(limit).all()
        return configs

    def get_config_by_key(self, db: Session, config_key: str) -> Optional[SystemConfig]:
        """通过键获取配置"""
        return db.query(SystemConfig).filter(SystemConfig.config_key == config_key).first()

    def create_config(self, db: Session, config_data: SystemConfigCreate) -> SystemConfig:
        """创建配置"""
        db_config = SystemConfig(
            config_key=config_data.config_key,
            config_value=config_data.config_value,
            description=config_data.description,
            is_public=config_data.is_public
        )

        db.add(db_config)
        db.commit()
        db.refresh(db_config)
        return db_config

    def update_config(
        self,
        db: Session,
        config_key: str,
        config_update: SystemConfigUpdate
    ) -> SystemConfig:
        """更新配置"""
        db_config = self.get_config_by_key(db, config_key)
        if not db_config:
            return None

        update_data = config_update.dict(exclude_unset=True)

        for key, value in update_data.items():
            if hasattr(db_config, key) and value is not None:
                setattr(db_config, key, value)

        db.commit()
        db.refresh(db_config)
        return db_config

    def delete_config(self, db: Session, config_key: str):
        """删除配置"""
        db_config = self.get_config_by_key(db, config_key)
        if not db_config:
            return

        db.delete(db_config)
        db.commit()

    def get_wvs_config(self, db: Session) -> Dict[str, Any]:
        """获取WVS扫描器配置"""
        config = self.get_config_by_key(db, "wvs_scanner_config")
        if not config:
            # 返回默认配置
            default_config = {
                "scanner_path": "/usr/local/bin/wvs",
                "version": "18.4",
                "max_concurrent_scans": 5,
                "scan_timeout": 3600,
                "report_formats": ["html", "pdf", "json", "xml"],
                "available_plugins": [
                    "sql_injection",
                    "xss",
                    "csrf",
                    "file_inclusion",
                    "command_injection",
                    "xxe",
                    "ssrf"
                ],
                "advanced_modules": [
                    "logic_vulnerability",
                    "api_security",
                    "auth_bypass",
                    "zero_day_detection"
                ]
            }
            return default_config

        return config.config_value

    def update_wvs_config(self, db: Session, config_data: Dict[str, Any]) -> SystemConfig:
        """更新WVS扫描器配置"""
        db_config = self.get_config_by_key(db, "wvs_scanner_config")
        if not db_config:
            # 创建新配置
            config_create = SystemConfigCreate(
                config_key="wvs_scanner_config",
                config_value=config_data,
                description="WVS扫描器配置",
                is_public=False
            )
            return self.create_config(db, config_create)
        else:
            # 更新现有配置
            config_update = SystemConfigUpdate(config_value=config_data)
            return self.update_config(db, "wvs_scanner_config", config_update)

    def get_performance_config(self, db: Session) -> Dict[str, Any]:
        """获取性能优化配置"""
        config = self.get_config_by_key(db, "performance_config")
        if not config:
            # 返回默认配置
            default_config = {
                "concurrent_workers": 3,
                "cache_enabled": True,
                "cache_ttl": 300,
                "rate_limiting_enabled": True,
                "rate_limit": 100,
                "rate_limit_period": 60,
                "scan_priority_levels": ["high", "medium", "low"],
                "resource_usage": {
                    "max_memory_mb": 2048,
                    "max_cpu_percent": 80,
                    "max_disk_gb": 10
                }
            }
            return default_config

        return config.config_value

    def update_performance_config(self, db: Session, config_data: Dict[str, Any]) -> SystemConfig:
        """更新性能优化配置"""
        db_config = self.get_config_by_key(db, "performance_config")
        if not db_config:
            # 创建新配置
            config_create = SystemConfigCreate(
                config_key="performance_config",
                config_value=config_data,
                description="性能优化配置",
                is_public=False
            )
            return self.create_config(db, config_create)
        else:
            # 更新现有配置
            config_update = SystemConfigUpdate(config_value=config_data)
            return self.update_config(db, "performance_config", config_update)

    def get_security_config(self, db: Session) -> Dict[str, Any]:
        """获取安全配置"""
        config = self.get_config_by_key(db, "security_config")
        if not config:
            # 返回默认配置
            default_config = {
                "enable_https": True,
                "session_timeout": 1800,
                "max_login_attempts": 5,
                "password_min_length": 8,
                "password_require_special": True,
                "password_require_numbers": True,
                "password_require_uppercase": True,
                "enable_two_factor_auth": False,
                "allowed_ip_ranges": ["0.0.0.0/0"],
                "blocked_ip_ranges": []
            }
            return default_config

        return config.config_value

    def update_security_config(self, db: Session, config_data: Dict[str, Any]) -> SystemConfig:
        """更新安全配置"""
        db_config = self.get_config_by_key(db, "security_config")
        if not db_config:
            # 创建新配置
            config_create = SystemConfigCreate(
                config_key="security_config",
                config_value=config_data,
                description="安全配置",
                is_public=False
            )
            return self.create_config(db, config_create)
        else:
            # 更新现有配置
            config_update = SystemConfigUpdate(config_value=config_data)
            return self.update_config(db, "security_config", config_update)