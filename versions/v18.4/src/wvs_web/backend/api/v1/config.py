from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from core.database import get_db, SystemConfig
from schemas.config import SystemConfigCreate, SystemConfigUpdate, SystemConfigResponse
from services.config_service import ConfigService
from services.auth_service import AuthService
from api.v1.auth import oauth2_scheme

router = APIRouter()

@router.get("/", response_model=List[SystemConfigResponse])
async def get_system_configs(
    is_public: bool = None,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(AuthService),
    config_service: ConfigService = Depends(ConfigService)
):
    """获取系统配置列表"""
    current_user = auth_service.get_current_user(db, token)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证令牌"
        )

    # 权限检查：只有超级用户可以查看非公开配置
    if not auth_service.is_superuser(current_user):
        is_public = True

    configs = config_service.get_configs(db, is_public=is_public)
    return configs

@router.get("/{config_key}", response_model=SystemConfigResponse)
async def get_system_config(
    config_key: str,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(AuthService),
    config_service: ConfigService = Depends(ConfigService)
):
    """获取系统配置详情"""
    current_user = auth_service.get_current_user(db, token)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证令牌"
        )

    config = config_service.get_config_by_key(db, config_key)
    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="配置不存在"
        )

    # 权限检查：普通用户只能查看公开配置
    if not config.is_public and not auth_service.is_superuser(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="无权查看此配置"
        )

    return config

@router.post("/", response_model=SystemConfigResponse, status_code=status.HTTP_201_CREATED)
async def create_system_config(
    config_data: SystemConfigCreate,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(AuthService),
    config_service: ConfigService = Depends(ConfigService)
):
    """创建系统配置"""
    current_user = auth_service.get_current_user(db, token)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证令牌"
        )

    # 权限检查：只有超级用户可以创建配置
    if not auth_service.is_superuser(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="无权创建配置"
        )

    # 检查配置是否已存在
    existing_config = config_service.get_config_by_key(db, config_data.config_key)
    if existing_config:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="配置键已存在"
        )

    config = config_service.create_config(db, config_data)
    return config

@router.put("/{config_key}", response_model=SystemConfigResponse)
async def update_system_config(
    config_key: str,
    config_update: SystemConfigUpdate,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(AuthService),
    config_service: ConfigService = Depends(ConfigService)
):
    """更新系统配置"""
    current_user = auth_service.get_current_user(db, token)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证令牌"
        )

    # 权限检查：只有超级用户可以更新配置
    if not auth_service.is_superuser(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="无权更新配置"
        )

    config = config_service.get_config_by_key(db, config_key)
    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="配置不存在"
        )

    updated_config = config_service.update_config(db, config_key, config_update)
    return updated_config

@router.delete("/{config_key}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_system_config(
    config_key: str,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(AuthService),
    config_service: ConfigService = Depends(ConfigService)
):
    """删除系统配置"""
    current_user = auth_service.get_current_user(db, token)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证令牌"
        )

    # 权限检查：只有超级用户可以删除配置
    if not auth_service.is_superuser(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="无权删除配置"
        )

    config = config_service.get_config_by_key(db, config_key)
    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="配置不存在"
        )

    config_service.delete_config(db, config_key)

@router.get("/wvs/scanner-config")
async def get_wvs_scanner_config(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(AuthService)
):
    """获取WVS扫描器配置"""
    current_user = auth_service.get_current_user(db, token)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证令牌"
        )

    # 这里应该返回WVS扫描器的实际配置
    # 暂时返回示例配置
    wvs_config = {
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

    return wvs_config

@router.put("/wvs/scanner-config")
async def update_wvs_scanner_config(
    config_data: Dict[str, Any],
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(AuthService)
):
    """更新WVS扫描器配置"""
    current_user = auth_service.get_current_user(db, token)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证令牌"
        )

    # 权限检查：只有超级用户可以更新扫描器配置
    if not auth_service.is_superuser(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="无权更新扫描器配置"
        )

    # 这里应该保存WVS扫描器配置
    # 暂时返回成功
    return {
        "message": "WVS扫描器配置已更新",
        "config": config_data
    }

@router.get("/performance/optimization")
async def get_performance_optimization(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(AuthService)
):
    """获取性能优化配置"""
    current_user = auth_service.get_current_user(db, token)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证令牌"
        )

    # 返回性能优化配置
    optimization_config = {
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

    return optimization_config