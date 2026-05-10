from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from core.database import get_db
from schemas.vulnerabilities import VulnerabilityResponse, VulnerabilityUpdate, VulnerabilitySummary
from services.vulnerability_service import VulnerabilityService
from services.auth_service import AuthService
from api.v1.auth import oauth2_scheme

router = APIRouter()

@router.get("/", response_model=List[VulnerabilitySummary])
async def get_vulnerabilities(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    scan_task_id: Optional[int] = Query(None),
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(AuthService),
    vuln_service: VulnerabilityService = Depends(VulnerabilityService)
):
    """获取漏洞列表"""
    current_user = auth_service.get_current_user(db, token)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证令牌"
        )

    # 权限检查：普通用户只能查看自己任务的漏洞
    if not auth_service.is_superuser(current_user):
        # 过滤用户自己的扫描任务
        vulnerabilities = vuln_service.get_vulnerabilities_by_user(
            db, current_user.id, skip, limit, severity, status, scan_task_id
        )
    else:
        vulnerabilities = vuln_service.get_vulnerabilities(
            db, skip, limit, severity, status, scan_task_id
        )

    return vulnerabilities

@router.get("/{vulnerability_id}", response_model=VulnerabilityResponse)
async def get_vulnerability(
    vulnerability_id: int,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(AuthService),
    vuln_service: VulnerabilityService = Depends(VulnerabilityService)
):
    """获取漏洞详情"""
    current_user = auth_service.get_current_user(db, token)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证令牌"
        )

    vulnerability = vuln_service.get_vulnerability_by_id(db, vulnerability_id)
    if not vulnerability:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="漏洞不存在"
        )

    # 权限检查：普通用户只能查看自己任务的漏洞
    if not auth_service.is_superuser(current_user):
        if vulnerability.scan_task.user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="无权查看此漏洞"
            )

    return vulnerability

@router.put("/{vulnerability_id}", response_model=VulnerabilityResponse)
async def update_vulnerability(
    vulnerability_id: int,
    vuln_update: VulnerabilityUpdate,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(AuthService),
    vuln_service: VulnerabilityService = Depends(VulnerabilityService)
):
    """更新漏洞信息"""
    current_user = auth_service.get_current_user(db, token)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证令牌"
        )

    vulnerability = vuln_service.get_vulnerability_by_id(db, vulnerability_id)
    if not vulnerability:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="漏洞不存在"
        )

    # 权限检查：普通用户只能更新自己任务的漏洞
    if not auth_service.is_superuser(current_user):
        if vulnerability.scan_task.user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="无权更新此漏洞"
            )

    updated_vuln = vuln_service.update_vulnerability(db, vulnerability_id, vuln_update)
    return updated_vuln

@router.delete("/{vulnerability_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_vulnerability(
    vulnerability_id: int,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(AuthService),
    vuln_service: VulnerabilityService = Depends(VulnerabilityService)
):
    """删除漏洞"""
    current_user = auth_service.get_current_user(db, token)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证令牌"
        )

    vulnerability = vuln_service.get_vulnerability_by_id(db, vulnerability_id)
    if not vulnerability:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="漏洞不存在"
        )

    # 权限检查：只有超级用户可以删除漏洞
    if not auth_service.is_superuser(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="无权删除漏洞"
        )

    vuln_service.delete_vulnerability(db, vulnerability_id)

@router.post("/{vulnerability_id}/confirm")
async def confirm_vulnerability(
    vulnerability_id: int,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(AuthService),
    vuln_service: VulnerabilityService = Depends(VulnerabilityService)
):
    """确认漏洞"""
    current_user = auth_service.get_current_user(db, token)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证令牌"
        )

    vulnerability = vuln_service.get_vulnerability_by_id(db, vulnerability_id)
    if not vulnerability:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="漏洞不存在"
        )

    # 权限检查：普通用户只能确认自己任务的漏洞
    if not auth_service.is_superuser(current_user):
        if vulnerability.scan_task.user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="无权确认此漏洞"
            )

    vuln_service.confirm_vulnerability(db, vulnerability_id)
    return {"message": "漏洞已确认"}

@router.post("/{vulnerability_id}/mark-false-positive")
async def mark_false_positive(
    vulnerability_id: int,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(AuthService),
    vuln_service: VulnerabilityService = Depends(VulnerabilityService)
):
    """标记为误报"""
    current_user = auth_service.get_current_user(db, token)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证令牌"
        )

    vulnerability = vuln_service.get_vulnerability_by_id(db, vulnerability_id)
    if not vulnerability:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="漏洞不存在"
        )

    # 权限检查：普通用户只能标记自己任务的漏洞
    if not auth_service.is_superuser(current_user):
        if vulnerability.scan_task.user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="无权标记此漏洞"
            )

    vuln_service.mark_false_positive(db, vulnerability_id)
    return {"message": "漏洞已标记为误报"}

@router.post("/{vulnerability_id}/mark-fixed")
async def mark_fixed(
    vulnerability_id: int,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(AuthService),
    vuln_service: VulnerabilityService = Depends(VulnerabilityService)
):
    """标记为已修复"""
    current_user = auth_service.get_current_user(db, token)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证令牌"
        )

    vulnerability = vuln_service.get_vulnerability_by_id(db, vulnerability_id)
    if not vulnerability:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="漏洞不存在"
        )

    # 权限检查：普通用户只能标记自己任务的漏洞
    if not auth_service.is_superuser(current_user):
        if vulnerability.scan_task.user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="无权标记此漏洞"
            )

    vuln_service.mark_fixed(db, vulnerability_id)
    return {"message": "漏洞已标记为已修复"}

@router.get("/scan/{scan_task_id}", response_model=List[VulnerabilitySummary])
async def get_scan_vulnerabilities(
    scan_task_id: int,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(AuthService),
    vuln_service: VulnerabilityService = Depends(VulnerabilityService)
):
    """获取指定扫描任务的漏洞"""
    current_user = auth_service.get_current_user(db, token)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证令牌"
        )

    # 检查扫描任务是否存在且用户有权访问
    from services.scan_service import ScanService
    scan_service = ScanService()
    scan_task = scan_service.get_scan_task_by_id(db, scan_task_id)
    if not scan_task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="扫描任务不存在"
        )

    # 权限检查
    if not auth_service.is_superuser(current_user) and scan_task.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="无权查看此任务的漏洞"
        )

    vulnerabilities = vuln_service.get_vulnerabilities_by_scan(
        db, scan_task_id, skip, limit, severity, status
    )
    return vulnerabilities

@router.get("/statistics/summary")
async def get_vulnerability_statistics(
    days: int = Query(30, ge=1, le=365),
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(AuthService),
    vuln_service: VulnerabilityService = Depends(VulnerabilityService)
):
    """获取漏洞统计摘要"""
    current_user = auth_service.get_current_user(db, token)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证令牌"
        )

    # 权限检查：只有超级用户可以查看全局统计
    if not auth_service.is_superuser(current_user):
        statistics = vuln_service.get_user_vulnerability_statistics(db, current_user.id, days)
    else:
        statistics = vuln_service.get_vulnerability_statistics(db, days)

    return statistics