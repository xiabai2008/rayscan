from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from core.database import get_db
from schemas.scans import ScanTaskCreate, ScanTaskResponse, ScanTaskUpdate, ScanTaskSummary
from services.scan_service import ScanService
from services.auth_service import AuthService
from api.v1.auth import oauth2_scheme

router = APIRouter()

@router.get("/", response_model=List[ScanTaskSummary])
async def get_scan_tasks(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    status: Optional[str] = Query(None),
    user_id: Optional[int] = Query(None),
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(AuthService),
    scan_service: ScanService = Depends(ScanService)
):
    """获取扫描任务列表"""
    # 验证用户
    current_user = auth_service.get_current_user(db, token)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证令牌"
        )

    # 普通用户只能查看自己的任务，超级用户可以查看所有
    if not auth_service.is_superuser(current_user):
        user_id = current_user.id

    tasks = scan_service.get_scan_tasks(db, skip=skip, limit=limit, status=status, user_id=user_id)
    return tasks

@router.post("/", response_model=ScanTaskResponse, status_code=status.HTTP_201_CREATED)
async def create_scan_task(
    task_data: ScanTaskCreate,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(AuthService),
    scan_service: ScanService = Depends(ScanService)
):
    """创建扫描任务"""
    current_user = auth_service.get_current_user(db, token)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证令牌"
        )

    # 创建任务
    task = scan_service.create_scan_task(db, task_data, current_user.id)
    return task

@router.get("/{task_id}", response_model=ScanTaskResponse)
async def get_scan_task(
    task_id: int,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(AuthService),
    scan_service: ScanService = Depends(ScanService)
):
    """获取扫描任务详情"""
    current_user = auth_service.get_current_user(db, token)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证令牌"
        )

    task = scan_service.get_scan_task_by_id(db, task_id)
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="扫描任务不存在"
        )

    # 权限检查：普通用户只能查看自己的任务
    if not auth_service.is_superuser(current_user) and task.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="无权访问此任务"
        )

    return task

@router.put("/{task_id}", response_model=ScanTaskResponse)
async def update_scan_task(
    task_id: int,
    task_update: ScanTaskUpdate,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(AuthService),
    scan_service: ScanService = Depends(ScanService)
):
    """更新扫描任务"""
    current_user = auth_service.get_current_user(db, token)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证令牌"
        )

    task = scan_service.get_scan_task_by_id(db, task_id)
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="扫描任务不存在"
        )

    # 权限检查
    if not auth_service.is_superuser(current_user) and task.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="无权更新此任务"
        )

    updated_task = scan_service.update_scan_task(db, task_id, task_update)
    return updated_task

@router.delete("/{task_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan_task(
    task_id: int,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(AuthService),
    scan_service: ScanService = Depends(ScanService)
):
    """删除扫描任务"""
    current_user = auth_service.get_current_user(db, token)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证令牌"
        )

    task = scan_service.get_scan_task_by_id(db, task_id)
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="扫描任务不存在"
        )

    # 权限检查
    if not auth_service.is_superuser(current_user) and task.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="无权删除此任务"
        )

    scan_service.delete_scan_task(db, task_id)

@router.post("/{task_id}/start")
async def start_scan_task(
    task_id: int,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(AuthService),
    scan_service: ScanService = Depends(ScanService)
):
    """启动扫描任务"""
    current_user = auth_service.get_current_user(db, token)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证令牌"
        )

    task = scan_service.get_scan_task_by_id(db, task_id)
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="扫描任务不存在"
        )

    # 权限检查
    if not auth_service.is_superuser(current_user) and task.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="无权操作此任务"
        )

    # 启动扫描
    success = await scan_service.start_scan_task(db, task_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="启动扫描任务失败"
        )

    return {"message": "扫描任务已启动", "task_id": task_id}

@router.post("/{task_id}/pause")
async def pause_scan_task(
    task_id: int,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(AuthService),
    scan_service: ScanService = Depends(ScanService)
):
    """暂停扫描任务"""
    current_user = auth_service.get_current_user(db, token)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证令牌"
        )

    task = scan_service.get_scan_task_by_id(db, task_id)
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="扫描任务不存在"
        )

    # 权限检查
    if not auth_service.is_superuser(current_user) and task.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="无权操作此任务"
        )

    success = scan_service.pause_scan_task(db, task_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="暂停扫描任务失败"
        )

    return {"message": "扫描任务已暂停", "task_id": task_id}

@router.post("/{task_id}/resume")
async def resume_scan_task(
    task_id: int,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(AuthService),
    scan_service: ScanService = Depends(ScanService)
):
    """恢复扫描任务"""
    current_user = auth_service.get_current_user(db, token)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证令牌"
        )

    task = scan_service.get_scan_task_by_id(db, task_id)
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="扫描任务不存在"
        )

    # 权限检查
    if not auth_service.is_superuser(current_user) and task.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="无权操作此任务"
        )

    success = scan_service.resume_scan_task(db, task_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="恢复扫描任务失败"
        )

    return {"message": "扫描任务已恢复", "task_id": task_id}

@router.post("/{task_id}/stop")
async def stop_scan_task(
    task_id: int,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(AuthService),
    scan_service: ScanService = Depends(ScanService)
):
    """停止扫描任务"""
    current_user = auth_service.get_current_user(db, token)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证令牌"
        )

    task = scan_service.get_scan_task_by_id(db, task_id)
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="扫描任务不存在"
        )

    # 权限检查
    if not auth_service.is_superuser(current_user) and task.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="无权操作此任务"
        )

    success = scan_service.stop_scan_task(db, task_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="停止扫描任务失败"
        )

    return {"message": "扫描任务已停止", "task_id": task_id}

@router.get("/{task_id}/progress")
async def get_scan_progress(
    task_id: int,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(AuthService),
    scan_service: ScanService = Depends(ScanService)
):
    """获取扫描进度"""
    current_user = auth_service.get_current_user(db, token)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证令牌"
        )

    task = scan_service.get_scan_task_by_id(db, task_id)
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="扫描任务不存在"
        )

    # 权限检查
    if not auth_service.is_superuser(current_user) and task.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="无权查看此任务进度"
        )

    progress = await scan_service.get_scan_progress(task_id)
    return {
        "task_id": task_id,
        "progress": progress,
        "status": task.status,
        "current_stage": task.current_stage
    }

@router.get("/{task_id}/logs")
async def get_scan_logs(
    task_id: int,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    log_level: Optional[str] = Query(None),
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(AuthService),
    scan_service: ScanService = Depends(ScanService)
):
    """获取扫描日志"""
    current_user = auth_service.get_current_user(db, token)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证令牌"
        )

    task = scan_service.get_scan_task_by_id(db, task_id)
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="扫描任务不存在"
        )

    # 权限检查
    if not auth_service.is_superuser(current_user) and task.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="无权查看此任务日志"
        )

    logs = scan_service.get_scan_logs(db, task_id, skip=skip, limit=limit, log_level=log_level)
    return logs

@router.get("/{task_id}/statistics")
async def get_scan_statistics(
    task_id: int,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(AuthService),
    scan_service: ScanService = Depends(ScanService)
):
    """获取扫描统计信息"""
    current_user = auth_service.get_current_user(db, token)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证令牌"
        )

    task = scan_service.get_scan_task_by_id(db, task_id)
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="扫描任务不存在"
        )

    # 权限检查
    if not auth_service.is_superuser(current_user) and task.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="无权查看此任务统计信息"
        )

    statistics = scan_service.get_scan_statistics(db, task_id)
    return statistics