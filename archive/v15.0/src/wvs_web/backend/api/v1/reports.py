from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Response
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
import os

from core.database import get_db
from schemas.reports import ReportGenerateRequest, ReportResponse
from services.report_service import ReportService
from services.auth_service import AuthService
from api.v1.auth import oauth2_scheme

router = APIRouter()

@router.get("/", response_model=List[ReportResponse])
async def get_reports(
    skip: int = 0,
    limit: int = 100,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(AuthService),
    report_service: ReportService = Depends(ReportService)
):
    """获取报告列表"""
    current_user = auth_service.get_current_user(db, token)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证令牌"
        )

    # 权限检查：普通用户只能查看自己的报告
    if not auth_service.is_superuser(current_user):
        reports = report_service.get_user_reports(db, current_user.id, skip, limit)
    else:
        reports = report_service.get_reports(db, skip, limit)

    return reports

@router.post("/generate")
async def generate_report(
    report_request: ReportGenerateRequest,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(AuthService),
    report_service: ReportService = Depends(ReportService)
):
    """生成报告"""
    current_user = auth_service.get_current_user(db, token)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证令牌"
        )

    # 检查扫描任务权限
    from services.scan_service import ScanService
    scan_service = ScanService()

    for task_id in report_request.scan_task_ids:
        scan_task = scan_service.get_scan_task_by_id(db, task_id)
        if not scan_task:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"扫描任务 {task_id} 不存在"
            )

        # 权限检查：普通用户只能为自己的任务生成报告
        if not auth_service.is_superuser(current_user) and scan_task.user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"无权为任务 {task_id} 生成报告"
            )

    # 生成报告
    report_path = await report_service.generate_report(
        db, report_request, current_user.id
    )

    if not report_path:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="报告生成失败"
        )

    return {
        "message": "报告生成成功",
        "report_path": report_path,
        "download_url": f"/api/v1/reports/download/{os.path.basename(report_path)}"
    }

@router.get("/download/{filename}")
async def download_report(
    filename: str,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(AuthService),
    report_service: ReportService = Depends(ReportService)
):
    """下载报告"""
    current_user = auth_service.get_current_user(db, token)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证令牌"
        )

    # 获取报告信息
    report = report_service.get_report_by_filename(db, filename)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="报告不存在"
        )

    # 权限检查：普通用户只能下载自己的报告
    if not auth_service.is_superuser(current_user) and report.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="无权下载此报告"
        )

    # 检查文件是否存在
    file_path = report.file_path
    if not os.path.exists(file_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="报告文件不存在"
        )

    # 根据格式返回文件
    if report.format == "pdf":
        media_type = "application/pdf"
    elif report.format == "html":
        media_type = "text/html"
    elif report.format == "json":
        media_type = "application/json"
    elif report.format == "csv":
        media_type = "text/csv"
    elif report.format == "xml":
        media_type = "application/xml"
    else:
        media_type = "application/octet-stream"

    return FileResponse(
        path=file_path,
        filename=filename,
        media_type=media_type
    )

@router.get("/scan/{scan_task_id}")
async def get_scan_reports(
    scan_task_id: int,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(AuthService),
    report_service: ReportService = Depends(ReportService)
):
    """获取扫描任务的报告"""
    current_user = auth_service.get_current_user(db, token)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证令牌"
        )

    # 检查扫描任务权限
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
            detail="无权查看此任务的报告"
        )

    reports = report_service.get_scan_reports(db, scan_task_id)
    return reports

@router.delete("/{report_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_report(
    report_id: int,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
    auth_service: AuthService = Depends(AuthService),
    report_service: ReportService = Depends(ReportService)
):
    """删除报告"""
    current_user = auth_service.get_current_user(db, token)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证令牌"
        )

    report = report_service.get_report_by_id(db, report_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="报告不存在"
        )

    # 权限检查：普通用户只能删除自己的报告
    if not auth_service.is_superuser(current_user) and report.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="无权删除此报告"
        )

    report_service.delete_report(db, report_id)

@router.get("/templates")
async def get_report_templates(
    token: str = Depends(oauth2_scheme),
    auth_service: AuthService = Depends(AuthService),
    report_service: ReportService = Depends(ReportService)
):
    """获取报告模板列表"""
    current_user = auth_service.get_current_user(db, token)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证令牌"
        )

    templates = report_service.get_report_templates()
    return templates

@router.post("/templates/{template_name}/preview")
async def preview_report_template(
    template_name: str,
    token: str = Depends(oauth2_scheme),
    auth_service: AuthService = Depends(AuthService),
    report_service: ReportService = Depends(ReportService)
):
    """预览报告模板"""
    current_user = auth_service.get_current_user(db, token)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证令牌"
        )

    # 权限检查：只有超级用户可以预览模板
    if not auth_service.is_superuser(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="无权预览报告模板"
        )

    preview = report_service.preview_template(template_name)
    if not preview:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="模板不存在"
        )

    return preview