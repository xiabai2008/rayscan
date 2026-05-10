from fastapi import APIRouter

from api.v1.auth import router as auth_router
from api.v1.scans import router as scans_router
from api.v1.vulnerabilities import router as vuln_router
from api.v1.config import router as config_router
from api.v1.reports import router as reports_router
from api.v1.websocket import router as websocket_router

api_router = APIRouter()

# 包含各个模块的路由
api_router.include_router(auth_router, prefix="/auth", tags=["认证"])
api_router.include_router(scans_router, prefix="/scans", tags=["扫描任务"])
api_router.include_router(vuln_router, prefix="/vulnerabilities", tags=["漏洞管理"])
api_router.include_router(config_router, prefix="/config", tags=["配置管理"])
api_router.include_router(reports_router, prefix="/reports", tags=["报告管理"])
api_router.include_router(websocket_router, prefix="/ws", tags=["WebSocket"])