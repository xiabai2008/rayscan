#!/usr/bin/env python3
"""
扫描器API端点 - 提供WVS扫描器功能
"""
from fastapi import APIRouter, HTTPException, BackgroundTasks
from typing import List, Optional
from pydantic import BaseModel, Field
import asyncio

from ...services.wvs_scanner_service import get_scanner_service

router = APIRouter(prefix="/scanner", tags=["scanner"])


# 请求/响应模型
class ScanConfig(BaseModel):
    """扫描配置"""
    scan_type: str = Field("comprehensive", description="扫描类型: quick/comprehensive/deep")
    targets: List[str] = Field(..., description="扫描目标URL列表")
    scan_depth: str = Field("medium", description="扫描深度: light/medium/deep")
    enable_concurrent: bool = Field(True, description="启用并发扫描")
    enable_cache: bool = Field(True, description="启用智能缓存")
    enable_rate_limit: bool = Field(True, description="启用智能限速")
    modules: dict = Field({
        "zero_day": True,
        "logic": True,
        "api_security": True,
        "auth_bypass": True
    }, description="启用模块配置")
    performance: dict = Field({
        "max_concurrent_targets": 3,
        "max_requests_per_second": 3
    }, description="性能配置")


class StartScanResponse(BaseModel):
    """启动扫描响应"""
    task_id: str
    status: str
    message: str
    estimated_time: str


class ScanStatusResponse(BaseModel):
    """扫描状态响应"""
    task_id: str
    status: str
    progress: int
    config: Optional[dict] = None
    start_time: str
    results_available: bool
    error: Optional[str] = None


class ScanResultsResponse(BaseModel):
    """扫描结果响应"""
    scan_id: str
    config: dict
    summary: dict
    vulnerabilities: List[dict]
    performance_metrics: Optional[dict] = None
    recommendations: Optional[List[str]] = None


class TaskInfo(BaseModel):
    """任务信息"""
    task_id: str
    status: str
    progress: int
    start_time: str
    target_count: int
    results_available: bool


class ScannerStatusResponse(BaseModel):
    """扫描器状态响应"""
    status: str
    version: str
    capabilities: dict
    performance: dict
    last_updated: str


@router.get("/status", response_model=ScannerStatusResponse)
async def get_scanner_status():
    """获取扫描器状态"""
    try:
        service = get_scanner_service()
        status = await service.get_scanner_status()
        return status
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"获取状态失败: {str(e)}")


@router.post("/start", response_model=StartScanResponse)
async def start_scan(scan_config: ScanConfig, background_tasks: BackgroundTasks):
    """启动扫描任务"""
    try:
        service = get_scanner_service()
        result = await service.start_scan(scan_config.dict())
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"启动扫描失败: {str(e)}")


@router.get("/status/{task_id}", response_model=ScanStatusResponse)
async def get_scan_status(task_id: str):
    """获取扫描任务状态"""
    try:
        service = get_scanner_service()
        status = await service.get_scan_status(task_id)
        
        if "error" in status:
            raise HTTPException(status_code=404, detail=status["error"])
        
        return status
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"获取任务状态失败: {str(e)}")


@router.get("/results/{task_id}", response_model=ScanResultsResponse)
async def get_scan_results(task_id: str):
    """获取扫描结果"""
    try:
        service = get_scanner_service()
        results = await service.get_scan_results(task_id)
        
        if "error" in results:
            raise HTTPException(status_code=404, detail=results["error"])
        
        if "message" in results and "扫描尚未完成" in results["message"]:
            raise HTTPException(status_code=202, detail=results["message"])
        
        return results
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"获取扫描结果失败: {str(e)}")


@router.get("/tasks", response_model=List[TaskInfo])
async def list_scan_tasks():
    """列出所有扫描任务"""
    try:
        service = get_scanner_service()
        tasks = await service.list_scan_tasks()
        return tasks
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"列出任务失败: {str(e)}")


@router.post("/cancel/{task_id}")
async def cancel_scan(task_id: str):
    """取消扫描任务"""
    try:
        service = get_scanner_service()
        result = await service.cancel_scan(task_id)
        
        if "error" in result:
            raise HTTPException(status_code=400, detail=result["error"])
        
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"取消任务失败: {str(e)}")


@router.post("/demo/quick")
async def start_demo_quick_scan():
    """启动快速演示扫描"""
    try:
        service = get_scanner_service()
        
        demo_config = {
            "scan_type": "quick",
            "targets": ["http://192.168.18.131/dvwa/"],
            "scan_depth": "light",
            "enable_concurrent": True,
            "modules": {
                "zero_day": True,
                "logic": False,
                "api_security": False,
                "auth_bypass": False
            }
        }
        
        result = await service.start_scan(demo_config)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"启动演示扫描失败: {str(e)}")


@router.post("/demo/comprehensive")
async def start_demo_comprehensive_scan():
    """启动全面演示扫描"""
    try:
        service = get_scanner_service()
        
        demo_config = {
            "scan_type": "comprehensive",
            "targets": [
                "http://192.168.18.131/dvwa/",
                "http://192.168.18.131/mutillidae/",
                "http://192.168.18.131/tikiwiki/"
            ],
            "scan_depth": "medium",
            "enable_concurrent": True,
            "enable_cache": True,
            "enable_rate_limit": True,
            "modules": {
                "zero_day": True,
                "logic": True,
                "api_security": True,
                "auth_bypass": True
            }
        }
        
        result = await service.start_scan(demo_config)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"启动演示扫描失败: {str(e)}")


@router.delete("/tasks/clear")
async def clear_completed_tasks():
    """清理已完成的任务"""
    try:
        service = get_scanner_service()
        
        # 获取所有任务
        tasks = await service.list_scan_tasks()
        cleared_count = 0
        
        # 这里应该实现实际的清理逻辑
        # 目前只是返回统计信息
        
        return {
            "message": f"找到 {len(tasks)} 个任务",
            "cleared_count": cleared_count,
            "note": "清理功能需要在实际的扫描器服务中实现"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"清理任务失败: {str(e)}")