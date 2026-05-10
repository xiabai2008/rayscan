"""RESTful API 服务 - HTTP 接口"""
import asyncio
import json
from typing import Dict, Any
from pathlib import Path

try:
    from aiohttp import web
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    web = None

from ..core.config_manager import ConfigManager
from ..core.scanner import WVSScanner
from ..core.scheduler import ScanTask, scheduler
from ..core.notifier import webhook_notifier


class WVSAPIServer:
    """WVS API 服务器"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 8080):
        self.host = host
        self.port = port
        self.app = web.Application() if AIOHTTP_AVAILABLE else None
        self.runner = None
        self.site = None
        
        if self.app:
            self._setup_routes()
    
    def _setup_routes(self):
        """设置路由"""
        self.app.router.add_get("/", self.handle_index)
        self.app.router.add_get("/health", self.handle_health)
        self.app.router.add_post("/api/v1/scan", self.handle_scan)
        self.app.router.add_get("/api/v1/scan/{scan_id}", self.handle_scan_status)
        self.app.router.add_get("/api/v1/scans", self.handle_scan_list)
        self.app.router.add_post("/api/v1/schedule", self.handle_schedule)
        self.app.router.add_get("/api/v1/profiles", self.handle_profiles)
        self.app.router.add_get("/api/v1/plugins", self.handle_plugins)
    
    async def handle_index(self, request):
        """首页"""
        return web.json_response({
            "name": "WVS API Server",
            "version": "6.0.0",
            "endpoints": [
                "GET  /health",
                "POST /api/v1/scan",
                "GET  /api/v1/scan/{scan_id}",
                "GET  /api/v1/scans",
                "POST /api/v1/schedule",
                "GET  /api/v1/profiles",
                "GET  /api/v1/plugins",
            ]
        })
    
    async def handle_health(self, request):
        """健康检查"""
        return web.json_response({
            "status": "healthy",
            "timestamp": asyncio.get_event_loop().time(),
        })
    
    async def handle_scan(self, request):
        """启动扫描"""
        try:
            data = await request.json()
            target = data.get("target")
            
            if not target:
                return web.json_response(
                    {"error": "缺少 target 参数"},
                    status=400
                )
            
            profile = data.get("profile", "standard")
            
            # 创建配置
            config = ConfigManager.create_scan_config(
                target=target,
                profile_name=profile,
            )
            
            # 启动扫描
            scanner = WVSScanner(config)
            
            # 在后台运行扫描
            asyncio.create_task(self._run_scan(scanner))
            
            return web.json_response({
                "scan_id": scanner.scan_id,
                "target": target,
                "status": "started",
                "message": "扫描已启动，使用 /api/v1/scan/{scan_id} 查询状态",
            })
            
        except Exception as e:
            return web.json_response(
                {"error": str(e)},
                status=500
            )
    
    async def _run_scan(self, scanner: WVSScanner):
        """后台运行扫描"""
        try:
            result = await scanner.scan()
            # 发送 webhook 通知
            await webhook_notifier.notify_scan_completed(result)
        except Exception as e:
            print(f"扫描失败: {e}")
    
    async def handle_scan_status(self, request):
        """查询扫描状态"""
        scan_id = request.match_info.get("scan_id")
        
        # 从调度器查询任务
        task = scheduler.get_task(scan_id)
        
        if not task:
            return web.json_response(
                {"error": "扫描任务不存在"},
                status=404
            )
        
        return web.json_response({
            "scan_id": task.task_id,
            "target": task.target,
            "status": task.status,
            "result": task.result,
            "error": task.error,
            "created_at": task.created_at,
        })
    
    async def handle_scan_list(self, request):
        """列出所有扫描"""
        status = request.query.get("status")
        tasks = scheduler.list_tasks(status)
        
        return web.json_response({
            "count": len(tasks),
            "scans": [
                {
                    "scan_id": t.task_id,
                    "target": t.target,
                    "status": t.status,
                    "created_at": t.created_at,
                }
                for t in tasks
            ]
        })
    
    async def handle_schedule(self, request):
        """添加定时扫描"""
        try:
            data = await request.json()
            target = data.get("target")
            interval = data.get("interval", 60)
            profile = data.get("profile", "standard")
            
            if not target:
                return web.json_response(
                    {"error": "缺少 target 参数"},
                    status=400
                )
            
            import uuid
            task = ScanTask(
                task_id=f"scheduled_{uuid.uuid4().hex[:8]}",
                target=target,
                profile=profile,
            )
            
            scheduler.add_task(task)
            
            return web.json_response({
                "task_id": task.task_id,
                "target": target,
                "status": "scheduled",
            })
            
        except Exception as e:
            return web.json_response(
                {"error": str(e)},
                status=500
            )
    
    async def handle_profiles(self, request):
        """列出扫描策略"""
        profiles = ConfigManager.list_profiles()
        return web.json_response({
            "profiles": [
                {"name": name, "description": desc}
                for name, desc in profiles.items()
            ]
        })
    
    async def handle_plugins(self, request):
        """列出插件"""
        from ..core.plugin_system import plugin_manager
        
        plugins = plugin_manager.list_plugins()
        return web.json_response({
            "plugins": plugins
        })
    
    async def start(self):
        """启动服务器"""
        if not AIOHTTP_AVAILABLE:
            print("错误: 需要安装 aiohttp: pip install aiohttp")
            return
        
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        
        self.site = web.TCPSite(self.runner, self.host, self.port)
        await self.site.start()
        
        print(f"WVS API 服务器已启动: http://{self.host}:{self.port}")
    
    async def stop(self):
        """停止服务器"""
        if self.runner:
            await self.runner.cleanup()
            print("WVS API 服务器已停止")


# 全局 API 服务器实例
api_server = WVSAPIServer()
