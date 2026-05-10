"""WVS v17.0 - 分布式扫描引擎

支持多节点并行扫描，任务分发与结果聚合
"""
import asyncio
import json
import time
import uuid
import hashlib
from typing import Dict, List, Optional, Set, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import logging
import socket

logger = logging.getLogger(__name__)


class NodeStatus(Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    BUSY = "busy"
    ERROR = "error"


class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ScanNode:
    """扫描节点"""
    id: str
    host: str
    port: int
    status: NodeStatus = NodeStatus.OFFLINE
    max_concurrent: int = 10
    current_tasks: int = 0
    last_heartbeat: datetime = field(default_factory=datetime.now)
    capabilities: List[str] = field(default_factory=list)
    metrics: Dict[str, float] = field(default_factory=dict)
    
    @property
    def available_slots(self) -> int:
        return max(0, self.max_concurrent - self.current_tasks)
    
    @property
    def address(self) -> str:
        return f"{self.host}:{self.port}"


@dataclass
class ScanTask:
    """扫描任务"""
    id: str
    target: str
    scan_type: str
    params: Dict[str, Any]
    status: TaskStatus = TaskStatus.PENDING
    assigned_node: Optional[str] = None
    result: Optional[Dict] = None
    error: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    progress: float = 0.0
    vulns_found: int = 0


@dataclass
class DistributedConfig:
    """分布式配置"""
    master_host: str = "0.0.0.0"
    master_port: int = 8765
    heartbeat_interval: int = 30
    task_timeout: int = 3600
    retry_count: int = 3
    load_balance_strategy: str = "least_busy"  # round_robin, least_busy, random


class DistributedScanner:
    """分布式扫描管理器"""
    
    def __init__(self, config: DistributedConfig = None):
        self.config = config or DistributedConfig()
        self.nodes: Dict[str, ScanNode] = {}
        self.tasks: Dict[str, ScanTask] = {}
        self.pending_queue: asyncio.Queue = None
        self._running = False
        self._server = None
    
    async def start_master(self):
        """启动主节点服务"""
        self._running = True
        self.pending_queue = asyncio.Queue()
        
        # 启动任务分发器
        asyncio.create_task(self._task_dispatcher())
        
        # 启动心跳检测
        asyncio.create_task(self._heartbeat_checker())
        
        # 启动 RPC 服务
        await self._start_rpc_server()
        
        logger.info(f"分布式扫描主节点启动: {self.config.master_host}:{self.config.master_port}")
    
    async def stop_master(self):
        """停止主节点"""
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        logger.info("分布式扫描主节点已停止")
    
    async def _start_rpc_server(self):
        """启动 RPC 服务器"""
        import aiohttp
        from aiohttp import web
        
        app = web.Application()
        app.router.add_post("/register", self._handle_register)
        app.router.add_post("/heartbeat", self._handle_heartbeat)
        app.router.add_post("/result", self._handle_result)
        app.router.add_get("/task", self._handle_get_task)
        app.router.add_get("/nodes", self._handle_list_nodes)
        app.router.add_get("/status", self._handle_status)
        
        runner = web.AppRunner(app)
        await runner.setup()
        self._server = await web.TCPSite(
            runner, 
            self.config.master_host, 
            self.config.master_port
        ).start()
    
    async def _handle_register(self, request):
        """处理节点注册"""
        data = await request.json()
        
        node = ScanNode(
            id=data.get("id", str(uuid.uuid4())),
            host=data.get("host", request.remote),
            port=data.get("port", 8766),
            max_concurrent=data.get("max_concurrent", 10),
            capabilities=data.get("capabilities", ["sqli", "xss", "ssrf"])
        )
        node.status = NodeStatus.ONLINE
        
        self.nodes[node.id] = node
        logger.info(f"节点注册: {node.id} @ {node.address}")
        
        return web.json_response({"status": "ok", "node_id": node.id})
    
    async def _handle_heartbeat(self, request):
        """处理心跳"""
        data = await request.json()
        node_id = data.get("node_id")
        
        if node_id not in self.nodes:
            return web.json_response({"status": "error", "message": "未注册节点"}, status=404)
        
        node = self.nodes[node_id]
        node.last_heartbeat = datetime.now()
        node.current_tasks = data.get("current_tasks", 0)
        node.status = NodeStatus.BUSY if node.current_tasks > 0 else NodeStatus.ONLINE
        node.metrics = data.get("metrics", {})
        
        return web.json_response({"status": "ok"})
    
    async def _handle_result(self, request):
        """处理任务结果"""
        data = await request.json()
        task_id = data.get("task_id")
        
        if task_id not in self.tasks:
            return web.json_response({"status": "error", "message": "未知任务"}, status=404)
        
        task = self.tasks[task_id]
        task.status = TaskStatus.COMPLETED if data.get("success") else TaskStatus.FAILED
        task.result = data.get("result")
        task.error = data.get("error")
        task.completed_at = datetime.now()
        task.vulns_found = data.get("vulns_found", 0)
        
        # 释放节点任务槽
        if task.assigned_node and task.assigned_node in self.nodes:
            self.nodes[task.assigned_node].current_tasks -= 1
        
        logger.info(f"任务完成: {task_id}, 漏洞数: {task.vulns_found}")
        
        return web.json_response({"status": "ok"})
    
    async def _handle_get_task(self, request):
        """处理任务请求"""
        node_id = request.query.get("node_id")
        
        if node_id and node_id in self.nodes:
            node = self.nodes[node_id]
            if node.available_slots > 0:
                try:
                    task = self.pending_queue.get_nowait()
                    task.assigned_node = node_id
                    task.status = TaskStatus.RUNNING
                    task.started_at = datetime.now()
                    node.current_tasks += 1
                    return web.json_response({"task": self._task_to_dict(task)})
                except asyncio.QueueEmpty:
                    pass
        
        return web.json_response({"task": None})
    
    async def _handle_list_nodes(self, request):
        """列出所有节点"""
        nodes = [
            {
                "id": n.id,
                "address": n.address,
                "status": n.status.value,
                "available_slots": n.available_slots,
                "capabilities": n.capabilities
            }
            for n in self.nodes.values()
        ]
        return web.json_response({"nodes": nodes})
    
    async def _handle_status(self, request):
        """获取整体状态"""
        total_tasks = len(self.tasks)
        completed = sum(1 for t in self.tasks.values() if t.status == TaskStatus.COMPLETED)
        pending = sum(1 for t in self.tasks.values() if t.status == TaskStatus.PENDING)
        running = sum(1 for t in self.tasks.values() if t.status == TaskStatus.RUNNING)
        
        return web.json_response({
            "nodes_online": sum(1 for n in self.nodes.values() if n.status in [NodeStatus.ONLINE, NodeStatus.BUSY]),
            "nodes_total": len(self.nodes),
            "tasks_total": total_tasks,
            "tasks_completed": completed,
            "tasks_pending": pending,
            "tasks_running": running
        })
    
    async def _task_dispatcher(self):
        """任务分发器"""
        while self._running:
            try:
                # 等待待分发任务
                task = await asyncio.wait_for(self.pending_queue.get(), timeout=1.0)
                
                # 选择节点
                node = self._select_node(task)
                if node:
                    # 通过 HTTP 推送任务
                    await self._push_task_to_node(node, task)
                else:
                    # 无可用节点，放回队列
                    await self.pending_queue.put(task)
                    await asyncio.sleep(1)
            
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"任务分发错误: {e}")
    
    def _select_node(self, task: ScanTask) -> Optional[ScanNode]:
        """选择执行节点"""
        available = [
            n for n in self.nodes.values()
            if n.status in [NodeStatus.ONLINE, NodeStatus.BUSY]
            and n.available_slots > 0
        ]
        
        if not available:
            return None
        
        if self.config.load_balance_strategy == "round_robin":
            # 轮询
            if not hasattr(self, "_rr_index"):
                self._rr_index = 0
            node = available[self._rr_index % len(available)]
            self._rr_index += 1
            return node
        
        elif self.config.load_balance_strategy == "least_busy":
            # 最少任务
            return min(available, key=lambda n: n.current_tasks)
        
        else:
            # 随机
            import random
            return random.choice(available)
    
    async def _push_task_to_node(self, node: ScanNode, task: ScanTask):
        """推送任务到节点"""
        import aiohttp
        
        url = f"http://{node.address}/scan"
        payload = {
            "task_id": task.id,
            "target": task.target,
            "scan_type": task.scan_type,
            "params": task.params
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload, timeout=5) as resp:
                    if resp.status == 200:
                        task.assigned_node = node.id
                        task.status = TaskStatus.RUNNING
                        task.started_at = datetime.now()
                        node.current_tasks += 1
                        logger.info(f"任务 {task.id} 分发到节点 {node.id}")
                    else:
                        logger.warning(f"任务推送失败: {resp.status}")
        except Exception as e:
            logger.error(f"推送任务到节点 {node.id} 失败: {e}")
    
    async def _heartbeat_checker(self):
        """心跳检测"""
        while self._running:
            now = datetime.now()
            for node in self.nodes.values():
                elapsed = (now - node.last_heartbeat).total_seconds()
                if elapsed > self.config.heartbeat_interval * 2:
                    if node.status != NodeStatus.OFFLINE:
                        node.status = NodeStatus.OFFLINE
                        logger.warning(f"节点离线: {node.id}")
                        
                        # 重新分配该节点的任务
                        await self._reassign_node_tasks(node.id)
            
            await asyncio.sleep(self.config.heartbeat_interval)
    
    async def _reassign_node_tasks(self, node_id: str):
        """重新分配节点任务"""
        for task in self.tasks.values():
            if task.assigned_node == node_id and task.status == TaskStatus.RUNNING:
                task.status = TaskStatus.PENDING
                task.assigned_node = None
                await self.pending_queue.put(task)
                logger.info(f"任务 {task.id} 重新入队")
    
    def submit_task(
        self,
        target: str,
        scan_type: str,
        params: Dict[str, Any] = None
    ) -> str:
        """提交扫描任务"""
        task = ScanTask(
            id=str(uuid.uuid4()),
            target=target,
            scan_type=scan_type,
            params=params or {}
        )
        
        self.tasks[task.id] = task
        self.pending_queue.put_nowait(task)
        
        logger.info(f"任务提交: {task.id} - {target}")
        return task.id
    
    def submit_batch(
        self,
        targets: List[str],
        scan_type: str,
        params: Dict[str, Any] = None
    ) -> List[str]:
        """批量提交任务"""
        task_ids = []
        for target in targets:
            task_id = self.submit_task(target, scan_type, params)
            task_ids.append(task_id)
        return task_ids
    
    async def wait_task(self, task_id: str, timeout: int = None) -> ScanTask:
        """等待任务完成"""
        timeout = timeout or self.config.task_timeout
        start = time.time()
        
        while True:
            if task_id not in self.tasks:
                raise ValueError(f"未知任务: {task_id}")
            
            task = self.tasks[task_id]
            if task.status in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED]:
                return task
            
            if time.time() - start > timeout:
                raise asyncio.TimeoutError(f"任务超时: {task_id}")
            
            await asyncio.sleep(0.5)
    
    def get_task_status(self, task_id: str) -> Optional[Dict]:
        """获取任务状态"""
        if task_id not in self.tasks:
            return None
        return self._task_to_dict(self.tasks[task_id])
    
    def cancel_task(self, task_id: str) -> bool:
        """取消任务"""
        if task_id not in self.tasks:
            return False
        
        task = self.tasks[task_id]
        if task.status in [TaskStatus.PENDING, TaskStatus.RUNNING]:
            task.status = TaskStatus.CANCELLED
            logger.info(f"任务取消: {task_id}")
            return True
        return False
    
    def _task_to_dict(self, task: ScanTask) -> Dict:
        """任务转字典"""
        return {
            "id": task.id,
            "target": task.target,
            "scan_type": task.scan_type,
            "status": task.status.value,
            "assigned_node": task.assigned_node,
            "progress": task.progress,
            "vulns_found": task.vulns_found,
            "error": task.error,
            "created_at": task.created_at.isoformat(),
            "started_at": task.started_at.isoformat() if task.started_at else None,
            "completed_at": task.completed_at.isoformat() if task.completed_at else None
        }


class ScanWorker:
    """扫描工作节点"""
    
    def __init__(self, master_host: str, master_port: int, worker_port: int = 8766):
        self.master_url = f"http://{master_host}:{master_port}"
        self.worker_id = str(uuid.uuid4())
        self.worker_port = worker_port
        self.host = self._get_local_ip()
        self._running = False
        self._current_tasks = 0
        self._max_concurrent = 10
    
    def _get_local_ip(self) -> str:
        """获取本机 IP"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    async def start(self):
        """启动工作节点"""
        self._running = True
        
        # 注册到主节点
        await self._register()
        
        # 启动本地扫描服务
        asyncio.create_task(self._scan_server())
        
        # 启动任务拉取
        asyncio.create_task(self._task_puller())
        
        # 启动心跳
        asyncio.create_task(self._heartbeat_sender())
        
        logger.info(f"工作节点启动: {self.worker_id} @ {self.host}:{self.worker_port}")
    
    async def stop(self):
        """停止工作节点"""
        self._running = False
    
    async def _register(self):
        """注册到主节点"""
        import aiohttp
        
        async with aiohttp.ClientSession() as session:
            async with session.post(f"{self.master_url}/register", json={
                "id": self.worker_id,
                "host": self.host,
                "port": self.worker_port,
                "max_concurrent": self._max_concurrent,
                "capabilities": ["sqli", "xss", "ssrf", "cmdi", "xxe"]
            }) as resp:
                data = await resp.json()
                if data.get("status") == "ok":
                    logger.info("注册成功")
                else:
                    raise Exception("注册失败")
    
    async def _task_puller(self):
        """任务拉取器"""
        import aiohttp
        
        while self._running:
            if self._current_tasks >= self._max_concurrent:
                await asyncio.sleep(1)
                continue
            
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        f"{self.master_url}/task",
                        params={"node_id": self.worker_id}
                    ) as resp:
                        data = await resp.json()
                        task = data.get("task")
                        
                        if task:
                            asyncio.create_task(self._execute_task(task))
            
            except Exception as e:
                logger.error(f"拉取任务失败: {e}")
            
            await asyncio.sleep(0.5)
    
    async def _execute_task(self, task_data: Dict):
        """执行扫描任务"""
        self._current_tasks += 1
        
        task_id = task_data["id"]
        target = task_data["target"]
        scan_type = task_data["scan_type"]
        params = task_data.get("params", {})
        
        try:
            # 调用本地扫描器
            result = await self._run_scan(target, scan_type, params)
            
            # 上报结果
            await self._report_result(task_id, result)
        
        except Exception as e:
            logger.error(f"任务执行失败: {task_id} - {e}")
            await self._report_error(task_id, str(e))
        
        finally:
            self._current_tasks -= 1
    
    async def _run_scan(self, target: str, scan_type: str, params: Dict) -> Dict:
        """执行扫描"""
        # 这里应该调用实际的扫描器
        # 简化实现：模拟扫描
        await asyncio.sleep(2)
        
        return {
            "target": target,
            "scan_type": scan_type,
            "vulns_found": 0,
            "vulnerabilities": []
        }
    
    async def _report_result(self, task_id: str, result: Dict):
        """上报结果"""
        import aiohttp
        
        async with aiohttp.ClientSession() as session:
            async with session.post(f"{self.master_url}/result", json={
                "task_id": task_id,
                "success": True,
                "result": result,
                "vulns_found": result.get("vulns_found", 0)
            }) as resp:
                await resp.json()
    
    async def _report_error(self, task_id: str, error: str):
        """上报错误"""
        import aiohttp
        
        async with aiohttp.ClientSession() as session:
            async with session.post(f"{self.master_url}/result", json={
                "task_id": task_id,
                "success": False,
                "error": error
            }) as resp:
                await resp.json()
    
    async def _heartbeat_sender(self):
        """心跳发送"""
        import aiohttp
        
        while self._running:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(f"{self.master_url}/heartbeat", json={
                        "node_id": self.worker_id,
                        "current_tasks": self._current_tasks,
                        "metrics": {
                            "cpu": 0,
                            "memory": 0
                        }
                    }) as resp:
                        await resp.json()
            except Exception as e:
                logger.warning(f"心跳发送失败: {e}")
            
            await asyncio.sleep(30)
    
    async def _scan_server(self):
        """本地扫描服务（接收主节点推送）"""
        from aiohttp import web
        
        app = web.Application()
        app.router.add_post("/scan", self._handle_scan)
        
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "0.0.0.0", self.worker_port)
        await site.start()
    
    async def _handle_scan(self, request):
        """处理扫描请求"""
        data = await request.json()
        asyncio.create_task(self._execute_task(data))
        return web.json_response({"status": "accepted"})
