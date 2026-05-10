"""分布式扫描模块 - 多节点协作扫描"""
import json
import asyncio
import uuid
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum


class NodeStatus(Enum):
    """节点状态"""
    ONLINE = "online"
    OFFLINE = "offline"
    BUSY = "busy"
    MAINTENANCE = "maintenance"


class TaskStatus(Enum):
    """任务状态"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ScanNode:
    """扫描节点"""
    node_id: str
    name: str
    host: str
    port: int
    status: str = "online"
    capabilities: List[str] = None
    max_concurrency: int = 50
    current_load: int = 0
    region: str = "default"
    version: str = "1.0"
    last_heartbeat: str = ""
    
    def __post_init__(self):
        if self.capabilities is None:
            self.capabilities = ["xss", "sqli", "csrf", "info"]
        if not self.last_heartbeat:
            self.last_heartbeat = datetime.now().isoformat()
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ScanTask:
    """扫描任务"""
    task_id: str
    target: str
    task_type: str = "web_scan"
    status: str = "pending"
    priority: int = 5
    assigned_node: str = ""
    created_at: str = ""
    started_at: str = ""
    completed_at: str = ""
    result: Dict = None
    error: str = ""
    
    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
        if self.result is None:
            self.result = {}
    
    def to_dict(self) -> Dict:
        return asdict(self)


class NodeManager:
    """节点管理器"""
    
    def __init__(self):
        self.nodes: Dict[str, ScanNode] = {}
        self.heartbeat_timeout = 60  # 秒
    
    def register_node(self, name: str, host: str, port: int, 
                     capabilities: List[str] = None, region: str = "default") -> ScanNode:
        """注册扫描节点"""
        node_id = f"node-{uuid.uuid4().hex[:8]}"
        
        node = ScanNode(
            node_id=node_id,
            name=name,
            host=host,
            port=port,
            capabilities=capabilities or ["xss", "sqli", "csrf"],
            region=region,
        )
        
        self.nodes[node_id] = node
        return node
    
    def unregister_node(self, node_id: str) -> bool:
        """注销节点"""
        if node_id in self.nodes:
            del self.nodes[node_id]
            return True
        return False
    
    def heartbeat(self, node_id: str) -> bool:
        """节点心跳"""
        node = self.nodes.get(node_id)
        if not node:
            return False
        
        node.last_heartbeat = datetime.now().isoformat()
        node.status = NodeStatus.ONLINE.value
        return True
    
    def get_active_nodes(self) -> List[ScanNode]:
        """获取活跃节点"""
        active = []
        now = datetime.now()
        
        for node in self.nodes.values():
            last_hb = datetime.fromisoformat(node.last_heartbeat)
            if (now - last_hb).seconds < self.heartbeat_timeout:
                if node.status == NodeStatus.ONLINE.value:
                    active.append(node)
        
        return active
    
    def get_best_node(self, required_caps: List[str] = None) -> Optional[ScanNode]:
        """获取最佳节点"""
        active = self.get_active_nodes()
        
        if not active:
            return None
        
        # 过滤具备所需能力的节点
        if required_caps:
            active = [
                n for n in active 
                if all(cap in n.capabilities for cap in required_caps)
            ]
        
        # 选择负载最低的节点
        best = min(active, key=lambda n: n.current_load / n.max_concurrency)
        return best
    
    def update_load(self, node_id: str, load: int):
        """更新节点负载"""
        node = self.nodes.get(node_id)
        if node:
            node.current_load = load


class TaskScheduler:
    """任务调度器"""
    
    def __init__(self, node_manager: NodeManager):
        self.node_manager = node_manager
        self.tasks: Dict[str, ScanTask] = {}
        self.task_queue: asyncio.Queue = asyncio.Queue()
        self.running = False
    
    def create_task(self, target: str, task_type: str = "web_scan", 
                   priority: int = 5) -> ScanTask:
        """创建扫描任务"""
        task_id = f"task-{uuid.uuid4().hex[:8]}"
        
        task = ScanTask(
            task_id=task_id,
            target=target,
            task_type=task_type,
            priority=priority,
        )
        
        self.tasks[task_id] = task
        return task
    
    async def submit_task(self, task: ScanTask):
        """提交任务到队列"""
        await self.task_queue.put(task)
        task.status = TaskStatus.PENDING.value
    
    async def start_scheduler(self):
        """启动调度器"""
        self.running = True
        
        while self.running:
            try:
                # 获取任务
                task = await asyncio.wait_for(self.task_queue.get(), timeout=1.0)
                
                # 分配节点
                node = self.node_manager.get_best_node()
                
                if not node:
                    # 没有可用节点，重新入队
                    await self.task_queue.put(task)
                    await asyncio.sleep(1)
                    continue
                
                # 分配任务
                task.assigned_node = node.node_id
                task.status = TaskStatus.RUNNING.value
                task.started_at = datetime.now().isoformat()
                
                # 更新节点负载
                self.node_manager.update_load(node.node_id, node.current_load + 1)
                
                # 异步执行任务
                asyncio.create_task(self._execute_task(task, node))
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                print(f"调度错误: {e}")
    
    async def _execute_task(self, task: ScanTask, node: ScanNode):
        """执行扫描任务"""
        try:
            # 模拟远程扫描
            await asyncio.sleep(2)
            
            # 生成模拟结果
            task.result = {
                "vulnerabilities": [
                    {"name": "XSS", "severity": "HIGH"},
                ],
                "duration": 2.0,
            }
            task.status = TaskStatus.COMPLETED.value
            
        except Exception as e:
            task.error = str(e)
            task.status = TaskStatus.FAILED.value
        
        finally:
            task.completed_at = datetime.now().isoformat()
            # 释放节点负载
            self.node_manager.update_load(
                node.node_id, 
                max(0, node.current_load - 1)
            )
    
    def stop_scheduler(self):
        """停止调度器"""
        self.running = False
    
    def get_task_status(self, task_id: str) -> Optional[Dict]:
        """获取任务状态"""
        task = self.tasks.get(task_id)
        if task:
            return task.to_dict()
        return None
    
    def list_tasks(self, status: str = None) -> List[Dict]:
        """列出任务"""
        tasks = list(self.tasks.values())
        
        if status:
            tasks = [t for t in tasks if t.status == status]
        
        return [t.to_dict() for t in tasks]


class DistributedScanner:
    """分布式扫描器"""
    
    def __init__(self):
        self.node_manager = NodeManager()
        self.task_scheduler = TaskScheduler(self.node_manager)
    
    async def scan(self, targets: List[str], 
                   task_type: str = "web_scan") -> List[Dict]:
        """分布式扫描多个目标"""
        # 创建任务
        tasks = []
        for target in targets:
            task = self.task_scheduler.create_task(target, task_type)
            tasks.append(task)
            await self.task_scheduler.submit_task(task)
        
        # 等待所有任务完成
        while True:
            all_done = all(
                t.status in [TaskStatus.COMPLETED.value, TaskStatus.FAILED.value]
                for t in tasks
            )
            if all_done:
                break
            await asyncio.sleep(0.5)
        
        # 收集结果
        results = []
        for task in tasks:
            results.append({
                "target": task.target,
                "status": task.status,
                "result": task.result,
                "error": task.error,
            })
        
        return results
    
    def get_cluster_status(self) -> Dict:
        """获取集群状态"""
        active_nodes = self.node_manager.get_active_nodes()
        all_tasks = self.task_scheduler.list_tasks()
        
        pending = len([t for t in all_tasks if t["status"] == TaskStatus.PENDING.value])
        running = len([t for t in all_tasks if t["status"] == TaskStatus.RUNNING.value])
        completed = len([t for t in all_tasks if t["status"] == TaskStatus.COMPLETED.value])
        failed = len([t for t in all_tasks if t["status"] == TaskStatus.FAILED.value])
        
        return {
            "nodes": {
                "total": len(self.node_manager.nodes),
                "active": len(active_nodes),
            },
            "tasks": {
                "pending": pending,
                "running": running,
                "completed": completed,
                "failed": failed,
                "total": len(all_tasks),
            },
            "load": sum(n.current_load for n in active_nodes),
            "capacity": sum(n.max_concurrency for n in active_nodes),
        }


# 全局分布式扫描器
distributed_scanner = DistributedScanner()
