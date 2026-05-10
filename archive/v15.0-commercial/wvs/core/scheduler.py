"""扫描调度器 - 定时任务和队列管理"""
import asyncio
import json
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
import threading
import time


@dataclass
class ScanTask:
    """扫描任务"""
    task_id: str
    target: str
    profile: str = "standard"
    config_file: Optional[str] = None
    schedule: Optional[str] = None  # cron 表达式或时间间隔
    priority: int = 5  # 1-10, 数字越小优先级越高
    created_at: str = ""
    status: str = "pending"  # pending, running, completed, failed
    result: Optional[Dict] = None
    error: Optional[str] = None
    
    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now().isoformat()


class ScanScheduler:
    """扫描调度器"""
    
    def __init__(self, max_concurrent: int = 3):
        self.max_concurrent = max_concurrent
        self.task_queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self.tasks: Dict[str, ScanTask] = {}
        self.running = False
        self.scheduler_thread = None
        self.callbacks: List[Callable] = []
        self.results_dir = Path("scan_results")
        self.results_dir.mkdir(exist_ok=True)
    
    def add_task(self, task: ScanTask) -> str:
        """添加扫描任务"""
        self.tasks[task.task_id] = task
        # 优先级队列: (priority, task_id, task)
        self.task_queue.put_nowait((task.priority, task.task_id, task))
        return task.task_id
    
    def add_callback(self, callback: Callable):
        """添加任务完成回调"""
        self.callbacks.append(callback)
    
    async def start(self):
        """启动调度器"""
        self.running = True
        
        # 启动调度循环
        while self.running:
            try:
                # 获取任务
                priority, task_id, task = await asyncio.wait_for(
                    self.task_queue.get(), timeout=1.0
                )
                
                if task.status != "pending":
                    continue
                
                # 执行任务
                await self._execute_task(task)
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                print(f"调度器错误: {e}")
    
    async def _execute_task(self, task: ScanTask):
        """执行单个任务"""
        task.status = "running"
        print(f"[调度器] 开始执行任务: {task.task_id} - {task.target}")
        
        try:
            # 导入并执行扫描
            from .config_manager import ConfigManager
            from .scanner import WVSScanner
            
            config = ConfigManager.create_scan_config(
                target=task.target,
                profile_name=task.profile,
                yaml_config=task.config_file,
            )
            
            scanner = WVSScanner(config)
            result = await scanner.scan()
            
            task.result = result
            task.status = "completed"
            
            # 保存结果
            self._save_task_result(task)
            
            print(f"[调度器] 任务完成: {task.task_id}")
            
        except Exception as e:
            task.status = "failed"
            task.error = str(e)
            print(f"[调度器] 任务失败: {task.task_id} - {e}")
        
        # 触发回调
        for callback in self.callbacks:
            try:
                callback(task)
            except Exception:
                pass
    
    def _save_task_result(self, task: ScanTask):
        """保存任务结果"""
        result_file = self.results_dir / f"{task.task_id}.json"
        with open(result_file, "w", encoding="utf-8") as f:
            json.dump(asdict(task), f, indent=2, ensure_ascii=False)
    
    def stop(self):
        """停止调度器"""
        self.running = False
    
    def get_task(self, task_id: str) -> Optional[ScanTask]:
        """获取任务状态"""
        return self.tasks.get(task_id)
    
    def list_tasks(self, status: str = None) -> List[ScanTask]:
        """列出任务"""
        tasks = list(self.tasks.values())
        if status:
            tasks = [t for t in tasks if t.status == status]
        return tasks
    
    def cancel_task(self, task_id: str) -> bool:
        """取消任务"""
        if task_id in self.tasks:
            task = self.tasks[task_id]
            if task.status == "pending":
                task.status = "cancelled"
                return True
        return False


class ScheduledScanner:
    """定时扫描器"""
    
    def __init__(self):
        self.schedules: Dict[str, Dict] = {}
        self.running = False
        self.scheduler_thread = None
    
    def add_schedule(self, schedule_id: str, target: str, 
                     interval_minutes: int = 60, profile: str = "standard"):
        """添加定时扫描"""
        self.schedules[schedule_id] = {
            "target": target,
            "interval": interval_minutes,
            "profile": profile,
            "last_run": None,
            "next_run": datetime.now(),
        }
    
    def start(self):
        """启动定时扫描"""
        self.running = True
        self.scheduler_thread = threading.Thread(target=self._scheduler_loop)
        self.scheduler_thread.daemon = True
        self.scheduler_thread.start()
    
    def _scheduler_loop(self):
        """调度循环"""
        while self.running:
            now = datetime.now()
            
            for schedule_id, schedule in self.schedules.items():
                if schedule["next_run"] <= now:
                    # 执行扫描
                    self._run_scheduled_scan(schedule_id, schedule)
                    
                    # 更新下次执行时间
                    schedule["last_run"] = now
                    schedule["next_run"] = now + timedelta(minutes=schedule["interval"])
            
            time.sleep(60)  # 每分钟检查一次
    
    def _run_scheduled_scan(self, schedule_id: str, schedule: Dict):
        """执行定时扫描"""
        print(f"[定时扫描] 执行 {schedule_id}: {schedule['target']}")
        
        # 创建异步任务执行扫描
        async def do_scan():
            from .config_manager import ConfigManager
            from .scanner import WVSScanner
            
            config = ConfigManager.create_scan_config(
                target=schedule["target"],
                profile_name=schedule["profile"],
            )
            
            scanner = WVSScanner(config)
            result = await scanner.scan()
            
            # 保存结果
            results_dir = Path("scheduled_results")
            results_dir.mkdir(exist_ok=True)
            
            result_file = results_dir / f"{schedule_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(result_file, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
        
        # 运行异步任务
        try:
            asyncio.run(do_scan())
        except Exception as e:
            print(f"[定时扫描] 失败 {schedule_id}: {e}")
    
    def stop(self):
        """停止定时扫描"""
        self.running = False
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=5)


# 全局调度器实例
scheduler = ScanScheduler()
scheduled_scanner = ScheduledScanner()
