"""
WVS v19 优先级任务调度器
====================

提供优先级队列和智能任务调度，提高扫描效率。

功能：
- 优先级队列（heapq）
- 任务去重
- 并发控制
- 任务状态追踪
"""
import asyncio
import heapq
import logging
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Dict, List, Optional

from ..models import ScanTarget
from ..core.session import HTTPPool

logger = logging.getLogger(__name__)


class TaskPriority(IntEnum):
    """任务优先级（数字越小优先级越高）"""
    CRITICAL = 0   # 已确认漏洞的利用
    HIGH = 1       # SQLi, CMDi, RCE
    MEDIUM = 2     # XSS, LFI, SSRF
    LOW = 3        # Info disclosure
    BACKGROUND = 4 # 爬虫、被动扫描


@dataclass(order=True)
class PrioritizedTask:
    """优先级任务"""
    priority: int
    task_id: str = field(compare=False)
    module: str = field(compare=False)
    target: ScanTarget = field(compare=False)
    callback: Callable = field(compare=False, default=None)
    created_at: float = field(compare=False, default_factory=time.time)
    status: str = field(compare=False, default="pending")  # pending/running/completed/failed


class TaskScheduler:
    """
    优先级任务调度器

    特性：
    - 基于堆的优先级队列
    - 自动并发控制
    - 任务状态追踪
    - 统计信息
    """

    def __init__(
        self,
        max_concurrent: int = 10,
        max_queue_size: int = 1000,
    ):
        """
        初始化调度器

        Args:
            max_concurrent: 最大并发任务数
            max_queue_size: 队列最大容量
        """
        self.max_concurrent = max_concurrent
        self.max_queue_size = max_queue_size
        self._queue: List[PrioritizedTask] = []
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._running_tasks: Dict[str, asyncio.Task] = {}
        self._stats = {
            "submitted": 0,
            "completed": 0,
            "failed": 0,
            "pending": 0,
        }

    def submit(
        self,
        task_id: str,
        module: str,
        target: ScanTarget,
        priority: TaskPriority = TaskPriority.MEDIUM,
        callback: Optional[Callable] = None,
    ) -> bool:
        """
        提交任务到队列

        Args:
            task_id: 唯一任务 ID
            module: 检测模块名
            target: 扫描目标
            priority: 任务优先级
            callback: 完成后回调函数

        Returns:
            是否提交成功
        """
        # 检查队列是否已满
        if len(self._queue) >= self.max_queue_size:
            logger.warning(f"[Scheduler] 队列已满，拒绝任务: {task_id}")
            return False

        # 检查是否重复
        if any(t.task_id == task_id for t in self._queue):
            logger.debug(f"[Scheduler] 任务重复，跳过: {task_id}")
            return False

        task = PrioritizedTask(
            priority=priority.value,
            task_id=task_id,
            module=module,
            target=target,
            callback=callback,
        )

        heapq.heappush(self._queue, task)
        self._stats["submitted"] += 1
        self._stats["pending"] = len(self._queue)

        logger.debug(f"[Scheduler] 提交任务: {task_id} (priority={priority.name})")
        return True

    def submit_batch(
        self,
        tasks: List[Dict[str, Any]],
        default_priority: TaskPriority = TaskPriority.MEDIUM,
    ) -> int:
        """
        批量提交任务

        Args:
            tasks: 任务列表，每个元素包含 task_id, module, target, priority(可选)
            default_priority: 默认优先级

        Returns:
            成功提交的任务数
        """
        count = 0
        for task_info in tasks:
            priority = task_info.get("priority", default_priority)
            if isinstance(priority, int):
                priority = TaskPriority(priority)

            if self.submit(
                task_id=task_info["task_id"],
                module=task_info["module"],
                target=task_info["target"],
                priority=priority,
                callback=task_info.get("callback"),
            ):
                count += 1

        return count

    async def run(self, executor: Callable) -> List[Any]:
        """
        执行队列中的所有任务

        Args:
            executor: 异步执行函数，签名为 async def(task) -> result

        Returns:
            所有任务的结果列表
        """
        results = []
        active_tasks = []

        while self._queue or active_tasks:
            # 从队列取出最高优先级任务
            while self._queue and len(active_tasks) < self.max_concurrent:
                task = heapq.heappop(self._queue)
                task.status = "running"
                self._stats["pending"] = len(self._queue)

                # 创建异步任务
                async def run_task(t=task):
                    async with self._semaphore:
                        try:
                            result = await executor(t)
                            t.status = "completed"
                            self._stats["completed"] += 1
                            return result
                        except Exception as e:
                            logger.error(f"[Scheduler] 任务执行失败: {t.task_id}, {e}")
                            t.status = "failed"
                            self._stats["failed"] += 1
                            return None

                async_task = asyncio.create_task(run_task(task))
                active_tasks.append(async_task)
                self._running_tasks[task.task_id] = async_task

            # 等待任意任务完成
            if active_tasks:
                done, active_tasks = await asyncio.wait(
                    active_tasks,
                    return_when=asyncio.FIRST_COMPLETED
                )

                # 收集结果
                for task in done:
                    try:
                        result = task.result()
                        if result is not None:
                            results.append(result)
                    except Exception as e:
                        logger.debug(f"[Scheduler] 任务异常: {e}")

                # 清理已完成的任务
                self._running_tasks = {
                    tid: t for tid, t in self._running_tasks.items()
                    if not t.done()
                }

            # 短暂让出控制权
            await asyncio.sleep(0.01)

        return results

    async def run_until_complete(
        self,
        executor: Callable,
        max_tasks: Optional[int] = None,
    ) -> List[Any]:
        """
        执行任务直到完成指定数量

        Args:
            executor: 异步执行函数
            max_tasks: 最大执行任务数（可选）

        Returns:
            结果列表
        """
        results = []
        completed = 0

        while (max_tasks is None or completed < max_tasks) and (self._queue or self._running_tasks):
            # 取任务
            if self._queue:
                task = heapq.heappop(self._queue)
                task.status = "running"
                self._stats["pending"] = len(self._queue)

                async def run_task(t=task):
                    async with self._semaphore:
                        try:
                            result = await executor(t)
                            t.status = "completed"
                            self._stats["completed"] += 1
                            return result
                        except Exception as e:
                            t.status = "failed"
                            self._stats["failed"] += 1
                            return None

                async_task = asyncio.create_task(run_task(task))
                self._running_tasks[task.task_id] = async_task

            # 等待
            if self._running_tasks:
                done, self._running_tasks = await asyncio.wait(
                    self._running_tasks.values(),
                    return_when=asyncio.FIRST_COMPLETED
                )

                for task in done:
                    try:
                        result = task.result()
                        if result is not None:
                            results.append(result)
                        completed += 1
                    except Exception:
                        pass

        return results

    def get_stats(self) -> Dict[str, Any]:
        """获取调度器统计信息"""
        return {
            **self._stats,
            "queue_size": len(self._queue),
            "running": len(self._running_tasks),
            "max_concurrent": self.max_concurrent,
        }

    def get_pending_tasks(self) -> List[PrioritizedTask]:
        """获取待执行任务列表"""
        return list(self._queue)

    def clear(self):
        """清空队列"""
        self._queue.clear()
        self._stats["pending"] = 0

    def cancel_all(self):
        """取消所有运行中的任务"""
        for task in self._running_tasks.values():
            task.cancel()
        self._running_tasks.clear()

    @property
    def is_empty(self) -> bool:
        """队列是否为空"""
        return len(self._queue) == 0 and len(self._running_tasks) == 0


# 便捷函数
def create_task_for_module(
    module_name: str,
    url: str,
    params: Dict[str, Any],
    target_url: str,
) -> Dict[str, Any]:
    """
    为检测模块创建任务配置

    Args:
        module_name: 模块名 (sqli, xss, cmdi, lfi, ssrf, xxe)
        url: 目标 URL
        params: 参数
        target_url: 原始目标 URL

    Returns:
        任务配置字典
    """
    # 优先级映射
    priority_map = {
        "sqli": TaskPriority.HIGH,
        "cmdi": TaskPriority.HIGH,
        "rce": TaskPriority.HIGH,
        "xss": TaskPriority.MEDIUM,
        "lfi": TaskPriority.MEDIUM,
        "ssrf": TaskPriority.MEDIUM,
        "xxe": TaskPriority.MEDIUM,
        "sensitive": TaskPriority.LOW,
    }

    priority = priority_map.get(module_name, TaskPriority.MEDIUM)

    task_id = f"{module_name}_{url}_{params}"

    return {
        "task_id": task_id,
        "module": module_name,
        "priority": priority,
        "target": ScanTarget(
            url=target_url,
            params=params,
        ),
    }