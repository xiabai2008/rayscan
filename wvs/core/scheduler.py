"""
RayScan priority task scheduler.

Provides a priority queue with deduplication, concurrency control,
and task status tracking for efficient scan orchestration.
"""

import asyncio
import heapq
import logging
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Dict, List, Optional

from ..models import ScanTarget

logger = logging.getLogger(__name__)


class TaskPriority(IntEnum):
    """Task priority (lower number = higher priority)"""

    CRITICAL = 0  # Confirmed vulnerability exploitation
    HIGH = 1  # SQLi, CMDi, RCE
    MEDIUM = 2  # XSS, LFI, SSRF
    LOW = 3  # Info disclosure
    BACKGROUND = 4  # Crawler, passive scanning


@dataclass(order=True)
class PrioritizedTask:
    """Prioritized task"""

    priority: int
    task_id: str = field(compare=False)
    module: str = field(compare=False)
    target: ScanTarget = field(compare=False)
    callback: Callable = field(compare=False, default=None)
    created_at: float = field(compare=False, default_factory=time.time)
    status: str = field(compare=False, default="pending")  # pending/running/completed/failed


class TaskScheduler:
    """
    Priority task scheduler

    Features:
    - Heap-based priority queue
    - Automatic concurrency control
    - Task status tracking
    - Statistics
    """

    def __init__(
        self,
        max_concurrent: int = 10,
        max_queue_size: int = 1000,
    ):
        """
        Initialize scheduler

        Args:
            max_concurrent: Maximum concurrent tasks
            max_queue_size: Maximum queue capacity
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
        Submit a task to the queue

        Args:
            task_id: Unique task ID
            module: Detection module name
            target: Scan target
            priority: Task priority
            callback: Callback function after completion

        Returns:
            Whether submission was successful
        """
        # Check if queue is full
        if len(self._queue) >= self.max_queue_size:
            logger.warning(f"[Scheduler] Queue is full, rejected task: {task_id}")
            return False

        # Check for duplicates
        if any(t.task_id == task_id for t in self._queue):
            logger.debug(f"[Scheduler] Duplicate task, skipped: {task_id}")
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

        logger.debug(f"[Scheduler] Submitted task: {task_id} (priority={priority.name})")
        return True

    def submit_batch(
        self,
        tasks: List[Dict[str, Any]],
        default_priority: TaskPriority = TaskPriority.MEDIUM,
    ) -> int:
        """
        Submit tasks in batch

        Args:
            tasks: List of tasks, each containing task_id, module, target, priority (optional)
            default_priority: Default priority

        Returns:
            Number of successfully submitted tasks
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
        Execute all tasks in the queue

        Args:
            executor: Async execution function with signature async def(task) -> result

        Returns:
            List of results from all tasks
        """
        results = []
        active_tasks = []

        while self._queue or active_tasks:
            # Take highest priority task from queue
            while self._queue and len(active_tasks) < self.max_concurrent:
                task = heapq.heappop(self._queue)
                task.status = "running"
                self._stats["pending"] = len(self._queue)

                # Create async task
                async def run_task(t=task):
                    async with self._semaphore:
                        try:
                            result = await executor(t)
                            t.status = "completed"
                            self._stats["completed"] += 1
                            return result
                        except Exception:
                            logger.exception(f"[Scheduler] Task execution failed: {t.task_id}")
                            t.status = "failed"
                            self._stats["failed"] += 1
                            return None

                async_task = asyncio.create_task(run_task(task))
                active_tasks.append(async_task)
                self._running_tasks[task.task_id] = async_task

            # Wait for any task to complete
            if active_tasks:
                done, active_tasks = await asyncio.wait(active_tasks, return_when=asyncio.FIRST_COMPLETED)

                # Collect results
                for task in done:
                    try:
                        result = task.result()
                        if result is not None:
                            results.append(result)
                    except Exception as e:
                        logger.debug(f"[Scheduler] Task exception: {e}")

                # Clean up completed tasks
                self._running_tasks = {tid: t for tid, t in self._running_tasks.items() if not t.done()}

            # Brief yield of control
            await asyncio.sleep(0.01)

        return results

    async def run_until_complete(
        self,
        executor: Callable,
        max_tasks: Optional[int] = None,
    ) -> List[Any]:
        """
        Execute tasks until a specified number is completed

        Args:
            executor: Async execution function
            max_tasks: Maximum number of tasks to execute (optional)

        Returns:
            List of results
        """
        results = []
        completed = 0

        while (max_tasks is None or completed < max_tasks) and (self._queue or self._running_tasks):
            # Take task
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
                        except Exception:
                            t.status = "failed"
                            self._stats["failed"] += 1
                            return None

                async_task = asyncio.create_task(run_task(task))
                self._running_tasks[task.task_id] = async_task

            # Wait
            if self._running_tasks:
                done, self._running_tasks = await asyncio.wait(
                    self._running_tasks.values(), return_when=asyncio.FIRST_COMPLETED
                )

                for task in done:
                    try:
                        result = task.result()
                        if result is not None:
                            results.append(result)
                        completed += 1
                    except Exception:  # noqa: S110
                        pass

        return results

    def get_stats(self) -> Dict[str, Any]:
        """Get scheduler statistics"""
        return {
            **self._stats,
            "queue_size": len(self._queue),
            "running": len(self._running_tasks),
            "max_concurrent": self.max_concurrent,
        }

    def get_pending_tasks(self) -> List[PrioritizedTask]:
        """Get list of pending tasks"""
        return list(self._queue)

    def clear(self):
        """Clear the queue"""
        self._queue.clear()
        self._stats["pending"] = 0

    def cancel_all(self):
        """Cancel all running tasks"""
        for task in self._running_tasks.values():
            task.cancel()
        self._running_tasks.clear()

    @property
    def is_empty(self) -> bool:
        """Check if queue is empty"""
        return len(self._queue) == 0 and len(self._running_tasks) == 0


# Convenience function
def create_task_for_module(
    module_name: str,
    url: str,
    params: Dict[str, Any],
    target_url: str,
) -> Dict[str, Any]:
    """
    Create a task configuration for a detection module

    Args:
        module_name: Module name (sqli, xss, cmdi, lfi, ssrf, xxe)
        url: Target URL
        params: Parameters
        target_url: Original target URL

    Returns:
        Task configuration dictionary
    """
    # Priority mapping
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
