import redis.asyncio as redis
from typing import Optional
import json

from core.config import settings

class RedisClient:
    """Redis客户端封装"""
    def __init__(self):
        self.pool: Optional[redis.ConnectionPool] = None
        self.client: Optional[redis.Redis] = None

    async def initialize(self):
        """初始化Redis连接池"""
        self.pool = redis.ConnectionPool.from_url(
            settings.REDIS_URL,
            max_connections=settings.REDIS_POOL_SIZE,
            decode_responses=True
        )
        self.client = redis.Redis(connection_pool=self.pool)

    async def close(self):
        """关闭Redis连接"""
        if self.client:
            await self.client.aclose()
        if self.pool:
            await self.pool.disconnect()

    async def set(self, key: str, value, expire: int = None):
        """设置键值"""
        if isinstance(value, (dict, list)):
            value = json.dumps(value)
        await self.client.set(key, value, ex=expire)

    async def get(self, key: str):
        """获取值"""
        value = await self.client.get(key)
        if value:
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return value
        return None

    async def delete(self, key: str):
        """删除键"""
        await self.client.delete(key)

    async def exists(self, key: str) -> bool:
        """检查键是否存在"""
        return await self.client.exists(key) > 0

    async def incr(self, key: str) -> int:
        """递增计数器"""
        return await self.client.incr(key)

    async def decr(self, key: str) -> int:
        """递减计数器"""
        return await self.client.decr(key)

    async def lpush(self, key: str, value):
        """列表左推"""
        if isinstance(value, (dict, list)):
            value = json.dumps(value)
        await self.client.lpush(key, value)

    async def rpush(self, key: str, value):
        """列表右推"""
        if isinstance(value, (dict, list)):
            value = json.dumps(value)
        await self.client.rpush(key, value)

    async def lrange(self, key: str, start: int = 0, end: int = -1):
        """获取列表范围"""
        values = await self.client.lrange(key, start, end)
        result = []
        for v in values:
            try:
                result.append(json.loads(v))
            except json.JSONDecodeError:
                result.append(v)
        return result

    async def publish(self, channel: str, message):
        """发布消息到频道"""
        if isinstance(message, (dict, list)):
            message = json.dumps(message)
        await self.client.publish(channel, message)

    async def subscribe(self, channel: str):
        """订阅频道"""
        pubsub = self.client.pubsub()
        await pubsub.subscribe(channel)
        return pubsub

    # 扫描任务相关方法
    async def set_scan_progress(self, task_id: str, progress: float):
        """设置扫描进度"""
        await self.set(f"scan:{task_id}:progress", progress, expire=86400)

    async def get_scan_progress(self, task_id: str) -> float:
        """获取扫描进度"""
        progress = await self.get(f"scan:{task_id}:progress")
        return float(progress) if progress else 0.0

    async def set_scan_status(self, task_id: str, status: str):
        """设置扫描状态"""
        await self.set(f"scan:{task_id}:status", status, expire=86400)

    async def get_scan_status(self, task_id: str) -> str:
        """获取扫描状态"""
        status = await self.get(f"scan:{task_id}:status")
        return status if status else "unknown"

    async def add_scan_vulnerability(self, task_id: str, vuln_data: dict):
        """添加扫描漏洞"""
        key = f"scan:{task_id}:vulnerabilities"
        await self.rpush(key, vuln_data)

    async def get_scan_vulnerabilities(self, task_id: str, limit: int = 100):
        """获取扫描漏洞"""
        key = f"scan:{task_id}:vulnerabilities"
        return await self.lrange(key, 0, limit - 1)

    async def clear_scan_data(self, task_id: str):
        """清理扫描数据"""
        keys = [
            f"scan:{task_id}:progress",
            f"scan:{task_id}:status",
            f"scan:{task_id}:vulnerabilities"
        ]
        for key in keys:
            await self.delete(key)

# 全局Redis客户端实例
redis_client = RedisClient()