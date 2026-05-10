"""
DNSLog.cn 客户端
================

国内可用的 OOB (Out-of-Band) 服务，适合无法访问 Interactsh 的场景。

使用方法:
    client = DNSLogClient()
    domain = await client.register()
    # 注入 domain 到 payload
    callbacks = await client.poll()
"""
import asyncio
import logging
import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import aiohttp

logger = logging.getLogger("wvs.oob.dnslog")


@dataclass
class DNSLogRecord:
    """DNS 回调记录"""
    domain: str
    ip: str
    timestamp: float
    type: str  # A, AAAA, TXT 等


class DNSLogClient:
    """
    DNSLog.cn 客户端

    功能:
    - 自动注册获取域名
    - 轮询 DNS 回调记录
    - 支持多域名管理

    注意:
    - DNSLog.cn 是公共服务，可能有延迟
    - 不支持 HTTP 回调，仅 DNS
    """

    # DNSLog.cn API 端点
    API_BASE = "https://www.dnslog.cn"

    # 备选服务
    FALLBACK_SERVICES = [
        "http://ceye.io",  # 需要注册
        "http://burpcollaborator.net",  # Burp Suite
    ]

    def __init__(self, timeout: int = 10):
        """
        初始化 DNSLog 客户端

        Args:
            timeout: 请求超时时间（秒）
        """
        self.timeout = timeout
        self._domain: Optional[str] = None
        self._token: Optional[str] = None
        self._session: Optional[aiohttp.ClientSession] = None
        self._registered = False

    async def register(self) -> bool:
        """
        注册并获取域名

        Returns:
            是否注册成功
        """
        try:
            session = await self._get_session()

            # DNSLog.cn 获取新域名
            async with session.get(
                f"{self.API_BASE}/newdomain.php",
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as resp:
                if resp.status == 200:
                    data = await resp.text()
                    # 响应格式: domain|token
                    if "|" in data:
                        parts = data.strip().split("|")
                        self._domain = parts[0]
                        self._token = parts[1] if len(parts) > 1 else None
                        self._registered = True
                        logger.info(f"[DNSLog] 注册成功: {self._domain}")
                        return True
                    else:
                        # 可能是纯域名
                        self._domain = data.strip()
                        self._registered = True
                        logger.info(f"[DNSLog] 注册成功 (无token): {self._domain}")
                        return True

        except asyncio.TimeoutError:
            logger.error("[DNSLog] 注册超时")
        except Exception as e:
            logger.error(f"[DNSLog] 注册失败: {e}")

        return False

    async def poll(self, token: str = None) -> List[DNSLogRecord]:
        """
        轮询 DNS 回调记录

        Args:
            token: 可选的 token（默认使用注册时的）

        Returns:
            DNS 回调记录列表
        """
        if not self._registered and not token:
            logger.warning("[DNSLog] 未注册，无法轮询")
            return []

        records = []

        try:
            session = await self._get_session()
            use_token = token or self._token

            if not use_token:
                logger.warning("[DNSLog] 无 token，无法轮询")
                return []

            # DNSLog.cn 获取记录
            async with session.get(
                f"{self.API_BASE}/getrecords.php",
                params={"token": use_token},
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as resp:
                if resp.status == 200:
                    data = await resp.text()
                    records = self._parse_records(data)

        except asyncio.TimeoutError:
            logger.warning("[DNSLog] 轮询超时")
        except Exception as e:
            logger.error(f"[DNSLog] 轮询失败: {e}")

        return records

    def _parse_records(self, data: str) -> List[DNSLogRecord]:
        """解析 DNS 记录"""
        records = []

        if not data or data.strip() == "":
            return records

        # DNSLog.cn 格式: 可能是 JSON 或纯文本
        try:
            # 尝试 JSON 格式
            import json
            items = json.loads(data)
            for item in items:
                records.append(DNSLogRecord(
                    domain=item.get("domain", ""),
                    ip=item.get("ip", ""),
                    timestamp=time.time(),
                    type="A",
                ))
        except json.JSONDecodeError:
            # 尝试纯文本格式: 每行一条记录
            for line in data.strip().split("\n"):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        records.append(DNSLogRecord(
                            domain=parts[0],
                            ip=parts[1] if len(parts) > 1 else "",
                            timestamp=time.time(),
                            type="A",
                        ))

        return records

    async def verify(self, expected_subdomain: str) -> bool:
        """
        验证特定子域名是否收到回调

        Args:
            expected_subdomain: 预期的子域名部分

        Returns:
            是否收到回调
        """
        records = await self.poll()
        for record in records:
            if expected_subdomain in record.domain:
                logger.info(f"[DNSLog] 验证成功: {expected_subdomain}")
                return True
        return False

    async def _get_session(self) -> aiohttp.ClientSession:
        """获取或创建 session"""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    @property
    def domain(self) -> str:
        """获取注册的域名"""
        return self._domain or ""

    def get_dns_callback(self, subdomain: str = None) -> str:
        """
        获取 DNS 回调域名

        Args:
            subdomain: 可选的子域名前缀

        Returns:
            完整的 DNS 回调域名
        """
        if not self._domain:
            raise RuntimeError("未注册，请先调用 register()")

        if subdomain:
            return f"{subdomain}.{self._domain}"
        return self._domain

    async def close(self):
        """关闭 session"""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None


class DNSLogManager:
    """
    DNSLog 管理器

    提供统一的接口，支持多个 DNS 回调服务：
    - DNSLog.cn (默认)
    - 自定义服务
    """

    def __init__(self, provider: str = "dnslog", custom_url: str = None):
        self.provider = provider
        self.custom_url = custom_url
        self._client: Optional[DNSLogClient] = None

    async def initialize(self) -> bool:
        """初始化"""
        if self.provider == "dnslog":
            self._client = DNSLogClient()
            return await self._client.register()
        return False

    async def generate_token(self, context: dict = None) -> str:
        """生成唯一 token"""
        return secrets.token_hex(4)

    def get_dns_callback(self, token: str = None) -> str:
        """获取 DNS 回调域名"""
        if self._client:
            return self._client.get_dns_callback(token)
        raise RuntimeError("未初始化")

    async def check_callback(self, token: str, timeout: float = 30) -> bool:
        """检查回调"""
        if self._client:
            return await self._client.verify(token)
        return False

    async def close(self):
        """关闭"""
        if self._client:
            await self._client.close()


if __name__ == "__main__":
    async def test():
        client = DNSLogClient()
        if await client.register():
            print(f"Domain: {client.domain}")
            print(f"DNS callback: {client.get_dns_callback('test123')}")

            # 模拟等待回调
            print("Waiting for DNS callback...")
            await asyncio.sleep(5)

            records = await client.poll()
            print(f"Records: {len(records)}")
            for r in records:
                print(f"  {r.domain} -> {r.ip}")

        await client.close()

    asyncio.run(test())
