"""
OOB 统一管理器

提供统一的 OOB 回调验证接口，支持多种 OOB 服务提供商。
为检测模块提供简化的 OOB 检测能力。
"""

import asyncio
import logging
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from .interactsh import InteractshClient, InteractshInteraction

logger = logging.getLogger("wvs.oob.manager")


class OOBProvider(Enum):
    """OOB 服务提供商"""
    INTERACTSH = "interactsh"
    DNSLOG = "dnslog"
    CUSTOM = "custom"


@dataclass
class OOBToken:
    """OOB Token 记录"""
    token: str
    callback_url: str
    dns_url: str
    created_at: float
    context: Dict[str, Any] = field(default_factory=dict)
    checked: bool = False


@dataclass
class OOBCallback:
    """OOB 回调结果"""
    token: str
    received_at: float
    source_ip: str
    protocol: str  # dns, http, smtp
    data: str
    raw_request: str = ""


class OOBManager:
    """
    统一 OOB 验证管理器

    功能：
    - 自动注册 OOB 服务
    - 生成唯一追踪 token
    - 轮询验证回调
    - 支持批量检查

    使用示例:
        manager = OOBManager(provider="interactsh")
        await manager.initialize()

        # 生成 token 并获取回调 URL
        token = await manager.generate_token({"url": "http://target", "param": "id"})
        callback_url = manager.get_callback_url(token)

        # 注入 payload...
        # 发送带 callback_url 的请求...

        # 等待并验证回调
        callback = await manager.check_callback(token, timeout=30)
        if callback:
            print(f"收到回调: {callback.source_ip}")
    """

    def __init__(
        self,
        provider: str = "interactsh",
        server_url: Optional[str] = None,
        auto_init: bool = False,
    ):
        """
        初始化 OOB 管理器

        Args:
            provider: OOB 服务提供商 (interactsh / dnslog / custom)
            server_url: 自定义服务器地址
            auto_init: 是否在构造时自动初始化（同步模式下使用）
        """
        self.provider = OOBProvider(provider.lower())
        self.server_url = server_url

        self._client: Optional[InteractshClient] = None
        self._initialized = False
        self._domain = ""

        # 待验证的 token 池
        self._pending_tokens: Dict[str, OOBToken] = {}

        # 已收到的回调缓存
        self._callbacks: Dict[str, OOBCallback] = {}

    async def initialize(self) -> bool:
        """
        初始化 OOB 服务（注册并获取域名）

        Returns:
            是否初始化成功
        """
        if self._initialized:
            return True

        try:
            if self.provider == OOBProvider.INTERACTSH:
                self._client = InteractshClient(server_url=self.server_url)
                await self._client.register()
                self._domain = self._client.domain
                self._initialized = True
                logger.info(f"[OOB] 初始化成功: {self._domain}")
                return True

            elif self.provider == OOBProvider.DNSLOG:
                # DNSLog.cn 集成（暂未实现，使用 Interactsh 回退）
                logger.warning("[OOB] DNSLog.cn 暂未实现，使用 Interactsh")
                self._client = InteractshClient()
                await self._client.register()
                self._domain = self._client.domain
                self._initialized = True
                return True

            elif self.provider == OOBProvider.CUSTOM:
                if not self.server_url:
                    logger.error("[OOB] 自定义模式需要提供 server_url")
                    return False
                self._domain = self.server_url
                self._initialized = True
                logger.info(f"[OOB] 使用自定义 OOB 服务器: {self._domain}")
                return True

        except Exception as e:
            logger.error(f"[OOB] 初始化失败: {e}")
            return False

        return False

    async def generate_token(
        self,
        context: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        生成唯一 OOB token

        Args:
            context: 上下文信息（如 url、param、module 等）

        Returns:
            唯一 token 字符串
        """
        if not self._initialized:
            await self.initialize()

        # 生成 6 位随机 token
        token = secrets.token_urlsafe(6).lower()

        # 创建 token 记录
        oob_token = OOBToken(
            token=token,
            callback_url=self.get_callback_url(token),
            dns_url=self.get_dns_callback(token),
            created_at=time.time(),
            context=context or {},
        )

        self._pending_tokens[token] = oob_token
        logger.debug(f"[OOB] 生成 token: {token} -> {oob_token.callback_url}")

        return token

    def get_callback_url(self, token: Optional[str] = None) -> str:
        """
        获取 HTTP 回调 URL

        Args:
            token: 可选的 token

        Returns:
            回调 URL
        """
        if not self._initialized and not self._domain:
            raise RuntimeError("OOB 管理器未初始化")

        if self.provider == OOBProvider.CUSTOM:
            base = self._domain.rstrip("/")
            return f"{base}/{token}" if token else base

        # Interactsh
        if self._client:
            return self._client.get_callback_url(token)
        return f"https://{token}.{self._domain}" if token else f"https://{self._domain}"

    def get_dns_callback(self, token: Optional[str] = None) -> str:
        """
        获取 DNS 回调域名

        Args:
            token: 可选的 token

        Returns:
            DNS 回调域名
        """
        if not self._initialized and not self._domain:
            raise RuntimeError("OOB 管理器未初始化")

        if self.provider == OOBProvider.CUSTOM:
            return f"{token}.{self._domain}" if token else self._domain

        # Interactsh
        if self._client:
            return self._client.get_dns_callback(token)
        return f"{token}.{self._domain}" if token else self._domain

    async def check_callback(
        self,
        token: str,
        timeout: float = 30.0,
        poll_interval: float = 2.0,
    ) -> Optional[OOBCallback]:
        """
        检查指定 token 是否收到回调

        Args:
            token: 要检查的 token
            timeout: 超时时间（秒）
            poll_interval: 轮询间隔（秒）

        Returns:
            如果收到回调，返回 OOBCallback；否则返回 None
        """
        if not self._initialized:
            return None

        # 检查缓存
        if token in self._callbacks:
            return self._callbacks[token]

        if self._client:
            # 使用 Interactsh 客户端轮询
            interaction = await self._client.verify_token(token, timeout=timeout)
            if interaction:
                callback = self._interaction_to_callback(interaction)
                self._callbacks[token] = callback
                self._pending_tokens[token].checked = True
                return callback

        return None

    async def poll_all(
        self,
        timeout: float = 60.0,
    ) -> List[OOBCallback]:
        """
        批量检查所有待验证的 token

        Args:
            timeout: 总超时时间

        Returns:
            收到回调的列表
        """
        if not self._initialized or not self._pending_tokens:
            return []

        callbacks = []

        if self._client:
            # 获取所有回调
            interactions = await self._client.poll(timeout=timeout)

            for interaction in interactions:
                # 尝试匹配 pending tokens
                for token, oob_token in self._pending_tokens.items():
                    if token in interaction.raw_request or token in interaction.get_dns_callback():
                        callback = self._interaction_to_callback(interaction)
                        callback.token = token
                        self._callbacks[token] = callback
                        oob_token.checked = True
                        callbacks.append(callback)
                        break

        return callbacks

    def get_pending_tokens(self) -> List[OOBToken]:
        """获取所有待验证的 token"""
        return list(self._pending_tokens.values())

    def get_token_context(self, token: str) -> Optional[Dict[str, Any]]:
        """获取 token 的上下文信息"""
        oob_token = self._pending_tokens.get(token)
        return oob_token.context if oob_token else None

    def _interaction_to_callback(self, interaction: InteractshInteraction) -> OOBCallback:
        """将 Interactsh Interaction 转换为 OOBCallback"""
        return OOBCallback(
            token=interaction.token,
            received_at=interaction.timestamp,
            source_ip=interaction.remote_addr,
            protocol=interaction.protocol,
            data=interaction.raw_response or interaction.raw_request,
            raw_request=interaction.raw_request,
        )

    async def close(self):
        """关闭资源"""
        if self._client:
            await self._client.close()
            self._client = None
        self._initialized = False

    @property
    def domain(self) -> str:
        """获取回调域名"""
        return self._domain

    @property
    def is_initialized(self) -> bool:
        """是否已初始化"""
        return self._initialized
