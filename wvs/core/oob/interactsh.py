"""
Interactsh OOB 客户端

Interactsh 是一个开源的 OOB 数据收集服务器，支持 DNS/HTTP/SMTP 回调。
官方服务器: https://interactsh.com
自建服务器: docker run -p 53:53 -p 80:80 -p 443:443 interactsh/interactsh-server

使用方法:
    client = InteractshClient()
    token = await client.register()
    callback_url = client.get_callback_url(token)
    # 注入 callback_url 到 payload...
    interactions = await client.poll(token, timeout=30)
"""

import base64
import hashlib
import logging
import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger("wvs.oob.interactsh")


@dataclass
class InteractshInteraction:
    """Interactsh 回调记录"""
    token: str
    protocol: str  # dns, http, smtp
    remote_addr: str
    timestamp: float
    raw_request: str
    raw_response: str


class InteractshClient:
    """
    Interactsh OOB 客户端

    支持自动注册、回调 URL 生成和轮询验证。
    """

    DEFAULT_SERVER = "https://interactsh.com"

    # 备选服务器列表（当默认服务器不可用时）
    FALLBACK_SERVERS = [
        "https://interactsh.com",
        "https://oast.pro",
        "https://oast.live",
        "https://interact.online",
    ]

    def __init__(self, server_url: Optional[str] = None):
        """
        初始化 Interactsh 客户端

        Args:
            server_url: Interactsh 服务器地址，默认使用官方服务器
        """
        self.server = server_url or self.DEFAULT_SERVER
        self._session: Optional[httpx.AsyncClient] = None

        # 注册后获取的凭证
        self._public_key: str = ""
        self._secret_key: str = ""
        self._token: str = ""
        self._domain: str = ""
        self._registered: bool = False

    async def _get_session(self) -> httpx.AsyncClient:
        """获取或创建 HTTP 会话"""
        if self._session is None or self._session.is_closed:
            self._session = httpx.AsyncClient(
                timeout=30.0,
                follow_redirects=True,
                headers={"User-Agent": "WVS/19.0 OOB Client"},
            )
        return self._session

    async def register(self) -> str:
        """
        向 Interactsh 服务器注册，获取回调域名

        Returns:
            注册 token

        Raises:
            httpx.HTTPError: 注册失败
        """
        session = await self._get_session()

        # 生成随机密钥对
        self._secret_key = secrets.token_hex(16)
        self._public_key = secrets.token_hex(16)
        self._token = secrets.token_urlsafe(16)

        # 构造注册请求
        # Interactsh 协议： publicKey 以 hex 编码
        pub_key_bytes = self._public_key.encode()
        secret_key_bytes = self._secret_key.encode()

        register_data = {
            "public-key": pub_key_bytes.hex(),
            "secret-key": secret_key_bytes.hex(),
            "correlation-id": self._token,
        }

        # 尝试注册
        last_error = None
        for server in [self.server] + self.FALLBACK_SERVERS:
            try:
                resp = await session.post(
                    f"{server}/register",
                    json=register_data,
                    timeout=10.0,
                )

                if resp.status_code == 200:
                    data = resp.json()
                    self._domain = data.get("domain", "")
                    if self._domain:
                        self._registered = True
                        logger.info(f"[OOB] 已注册 Interactsh: {self._domain}")
                        return self._token

            except Exception as e:
                last_error = e
                logger.debug(f"[OOB] 注册 {server} 失败: {e}")
                continue

        raise RuntimeError(f"无法注册 Interactsh 服务器: {last_error}")

    def get_callback_url(self, token: Optional[str] = None) -> str:
        """
        获取回调 URL

        Args:
            token: 可选的子 token，用于区分不同的注入点

        Returns:
            回调 URL（如 https://abc123.interactsh.com）
        """
        if not self._registered or not self._domain:
            raise RuntimeError("请先调用 register() 注册")

        if token:
            return f"https://{token}.{self._domain}"
        return f"https://{self._domain}"

    def get_dns_callback(self, token: Optional[str] = None) -> str:
        """
        获取 DNS 回调域名

        Args:
            token: 可选的子 token

        Returns:
            DNS 回调域名（如 abc123.interactsh.com）
        """
        if not self._registered or not self._domain:
            raise RuntimeError("请先调用 register() 注册")

        if token:
            return f"{token}.{self._domain}"
        return self._domain

    async def poll(
        self,
        token: Optional[str] = None,
        timeout: float = 30.0,
        poll_interval: float = 2.0,
    ) -> List[InteractshInteraction]:
        """
        轮询获取回调记录

        Args:
            token: 可选的 token 过滤
            timeout: 轮询超时时间（秒）
            poll_interval: 轮询间隔（秒）

        Returns:
            回调记录列表
        """
        if not self._registered:
            return []

        session = await self._get_session()
        interactions = []
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                # 构造轮询请求
                poll_url = f"{self.server}/poll"
                params = {
                    "correlation-id": self._token,
                    "secret": self._secret_key,
                }

                resp = await session.get(poll_url, params=params, timeout=10.0)

                if resp.status_code == 200:
                    data = resp.json()
                    raw_interactions = data.get("interactions", []) or data.get("data", [])

                    for item in raw_interactions:
                        interaction = self._parse_interaction(item)
                        if interaction:
                            # 如果指定了 token，过滤匹配的记录
                            if token and token not in interaction.raw_request:
                                continue
                            interactions.append(interaction)

                    if interactions:
                        return interactions

            except Exception as e:
                logger.debug(f"[OOB] 轮询失败: {e}")

            await asyncio.sleep(poll_interval)

        return interactions

    def _parse_interaction(self, data: Dict[str, Any]) -> Optional[InteractshInteraction]:
        """解析回调数据"""
        try:
            # Interactsh v2 协议
            full_id = data.get("full-id", "") or data.get("token", "")
            protocol = data.get("protocol", "http")
            remote_addr = data.get("remote-address", "") or data.get("client_ip", "")

            # 时间戳
            ts = data.get("timestamp")
            if isinstance(ts, (int, float)):
                timestamp = float(ts)
            else:
                timestamp = time.time()

            # 原始请求/响应
            raw_request = data.get("raw-request", "") or data.get("request", "")
            raw_response = data.get("raw-response", "") or data.get("response", "")

            # 如果是 base64 编码，尝试解码
            if raw_request and not raw_request.startswith(("GET", "POST", "DNS")):
                try:
                    raw_request = base64.b64decode(raw_request).decode("utf-8", errors="ignore")
                except:
                    pass

            return InteractshInteraction(
                token=full_id.split(".")[0] if full_id else "",
                protocol=protocol,
                remote_addr=remote_addr,
                timestamp=timestamp,
                raw_request=raw_request,
                raw_response=raw_response,
            )
        except Exception as e:
            logger.debug(f"[OOB] 解析回调数据失败: {e}")
            return None

    async def verify_token(self, token: str, timeout: float = 10.0) -> Optional[InteractshInteraction]:
        """
        验证指定 token 是否收到回调

        Args:
            token: 要验证的 token
            timeout: 超时时间

        Returns:
            如果收到回调，返回 Interaction 对象；否则返回 None
        """
        interactions = await self.poll(token=token, timeout=timeout)
        for interaction in interactions:
            if token in interaction.raw_request or token in interaction.get_dns_callback():
                return interaction
        return None

    async def close(self):
        """关闭 HTTP 会话"""
        if self._session and not self._session.is_closed:
            await self._session.aclose()
            self._session = None

    @property
    def domain(self) -> str:
        """获取注册的回调域名"""
        return self._domain

    @property
    def is_registered(self) -> bool:
        """是否已注册"""
        return self._registered


# 导入 asyncio（模块级别需要）
import asyncio
