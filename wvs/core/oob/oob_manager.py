"""
OOB Unified Manager

Provides a unified OOB callback verification interface, supporting multiple OOB service providers.
Offers simplified OOB detection capabilities for detection modules.
"""

import logging
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from .interactsh import InteractshClient, InteractshInteraction

logger = logging.getLogger("wvs.oob.manager")


class OOBProvider(Enum):
    """OOB service provider"""

    INTERACTSH = "interactsh"
    DNSLOG = "dnslog"
    CUSTOM = "custom"


@dataclass
class OOBToken:
    """OOB Token record"""

    token: str
    callback_url: str
    dns_url: str
    created_at: float
    context: Dict[str, Any] = field(default_factory=dict)
    checked: bool = False


@dataclass
class OOBCallback:
    """OOB callback result"""

    token: str
    received_at: float
    source_ip: str
    protocol: str  # dns, http, smtp
    data: str
    raw_request: str = ""


class OOBManager:
    """
    Unified OOB verification manager

    Features:
    - Auto-register OOB service
    - Generate unique tracking tokens
    - Poll and verify callbacks
    - Batch check support

    Usage example:
        manager = OOBManager(provider="interactsh")
        await manager.initialize()

        # Generate token and get callback URL
        token = await manager.generate_token({"url": "http://target", "param": "id"})
        callback_url = manager.get_callback_url(token)

        # Inject payload...
        # Send request with callback_url...

        # Wait and verify callback
        callback = await manager.check_callback(token, timeout=30)
        if callback:
            print(f"Received callback: {callback.source_ip}")
    """

    def __init__(
        self,
        provider: str = "interactsh",
        server_url: Optional[str] = None,
        auto_init: bool = False,
    ):
        """
        Initialize the OOB manager

        Args:
            provider: OOB service provider (interactsh / dnslog / custom)
            server_url: Custom server address
            auto_init: Whether to auto-initialize on construction (used in synchronous mode)
        """
        self.provider = OOBProvider(provider.lower())
        self.server_url = server_url

        self._client: Optional[InteractshClient] = None
        self._initialized = False
        self._domain = ""

        # Pool of pending tokens to verify
        self._pending_tokens: Dict[str, OOBToken] = {}

        # Cache of received callbacks
        self._callbacks: Dict[str, OOBCallback] = {}

    async def initialize(self) -> bool:
        """
        Initialize OOB service (register and obtain domain)

        Returns:
            Whether initialization was successful
        """
        if self._initialized:
            return True

        try:
            if self.provider == OOBProvider.INTERACTSH:
                self._client = InteractshClient(server_url=self.server_url)
                await self._client.register()
                self._domain = self._client.domain
                self._initialized = True
                logger.info(f"[OOB] Initialization successful: {self._domain}")
                return True

            elif self.provider == OOBProvider.DNSLOG:
                # DNSLog.cn integration (not yet implemented, falling back to Interactsh)
                logger.warning("[OOB] DNSLog.cn not yet implemented, using Interactsh")
                self._client = InteractshClient()
                await self._client.register()
                self._domain = self._client.domain
                self._initialized = True
                return True

            elif self.provider == OOBProvider.CUSTOM:
                if not self.server_url:
                    logger.error("[OOB] Custom mode requires a server_url")
                    return False
                self._domain = self.server_url
                self._initialized = True
                logger.info(f"[OOB] Using custom OOB server: {self._domain}")
                return True

        except Exception as e:
            logger.error(f"[OOB] Initialization failed: {e}")
            return False

        return False

    async def generate_token(
        self,
        context: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Generate a unique OOB token

        Args:
            context: Contextual information (e.g. url, param, module, etc.)

        Returns:
            Unique token string
        """
        if not self._initialized:
            await self.initialize()

        # Generate a 6-character random token
        token = secrets.token_urlsafe(6).lower()

        # Create token record
        oob_token = OOBToken(
            token=token,
            callback_url=self.get_callback_url(token),
            dns_url=self.get_dns_callback(token),
            created_at=time.time(),
            context=context or {},
        )

        self._pending_tokens[token] = oob_token
        logger.debug(f"[OOB] Generated token: {token} -> {oob_token.callback_url}")

        return token

    def get_callback_url(self, token: Optional[str] = None) -> str:
        """
        Get the HTTP callback URL

        Args:
            token: Optional token

        Returns:
            Callback URL
        """
        if not self._initialized and not self._domain:
            raise RuntimeError("OOB manager not initialized")

        if self.provider == OOBProvider.CUSTOM:
            base = self._domain.rstrip("/")
            return f"{base}/{token}" if token else base

        # Interactsh
        if self._client:
            return self._client.get_callback_url(token)
        return f"https://{token}.{self._domain}" if token else f"https://{self._domain}"

    def get_dns_callback(self, token: Optional[str] = None) -> str:
        """
        Get the DNS callback domain

        Args:
            token: Optional token

        Returns:
            DNS callback domain
        """
        if not self._initialized and not self._domain:
            raise RuntimeError("OOB manager not initialized")

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
        Check whether a specific token received a callback

        Args:
            token: The token to check
            timeout: Timeout (seconds)
            poll_interval: Poll interval (seconds)

        Returns:
            OOBCallback if a callback was received, None otherwise
        """
        if not self._initialized:
            return None

        # Check cache
        if token in self._callbacks:
            return self._callbacks[token]

        if self._client:
            # Use Interactsh client to poll
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
        Batch check all pending tokens

        Args:
            timeout: Total timeout

        Returns:
            List of received callbacks
        """
        if not self._initialized or not self._pending_tokens:
            return []

        callbacks = []

        if self._client:
            # Get all interactions
            interactions = await self._client.poll(timeout=timeout)

            for interaction in interactions:
                # Try to match pending tokens
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
        """Get all pending tokens"""
        return list(self._pending_tokens.values())

    def get_token_context(self, token: str) -> Optional[Dict[str, Any]]:
        """Get the context of a token"""
        oob_token = self._pending_tokens.get(token)
        return oob_token.context if oob_token else None

    def _interaction_to_callback(self, interaction: InteractshInteraction) -> OOBCallback:
        """Convert an Interactsh Interaction to OOBCallback"""
        return OOBCallback(
            token=interaction.token,
            received_at=interaction.timestamp,
            source_ip=interaction.remote_addr,
            protocol=interaction.protocol,
            data=interaction.raw_response or interaction.raw_request,
            raw_request=interaction.raw_request,
        )

    async def close(self):
        """Close resources"""
        if self._client:
            await self._client.close()
            self._client = None
        self._initialized = False

    @property
    def domain(self) -> str:
        """Get the callback domain"""
        return self._domain

    @property
    def is_initialized(self) -> bool:
        """Whether initialized"""
        return self._initialized
