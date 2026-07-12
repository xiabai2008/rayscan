"""
Interactsh OOB Client

Interactsh is an open-source OOB data collection server supporting DNS/HTTP/SMTP callbacks.
Official server: https://interactsh.com
Self-hosted server: docker run -p 53:53 -p 80:80 -p 443:443 interactsh/interactsh-server

Usage:
    client = InteractshClient()
    token = await client.register()
    callback_url = client.get_callback_url(token)
    # inject callback_url into payload...
    interactions = await client.poll(token, timeout=30)
"""

import asyncio
import base64
import logging
import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger("wvs.oob.interactsh")


@dataclass
class InteractshInteraction:
    """Interactsh interaction record"""

    token: str
    protocol: str  # dns, http, smtp
    remote_addr: str
    timestamp: float
    raw_request: str
    raw_response: str


class InteractshClient:
    """
    Interactsh OOB Client

    Supports automatic registration, callback URL generation, and poll verification.
    """

    DEFAULT_SERVER = "https://interactsh.com"

    # List of fallback servers (used when the default server is unavailable)
    FALLBACK_SERVERS = [
        "https://interactsh.com",
        "https://oast.pro",
        "https://oast.live",
        "https://interact.online",
    ]

    def __init__(self, server_url: Optional[str] = None):
        """
        Initialize the Interactsh client

        Args:
            server_url: Interactsh server URL, defaults to the official server
        """
        self.server = server_url or self.DEFAULT_SERVER
        self._session: Optional[httpx.AsyncClient] = None

        # Credentials obtained after registration
        self._public_key: str = ""
        self._secret_key: str = ""
        self._token: str = ""
        self._domain: str = ""
        self._registered: bool = False

    async def _get_session(self) -> httpx.AsyncClient:
        """Get or create an HTTP session"""
        if self._session is None or self._session.is_closed:
            self._session = httpx.AsyncClient(
                timeout=30.0,
                follow_redirects=True,
                headers={"User-Agent": "WVS/19.0 OOB Client"},
            )
        return self._session

    async def register(self) -> str:
        """
        Register with the Interactsh server and obtain a callback domain

        Returns:
            Registration token

        Raises:
            httpx.HTTPError: Registration failed
        """
        session = await self._get_session()

        # Generate random key pair
        self._secret_key = secrets.token_hex(16)
        self._public_key = secrets.token_hex(16)
        self._token = secrets.token_urlsafe(16)

        # Build registration request
        # Interactsh protocol: publicKey is hex-encoded
        pub_key_bytes = self._public_key.encode()
        secret_key_bytes = self._secret_key.encode()

        register_data = {
            "public-key": pub_key_bytes.hex(),
            "secret-key": secret_key_bytes.hex(),
            "correlation-id": self._token,
        }

        # Try to register
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
                        logger.info(f"[OOB] Registered Interactsh: {self._domain}")
                        return self._token

            except Exception as e:
                last_error = e
                logger.debug(f"[OOB] Registration at {server} failed: {e}")
                continue

        raise RuntimeError(f"Cannot register with Interactsh server: {last_error}")

    def get_callback_url(self, token: Optional[str] = None) -> str:
        """
        Get the callback URL

        Args:
            token: Optional sub-token for distinguishing different injection points

        Returns:
            Callback URL (e.g. https://abc123.interactsh.com)
        """
        if not self._registered or not self._domain:
            raise RuntimeError("Please call register() first")

        if token:
            return f"https://{token}.{self._domain}"
        return f"https://{self._domain}"

    def get_dns_callback(self, token: Optional[str] = None) -> str:
        """
        Get the DNS callback domain

        Args:
            token: Optional sub-token

        Returns:
            DNS callback domain (e.g. abc123.interactsh.com)
        """
        if not self._registered or not self._domain:
            raise RuntimeError("Please call register() first")

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
        Poll for callback records

        Args:
            token: Optional token filter
            timeout: Poll timeout (seconds)
            poll_interval: Poll interval (seconds)

        Returns:
            List of callback records
        """
        if not self._registered:
            return []

        session = await self._get_session()
        interactions = []
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                # Build poll request
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
                            # If token is specified, filter matching records
                            if token and token not in interaction.raw_request:
                                continue
                            interactions.append(interaction)

                    if interactions:
                        return interactions

            except Exception as e:
                logger.debug(f"[OOB] Poll failed: {e}")

            await asyncio.sleep(poll_interval)

        return interactions

    def _parse_interaction(self, data: Dict[str, Any]) -> Optional[InteractshInteraction]:
        """Parse interaction data"""
        try:
            # Interactsh v2 protocol
            full_id = data.get("full-id", "") or data.get("token", "")
            protocol = data.get("protocol", "http")
            remote_addr = data.get("remote-address", "") or data.get("client_ip", "")

            # Timestamp
            ts = data.get("timestamp")
            if isinstance(ts, (int, float)):
                timestamp = float(ts)
            else:
                timestamp = time.time()

            # Raw request/response
            raw_request = data.get("raw-request", "") or data.get("request", "")
            raw_response = data.get("raw-response", "") or data.get("response", "")

            # If base64 encoded, try to decode
            if raw_request and not raw_request.startswith(("GET", "POST", "DNS")):
                try:
                    raw_request = base64.b64decode(raw_request).decode("utf-8", errors="ignore")
                except Exception:
                    logger.debug("[OOB] Failed to decode base64 interaction data", exc_info=True)

            return InteractshInteraction(
                token=full_id.split(".")[0] if full_id else "",
                protocol=protocol,
                remote_addr=remote_addr,
                timestamp=timestamp,
                raw_request=raw_request,
                raw_response=raw_response,
            )
        except Exception as e:
            logger.debug(f"[OOB] Failed to parse interaction data: {e}")
            return None

    async def verify_token(self, token: str, timeout: float = 10.0) -> Optional[InteractshInteraction]:
        """
        Verify whether a specific token received a callback

        Args:
            token: The token to verify
            timeout: Timeout

        Returns:
            Interaction object if a callback was received, None otherwise
        """
        interactions = await self.poll(token=token, timeout=timeout)
        for interaction in interactions:
            if token in interaction.raw_request or token in interaction.get_dns_callback():
                return interaction
        return None

    async def close(self):
        """Close the HTTP session"""
        if self._session and not self._session.is_closed:
            await self._session.aclose()
            self._session = None

    @property
    def domain(self) -> str:
        """Get the registered callback domain"""
        return self._domain

    @property
    def is_registered(self) -> bool:
        """Whether registered"""
        return self._registered
