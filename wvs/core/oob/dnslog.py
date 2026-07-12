"""
DNSLog.cn Client
================

A domestic OOB (Out-of-Band) service, suitable for scenarios where Interactsh is not accessible.

Usage:
    client = DNSLogClient()
    domain = await client.register()
    # inject domain into payload
    callbacks = await client.poll()
"""

import asyncio
import logging
import secrets
import time
from dataclasses import dataclass
from typing import List, Optional

import aiohttp

logger = logging.getLogger("wvs.oob.dnslog")


@dataclass
class DNSLogRecord:
    """DNS callback record"""

    domain: str
    ip: str
    timestamp: float
    type: str  # A, AAAA, TXT, etc.


class DNSLogClient:
    """
    DNSLog.cn Client

    Features:
    - Auto-register to obtain a domain
    - Poll DNS callback records
    - Multi-domain management

    Note:
    - DNSLog.cn is a public service and may experience delays
    - Only DNS callbacks are supported, no HTTP callbacks
    """

    # DNSLog.cn API endpoint
    API_BASE = "https://www.dnslog.cn"

    # Fallback services
    FALLBACK_SERVICES = [
        "http://ceye.io",  # requires registration
        "http://burpcollaborator.net",  # Burp Suite
    ]

    def __init__(self, timeout: int = 10):
        """
        Initialize the DNSLog client

        Args:
            timeout: Request timeout (seconds)
        """
        self.timeout = timeout
        self._domain: Optional[str] = None
        self._token: Optional[str] = None
        self._session: Optional[aiohttp.ClientSession] = None
        self._registered = False

    async def register(self) -> bool:
        """
        Register and obtain a domain

        Returns:
            Whether registration was successful
        """
        try:
            session = await self._get_session()

            # Get new domain from DNSLog.cn
            async with session.get(
                f"{self.API_BASE}/newdomain.php", timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as resp:
                if resp.status == 200:
                    data = await resp.text()
                    # Response format: domain|token
                    if "|" in data:
                        parts = data.strip().split("|")
                        self._domain = parts[0]
                        self._token = parts[1] if len(parts) > 1 else None
                        self._registered = True
                        logger.info(f"[DNSLog] Registration successful: {self._domain}")
                        return True
                    else:
                        # Possibly a plain domain
                        self._domain = data.strip()
                        self._registered = True
                        logger.info(f"[DNSLog] Registration successful (no token): {self._domain}")
                        return True

        except asyncio.TimeoutError:
            logger.exception("[DNSLog] Registration timeout")
        except Exception:
            logger.exception("[DNSLog] Registration failed")

        return False

    async def poll(self, token: str = None) -> List[DNSLogRecord]:
        """
        Poll DNS callback records

        Args:
            token: Optional token (defaults to the one from registration)

        Returns:
            List of DNS callback records
        """
        if not self._registered and not token:
            logger.warning("[DNSLog] Not registered, cannot poll")
            return []

        records = []

        try:
            session = await self._get_session()
            use_token = token or self._token

            if not use_token:
                logger.warning("[DNSLog] No token, cannot poll")
                return []

            # Get records from DNSLog.cn
            async with session.get(
                f"{self.API_BASE}/getrecords.php",
                params={"token": use_token},
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            ) as resp:
                if resp.status == 200:
                    data = await resp.text()
                    records = self._parse_records(data)

        except asyncio.TimeoutError:
            logger.warning("[DNSLog] Poll timeout")
        except Exception:
            logger.exception("[DNSLog] Poll failed")

        return records

    def _parse_records(self, data: str) -> List[DNSLogRecord]:
        """Parse DNS records"""
        records = []

        if not data or data.strip() == "":
            return records

        # DNSLog.cn format: could be JSON or plain text
        try:
            # Try JSON format
            import json

            items = json.loads(data)
            for item in items:
                records.append(
                    DNSLogRecord(
                        domain=item.get("domain", ""),
                        ip=item.get("ip", ""),
                        timestamp=time.time(),
                        type="A",
                    )
                )
        except json.JSONDecodeError:
            # Try plain text format: one record per line
            for line in data.strip().split("\n"):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        records.append(
                            DNSLogRecord(
                                domain=parts[0],
                                ip=parts[1] if len(parts) > 1 else "",
                                timestamp=time.time(),
                                type="A",
                            )
                        )

        return records

    async def verify(self, expected_subdomain: str) -> bool:
        """
        Verify whether a specific subdomain received a callback

        Args:
            expected_subdomain: The expected subdomain prefix

        Returns:
            Whether a callback was received
        """
        records = await self.poll()
        for record in records:
            if expected_subdomain in record.domain:
                logger.info(f"[DNSLog] Verification successful: {expected_subdomain}")
                return True
        return False

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create a session"""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    @property
    def domain(self) -> str:
        """Get the registered domain"""
        return self._domain or ""

    def get_dns_callback(self, subdomain: str = None) -> str:
        """
        Get the DNS callback domain

        Args:
            subdomain: Optional subdomain prefix

        Returns:
            The full DNS callback domain
        """
        if not self._domain:
            raise RuntimeError("Not registered, please call register() first")

        if subdomain:
            return f"{subdomain}.{self._domain}"
        return self._domain

    async def close(self):
        """Close the session"""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None


class DNSLogManager:
    """
    DNSLog Manager

    Provides a unified interface supporting multiple DNS callback services:
    - DNSLog.cn (default)
    - Custom service
    """

    def __init__(self, provider: str = "dnslog", custom_url: str = None):
        self.provider = provider
        self.custom_url = custom_url
        self._client: Optional[DNSLogClient] = None

    async def initialize(self) -> bool:
        """Initialize the manager"""
        if self.provider == "dnslog":
            self._client = DNSLogClient()
            return await self._client.register()
        return False

    async def generate_token(self, context: dict = None) -> str:
        """Generate a unique token"""
        return secrets.token_hex(4)

    def get_dns_callback(self, token: str = None) -> str:
        """Get the DNS callback domain"""
        if self._client:
            return self._client.get_dns_callback(token)
        raise RuntimeError("Not initialized")

    async def check_callback(self, token: str, timeout: float = 30) -> bool:
        """Check callback"""
        if self._client:
            return await self._client.verify(token)
        return False

    async def close(self):
        """Close the manager"""
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
