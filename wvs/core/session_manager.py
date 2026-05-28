"""
RayScan 1.0.2 — Session lifecycle manager

Handles:
- Session health monitoring (cookie expiry, redirect to login)
- Auto re-authentication when session expires
- Session state persistence across scan
- CSRF token refresh across multi-step flows
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)


@dataclass
class SessionState:
    host: str
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    csrf_token: Optional[str] = None
    csrf_token_name: Optional[str] = None
    last_verified: float = 0.0
    authenticated: bool = False
    expires_at: float = float("inf")
    consecutive_failures: int = 0


class SessionManager:
    """Manages session lifecycle including health checks and auto-reauth."""

    def __init__(
        self,
        health_check_url: Optional[str] = None,
        health_check_interval: float = 60.0,
        max_consecutive_failures: int = 3,
    ):
        self._sessions: Dict[str, SessionState] = {}
        self._auth_providers: Dict[str, Callable] = {}  # host -> reauth coroutine
        self.health_check_url = health_check_url
        self.health_check_interval = health_check_interval
        self.max_consecutive_failures = max_consecutive_failures
        self._lock = asyncio.Lock()

    def register_session(
        self,
        host: str,
        cookies: Dict[str, str],
        headers: Optional[Dict[str, str]] = None,
        authenticated: bool = True,
        session_duration: float = 3600.0,
    ):
        state = SessionState(
            host=host,
            cookies=cookies.copy(),
            headers=(headers or {}).copy(),
            last_verified=time.time(),
            authenticated=authenticated,
            expires_at=time.time() + session_duration if session_duration else float("inf"),
        )
        self._sessions[host] = state
        logger.debug(f"[Session] registered {host}: {len(cookies)} cookies, authenticated={authenticated}")

    def register_auth_provider(self, host: str, provider: Callable):
        """Register a coroutine that re-authenticates and returns new cookies."""
        self._auth_providers[host] = provider

    def get_cookies(self, host: str) -> Dict[str, str]:
        state = self._sessions.get(host)
        return state.cookies.copy() if state else {}

    def get_headers(self, host: str) -> Dict[str, str]:
        state = self._sessions.get(host)
        return state.headers.copy() if state else {}

    def get_csrf_token(self, host: str) -> Optional[tuple]:
        """Returns (token_name, token_value) or None."""
        state = self._sessions.get(host)
        if state and state.csrf_token:
            return (state.csrf_token_name, state.csrf_token)
        return None

    def update_csrf_token(self, host: str, token_name: str, token_value: str):
        state = self._sessions.get(host)
        if state:
            state.csrf_token_name = token_name
            state.csrf_token = token_value
            state.last_verified = time.time()

    async def check_health(self, host: str, client: httpx.AsyncClient) -> bool:
        """Check if the session is still valid."""
        state = self._sessions.get(host)
        if not state or not state.authenticated:
            return False

        # Skip if recently verified
        if time.time() - state.last_verified < self.health_check_interval:
            return True

        # Check expiry
        if time.time() > state.expires_at:
            logger.info(f"[Session] {host} session expired")
            state.authenticated = False
            return False

        if not self.health_check_url:
            # No health check URL configured, assume valid
            state.last_verified = time.time()
            return True

        try:
            resp = await client.get(
                self.health_check_url,
                cookies=state.cookies,
                headers=state.headers,
                follow_redirects=False,
                timeout=10.0,
            )
            # If redirected to login page, session is dead
            if resp.status_code in (301, 302):
                location = resp.headers.get("location", "").lower()
                if any(kw in location for kw in ("login", "signin", "auth")):
                    logger.info(f"[Session] {host} redirected to login — session expired")
                    state.authenticated = False
                    return False

            state.authenticated = True
            state.last_verified = time.time()
            state.consecutive_failures = 0
            return True

        except Exception as e:
            logger.debug(f"[Session] health check failed {host}: {e}")
            state.consecutive_failures += 1
            if state.consecutive_failures >= self.max_consecutive_failures:
                state.authenticated = False
            return state.authenticated

    async def ensure_authenticated(self, host: str, client: httpx.AsyncClient) -> Dict[str, str]:
        """Ensure session is authenticated; re-authenticate if needed."""
        is_healthy = await self.check_health(host, client)
        if is_healthy:
            return self.get_cookies(host)

        # Try re-authentication
        provider = self._auth_providers.get(host)
        if not provider:
            logger.warning(f"[Session] no reauth provider for {host}")
            return self.get_cookies(host)

        try:
            logger.info(f"[Session] re-authenticating {host}...")
            result = await provider()
            if isinstance(result, dict) and result.get("authenticated"):
                new_cookies = result.get("cookies", {})
                new_headers = result.get("headers", {})
                state = self._sessions.get(host)
                if state:
                    state.cookies.update(new_cookies)
                    state.headers.update(new_headers)
                    state.authenticated = True
                    state.last_verified = time.time()
                    state.consecutive_failures = 0
                    state.expires_at = time.time() + 3600
                logger.info(f"[Session] {host} re-auth OK: {len(new_cookies)} cookies")
            else:
                logger.warning(f"[Session] re-auth failed for {host}")
        except Exception as e:
            logger.exception(f"[Session] re-auth error {host}")

        return self.get_cookies(host)

    async def extract_csrf_from_page(
        self,
        host: str,
        client: httpx.AsyncClient,
        url: str,
        csrf_names: Optional[List[str]] = None,
    ) -> Optional[str]:
        """Extract CSRF token from a page."""
        default_names = ["csrf_token", "_csrf", "csrf", "xsrf_token", "_token", "authenticity_token", "user_token", "nonce", "_wpnonce"]
        names = csrf_names or default_names

        try:
            resp = await client.get(url, follow_redirects=True, timeout=10.0)
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(resp.text, "lxml")

            for name in names:
                # Try input with matching name
                elem = soup.find("input", {"name": name})
                if elem and elem.get("value"):
                    self.update_csrf_token(host, name, elem["value"])
                    return elem["value"]
                # Try meta tag
                meta = soup.find("meta", {"name": name})
                if meta and meta.get("content"):
                    self.update_csrf_token(host, name, meta["content"])
                    return meta["content"]

        except Exception as e:
            logger.debug(f"[Session] CSRF extraction failed {url}: {e}")

        return None

    def is_authenticated(self, host: str) -> bool:
        state = self._sessions.get(host)
        return state is not None and state.authenticated

    def get_state(self, host: str) -> Optional[SessionState]:
        return self._sessions.get(host)

    def remove_session(self, host: str):
        self._sessions.pop(host, None)
        self._auth_providers.pop(host, None)

    def get_stats(self) -> Dict[str, Any]:
        return {
            "active_sessions": len(self._sessions),
            "authenticated": sum(1 for s in self._sessions.values() if s.authenticated),
            "hosts": list(self._sessions.keys()),
        }
