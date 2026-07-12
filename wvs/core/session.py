"""
RayScan HTTP session manager.

- httpx.AsyncClient with connection pooling
- Retry with exponential backoff
- Intelligent rate limiting (adaptive + WAF evasion)
- Cookie persistence (encrypted session file)
- Configurable timeout and SSL verification
"""

import asyncio
import hashlib
import json
import logging
import os
import random
import time
from pathlib import Path
from typing import Any, Dict, Optional, Set
from urllib.parse import urljoin, urlparse

import httpx

from ..config import ConfigManager
from ..constants import (
    COOKIE_PLAINTEXT_PATH,
    COOKIE_STORAGE_PATH,
    DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_MAX_RPS,
    DEFAULT_RETRY_COUNT,
    DEFAULT_RETRY_DELAYS,
    DEFAULT_TIMEOUT,
    DEFAULT_VERIFY_SSL,
)
from ..exceptions import RateLimitError, RequestError, TimeoutError
from .rate_limiter import IntelligentRateLimiter

logger = logging.getLogger(__name__)


# User-Agent rotation pool — WAF evasion
UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
]


# ============================================================
# Secure Cookie Storage
# ============================================================


class SecureCookieStorage:
    """
    Encrypted Cookie storage class

    Uses Fernet symmetric encryption to protect Cookie data from sensitive information leakage.
    Keys are derived from machine-specific data, ensuring session recoverability on the same machine.
    """

    def __init__(self, storage_path: Path, legacy_path: Optional[Path] = None):
        """
        Initialize secure storage

        Args:
            storage_path: Path to encrypted storage file
            legacy_path: Path to legacy plaintext file (for migration)
        """
        self.storage_path = storage_path
        self.legacy_path = legacy_path
        self._fernet = self._init_fernet()

    def _init_fernet(self):
        """Initialize Fernet encryptor"""
        try:
            import base64
            import platform

            from cryptography.fernet import Fernet
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

            # Derive key from machine-specific data
            key_source = f"{platform.node()}-{platform.system()}-{os.environ.get('USERNAME', 'default')}"
            salt = hashlib.sha256(key_source.encode()).digest()[:16]

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(b"wvs-cookie-encryption-key"))
            return Fernet(key)

        except ImportError:
            logger.warning(
                "[Cookie] cryptography library not installed, Cookies will be stored in plaintext. Suggestion: pip install cryptography"
            )
            return None

    def save(self, cookies: Dict[str, Any]) -> None:
        """Encrypt and save Cookies"""
        try:
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)

            data = json.dumps(cookies, ensure_ascii=False, indent=2)

            if self._fernet:
                encrypted = self._fernet.encrypt(data.encode())
                self.storage_path.write_bytes(encrypted)
                logger.debug(f"[Cookie] Encrypted and saved Cookies for {len(cookies)} hosts")
            else:
                # Fallback to plaintext storage
                self.storage_path.write_text(data, encoding="utf-8")
                logger.debug(f"[Cookie] Saved Cookies in plaintext for {len(cookies)} hosts")

            # Set file permissions (Windows via hidden attribute, Linux via chmod)
            if hasattr(os, "chmod"):
                os.chmod(self.storage_path, 0o600)

        except Exception as e:
            logger.warning(f"[Cookie] Save failed: {e}")

    def load(self) -> Dict[str, Any]:
        """Load and decrypt Cookies"""
        cookies = {}

        # Try to load encrypted file
        if self.storage_path.exists():
            try:
                data = self.storage_path.read_bytes()

                if self._fernet:
                    decrypted = self._fernet.decrypt(data)
                    cookies = json.loads(decrypted.decode())
                else:
                    cookies = json.loads(data.decode())

                logger.debug(f"[Cookie] Loaded Cookies for {len(cookies)} hosts")

            except Exception as e:
                logger.debug(f"[Cookie] Failed to load encrypted file: {e}")

        # Try to migrate legacy plaintext file
        if not cookies and self.legacy_path and self.legacy_path.exists():
            cookies = self._migrate_from_plaintext()

        return cookies

    def _migrate_from_plaintext(self) -> Dict[str, Any]:
        """Migrate legacy plaintext Cookie file"""
        cookies = {}

        try:
            data = self.legacy_path.read_text(encoding="utf-8")
            cookies = json.loads(data)

            if cookies:
                # Save to new encrypted location
                self.save(cookies)

                # Create backup
                backup_path = self.legacy_path.with_suffix(".json.bak")
                self.legacy_path.rename(backup_path)

                logger.info(
                    f"[Cookie] Migrated plaintext Cookies to encrypted storage, original backed up: {backup_path}"
                )

        except Exception as e:
            logger.warning(f"[Cookie] Failed to migrate plaintext file: {e}")

        return cookies


class HTTPPool:
    """
    HTTP Session Manager

    Provides a unified asynchronous HTTP request interface with:
    - Automatic retry (exponential backoff)
    - Per-host rate limiting
    - Cookie persistence
    - Unified error handling

    Uses httpx.AsyncClient under the hood, supports HTTP/2.
    """

    def __init__(self, config: Optional[ConfigManager] = None):
        """
        Initialize HTTPPool

        Args:
            config: Config manager (reads timeout / retry_count / max_requests_per_second etc.)
        """
        self.config = config or ConfigManager()
        self._sc = None  # httpx.AsyncClient singleton

        # P8: Request-level dedup cache — avoids identical GET requests across modules
        self._request_cache: Dict[str, httpx.Response] = {}
        self._cache_hits: int = 0

        # Read parameters from config
        self.timeout = self.config.get("timeout", DEFAULT_TIMEOUT)
        self.retry_count = self.config.get("retry_count", DEFAULT_RETRY_COUNT)
        self.max_rps = self.config.get("max_requests_per_second", DEFAULT_MAX_RPS)

        # User-Agent
        self.user_agent = self.config.get(
            "user_agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        )

        # UA rotation — auto-rotate on every request (WAF evasion)
        self._ua_pool = list(UA_POOL)
        self._ua_idx = random.randint(0, len(self._ua_pool) - 1)
        self._fake_ua = None
        try:
            from fake_useragent import UserAgent

            self._fake_ua = UserAgent()
            logger.debug("[HTTPPool] fake_useragent loaded for UA rotation")
        except Exception:  # noqa: S110
            pass  # fallback to UA_POOL

        # Follow redirects
        self.follow_redirects = self.config.get("follow_redirects", True)

        # SSL verification (enabled by default)
        self.verify_ssl = self.config.get("verify_ssl", DEFAULT_VERIFY_SSL)

        # Cookie persistence path and secure storage
        self._cookie_jar: Dict[str, Dict[str, str]] = {}  # host -> {key: value}
        self._cookie_file = Path(COOKIE_STORAGE_PATH).expanduser()
        self._legacy_cookie_file = Path(COOKIE_PLAINTEXT_PATH).expanduser()
        self._cookie_storage = SecureCookieStorage(self._cookie_file, self._legacy_cookie_file)

        # Initialize intelligent rate limiter (replaces raw Semaphore)
        rate_config = {
            "max_rps": self.max_rps,
            "mode": self.config.get("rate_mode", "burst"),
            "enable_adaptive": self.config.get("enable_adaptive_rate", True),
            "enable_waf_evasion": self.config.get("enable_waf_evasion", False),
            "window_size": self.config.get("rate_window", 1.0),
            "min_rps": self.config.get("min_rps", 1),
            "recovery_rate": self.config.get("recovery_rate", 0.1),
            "backoff_factor": self.config.get("backoff_factor", 2.0),
        }
        self._rate_limiter = IntelligentRateLimiter(rate_config)

        # Request counts per host (for logging and statistics)
        self._request_counts: Dict[str, int] = {}

        # Retry backoff parameters (using constants)
        self._backoff_delays = DEFAULT_RETRY_DELAYS

        # Proxy pool (from smart-crawler concept)
        self._proxy_pool = list(self.config.get("proxy_pool", []))
        self._proxy_index = 0
        self._bad_proxies: Set[str] = set()
        self._fallback_direct = False  # all proxies failed, use direct

        # Runtime statistics
        self._stats = {
            "total_requests": 0,
            "total_errors": 0,
            "total_retries": 0,
        }

        # Load saved Cookies
        self._load_cookies()

    def mark_bad_proxy(self, proxy_url: str) -> None:
        """Mark a proxy as failed (from smart-crawler concept).
        Forces client recreation on next request."""
        self._bad_proxies.add(proxy_url)
        if self._sc is not None:
            self._sc = None  # Force recreate
            logger.info(f"[HTTPPool] Proxy marked bad: {proxy_url}, will recreate client")

    # ─────────────────────────────────────────────────────────────
    # Internal Utilities
    # ─────────────────────────────────────────────────────────────

    def _ensure_client(self) -> httpx.AsyncClient:
        """Ensure httpx.AsyncClient is initialized (lazy-loading singleton)"""
        if self._sc is None:
            # Proxy support — round-robin rotation (from smart-crawler concept)
            proxy_url = None
            if not self._fallback_direct and self._proxy_pool:
                # Find a working proxy (skip bad ones)
                working_proxies = [p for p in self._proxy_pool if p not in self._bad_proxies]
                if working_proxies:
                    proxy_url = working_proxies[self._proxy_index % len(working_proxies)]
                    self._proxy_index += 1
                else:
                    # All proxies failed — fall back to direct connection
                    self._fallback_direct = True
                    logger.warning("[HTTPPool] All proxies failed, falling back to direct connection")

            client_kwargs = dict(
                timeout=httpx.Timeout(self.timeout, connect=DEFAULT_CONNECT_TIMEOUT),
                follow_redirects=self.follow_redirects,
                verify=self.verify_ssl,
                headers={"User-Agent": self.user_agent},
                http2=False,  # HTTP/1.1 (avoid HTTP/2 cookie handling differences)
                limits=httpx.Limits(max_connections=30, max_keepalive_connections=10),
            )
            if proxy_url:
                client_kwargs["proxies"] = proxy_url
                logger.info(f"[HTTPPool] Using proxy: {proxy_url}")
            self._sc = httpx.AsyncClient(**client_kwargs)
        return self._sc

    def _get_httpx_client(self) -> httpx.AsyncClient:
        """Expose raw httpx client for auth plugin use"""
        return self._ensure_client()

    def set_cookie(self, url: str, name: str, value: str, domain: Optional[str] = None):
        """Manually inject a cookie (for session persistence after login)

        Writes directly to the httpx client's cookiejar; httpx will automatically send it in subsequent requests.
        """
        sc = self._ensure_client()
        if domain is None:
            domain = urlparse(url).netloc
        sc.cookies.set(name, value, domain=domain)

    def set_header(self, name: str, value: str):
        """Manually inject an auth header (applies to all requests)"""
        sc = self._ensure_client()
        if sc.headers is None:
            sc.headers = httpx.Headers()
        sc.headers[name] = value

    def _get_host(self, url: str) -> str:
        """Extract host from URL (for statistics)"""
        parsed = urlparse(url)
        return parsed.netloc or url

    def _rotate_ua(self) -> str:
        """Rotate User-Agent on each call — WAF evasion."""
        if self._fake_ua:
            try:
                return self._fake_ua.random
            except Exception:  # noqa: S110
                pass
        self._ua_idx = (self._ua_idx + 1) % len(self._ua_pool)
        return self._ua_pool[self._ua_idx]

    def _merge_headers(self, url: str, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        """Merge default headers and append jar cookies to the Cookie header (fixes httpx jar not auto-sending issue)"""
        headers = {"User-Agent": self._rotate_ua()}
        if kwargs.get("headers"):
            headers.update(kwargs["headers"])

        # Read cookies from httpx jar, explicitly write Cookie header as fallback
        # Note: httpx 0.28.x cookies.items() throws CookieConflict when duplicate cookies exist,
        # use list(cookies.jar) to iterate CookieJar instead, handles duplicate cookies automatically
        sc = self._ensure_client()
        cookie_parts = [f"{c.name}={c.value}" for c in list(sc.cookies.jar)]
        if cookie_parts:
            existing = headers.get("Cookie", "")
            new_cookie = "; ".join(cookie_parts)
            headers["Cookie"] = new_cookie if not existing else f"{existing}; {new_cookie}"

        kwargs["headers"] = headers
        return kwargs

    # ─────────────────────────────────────────────────────────────
    # Cookie Management
    # ─────────────────────────────────────────────────────────────

    def get_cookie(self, host: str, key: str) -> Optional[str]:
        """
        Get Cookie value for the specified host

        Args:
            host: Hostname (e.g. "example.com")
            key: Cookie name

        Returns:
            Cookie value, or None if not found
        """
        return self._cookie_jar.get(host, {}).get(key)

    def _inject_cookies(self, url: str, kwargs: Dict[str, Any]) -> None:
        """Inject persisted Cookies into the request"""
        host = self._get_host(url)
        cookies = self.get_all_cookies(host)
        if cookies:
            existing = kwargs.get("headers", {})
            cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
            existing["Cookie"] = cookie_str
            kwargs["headers"] = existing

    def _extract_response_cookies(self, url: str, response: httpx.Response) -> None:
        """Extract and persist Set-Cookie from response"""
        host = self._get_host(url)
        set_cookie = response.headers.get_list("set-cookie")
        for sc in set_cookie:
            # Simple parse: name=value; ...
            parts = sc.split(";")
            if parts:
                kv = parts[0].strip()
                if "=" in kv:
                    name, _, value = kv.partition("=")
                    self.set_cookie(host, name.strip(), value.strip())

    def _load_cookies(self) -> None:
        """Load persisted Cookies from encrypted file"""
        try:
            self._cookie_jar = self._cookie_storage.load()
            if self._cookie_jar:
                logger.debug(f"Loaded Cookies for {len(self._cookie_jar)} hosts")
        except Exception as e:
            logger.warning(f"Failed to load Cookies: {e}")

    def _save_cookies(self) -> None:
        """Encrypt and persist Cookies to file"""
        try:
            self._cookie_storage.save(self._cookie_jar)
        except Exception as e:
            logger.warning(f"Failed to save Cookies: {e}")

    # ─────────────────────────────────────────────────────────────
    # Core Request Entry Point
    # ─────────────────────────────────────────────────────────────

    async def request(self, method: str, url: str, follow_redirects=None, **kwargs) -> httpx.Response:
        """
        Unified HTTP request entry point

        Built-in:
        - retry=3 (exponential backoff 1s -> 2s -> 4s)
        - Intelligent rate limiting (IntelligentRateLimiter)
        - Automatic Cookie injection + extraction
        - P8: GET request dedup cache (reduce cross-module duplicate requests)
        - Unified error handling

        Args:
            method: HTTP method (GET / POST / PUT / DELETE etc.)
            url: Target URL
            **kwargs: Additional parameters passed to httpx

        Returns:
            httpx.Response

        Raises:
            RequestError: Request failed (status code error / connection failed)
            TimeoutError: Request timed out
            RateLimitError: Rate limited (429)
        """
        # P8: GET request dedup cache — skip identical requests across modules
        if method.upper() == "GET":
            cache_key_parts = [method.upper(), url]
            if kwargs.get("params"):
                sorted_params = tuple(sorted(kwargs["params"].items()))
                cache_key_parts.append(str(sorted_params))
            cache_key = "|".join(cache_key_parts)
            if cache_key in self._request_cache:
                self._cache_hits += 1
                return self._request_cache[cache_key]

        host = self._get_host(url)

        # Merge default headers (url used for cookie appending)
        kwargs = self._merge_headers(url, kwargs)

        # Inject WAF evasion headers (UA rotation, etc.)
        evasion_headers = self._rate_limiter.get_evasion_headers()
        if evasion_headers:
            kwargs.setdefault("headers", {}).update(evasion_headers)

        # follow_redirects override (supports crawler disabling external redirects)
        _fr = follow_redirects if follow_redirects is not None else self.follow_redirects

        # Ensure client is initialized
        sc = self._ensure_client()

        last_exc: Optional[Exception] = None

        # Handle redirects manually (avoid httpx internal redirect losing Cookie issues)
        should_follow = _fr

        for attempt in range(self.retry_count + 1):
            # ── Intelligent rate limit wait ──
            await self._rate_limiter.acquire()

            if attempt > 0:
                # Extra wait on retry to avoid immediate retry
                delay = self._backoff_delays[min(attempt - 1, len(self._backoff_delays) - 1)]
                await asyncio.sleep(delay)

            self._request_counts[host] = self._request_counts.get(host, 0) + 1
            self._stats["total_requests"] += 1

            request_start_time = time.perf_counter()

            try:
                # Always follow_redirects=False, handle redirect chain manually to preserve Cookies
                resp = await sc.request(method, url, follow_redirects=False, **kwargs)
                self._stats["total_retries"] += max(0, attempt)

                # Update rate limiter metrics
                response_time = time.perf_counter() - request_start_time
                self._rate_limiter.update_metrics(resp.status_code, response_time)

                # Handle redirects manually (same host only)
                if should_follow and resp.status_code in (301, 302, 303, 307, 308):
                    loc = resp.headers.get("location") or resp.headers.get("Location")
                    if loc:
                        final_url = urljoin(str(resp.url), loc)
                        final_parsed = urlparse(final_url)
                        # Only follow same-host redirects
                        if final_parsed.netloc == urlparse(url).netloc:
                            method = "GET" if resp.status_code in (301, 302, 303) else method
                            url = final_url
                            continue  # Retry new URL (no exception)
                        else:
                            # External redirect: stop, return redirect response (let caller handle)
                            return resp
                    else:
                        return resp

                # 4xx client errors
                if 400 <= resp.status_code < 500:
                    if resp.status_code == 429:
                        # 429 = rate limited by target site, wait longer
                        retry_after = int(resp.headers.get("retry-after", "5"))
                        logger.warning(f"Rate limited by {host}, waiting {retry_after}s")
                        await asyncio.sleep(retry_after)
                        last_exc = RateLimitError(f"Rate limited by {host}", retry_after=retry_after)
                        continue
                    else:
                        raise RequestError(
                            f"HTTP {resp.status_code}: {resp.reason_phrase}", status_code=resp.status_code, url=url
                        )

                # 5xx server errors -> retry
                if 500 <= resp.status_code < 600:
                    last_exc = RequestError(
                        f"HTTP {resp.status_code}: {resp.reason_phrase}", status_code=resp.status_code, url=url
                    )
                    if attempt < self.retry_count:
                        logger.warning(f"Server error {resp.status_code} for {url}, retrying...")
                        continue
                    raise last_exc

                # Success — cache GET responses for cross-module dedup
                if method.upper() == "GET" and resp.status_code < 400:
                    cache_key_parts = [method.upper(), url]
                    if kwargs.get("params"):
                        sorted_params = tuple(sorted(kwargs["params"].items()))
                        cache_key_parts.append(str(sorted_params))
                    self._request_cache["|".join(cache_key_parts)] = resp
                return resp

            except httpx.TimeoutException:
                # Proxy failure detection — if using a proxy, mark it and retry direct
                if not self._fallback_direct and self._proxy_pool:
                    proxy_in_use = getattr(self._sc, "_transport", None)
                    logger.warning(f"[HTTPPool] Proxy timeout on {url}, marking bad and retrying...")
                    for p in self._proxy_pool:
                        if p not in self._bad_proxies:
                            self.mark_bad_proxy(p)
                            break
                last_exc = TimeoutError(
                    f"Timeout after {self.timeout}s for {url}", timeout=float(self.timeout), url=url
                )
                if attempt < self.retry_count:
                    logger.debug(f"Timeout for {url}, retrying ({attempt + 1}/{self.retry_count})...")
                    continue
                raise last_exc

            except httpx.ConnectError as e:
                # Proxy failure detection — mark bad proxy, recreate client without it
                if not self._fallback_direct and self._proxy_pool:
                    proxy_in_use = None
                    working = [p for p in self._proxy_pool if p not in self._bad_proxies]
                    if working:
                        proxy_in_use = working[0]
                    if proxy_in_use:
                        logger.warning(f"[HTTPPool] Proxy connection failed ({proxy_in_use}), marking bad")
                        self.mark_bad_proxy(proxy_in_use)
                last_exc = RequestError(f"Connection failed for {url}: {e}", url=url)
                if attempt < self.retry_count:
                    logger.debug(f"Connect error for {url}, retrying...")
                    continue
                raise last_exc

            except Exception as e:
                self._stats["total_errors"] += 1
                raise RequestError(f"Unexpected error for {url}: {e}", url=url) from e

        # All retries exhausted
        raise last_exc or RequestError(f"All retries exhausted for {url}", url=url)

    # ─────────────────────────────────────────────────────────────
    # Convenience Methods
    # ─────────────────────────────────────────────────────────────

    async def get(self, url: str, **kwargs) -> httpx.Response:
        """
        GET request

        Args:
            url: Target URL
            **kwargs: Additional httpx parameters (params, headers, timeout, etc.)

        Returns:
            httpx.Response
        """
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> httpx.Response:
        """
        POST request

        Args:
            url: Target URL
            **kwargs: Additional httpx parameters (data, json, headers, timeout, etc.)

        Returns:
            httpx.Response
        """
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs) -> httpx.Response:
        """PUT request"""
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs) -> httpx.Response:
        """DELETE request"""
        return await self.request("DELETE", url, **kwargs)

    async def head(self, url: str, **kwargs) -> httpx.Response:
        """HEAD request (get response headers, no body)"""
        return await self.request("HEAD", url, **kwargs)

    # ─────────────────────────────────────────────────────────────
    # Rate Limiting
    # ─────────────────────────────────────────────────────────────

    async def rate_limit_wait(self, host: str) -> None:
        """
        Manually wait for the rate limit token for the specified host

        Normally not needed (request() handles it automatically).
        Useful for scenarios where you want to pre-wait before sending a request.

        Args:
            host: Hostname
        """
        sem = self._get_semaphore(host)
        await sem.acquire()
        try:
            # Empty block, acquire then immediately release
            pass
        finally:
            sem.release()

    def rate_limit_per_host(self, host: str) -> asyncio.Semaphore:
        """
        Get the rate limiter semaphore for the specified host

        For scenarios where manual concurrency control is needed.

        Args:
            host: Hostname

        Returns:
            asyncio.Semaphore
        """
        return self._get_semaphore(host)

    def get_rps(self, host: str) -> int:
        """Get the current request count for the specified host"""
        return self._request_counts.get(host, 0)

    # ─────────────────────────────────────────────────────────────
    # Lifecycle Management
    # ─────────────────────────────────────────────────────────────

    async def close(self) -> None:
        """
        Close all connections and clean up resources

        Must be called after each scan, or use the async with context manager.
        """
        if self._sc is not None:
            await self._sc.aclose()
            self._sc = None
            logger.debug("HTTPPool closed")

        # Save Cookies
        self._save_cookies()

        # Clear statistics
        self._request_counts.clear()
        self._request_cache.clear()
        self._cache_hits = 0

    def get_stats(self) -> Dict[str, Any]:
        """Get runtime statistics"""
        return {
            **self._stats,
            "active_hosts": len(self._request_counts),
            "cookie_hosts": len(self._cookie_jar),
            "cache_entries": len(self._request_cache),
            "cache_hits": self._cache_hits,
            "rate_limiter": self._rate_limiter.get_stats(),
        }

    async def __aenter__(self) -> "HTTPPool":
        """async with entry"""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """async with exit"""
        await self.close()

    def __repr__(self) -> str:
        return f"HTTPPool(timeout={self.timeout}s, retry={self.retry_count}, rps={self.max_rps}, hosts={len(self._request_counts)})"
