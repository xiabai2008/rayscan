"""
HTTP Session 管理器
- httpx.AsyncClient 全局单例
- retry=3（exponential backoff: 1s → 2s → 4s）
- 智能速率限制：IntelligentRateLimiter（自适应 + WAF 规避）
- 自动跟随重定向
- Cookie 持久化（session 文件）
- 超时默认 30s
"""
import asyncio
import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import httpx

from ..config import ConfigManager
from ..constants import (
    DEFAULT_TIMEOUT, DEFAULT_CONNECT_TIMEOUT, DEFAULT_RETRY_COUNT,
    DEFAULT_MAX_RPS, DEFAULT_RETRY_DELAYS, DEFAULT_VERIFY_SSL,
    COOKIE_STORAGE_PATH, COOKIE_PLAINTEXT_PATH
)
from ..exceptions import RequestError, TimeoutError, RateLimitError
from .rate_limiter import IntelligentRateLimiter

logger = logging.getLogger(__name__)


# ============================================================
# Cookie 安全存储
# ============================================================

class SecureCookieStorage:
    """
    加密的 Cookie 存储类

    使用 Fernet 对称加密保护 Cookie 数据，防止敏感信息泄露。
    密钥从机器特定数据派生，确保同一台机器上的会话可恢复。
    """

    def __init__(self, storage_path: Path, legacy_path: Optional[Path] = None):
        """
        初始化安全存储

        Args:
            storage_path: 加密存储文件路径
            legacy_path: 旧明文文件路径（用于迁移）
        """
        self.storage_path = storage_path
        self.legacy_path = legacy_path
        self._fernet = self._init_fernet()

    def _init_fernet(self):
        """初始化 Fernet 加密器"""
        try:
            from cryptography.fernet import Fernet
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            import base64
            import platform

            # 从机器特定数据派生密钥
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
            logger.warning("[Cookie] cryptography 库未安装，Cookie 将以明文存储。建议: pip install cryptography")
            return None

    def save(self, cookies: Dict[str, Any]) -> None:
        """加密并保存 Cookie"""
        try:
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)

            data = json.dumps(cookies, ensure_ascii=False, indent=2)

            if self._fernet:
                encrypted = self._fernet.encrypt(data.encode())
                self.storage_path.write_bytes(encrypted)
                logger.debug(f"[Cookie] 已加密保存 {len(cookies)} 个 host 的 Cookie")
            else:
                # 回退到明文存储
                self.storage_path.write_text(data, encoding="utf-8")
                logger.debug(f"[Cookie] 已明文保存 {len(cookies)} 个 host 的 Cookie")

            # 设置文件权限（仅限 Windows 通过隐藏属性，Linux 通过 chmod）
            if hasattr(os, 'chmod'):
                os.chmod(self.storage_path, 0o600)

        except Exception as e:
            logger.warning(f"[Cookie] 保存失败: {e}")

    def load(self) -> Dict[str, Any]:
        """加载并解密 Cookie"""
        cookies = {}

        # 尝试加载加密文件
        if self.storage_path.exists():
            try:
                data = self.storage_path.read_bytes()

                if self._fernet:
                    decrypted = self._fernet.decrypt(data)
                    cookies = json.loads(decrypted.decode())
                else:
                    cookies = json.loads(data.decode())

                logger.debug(f"[Cookie] 已加载 {len(cookies)} 个 host 的 Cookie")

            except Exception as e:
                logger.debug(f"[Cookie] 加载加密文件失败: {e}")

        # 尝试迁移旧明文文件
        if not cookies and self.legacy_path and self.legacy_path.exists():
            cookies = self._migrate_from_plaintext()

        return cookies

    def _migrate_from_plaintext(self) -> Dict[str, Any]:
        """迁移旧明文 Cookie 文件"""
        cookies = {}

        try:
            data = self.legacy_path.read_text(encoding="utf-8")
            cookies = json.loads(data)

            if cookies:
                # 保存到新的加密位置
                self.save(cookies)

                # 创建备份
                backup_path = self.legacy_path.with_suffix(".json.bak")
                self.legacy_path.rename(backup_path)

                logger.info(f"[Cookie] 已迁移明文 Cookie 到加密存储，原文件备份: {backup_path}")

        except Exception as e:
            logger.warning(f"[Cookie] 迁移明文文件失败: {e}")

        return cookies


class HTTPPool:
    """
    HTTP Session 管理器

    提供统一的异步 HTTP 请求接口，内置：
    - 自动重试（exponential backoff）
    - per-host 速率限制
    - Cookie 持久化
    - 统一的错误处理

    使用 httpx.AsyncClient 底层实现，支持 HTTP/2。
    """

    def __init__(self, config: Optional[ConfigManager] = None):
        """
        初始化 HTTPPool

        Args:
            config: 配置管理器（从中读取 timeout / retry_count / max_requests_per_second 等）
        """
        self.config = config or ConfigManager()
        self._sc = None  # httpx.AsyncClient 单例

        # P8: Request-level dedup cache — avoids identical GET requests across modules
        self._request_cache: Dict[str, httpx.Response] = {}
        self._cache_hits: int = 0

        # 从配置读取参数
        self.timeout = self.config.get("timeout", DEFAULT_TIMEOUT)
        self.retry_count = self.config.get("retry_count", DEFAULT_RETRY_COUNT)
        self.max_rps = self.config.get("max_requests_per_second", DEFAULT_MAX_RPS)

        # User-Agent
        self.user_agent = self.config.get("user_agent", "WVS/19.0")

        # 跟随重定向
        self.follow_redirects = self.config.get("follow_redirects", True)

        # SSL 验证（默认启用）
        self.verify_ssl = self.config.get("verify_ssl", DEFAULT_VERIFY_SSL)

        # Cookie 持久化路径和安全存储
        self._cookie_jar: Dict[str, Dict[str, str]] = {}  # host -> {key: value}
        self._cookie_file = Path(COOKIE_STORAGE_PATH).expanduser()
        self._legacy_cookie_file = Path(COOKIE_PLAINTEXT_PATH).expanduser()
        self._cookie_storage = SecureCookieStorage(self._cookie_file, self._legacy_cookie_file)

        # 初始化智能限速器（替代原始 Semaphore）
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

        # 每个 host 的请求计数（用于日志和统计）
        self._request_counts: Dict[str, int] = {}

        # 重试退避参数（使用常量）
        self._backoff_delays = DEFAULT_RETRY_DELAYS

        # 运行时统计
        self._stats = {
            "total_requests": 0,
            "total_errors": 0,
            "total_retries": 0,
        }

        # 加载已保存的 Cookie
        self._load_cookies()

    # ─────────────────────────────────────────────────────────────
    # 内部工具
    # ─────────────────────────────────────────────────────────────

    def _ensure_client(self) -> httpx.AsyncClient:
        """确保 httpx.AsyncClient 已初始化（懒加载单例）"""
        if self._sc is None:
            self._sc = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout, connect=DEFAULT_CONNECT_TIMEOUT),
                follow_redirects=self.follow_redirects,
                verify=self.verify_ssl,
                headers={"User-Agent": self.user_agent},
                http2=False,  # HTTP/1.1（避免 HTTP/2 的 cookie 处理差异）
                limits=httpx.Limits(max_connections=30, max_keepalive_connections=10),
            )
        return self._sc

    def _get_httpx_client(self) -> httpx.AsyncClient:
        """暴露原始 httpx client 给 auth plugin 使用"""
        return self._ensure_client()

    def set_cookie(self, url: str, name: str, value: str, domain: Optional[str] = None):
        """手动注入 cookie（用于登录后的 session 保持）
        
        直接写入 httpx client 的 cookiejar，httpx 会在后续请求中自动发送。
        """
        sc = self._ensure_client()
        if domain is None:
            from urllib.parse import urlparse as _urlparse
            domain = _urlparse(url).netloc
        sc.cookies.set(name, value, domain=domain)

    def set_header(self, name: str, value: str):
        """手动注入 auth header（对所有请求生效）"""
        sc = self._ensure_client()
        if sc.headers is None:
            sc.headers = httpx.Headers()
        sc.headers[name] = value

    def _get_host(self, url: str) -> str:
        """从 URL 提取 host（用于统计）"""
        parsed = urlparse(url)
        return parsed.netloc or url

    def _merge_headers(self, url: str, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        """合并默认 headers，并将 jar 里的 cookies 追加到 Cookie header（解决 httpx jar 不自动发送的问题）"""
        headers = {"User-Agent": self.user_agent}
        if "headers" in kwargs and kwargs["headers"]:
            headers.update(kwargs["headers"])

        # 从 httpx jar 读 cookies，显式写 Cookie header 兜底
        # 注意：httpx 0.28.x 的 cookies.items() 在有同名 cookie 时抛 CookieConflict，
        # 改用 list(cookies.jar) 遍历 CookieJar，自动处理同名 cookie
        sc = self._ensure_client()
        cookie_parts = [f"{c.name}={c.value}" for c in list(sc.cookies.jar)]
        if cookie_parts:
            existing = headers.get("Cookie", "")
            new_cookie = "; ".join(cookie_parts)
            headers["Cookie"] = new_cookie if not existing else f"{existing}; {new_cookie}"

        kwargs["headers"] = headers
        return kwargs

    # ─────────────────────────────────────────────────────────────
    # Cookie 管理
    # ─────────────────────────────────────────────────────────────

    def get_cookie(self, host: str, key: str) -> Optional[str]:
        """
        获取指定 host 的 Cookie 值

        Args:
            host: 主机名（如 "example.com"）
            key: Cookie 名称

        Returns:
            Cookie 值，不存在返回 None
        """
        return self._cookie_jar.get(host, {}).get(key)

    def _inject_cookies(self, url: str, kwargs: Dict[str, Any]) -> None:
        """将持久化 Cookie 注入请求"""
        host = self._get_host(url)
        cookies = self.get_all_cookies(host)
        if cookies:
            existing = kwargs.get("headers", {})
            cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
            existing["Cookie"] = cookie_str
            kwargs["headers"] = existing

    def _extract_response_cookies(self, url: str, response: httpx.Response) -> None:
        """从响应中提取并持久化 Set-Cookie"""
        host = self._get_host(url)
        set_cookie = response.headers.get_list("set-cookie")
        for sc in set_cookie:
            # 简单解析：name=value; ...
            parts = sc.split(";")
            if parts:
                kv = parts[0].strip()
                if "=" in kv:
                    name, _, value = kv.partition("=")
                    self.set_cookie(host, name.strip(), value.strip())

    def _load_cookies(self) -> None:
        """从加密文件加载持久化 Cookie"""
        try:
            self._cookie_jar = self._cookie_storage.load()
            if self._cookie_jar:
                logger.debug(f"已加载 {len(self._cookie_jar)} 个 host 的 Cookie")
        except Exception as e:
            logger.warning(f"加载 Cookie 失败: {e}")

    def _save_cookies(self) -> None:
        """将 Cookie 加密后持久化到文件"""
        try:
            self._cookie_storage.save(self._cookie_jar)
        except Exception as e:
            logger.warning(f"保存 Cookie 失败: {e}")

    # ─────────────────────────────────────────────────────────────
    # 核心请求入口
    # ─────────────────────────────────────────────────────────────

    async def request(
        self,
        method: str,
        url: str,
        follow_redirects=None,
        **kwargs
    ) -> httpx.Response:
        """
        统一 HTTP 请求入口

        内置：
        - retry=3（指数退避 1s → 2s → 4s）
        - 智能速率限制（IntelligentRateLimiter）
        - Cookie 自动注入 + 提取
        - P8: GET 请求去重缓存（减少跨模块重复请求）
        - 统一错误处理

        Args:
            method: HTTP 方法（GET / POST / PUT / DELETE 等）
            url: 目标 URL
            **kwargs: 传递给 httpx 的其他参数

        Returns:
            httpx.Response

        Raises:
            RequestError: 请求失败（状态码错误 / 连接失败）
            TimeoutError: 请求超时
            RateLimitError: 速率限制（429）
        """
        # P8: GET request dedup cache — skip identical requests across modules
        if method.upper() == "GET":
            cache_key_parts = [method.upper(), url]
            if "params" in kwargs and kwargs["params"]:
                sorted_params = tuple(sorted(kwargs["params"].items()))
                cache_key_parts.append(str(sorted_params))
            cache_key = "|".join(cache_key_parts)
            if cache_key in self._request_cache:
                self._cache_hits += 1
                return self._request_cache[cache_key]

        host = self._get_host(url)

        # 合并默认 headers（url 用于 cookie 追加）
        kwargs = self._merge_headers(url, kwargs)

        # 注入 WAF 规避 headers（UA 轮换等）
        evasion_headers = self._rate_limiter.get_evasion_headers()
        if evasion_headers:
            kwargs.setdefault("headers", {}).update(evasion_headers)

        # follow_redirects 覆盖（支持爬虫禁用外部重定向）
        _fr = follow_redirects if follow_redirects is not None else self.follow_redirects

        # 确保 client 已初始化
        sc = self._ensure_client()

        last_exc: Optional[Exception] = None

        # 手动处理重定向（避免 httpx 内部重定向丢失 Cookie 问题）
        should_follow = _fr

        for attempt in range(self.retry_count + 1):
            # ── 智能速率限制等待 ──
            await self._rate_limiter.acquire()

            if attempt > 0:
                # 重试时额外等一下，避免立刻重试
                delay = self._backoff_delays[min(attempt - 1, len(self._backoff_delays) - 1)]
                await asyncio.sleep(delay)

            self._request_counts[host] = self._request_counts.get(host, 0) + 1
            self._stats["total_requests"] += 1

            request_start_time = time.perf_counter()

            try:
                # 始终 follow_redirects=False，手动处理重定向链以保留 Cookie
                resp = await sc.request(method, url, follow_redirects=False, **kwargs)
                self._stats["total_retries"] += max(0, attempt)

                # 更新限速器指标
                response_time = time.perf_counter() - request_start_time
                self._rate_limiter.update_metrics(resp.status_code, response_time)

                # 手动处理重定向（仅对同 host 跳转）
                if should_follow and resp.status_code in (301, 302, 303, 307, 308):
                    loc = resp.headers.get("location") or resp.headers.get("Location")
                    if loc:
                        from urllib.parse import urljoin
                        final_url = urljoin(str(resp.url), loc)
                        final_parsed = urlparse(final_url)
                        # 仅跟随同 host 重定向
                        if final_parsed.netloc == urlparse(url).netloc:
                            method = "GET" if resp.status_code in (301, 302, 303) else method
                            url = final_url
                            continue  # 重试新 URL（不抛异常）
                        else:
                            # 外部重定向：停止，返回重定向响应（让调用者处理）
                            return resp
                    else:
                        return resp

                # 4xx 客户端错误
                if 400 <= resp.status_code < 500:
                    if resp.status_code == 429:
                        # 429 = 被目标站点限速，等长一点再试
                        retry_after = int(resp.headers.get("retry-after", "5"))
                        logger.warning(f"Rate limited by {host}, waiting {retry_after}s")
                        await asyncio.sleep(retry_after)
                        last_exc = RateLimitError(f"Rate limited by {host}", retry_after=retry_after)
                        continue
                    else:
                        raise RequestError(
                            f"HTTP {resp.status_code}: {resp.reason_phrase}",
                            status_code=resp.status_code,
                            url=url
                        )

                # 5xx 服务端错误 → 重试
                if 500 <= resp.status_code < 600:
                    last_exc = RequestError(
                        f"HTTP {resp.status_code}: {resp.reason_phrase}",
                        status_code=resp.status_code,
                        url=url
                    )
                    if attempt < self.retry_count:
                        logger.warning(f"Server error {resp.status_code} for {url}, retrying...")
                        continue
                    raise last_exc

                # 成功 — cache GET responses for cross-module dedup
                if method.upper() == "GET" and resp.status_code < 400:
                    cache_key_parts = [method.upper(), url]
                    if "params" in kwargs and kwargs["params"]:
                        sorted_params = tuple(sorted(kwargs["params"].items()))
                        cache_key_parts.append(str(sorted_params))
                    self._request_cache["|".join(cache_key_parts)] = resp
                return resp

            except httpx.TimeoutException as e:
                last_exc = TimeoutError(f"Timeout after {self.timeout}s for {url}", timeout=float(self.timeout), url=url)
                if attempt < self.retry_count:
                    logger.debug(f"Timeout for {url}, retrying ({attempt + 1}/{self.retry_count})...")
                    continue
                raise last_exc

            except httpx.ConnectError as e:
                last_exc = RequestError(f"Connection failed for {url}: {e}", url=url)
                if attempt < self.retry_count:
                    logger.debug(f"Connect error for {url}, retrying...")
                    continue
                raise last_exc

            except Exception as e:
                self._stats["total_errors"] += 1
                raise RequestError(f"Unexpected error for {url}: {e}", url=url) from e

        # 所有重试都失败
        raise last_exc or RequestError(f"All retries exhausted for {url}", url=url)

    # ─────────────────────────────────────────────────────────────
    # 快捷方法
    # ─────────────────────────────────────────────────────────────

    async def get(self, url: str, **kwargs) -> httpx.Response:
        """
        GET 请求

        Args:
            url: 目标 URL
            **kwargs: 其他 httpx 参数（params, headers, timeout 等）

        Returns:
            httpx.Response
        """
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> httpx.Response:
        """
        POST 请求

        Args:
            url: 目标 URL
            **kwargs: 其他 httpx 参数（data, json, headers, timeout 等）

        Returns:
            httpx.Response
        """
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs) -> httpx.Response:
        """PUT 请求"""
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs) -> httpx.Response:
        """DELETE 请求"""
        return await self.request("DELETE", url, **kwargs)

    async def head(self, url: str, **kwargs) -> httpx.Response:
        """HEAD 请求（获取响应头，不读 body）"""
        return await self.request("HEAD", url, **kwargs)

    # ─────────────────────────────────────────────────────────────
    # 速率限制
    # ─────────────────────────────────────────────────────────────

    async def rate_limit_wait(self, host: str) -> None:
        """
        手动等待指定 host 的速率限制令牌

        正常情况下无需调用（request() 已自动处理）。
        适用于想在发请求前预先等待的场景。

        Args:
            host: 主机名
        """
        sem = self._get_semaphore(host)
        await sem.acquire()
        try:
            # 空块，acquire 后立即 release
            pass
        finally:
            sem.release()

    def rate_limit_per_host(self, host: str) -> asyncio.Semaphore:
        """
        获取指定 host 的速率限制信号量

        用于需要自行控制并发上限的场景。

        Args:
            host: 主机名

        Returns:
            asyncio.Semaphore
        """
        return self._get_semaphore(host)

    def get_rps(self, host: str) -> int:
        """获取指定 host 的当前请求计数"""
        return self._request_counts.get(host, 0)

    # ─────────────────────────────────────────────────────────────
    # 生命周期管理
    # ─────────────────────────────────────────────────────────────

    async def close(self) -> None:
        """
        关闭所有连接，清理资源

        每次扫描结束后必须调用，或使用 async with 上下文管理器。
        """
        if self._sc is not None:
            await self._sc.aclose()
            self._sc = None
            logger.debug("HTTPPool closed")

        # 保存 Cookie
        self._save_cookies()

        # 清空统计
        self._request_counts.clear()
        self._request_cache.clear()
        self._cache_hits = 0

    def get_stats(self) -> Dict[str, Any]:
        """获取运行时统计信息"""
        return {
            **self._stats,
            "active_hosts": len(self._request_counts),
            "cookie_hosts": len(self._cookie_jar),
            "cache_entries": len(self._request_cache),
            "cache_hits": self._cache_hits,
            "rate_limiter": self._rate_limiter.get_stats(),
        }

    async def __aenter__(self) -> "HTTPPool":
        """async with 入口"""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """async with 退出"""
        await self.close()

    def __repr__(self) -> str:
        return (
            f"HTTPPool(timeout={self.timeout}s, retry={self.retry_count}, "
            f"rps={self.max_rps}, hosts={len(self._request_counts)})"
        )
