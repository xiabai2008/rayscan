"""轻量被动扫描 MITM 代理 (Phase 1: --proxy)。

设计:
- 基于 asyncio + http 原始解析,零第三方依赖(避免引入 mitmproxy 重依赖)
- 拦截经过代理的 HTTP/HTTPS-CONNECT 请求,解析出端点 → 注入检测管线
- 仅做"流量 → 检测"单向:转发请求原样返回,不缓存、不重放
- 结果 source="passive",可合并去重

用法(CLI):
    rayscan passive --listen 127.0.0.1:8081 [--target example.com] [--all-modules]
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

logger = logging.getLogger(__name__)


@dataclass
class PassiveScanResult:
    """被动扫描运行结果。"""

    requests_captured: int = 0
    endpoints_discovered: int = 0
    requests_scanned: int = 0
    vulnerabilities: List[Any] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "requests_captured": self.requests_captured,
            "endpoints_discovered": self.endpoints_discovered,
            "requests_scanned": self.requests_scanned,
            "vulnerabilities": [v.to_dict() if hasattr(v, "to_dict") else str(v) for v in self.vulnerabilities],
            "errors": self.errors,
        }


class PassiveProxy:
    """异步 HTTP 代理,捕获流量并交给扫描回调。

    线程模型:单事件循环内 asyncio server;每个连接一个 handler。
    目标过滤:若指定 target,仅检测请求 Host 属于该目标域名的流量,
    其余请求透明转发不检测(避免误扫第三方)。
    """

    def __init__(
        self,
        scan_callback=None,
        target_filter: Optional[str] = None,
        listen_host: str = "127.0.0.1",
        listen_port: int = 8081,
        buffer_size: int = 65536,
    ):
        self.scan_callback = scan_callback  # async callable(endpoint_dict) -> List[vuln]
        self.target_filter = target_filter
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.buffer_size = buffer_size
        self.result = PassiveScanResult()
        self._server: Optional[asyncio.AbstractServer] = None

    # ─────────────────────────────────────────────────────────────
    # 生命周期
    # ─────────────────────────────────────────────────────────────

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle_connection, self.listen_host, self.listen_port)
        host, port = self._server.sockets[0].getsockname()
        logger.info("[Passive] 代理已启动: http://%s:%s (Ctrl+C 停止)", host, port)
        if self.target_filter:
            logger.info("[Passive] 仅检测目标域: %s (其余流量透明转发)", self.target_filter)

    async def serve_forever(self) -> None:
        if not self._server:
            await self.start()
        async with self._server:
            await self._server.serve_forever()

    async def close(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    # ─────────────────────────────────────────────────────────────
    # 连接处理
    # ─────────────────────────────────────────────────────────────

    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            # 读取请求行 + 请求头
            request_line = await reader.readline()
            if not request_line:
                writer.close()
                return
            headers: Dict[str, str] = {}
            while True:
                line = await reader.readline()
                if line in (b"\r\n", b"\n", b""):
                    break
                if b":" in line:
                    k, _, v = line.decode("utf-8", errors="replace").partition(":")
                    headers[k.strip().lower()] = v.strip()

            try:
                method, raw_url, _ = request_line.decode("utf-8", errors="replace").strip().split(" ", 2)
            except ValueError:
                writer.close()
                return

            # HTTPS CONNECT:仅建立隧道(不检测加密流量,避免 MITM 复杂度)
            if method.upper() == "CONNECT":
                await self._handle_connect(reader, writer)
                return

            # 读取请求体(POST 场景)
            content_length = int(headers.get("content-length", "0") or 0)
            body = b""
            if content_length > 0:
                body = await reader.read(min(content_length, self.buffer_size))

            # 解析 URL
            parsed = urlparse(raw_url)
            host = headers.get("host", parsed.netloc or "")
            full_url = f"{parsed.scheme or 'http'}://{host}{parsed.path or '/'}"
            if parsed.query:
                full_url += f"?{parsed.query}"

            self.result.requests_captured += 1

            # 目标过滤:非目标域仅透明转发
            if self.target_filter and not self._host_matches(host, self.target_filter):
                await self._relay_plain(method, full_url, headers, body, reader, writer)
                return

            # 构造端点 → 交给扫描回调(不阻塞转发)
            endpoint = self._build_endpoint(method, full_url, parsed, body, headers)
            if endpoint:
                self.result.endpoints_discovered += 1
                if self.scan_callback:
                    try:
                        vulns = await self.scan_callback(endpoint)
                        if vulns:
                            self.result.vulnerabilities.extend(vulns)
                            self.result.requests_scanned += 1
                    except Exception as e:  # noqa: BLE001
                        self.result.errors.append(str(e))
                        logger.debug("[Passive] 扫描端点失败: %s", e)

            # 透明转发原请求
            await self._relay_plain(method, full_url, headers, body, reader, writer)

        except asyncio.CancelledError:
            pass
        except Exception as e:  # noqa: BLE001
            logger.debug("[Passive] 连接处理异常: %s", e)
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass

    async def _handle_connect(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """CONNECT 隧道:响应 200 后建立双向转发(HTTPS 流量不检测)。"""
        try:
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()

            async def _pipe(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
                try:
                    while True:
                        data = await r.read(self.buffer_size)
                        if not data:
                            break
                        w.write(data)
                        await w.drain()
                except Exception:  # noqa: BLE001
                    pass
                finally:
                    try:
                        w.close()
                    except Exception:  # noqa: BLE001
                        pass

            await asyncio.gather(_pipe(reader, writer), _pipe(writer, reader))
        except Exception as e:  # noqa: BLE001
            logger.debug("[Passive] CONNECT 隧道异常: %s", e)
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass

    # ─────────────────────────────────────────────────────────────
    # 转发
    # ─────────────────────────────────────────────────────────────

    async def _relay_plain(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: bytes,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """透明转发:连接上游,原样转发请求并回传响应。"""
        parsed = urlparse(url)
        host = parsed.hostname or "localhost"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        try:
            up_reader, up_writer = await asyncio.open_connection(host, port)
            try:
                request_target = parsed.path or "/"
                if parsed.query:
                    request_target += f"?{parsed.query}"
                head = f"{method} {request_target} HTTP/1.1\r\n"
                for k, v in headers.items():
                    head += f"{k}: {v}\r\n"
                head += "\r\n"
                up_writer.write(head.encode("utf-8", errors="replace") + body)
                await up_writer.drain()
                while True:
                    data = await up_reader.read(self.buffer_size)
                    if not data:
                        break
                    writer.write(data)
                    await writer.drain()
            finally:
                up_writer.close()
                try:
                    await up_writer.wait_closed()
                except Exception:  # noqa: BLE001
                    pass
        except Exception as e:  # noqa: BLE001
            logger.debug("[Passive] 转发失败: %s", e)
            try:
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                await writer.drain()
            except Exception:  # noqa: BLE001
                pass
        finally:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass

    # ─────────────────────────────────────────────────────────────
    # 辅助
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def _host_matches(host: str, target: str) -> bool:
        """判断请求 Host 是否属于目标域(支持子域)。"""
        target = target.lower().rstrip(".").lstrip("www.")
        h = host.lower().split(":")[0].rstrip(".").lstrip("www.")
        return h == target or h.endswith("." + target)

    def _build_endpoint(self, method: str, full_url: str, parsed, body: bytes, headers: Dict[str, str]):
        """从捕获请求构造检测端点(与 crawler 的 DiscoveredEndpoint 同构)。"""
        from ..crawler import DiscoveredEndpoint

        ep = DiscoveredEndpoint(url=full_url.split("?")[0], method=method.upper(), source_url=full_url, is_api=True)

        params: Dict[str, str] = {}
        param_types: Dict[str, str] = {}
        if parsed.query:
            for k, vals in parse_qs(parsed.query).items():
                params[k] = vals[0] if vals else ""
                param_types[k] = "query"
        # POST body(简单 form 解析)
        if method.upper() == "POST" and body:
            ctype = headers.get("content-type", "")
            if "application/x-www-form-urlencoded" in ctype:
                try:
                    text = body.decode("utf-8", errors="replace")
                except Exception:  # noqa: BLE001
                    text = ""
                for k, vals in parse_qs(text).items():
                    params[k] = vals[0] if vals else ""
                    param_types[k] = "body"
            elif "application/json" in ctype:
                # JSON body:仅记录顶层字符串字段名(不重放,避免破坏业务状态)
                import json as _json

                try:
                    data = _json.loads(body.decode("utf-8", errors="replace"))
                    if isinstance(data, dict):
                        for k, v in data.items():
                            if isinstance(v, (str, int, float)):
                                params[k] = str(v)
                                param_types[k] = "body"
                except Exception:  # noqa: BLE001
                    pass
        # Cookie 参数
        if headers.get("cookie"):
            try:
                from http.cookies import SimpleCookie

                sc = SimpleCookie()
                sc.load(headers["cookie"])
                for morsel in sc.values():
                    params.setdefault(morsel.key, morsel.value)
                    param_types.setdefault(morsel.key, "cookie")
            except Exception:  # noqa: BLE001
                pass

        ep.parameters = params
        ep.param_types = param_types
        return ep


async def run_passive_proxy(
    scan_callback=None,
    target_filter: Optional[str] = None,
    listen_host: str = "127.0.0.1",
    listen_port: int = 8081,
) -> PassiveScanResult:
    """运行被动代理直到被中断,返回捕获统计。"""
    proxy = PassiveProxy(
        scan_callback=scan_callback,
        target_filter=target_filter,
        listen_host=listen_host,
        listen_port=listen_port,
    )
    try:
        await proxy.serve_forever()
    except asyncio.CancelledError:
        pass
    finally:
        await proxy.close()
    return proxy.result
