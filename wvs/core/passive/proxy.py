"""轻量被动扫描 MITM 代理 (Phase 1: --proxy)。

设计:
- 基于 asyncio + http 原始解析,零第三方依赖(避免引入 mitmproxy 重依赖)
- 拦截经过代理的 HTTP/HTTPS-CONNECT 请求,解析出端点 → 注入检测管线
- 仅做"流量 → 检测"单向:转发请求原样返回,不缓存、不重放
- HTTPS:默认仅 CONNECT 隧道转发;启用 --tls-intercept 后用 MITM CA 按需签发
  叶证书伪装目标站点,解密流量进入检测管线(客户端需信任 CA,见 tls_intercept)
- 结果 source="passive",可合并去重

用法(CLI):
    rayscan passive --listen 127.0.0.1:8081 [--target example.com] [--all-modules]
    rayscan passive --tls-intercept   # 解密 HTTPS(需先信任生成的 CA 证书)
"""

from __future__ import annotations

import asyncio
import logging
import ssl
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from .tls_intercept import CA_CERT_NAME, default_ca_dir, trust_instructions

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
    TLS 拦截:tls_intercept=True 时,CONNECT 隧道用 MITM CA 签发的叶证书
    升级为服务端 TLS,解密后的请求进入检测管线(需客户端信任 CA);
    cryptography 缺失或 CA 初始化失败时自动回退纯隧道模式。
    """

    def __init__(
        self,
        scan_callback=None,
        target_filter: Optional[str] = None,
        listen_host: str = "127.0.0.1",
        listen_port: int = 8081,
        buffer_size: int = 65536,
        tls_intercept: bool = False,
        ca_dir: Optional[str] = None,
    ):
        self.scan_callback = scan_callback  # async callable(endpoint_dict) -> List[vuln]
        self.target_filter = target_filter
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.buffer_size = buffer_size
        self.tls_intercept = tls_intercept
        self.ca_dir = ca_dir or str(default_ca_dir())
        self._cert_authority: Any = None
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
        if self.tls_intercept and self._intercept_ready():
            ca_path = self.ca_cert_path()
            logger.info("[Passive] TLS 拦截已启用,CA 证书: %s", ca_path)
            logger.info("[Passive] 客户端需先信任该 CA 才能解密 HTTPS: %s", trust_instructions(ca_path))
        elif self.tls_intercept:
            logger.warning("[Passive] TLS 拦截不可用,HTTPS 流量将仅隧道转发(不检测)")

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

            # HTTPS CONNECT:启用拦截则解密检测,否则仅建立隧道
            if method.upper() == "CONNECT":
                if self._intercept_ready():
                    await self._handle_connect_intercept(reader, writer, raw_url.strip())
                else:
                    await self._handle_connect(reader, writer, raw_url.strip())
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

            await self._capture_and_scan(method, full_url, parsed, headers, body)

            # 透明转发原请求
            await self._relay_plain(method, full_url, headers, body, writer)

        except asyncio.CancelledError:
            pass
        except Exception as e:  # noqa: BLE001
            logger.debug("[Passive] 连接处理异常: %s", e)
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass

    async def _handle_connect(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, authority: str) -> None:
        """CONNECT 隧道:先连通目标,再响应 200 并双向转发(HTTPS 流量不检测)。"""
        from .tls_intercept import parse_authority

        host, port = parse_authority(authority)
        up_reader: Optional[asyncio.StreamReader] = None
        up_writer: Optional[asyncio.StreamWriter] = None
        try:
            try:
                up_reader, up_writer = await asyncio.open_connection(host, port)
            except OSError as e:
                logger.debug("[Passive] CONNECT 目标不可达(%s): %s", authority, e)
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                await writer.drain()
                return

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

            await asyncio.gather(_pipe(reader, up_writer), _pipe(up_reader, writer))
        except Exception as e:  # noqa: BLE001
            logger.debug("[Passive] CONNECT 隧道异常: %s", e)
        finally:
            for w in (up_writer, writer):
                if w is not None:
                    try:
                        w.close()
                    except Exception:  # noqa: BLE001
                        pass

    # ─────────────────────────────────────────────────────────────
    # TLS 拦截(HTTPS 解密)
    # ─────────────────────────────────────────────────────────────

    def _intercept_ready(self) -> bool:
        """TLS 拦截是否可用(懒初始化 CA;cryptography 缺失或初始化失败回退隧道模式)。"""
        if not self.tls_intercept:
            return False
        if self._cert_authority is not None:
            return True
        try:
            from .tls_intercept import CertAuthority

            if not CertAuthority.available():
                logger.warning("[Passive] 未安装 cryptography,HTTPS 将仅隧道转发: pip install 'rayscan[tls]'")
                return False
            self._cert_authority = CertAuthority(self.ca_dir)
            self._cert_authority.ensure_ca()
            return True
        except Exception as e:  # noqa: BLE001
            logger.warning("[Passive] TLS 拦截初始化失败,HTTPS 将仅隧道转发: %s", e)
            return False

    def ca_cert_path(self) -> Optional[Path]:
        """CA 证书路径(拦截未启用或未初始化时为 None)。"""
        if self._cert_authority is None:
            return None
        return self._cert_authority.ca_dir / CA_CERT_NAME

    async def _handle_connect_intercept(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, authority: str
    ) -> None:
        """TLS 拦截:用 MITM CA 叶证书对客户端伪装目标站点,上游保持真实 TLS。

        解密后的明文 HTTP 逐请求进入检测管线,支持 keep-alive(响应 framing 精确截断)。
        时序依赖:客户端仅在收到 200 后才发起 TLS 握手,因此升级前连接上不会有应用数据。
        """
        from .tls_intercept import parse_authority

        host, port = parse_authority(authority)
        up_writer: Optional[asyncio.StreamWriter] = None
        try:
            leaf_ctx = self._cert_authority.server_ssl_context(host)
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            writer = await self._tls_server_upgrade(writer, leaf_ctx)

            # 上游保持真实 TLS;校验失败(自签名/内网目标)降级为不校验
            verify_ctx = ssl.create_default_context()
            try:
                up_reader, up_writer = await asyncio.open_connection(host, port, ssl=verify_ctx, server_hostname=host)
            except ssl.SSLCertVerificationError:
                logger.debug("[Passive] 上游 %s 证书校验失败,降级为不校验", authority)
                insecure_ctx = ssl.create_default_context()
                insecure_ctx.check_hostname = False
                insecure_ctx.verify_mode = ssl.CERT_NONE
                up_reader, up_writer = await asyncio.open_connection(host, port, ssl=insecure_ctx, server_hostname=host)

            while True:
                request_line = await reader.readline()
                if not request_line:
                    break
                req_headers: Dict[str, str] = {}
                while True:
                    line = await reader.readline()
                    if line in (b"\r\n", b"\n", b""):
                        break
                    if b":" in line:
                        k, _, v = line.decode("utf-8", errors="replace").partition(":")
                        req_headers[k.strip().lower()] = v.strip()
                try:
                    method, raw_path, _version = request_line.decode("utf-8", errors="replace").strip().split(" ", 2)
                except ValueError:
                    break
                content_length = int(req_headers.get("content-length", "0") or 0)
                req_body = await reader.read(min(content_length, self.buffer_size)) if content_length > 0 else b""

                full_url = f"https://{authority}{raw_path or '/'}"
                parsed = urlparse(full_url)
                await self._capture_and_scan(method, full_url, parsed, req_headers, req_body)

                await self._write_request(up_writer, method, raw_path or "/", req_headers, req_body)
                keep_alive = await self._relay_response_framed(up_reader, writer, method)
                # 客户端请求声明 close,或响应不可复用 → 结束该连接
                if "close" in req_headers.get("connection", "").lower() or not keep_alive:
                    break
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001
            logger.debug("[Passive] TLS 拦截异常(%s): %s", authority, e)
        finally:
            for w in (up_writer, writer):
                if w is not None:
                    try:
                        w.close()
                    except Exception:  # noqa: BLE001
                        pass

    @staticmethod
    async def _write_request(
        up_writer: asyncio.StreamWriter, method: str, request_target: str, headers: Dict[str, str], body: bytes
    ) -> None:
        """向上游写出请求头与请求体。"""
        head = f"{method} {request_target} HTTP/1.1\r\n"
        for k, v in headers.items():
            head += f"{k}: {v}\r\n"
        head += "\r\n"
        up_writer.write(head.encode("utf-8", errors="replace") + body)
        await up_writer.drain()

    @staticmethod
    async def _tls_server_upgrade(writer: asyncio.StreamWriter, ssl_ctx: ssl.SSLContext) -> asyncio.StreamWriter:
        """把明文 StreamWriter 升级为服务端 TLS,返回绑定新传输层的 StreamWriter。

        统一走 loop.start_tls + 重包(3.8-3.10 无 writer.start_tls);解密数据
        经原 StreamReaderProtocol 流入原 reader,可直接继续读取。
        """
        loop = asyncio.get_running_loop()
        protocol = writer.transport.get_protocol()
        new_transport = await loop.start_tls(writer.transport, protocol, ssl_ctx, server_side=True)
        return asyncio.StreamWriter(new_transport, protocol, None, loop)

    async def _relay_response_framed(
        self, up_reader: asyncio.StreamReader, writer: asyncio.StreamWriter, method: str
    ) -> bool:
        """转发一个响应并按 framing 精确截断,返回连接是否可复用(keep-alive)。"""
        status_line = await up_reader.readline()
        if not status_line:
            return False
        resp_headers: Dict[str, str] = {}
        writer.write(status_line)
        while True:
            line = await up_reader.readline()
            if line in (b"\r\n", b"\n", b""):
                writer.write(b"\r\n")
                break
            writer.write(line)
            if b":" in line:
                k, _, v = line.decode("latin-1").partition(":")
                resp_headers[k.strip().lower()] = v.strip()
        await writer.drain()

        try:
            status = int(status_line.split(b" ", 2)[1].decode("latin-1", errors="replace"))
        except (IndexError, ValueError):
            status = 200
        connection = resp_headers.get("connection", "").lower()

        if method.upper() == "HEAD" or status in (204, 304) or 100 <= status < 200:
            return "close" not in connection

        if "chunked" in resp_headers.get("transfer-encoding", "").lower():
            while True:
                size_line = await up_reader.readline()
                writer.write(size_line)
                try:
                    size = int(size_line.strip().split(b";")[0], 16)
                except ValueError:
                    return False
                if size == 0:
                    while True:  # 尾随头
                        t = await up_reader.readline()
                        writer.write(t)
                        if t in (b"\r\n", b"\n", b""):
                            break
                    await writer.drain()
                    return "close" not in connection
                writer.write(await up_reader.readexactly(size))
                writer.write(await up_reader.readexactly(2))  # 块尾 CRLF
                await writer.drain()

        if "content-length" in resp_headers:
            remaining = int(resp_headers["content-length"] or 0)
            while remaining > 0:
                data = await up_reader.read(min(remaining, self.buffer_size))
                if not data:
                    return False
                writer.write(data)
                await writer.drain()
                remaining -= len(data)
            return "close" not in connection

        # 无 framing 头(HTTP/1.0 风格):读到上游关闭,连接不可复用
        while True:
            data = await up_reader.read(self.buffer_size)
            if not data:
                break
            writer.write(data)
            await writer.drain()
        return False

    async def _capture_and_scan(self, method: str, full_url: str, parsed, headers: Dict[str, str], body: bytes) -> None:
        """统计捕获 → 目标过滤 → 构造端点 → 扫描回调(明文 HTTP 与解密 HTTPS 共用)。"""
        self.result.requests_captured += 1

        # 目标过滤:非目标域不检测(仍会透明转发)
        host = headers.get("host", parsed.netloc or "")
        if self.target_filter and not self._host_matches(host, self.target_filter):
            return

        endpoint = self._build_endpoint(method, full_url, parsed, body, headers)
        if not endpoint:
            return
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

    # ─────────────────────────────────────────────────────────────
    # 转发
    # ─────────────────────────────────────────────────────────────

    async def _relay_plain(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: bytes,
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
        target = target.lower().rstrip(".")
        if target.startswith("www."):
            target = target[4:]
        h = host.lower().split(":")[0].rstrip(".")
        if h.startswith("www."):
            h = h[4:]
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
    tls_intercept: bool = False,
    ca_dir: Optional[str] = None,
) -> PassiveScanResult:
    """运行被动代理直到被中断,返回捕获统计。"""
    proxy = PassiveProxy(
        scan_callback=scan_callback,
        target_filter=target_filter,
        listen_host=listen_host,
        listen_port=listen_port,
        tls_intercept=tls_intercept,
        ca_dir=ca_dir,
    )
    try:
        await proxy.serve_forever()
    except asyncio.CancelledError:
        pass
    finally:
        await proxy.close()
    return proxy.result
