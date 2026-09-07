"""被动代理 TLS 拦截测试(CA 签发 / CONNECT 拦截端到端 / 降级行为)。

端到端用例的"浏览器"角色使用 writer.start_tls(官方 API,Python 3.11+);
代理端的服务端 TLS 升级走 loop.start_tls + 重包 StreamWriter(全版本同源实现)。
"""

from __future__ import annotations

import asyncio
import socket
import ssl
import sys

import pytest

try:
    from cryptography import x509

    from wvs.core.passive.tls_intercept import CertAuthority, parse_authority
except ImportError:  # pragma: no cover - cryptography 为可选依赖
    CertAuthority = None
    x509 = None

pytestmark = pytest.mark.skipif(CertAuthority is None, reason="未安装 cryptography")

from wvs.core.passive.proxy import PassiveProxy  # noqa: E402


def test_ca_generate_and_persist(tmp_path):
    """CA 首次生成并落盘;重复初始化应加载同一 CA。"""
    ca = CertAuthority(tmp_path)
    ca.ensure_ca()
    assert (tmp_path / "ca.pem").exists()
    assert (tmp_path / "ca_key.pem").exists()
    first_pem = ca.ca_cert_pem

    ca2 = CertAuthority(tmp_path)
    ca2.ensure_ca()
    assert ca2.ca_cert_pem == first_pem


def test_leaf_cert_issued_by_ca_with_san(tmp_path):
    """叶证书应由 CA 签发、SAN 包含主机名,且重复获取走缓存。"""
    ca = CertAuthority(tmp_path)
    cert_path, key_path = ca.get_leaf_paths("secure.example.test")
    assert cert_path.exists() and key_path.exists()

    leaf = x509.load_pem_x509_certificate(cert_path.read_bytes())
    ca_cert = x509.load_pem_x509_certificate((tmp_path / "ca.pem").read_bytes())
    leaf.verify_directly_issued_by(ca_cert)
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "secure.example.test" in san.get_values_for_type(x509.DNSName)

    # 缓存:同一主机再次获取应返回相同文件
    assert ca.get_leaf_paths("secure.example.test") == (cert_path, key_path)


def test_parse_authority_variants():
    assert parse_authority("example.com:443") == ("example.com", 443)
    assert parse_authority("example.com") == ("example.com", 443)
    assert parse_authority("example.com:8443") == ("example.com", 8443)
    assert parse_authority("[::1]:443") == ("::1", 443)


def test_connect_tunnel_when_intercept_unavailable(monkeypatch, tmp_path):
    """cryptography 缺失时,启用拦截的代理应回退为纯隧道(不检测但不断流)。"""
    from wvs.core.passive import tls_intercept as ti

    monkeypatch.setattr(ti.CertAuthority, "available", staticmethod(lambda: False))
    p = PassiveProxy(
        scan_callback=None, listen_host="127.0.0.1", listen_port=0, tls_intercept=True, ca_dir=str(tmp_path)
    )

    async def echo(reader, writer):
        line = await reader.readline()
        writer.write(b"ECHO:" + line)
        await writer.drain()
        writer.close()

    async def _run():
        up_server = await asyncio.start_server(echo, "127.0.0.1", 0)
        up_port = up_server.sockets[0].getsockname()[1]
        await p.start()
        p_port = p._server.sockets[0].getsockname()[1]
        writer = None
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", p_port)
            writer.write(f"CONNECT 127.0.0.1:{up_port} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".encode())
            await writer.drain()
            status = await reader.readline()
            assert b"200" in status
            while (await reader.readline()) not in (b"\r\n", b"\n", b""):
                pass
            writer.write(b"ping\r\n")
            await writer.drain()
            assert await reader.readline() == b"ECHO:ping\r\n"
        finally:
            if writer is not None:
                writer.close()
            await p.close()
            up_server.close()

    asyncio.run(_run())


@pytest.mark.skipif(sys.version_info < (3, 11), reason="测试客户端依赖 writer.start_tls (3.11+)")
def test_tls_intercept_end_to_end(tmp_path, monkeypatch):
    """CONNECT → 伪装叶证书握手 → 解密请求进检测管线 → keep-alive 多请求正确转发回传。"""
    captured = []

    async def scan_callback(endpoint):
        captured.append(endpoint)
        return []

    ca = CertAuthority(tmp_path / "ca")
    up_port_ref = {}

    # 假域名解析到本机(代理上游连接与真实 DNS 行为一致,走 socket.getaddrinfo)
    real_getaddrinfo = socket.getaddrinfo

    def fake_getaddrinfo(host, *args, **kwargs):
        if host == "secure.example.test":
            host = "127.0.0.1"
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    async def up_handler(reader, writer):
        try:
            while True:
                request_line = await reader.readline()
                if not request_line:
                    break
                while (await reader.readline()) not in (b"\r\n", b"\n", b""):
                    pass
                target = request_line.split(b" ")[1]
                body = b"up:" + target
                writer.write(
                    b"HTTP/1.1 200 OK\r\nContent-Length: "
                    + str(len(body)).encode()
                    + b"\r\nConnection: keep-alive\r\n\r\n"
                    + body
                )
                await writer.drain()
        finally:
            writer.close()

    async def _run():
        # 上游 TLS 服务(证书由 MITM CA 签发,但主机名与 127.0.0.1 不匹配 → 代理侧降级不校验)
        up_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cert_path, key_path = ca.get_leaf_paths("upstream.local")
        up_ctx.load_cert_chain(str(cert_path), str(key_path))
        up_server = await asyncio.start_server(up_handler, "127.0.0.1", 0, ssl=up_ctx)
        up_port_ref["port"] = up_server.sockets[0].getsockname()[1]

        proxy = PassiveProxy(
            scan_callback=scan_callback,
            listen_host="127.0.0.1",
            listen_port=0,
            tls_intercept=True,
            ca_dir=str(tmp_path / "ca"),
        )
        await proxy.start()
        p_port = proxy._server.sockets[0].getsockname()[1]
        reader = writer = None
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", p_port)
            writer.write(
                f"CONNECT secure.example.test:{up_port_ref['port']} HTTP/1.1\r\nHost: secure.example.test:{up_port_ref['port']}\r\n\r\n".encode()
            )
            await writer.drain()
            status = await reader.readline()
            assert b"200" in status
            while (await reader.readline()) not in (b"\r\n", b"\n", b""):
                pass

            # 客户端(浏览器角色)与代理完成 TLS 握手,验证叶证书由 MITM CA 签发
            cctx = ssl.create_default_context(cafile=str(tmp_path / "ca" / "ca.pem"))
            await writer.start_tls(cctx, server_hostname="secure.example.test")

            async def _request(req: bytes) -> bytes:
                writer.write(req)
                await writer.drain()
                status_line = await reader.readline()
                assert b"200 OK" in status_line
                headers = {}
                while True:
                    line = await reader.readline()
                    if line in (b"\r\n", b"\n", b""):
                        break
                    k, _, v = line.decode().partition(":")
                    headers[k.strip().lower()] = v.strip()
                return await reader.readexactly(int(headers["content-length"]))

            body1 = await _request(b"GET /api/user?id=1 HTTP/1.1\r\nHost: secure.example.test\r\n\r\n")
            assert body1 == b"up:/api/user?id=1"
            body2 = await _request(b"GET /api/order?no=42 HTTP/1.1\r\nHost: secure.example.test\r\n\r\n")
            assert body2 == b"up:/api/order?no=42"

            # 请求声明 Connection: close → 代理回完该响应后应关闭连接
            body3 = await _request(b"GET /bye HTTP/1.1\r\nHost: secure.example.test\r\nConnection: close\r\n\r\n")
            assert body3 == b"up:/bye"
            assert await reader.readline() == b""
            writer.close()
        finally:
            if writer is not None:
                writer.close()
            await proxy.close()
            up_server.close()

    asyncio.run(_run())

    assert len(captured) == 3
    base = f"https://secure.example.test:{up_port_ref['port']}"
    assert captured[0].url == f"{base}/api/user"
    assert captured[0].parameters == {"id": "1"}
    assert captured[0].param_types == {"id": "query"}
    assert captured[1].url == f"{base}/api/order"
    assert captured[1].parameters == {"no": "42"}
    assert captured[2].url == f"{base}/bye"
