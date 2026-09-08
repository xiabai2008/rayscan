"""HTTPPool GET 去重缓存键回归测试:语义请求头必须参与缓存键。

背景:P8 缓存原本只按 method|url|params 键——CORS 类探测(同 URL 不同 Origin 头)
会命中旧响应,导致 api 模块 CORS 检测漏检;认证头差异探测同理。
"""

from __future__ import annotations

import asyncio

from wvs.config import ConfigManager
from wvs.core.session import HTTPPool


async def _handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        await reader.readline()  # 请求行(路径无关,按 Origin 头分支)
        headers = {}
        while True:
            line = await reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break
            if b":" in line:
                k, _, v = line.decode("latin-1").partition(":")
                headers[k.strip().lower()] = v.strip()
        if headers.get("origin") == "https://evil.com":
            body = b'{"acao":"reflected"}'
            writer.write(
                b"HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: https://evil.com\r\n"
                b"Access-Control-Allow-Credentials: true\r\nContent-Length: "
                + str(len(body)).encode()
                + b"\r\nConnection: close\r\n\r\n"
                + body
            )
        else:
            body = b'{"plain":true}'
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Length: "
                + str(len(body)).encode()
                + b"\r\nConnection: close\r\n\r\n"
                + body
            )
        await writer.drain()
    finally:
        writer.close()


def test_semantic_headers_bypass_stale_cache() -> None:
    """同 URL 同参数、不同 Origin 头的 GET 必须各自拿到真实响应(不得共用缓存)。"""

    async def _run():
        server = await asyncio.start_server(_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        url = f"http://127.0.0.1:{port}/api/thing"
        pool = HTTPPool(ConfigManager())
        try:
            # 第一次:无 Origin 头 → 缓存普通响应
            r1 = await pool.get(url, params={"id": "1"})
            assert b"plain" in r1.content
            # 第二次:带 Origin 头 → 语义头不同,必须重新请求(不得返回第一次的缓存)
            r2 = await pool.get(url, params={"id": "1"}, headers={"Origin": "https://evil.com"})
            assert b"acao" in r2.content, "带 Origin 的请求命中了无 Origin 的缓存(缓存键未含语义头)"
            # 同头重复请求仍走缓存
            r3 = await pool.get(url, params={"id": "1"}, headers={"Origin": "https://evil.com"})
            assert b"acao" in r3.content
        finally:
            await pool.close()
            server.close()

    asyncio.run(_run())
