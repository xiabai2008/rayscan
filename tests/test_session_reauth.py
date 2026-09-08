"""T2.4 登录态维持测试:HTTPPool 会话失效(401/登录重定向)自动重登并重放。

用本地原始 asyncio HTTP 服务验证全链路:首次 401 → 触发重登回调(经 /login
取得新 cookie)→ 重放请求变 200;冷却期内不重复重登;无回调时行为不变。
"""

from __future__ import annotations

import asyncio

import httpx

from wvs.config import ConfigManager
from wvs.core.session import HTTPPool


async def _http_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        request_line = await reader.readline()
        headers = {}
        while True:
            line = await reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break
            if b":" in line:
                k, _, v = line.decode("latin-1").partition(":")
                headers[k.strip().lower()] = v.strip()
        path = request_line.split(b" ")[1].decode() if request_line else "/"
        if path == "/login":
            writer.write(
                b"HTTP/1.1 200 OK\r\nSet-Cookie: auth=1; Path=/\r\nContent-Length: 8\r\nConnection: close\r\n\r\nlogin ok"
            )
        elif path == "/protected":
            if headers.get("cookie", "").strip() == "auth=1":
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            else:
                writer.write(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 6\r\nConnection: close\r\n\r\ndenied")
        await writer.drain()
    finally:
        writer.close()


def test_session_loss_detection() -> None:
    """401 / 重定向到登录页判为会话失效;其他响应不是。"""

    def resp(status: int, location: str = None) -> httpx.Response:
        headers = {"location": location} if location else {}
        return httpx.Response(status, headers=headers)

    assert HTTPPool._looks_like_session_loss(resp(401)) is True
    assert HTTPPool._looks_like_session_loss(resp(302, "http://x/login")) is True
    assert HTTPPool._looks_like_session_loss(resp(301, "http://x/signin")) is True
    assert HTTPPool._looks_like_session_loss(resp(302, "http://x/dashboard")) is False
    assert HTTPPool._looks_like_session_loss(resp(200)) is False
    assert HTTPPool._looks_like_session_loss(resp(403)) is False


def test_reauth_on_401_relogins_and_replays() -> None:
    """首次 401 → 自动重登(取新 cookie)→ 重放 200;冷却期内不重复重登。"""

    async def _run():
        server = await asyncio.start_server(_http_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        base = f"http://127.0.0.1:{port}"
        pool = HTTPPool(ConfigManager())
        reauth_calls = []

        async def reauth() -> bool:
            reauth_calls.append(1)
            resp = await pool.get(f"{base}/login")
            return resp.status_code == 200

        pool.set_reauth_handler(reauth)
        try:
            resp = await pool.get(f"{base}/protected")
            assert resp.status_code == 200, f"重登后重放应 200, got {resp.status_code}"
            assert len(reauth_calls) == 1
            assert pool.reauth_count == 1

            # 新 cookie 已生效:直接 200,且冷却期内不再触发重登
            resp2 = await pool.get(f"{base}/protected")
            assert resp2.status_code == 200
            assert len(reauth_calls) == 1
        finally:
            await pool.close()
            server.close()

    asyncio.run(_run())


def test_no_reauth_without_handler() -> None:
    """未注册重登回调时,401 原样返回(检测器按状态码自然跳过)。"""

    async def _run():
        server = await asyncio.start_server(_http_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        pool = HTTPPool(ConfigManager())
        try:
            resp = await pool.get(f"http://127.0.0.1:{port}/protected")
            assert resp.status_code == 401
            assert pool.reauth_count == 0
        finally:
            await pool.close()
            server.close()

    asyncio.run(_run())
