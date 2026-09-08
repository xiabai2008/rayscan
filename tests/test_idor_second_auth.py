"""T2.5 双账号 IDOR 验证测试。

- _verify_second_account:对真实本地服务验证 B 会话读取判定(200 跨账号 → True / 403 → False)
- 升级逻辑:双账号确认 → HIGH/HIGH,未确认 → MEDIUM/MEDIUM(单会话疑似语义保持)
"""

from __future__ import annotations

import asyncio

from wvs.config import ConfigManager
from wvs.models import Confidence, ScanTarget, Severity
from wvs.modules.idor.detector import IDORDetector

_INVOICE_PAGE = (
    "<html><head><title>Invoice Detail</title></head><body>"
    "<h1>Invoice 1001</h1><p>customer: cust-1001</p><p>amount: 128.50</p>"
    "<p>status: paid</p><table><tr><th>item</th></tr><tr><td>license</td></tr>"
    "<tr><td>support</td></tr></table></body></html>"
)


async def _http_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """任意 id 均返回同结构发票页(同主靶场 /api/invoice 语义)。"""
    try:
        await reader.readline()  # 请求行(内容无关)
        while (await reader.readline()) not in (b"\r\n", b"\n", b""):
            pass
        writer.write(
            f"HTTP/1.1 200 OK\r\nContent-Length: {len(_INVOICE_PAGE)}\r\nConnection: close\r\n\r\n{_INVOICE_PAGE}".encode()
        )
        await writer.drain()
    finally:
        writer.close()


def _detector(second_auth: dict = None) -> IDORDetector:
    config = ConfigManager()
    if second_auth:
        config.set("modules.idor.second_auth_headers", second_auth)
    return IDORDetector(config)


def test_verify_second_account_true_on_cross_account_read() -> None:
    """B 会话读取 B 对象与 A 对象均 200 → 确认跨账号读取。"""

    async def _run():
        server = await asyncio.start_server(_http_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        d = _detector({"X-Account": "account-b"})
        try:
            ok = await d._verify_second_account(
                f"http://127.0.0.1:{port}/api/invoice",
                {"id": "1001"},
                {"id": "1000"},
                {"X-Account": "account-b"},
            )
            assert ok is True
        finally:
            server.close()

    asyncio.run(_run())


def test_verify_second_account_false_on_403() -> None:
    """B 会话读 A 对象被拒(403) → 不能确认。"""

    async def _run():
        async def handler(reader, writer):
            try:
                await reader.readline()
                while (await reader.readline()) not in (b"\r\n", b"\n", b""):
                    pass
                writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 13\r\nConnection: close\r\n\r\nAccess Denied")
                await writer.drain()
            finally:
                writer.close()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        d = _detector({"X-Account": "account-b"})
        try:
            ok = await d._verify_second_account(
                f"http://127.0.0.1:{port}/api/secure",
                {"id": "1001"},
                {"id": "1000"},
                {"X-Account": "account-b"},
            )
            assert ok is False
        finally:
            server.close()

    asyncio.run(_run())


def test_object_replacement_severity_upgrade_on_confirmation() -> None:
    """双账号确认 → HIGH/HIGH;未配置/未确认 → MEDIUM/MEDIUM(疑似语义保持)。"""

    async def _run():
        async def fake_send(*_args, **_kwargs):
            return {"status_code": 200, "text": _INVOICE_PAGE, "headers": {}}

        async def _scenario(detector: IDORDetector):
            detector._send_request = fake_send  # type: ignore[method-assign]
            target = ScanTarget(url="http://lab.test/api/invoice?id=1001", params={"id": "1001"})
            return await detector._detect_object_replacement(target)

        d_confirmed = _detector({"X-Account": "account-b"})

        async def _always_true(*_args, **_kwargs) -> bool:
            return True

        d_confirmed._verify_second_account = _always_true  # type: ignore[method-assign]
        vulns = await _scenario(d_confirmed)
        assert len(vulns) == 1
        assert vulns[0].severity == Severity.HIGH
        assert vulns[0].confidence == Confidence.HIGH
        assert "second-account" in (vulns[0].evidence or "")

        d_plain = _detector()
        vulns2 = await _scenario(d_plain)
        assert len(vulns2) == 1
        assert vulns2[0].severity == Severity.MEDIUM
        assert vulns2[0].confidence == Confidence.MEDIUM

    asyncio.run(_run())
