"""RayScan 内置演示靶场 (Phase 4: P4-1 一键 Demo)。

一个极简 Flask 应用,模拟 SQLi 与 XSS 漏洞,供 `rayscan demo` 一键体验。
仅监听 127.0.0.1,绝不对外暴露;仅供本地功能验证。
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Optional

logger = logging.getLogger("wvs.demo_lab")

# 内存"数据库"
_USERS = [
    {"id": 1, "name": "alice", "email": "alice@example.com", "secret": "flaG{demo_sqli_ok}"},
    {"id": 2, "name": "bob", "email": "bob@example.com", "secret": "not-a-real-flag"},
    {"id": 3, "name": "carol", "email": "carol@example.com", "secret": "nothing-here"},
]

_HTML_TPL = """<!DOCTYPE html>
<html><head><title>RayScan Demo Lab</title>
<style>body{{font-family:sans-serif;max-width:600px;margin:40px auto}}code{{background:#f0f0f0;padding:2px 6px}}</style>
</head><body>
<h1>RayScan Demo Lab</h1>
<p>内置演示靶场 — 仅本地使用,包含以下漏洞:</p>
<ul>
<li><b>SQLi (error-based)</b>:<code>/?id=1' AND (SELECT 1 FROM (SELECT SLEEP(0))a)--</code></li>
<li><b>XSS (reflected)</b>:<code>/?name=&lt;script&gt;alert(1)&lt;/script&gt;</code></li>
</ul>
<hr>
{content}
</body></html>"""


def _build_app():
    """构建 Flask 应用(延迟导入避免硬依赖)。"""
    from flask import Flask, request

    app = Flask(__name__)

    @app.route("/")
    def index():
        # XSS: name 参数反射未过滤
        name = request.args.get("name", "world")
        content = (
            f"<h2>Hello, {name}!</h2>\n"
            '<p><a href="/user?id=1">查看用户 (SQLi 端点)</a></p>\n'
            '<p><a href="/?name=world">首页</a></p>'
        )
        return _HTML_TPL.format(content=content)

    @app.route("/user")
    def user():
        # SQLi: id 参数拼接进 SQL
        uid = request.args.get("id", "1")
        sql = f"SELECT * FROM users WHERE id = {uid}"
        content = f"<h3>SQL executed:</h3><code>{sql}</code><ul>"
        try:
            i = int(uid)
            u = next((x for x in _USERS if x["id"] == i), None)
            if u:
                content += f"<li>id={u['id']} name={u['name']} email={u['email']}</li>"
            else:
                content += "<li>no user</li>"
        except (TypeError, ValueError):
            # 非数字输入触发 SQL 语法错误回显(模拟 error-based SQLi)
            content += f"<li style='color:red'>SQL syntax error near '{uid}'</li>"
        content += "</ul>"
        return _HTML_TPL.format(content=content)

    @app.route("/health")
    def health():
        return "ok"

    return app


class DemoLab:
    """启动/停止内置演示靶场。"""

    def __init__(self, host: str = "127.0.0.1", port: int = 18923):
        self.host = host
        self.port = port
        self._thread: Optional[threading.Thread] = None
        self._server = None

    def start(self) -> str:
        """启动 Flask 应用(后台线程),返回基础 URL。"""
        app = _build_app()
        # 禁用 werkzeug 请求日志噪音
        logging.getLogger("werkzeug").setLevel(logging.ERROR)

        from werkzeug.serving import make_server

        self._server = make_server(self.host, self.port, app, threaded=True)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        # port=0 时获取实际绑定端口
        actual_port = self._server.server_port
        base = f"http://{self.host}:{actual_port}"
        # 等待就绪
        for _ in range(30):
            try:
                import urllib.request

                with urllib.request.urlopen(base + "/health", timeout=1):
                    break
            except Exception:  # noqa: BLE001
                time.sleep(0.1)
        logger.info("[DemoLab] 演示靶场已启动: %s", base)
        return base

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server = None
