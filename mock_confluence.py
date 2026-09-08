"""S5 合成靶场：忠实模拟已安装 Confluence 7.4.10 的响应签名。

用于验证 OA 模块 Confluence 检测链路（指纹 → 版本 → CVE-2021-26084 OGNL 注入）。
真实环境安装需 Atlassian 试用 license（2026-03-30 起官方停止发放），故用合成靶场闭环检测逻辑。
"""
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = 8897

HOMEPAGE = b"""<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="X-UA-Compatible" content="IE=EDGE,chrome=IE7">
    <meta charset="utf-8">
    <title>Confluence</title>
    <meta name="ajs-version-number" content="7.4.10">
    <script>window.WRM=window.WRM||{};window.WRM._unparsedData=window.WRM._unparsedData||{};</script>
</head>
<body>
    <div id="com-atlassian-confluence">Confluence</div>
    <div class="aui-page-panel">Welcome to Confluence. Log in to start collaborating.</div>
    <script src="/s/1411724483adabf457b15d46a5b0062-CDN/g9fsxv/8402/s-825361645/7.4.10/_/download/batch/com.atlassian.confluence:confluence-aui-staging/confluence.aui.staging.js"></script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ctype="text/html;charset=UTF-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Confluence-Request-Time", "1787570495124")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            self._send(200, HOMEPAGE)
        elif path == "/pages/doenterpagevariables.action":
            # 未带 payload 的 GET 探测：返回正常页面（不应命中）
            self._send(200, b"<html><head><title>Confluence</title></head><body>Page variables</body></html>")
        else:
            self._send(404, b"<html><head><title>Confluence</title></head><body>Not Found</body></html>")

    def do_POST(self):
        path = self.path.split("?")[0]
        if path == "/pages/doenterpagevariables.action":
            # CVE-2021-26084: OGNL 表达式 {233*233} 执行结果 54289 回显
            body = (
                b"<html><head><title>Confluence</title></head><body>"
                b"<div class=\"error\">54289</div>"
                b"</body></html>"
            )
            self._send(200, body)
        else:
            self._send(404, b"<html><head><title>Confluence</title></head><body>Not Found</body></html>")


if __name__ == "__main__":
    print(f"Confluence 7.4.10 mock listening on :{PORT}")
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
