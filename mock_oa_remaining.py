"""S5 合成靶场：8 种剩余 OA 的忠实响应签名模拟。

用于验证 OA 模块检测链路（指纹 → 检查项 → 规则级证据验证）。
每个 OA 一个端口，响应内容参照真实系统/公开 PoC 构造。

端口分配（避开 Hyper-V 保留区间 8001-8100 与既有靶场端口）：
  8901 泛微-Ecology    8902 通达OA        8903 金蝶-Kingdee
  8904 蓝凌-Landray    8905 致远-Seeyon   8906 用友-Yonyou
  8907 禅道-Zentao     8908 万户-Whir
"""
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

SAFE_MODE = os.environ.get("OA_SAFE_MODE") == "1"

# ── 通用响应体 ──────────────────────────────────────────────
PASSWD = (
    b"root:x:0:0:root:/root:/bin/bash\n"
    b"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    b"bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
)
WIN_INI = b"; for 16-bit app support\n[fonts]\n[extensions]\n[mci extensions]\n[files]\n[Mail]\nMAPI=1\n"
WEB_XML = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n'
    b'<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee">\n'
    b'  <display-name>nc_web</display-name>\n'
    b'  <servlet><servlet-name>NCInvokerServlet</servlet-name></servlet>\n'
    b"</web-app>\n"
)
JSP_SRC = (
    b'<%@ page language="java" contentType="text/html; charset=UTF-8" %>\n'
    b'<% String var = request.getParameter("var"); out.println(var); %>\n'
)
SQL_ERROR = (
    b"<html><body><h1>SQL Error</h1>"
    b"<p>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version</p>"
    b"</body></html>"
)
XPATH_ERROR = (
    b"<html><body><p>SQLSTATE[HY000]: General error: 1105 XPATH syntax error: '~root@localhost~'</p></body></html>"
)
BINARY = bytes(range(256)) * 100  # 25KB 二进制（非 HTML）

# ── 各 OA 首页（含内容指纹） ────────────────────────────────
HOMEPAGES = {
    "泛微-Ecology": "<html><head><title>泛微协同办公平台</title></head><body>e-cology 协同办公系统</body></html>".encode("utf-8"),
    "通达OA": "<html><head><title>通达OA</title></head><body>tongda OA 办公系统</body></html>".encode("utf-8"),
    "金蝶-Kingdee": "<html><head><title>金蝶云星空</title></head><body>Kingdee K3Cloud 企业管理软件</body></html>".encode("utf-8"),
    "蓝凌-Landray": "<html><head><title>蓝凌OA</title></head><body>Landray EKP 协同办公平台</body></html>".encode("utf-8"),
    "致远-Seeyon": "<html><head><title>致远OA</title></head><body>Seeyon A8 协同办公</body></html>".encode("utf-8"),
    "用友-Yonyou": "<html><head><title>用友NC</title></head><body>Yonyou NC Cloud 企业互联网</body></html>".encode("utf-8"),
    "禅道-Zentao": "<html><head><title>禅道</title></head><body>Zentao PMS 项目管理软件</body></html>".encode("utf-8"),
    "万户-Whir": "<html><head><title>万户OA</title></head><body>Whir 协同办公系统</body></html>".encode("utf-8"),
}

PORTS = {
    "泛微-Ecology": 8901,
    "通达OA": 8902,
    "金蝶-Kingdee": 8903,
    "蓝凌-Landray": 8904,
    "致远-Seeyon": 8905,
    "用友-Yonyou": 8906,
    "禅道-Zentao": 8907,
    "万户-Whir": 8908,
}


class Handler(BaseHTTPRequestHandler):
    oa = "泛微-Ecology"  # 每个 server 实例覆盖
    safe = False  # 安全模式：漏洞端点返回无特征响应

    def log_message(self, *args):
        pass

    def _send(self, code, body, ctype="text/html;charset=UTF-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _query(self):
        return parse_qs(urlparse(self.path).query)

    def _form(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            return parse_qs(raw.decode("utf-8"))
        except Exception:
            return {}

    def _route(self, method):
        path = urlparse(self.path).path
        q = self._query()
        f = self._form() if method == "POST" else {}
        # 合并 query + form 参数（检测器 POST 默认把 params 放 query string）
        merged = {**q, **f}
        oa = self.oa

        if path == "/":
            return 200, HOMEPAGES[oa], "text/html;charset=UTF-8"

        if self.safe:
            return self._safe_route(method, path, merged)

        # ── 泛微-Ecology ──
        if oa == "泛微-Ecology":
            if path == "/weaver/weaver.file.FileDownloadForOutDoc":
                fid = merged.get("downloadFileId", [""])[0]
                if "etc/passwd" in fid:
                    return 200, PASSWD, "text/plain;charset=UTF-8"
                return 200, b"<html><body>file not found</body></html>"
            if path == "/api/portal/weaver/weaver.do":
                return 200, BINARY, "application/octet-stream"
            if path == "/workflow/WorkflowCenterTreeData.jsp":
                return 200, SQL_ERROR, "text/html;charset=UTF-8"

        # ── 通达OA ──
        if oa == "通达OA":
            if path == "/ispirit/login_code_scan.php":
                if merged.get("type", [""])[0] == "confirm":
                    return 200, b'{"status":1,"msg":"success"}', "application/json;charset=UTF-8"
                return 200, b'{"status":0,"msg":"fail"}', "application/json;charset=UTF-8"
            if path in ("/mac/gateway.php", "/general/document/index.php"):
                return 200, SQL_ERROR, "text/html;charset=UTF-8"

        # ── 金蝶-Kingdee ──
        if oa == "金蝶-Kingdee":
            if path.endswith("commoninstallServiceHttpFlowService"):
                return 200, BINARY, "application/octet-stream"
            if path == "/CommonFileServer/c:/windows/win.ini":
                return 200, WIN_INI, "text/plain;charset=UTF-8"

        # ── 蓝凌-Landray ──
        if oa == "蓝凌-Landray":
            if path == "/sys/ui/extend/varkind/custom.jsp":
                var = merged.get("var", [""])[0]
                if "file:///etc/passwd" in var:
                    return 200, PASSWD, "text/plain;charset=UTF-8"
                return 200, b"<html><body>ok</body></html>"
            if path == "/sys/ui/extend/varkind/custom_pf.jsp":
                return 200, JSP_SRC, "text/html;charset=UTF-8"

        # ── 致远-Seeyon ──
        if oa == "致远-Seeyon":
            if path in ("/seeyon/htmlofficeservlet", "/seeyon/thirdpartyController.do"):
                return 200, BINARY, "application/octet-stream"
            if path == "/seeyon/ajax.do":
                if merged.get("method", [""])[0] == "uploadPageLayoutAttachment":
                    return 500, b'{"code":"08441","message":"upload success"}', "application/json;charset=UTF-8"
                return 200, b'{"code":"0","message":"ok"}', "application/json;charset=UTF-8"

        # ── 用友-Yonyou ──
        if oa == "用友-Yonyou":
            if path == "/servlet/~uapss/uploadServlet":
                return 200, BINARY, "application/octet-stream"
            if path == "/portal/file":
                fid = merged.get("fileid", [""])[0]
                if "web.xml" in fid:
                    return 200, WEB_XML, "text/xml;charset=UTF-8"
                return 404, b"<html><body>Not Found</body></html>", "text/html;charset=UTF-8"

        # ── 禅道-Zentao ──
        if oa == "禅道-Zentao":
            if path == "/zentao/api-getModel-api-sql.json":
                return 200, b'{"success":true,"data":{"result":"1"}}', "application/json;charset=UTF-8"
            if path == "/zentao/user-login.html":
                acct = merged.get("account", [""])[0]
                if "updatexml" in acct:
                    return 200, XPATH_ERROR, "text/html;charset=UTF-8"
                return 200, b"<html><body>login page</body></html>"

        # ── 万户-Whir ──
        if oa == "万户-Whir":
            if path == "/defaultroot/evoInterfaceServlet":
                if merged.get("paramType", [""])[0] == "user":
                    return 200, b'{"userList":[{"id":"1","userName":"admin","password":"21232f297a57a5a743894a0e4a801fc3"}]}', "application/json;charset=UTF-8"
                return 403, b"<html><body>Forbidden</body></html>"

        return 404, b"<html><body>Not Found</body></html>", "text/html;charset=UTF-8"

    def _safe_route(self, method, path, merged):
        """安全模式：所有漏洞端点返回无漏洞特征响应（用于误报验证）。"""
        oa = self.oa
        if oa == "泛微-Ecology":
            if path == "/weaver/weaver.file.FileDownloadForOutDoc":
                return 200, b"<html><body>file not found</body></html>"
            if path == "/api/portal/weaver/weaver.do":
                return 200, b'{"code":"0","message":"ok"}', "application/json;charset=UTF-8"
            if path == "/workflow/WorkflowCenterTreeData.jsp":
                return 200, b"<html><body>ok</body></html>"
        if oa == "通达OA":
            if path == "/ispirit/login_code_scan.php":
                return 200, b'{"status":0,"msg":"fail"}', "application/json;charset=UTF-8"
            if path in ("/mac/gateway.php", "/general/document/index.php"):
                return 200, b"<html><body>ok</body></html>"
        if oa == "金蝶-Kingdee":
            if path.endswith("commoninstallServiceHttpFlowService"):
                return 200, b"<html><body>ok</body></html>"
            if path == "/CommonFileServer/c:/windows/win.ini":
                return 200, b"; empty", "text/plain;charset=UTF-8"
        if oa == "蓝凌-Landray":
            if path == "/sys/ui/extend/varkind/custom.jsp":
                return 200, b"<html><body>ok</body></html>"
            if path == "/sys/ui/extend/varkind/custom_pf.jsp":
                return 200, b"<html><body>ok</body></html>"
        if oa == "致远-Seeyon":
            if path in ("/seeyon/htmlofficeservlet", "/seeyon/thirdpartyController.do"):
                return 200, b"<html><body>ok</body></html>"
            if path == "/seeyon/ajax.do":
                return 200, b'{"code":"0","message":"ok"}', "application/json;charset=UTF-8"
        if oa == "用友-Yonyou":
            if path == "/servlet/~uapss/uploadServlet":
                return 200, b"<html><body>ok</body></html>"
            if path == "/portal/file":
                return 404, b"<html><body>Not Found</body></html>", "text/html;charset=UTF-8"
        if oa == "禅道-Zentao":
            if path == "/zentao/api-getModel-api-sql.json":
                return 200, b'{"success":false}', "application/json;charset=UTF-8"
            if path == "/zentao/user-login.html":
                return 200, b"<html><body>login page</body></html>"
        if oa == "万户-Whir":
            if path == "/defaultroot/evoInterfaceServlet":
                return 403, b"<html><body>Forbidden</body></html>"
        return 404, b"<html><body>Not Found</body></html>", "text/html;charset=UTF-8"

    def do_GET(self):
        code, body, ctype = self._route("GET")
        self._send(code, body, ctype)

    def do_POST(self):
        code, body, ctype = self._route("POST")
        self._send(code, body, ctype)


def start_servers(safe_mode=False):
    """启动全部 8 个 OA mock server，返回 (servers, threads)。"""
    servers = []
    for oa, port in PORTS.items():
        handler = type(f"Handler_{oa}", (Handler,), {"oa": oa, "safe": safe_mode})
        srv = HTTPServer(("127.0.0.1", port), handler)
        servers.append((oa, port, srv))
        print(f"{oa} mock listening on :{port} (safe={safe_mode})")
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for _, _, s in servers]
    for t in threads:
        t.start()
    return servers, threads


def stop_servers(servers):
    for _, _, s in servers:
        s.shutdown()


def main():
    servers, threads = start_servers(safe_mode=SAFE_MODE)
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        stop_servers(servers)


if __name__ == "__main__":
    main()
