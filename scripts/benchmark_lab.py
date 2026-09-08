"""
RayScan 基准靶场（benchmark lab）— 建立检测基线用的本地漏洞样本。

- 仅绑定 127.0.0.1，随机端口，禁止公网访问（内置 403 拦截非本机来源）
- 主靶场覆盖：sqli（error/union/blind/time）/ xss / cmdi / lfi / rce / xxe / ssrf /
  sensitive / idor(业务逻辑) / 误报护栏（反射端点、success:false JSON）
- OA 靶标（--oa-port，独立端口）：Nacos 形态三级链路靶标 —— 指纹→版本→规则证据，
  --oa-version 控制版本（<1.4.1 漏洞版应检出 / ≥1.4.1 修复版应被版本过滤跳过）
- 用法：python scripts/benchmark_lab.py --port 18099
        python scripts/benchmark_lab.py --oa-port 18101 --oa-version 1.3.2
- 基准记录见 docs/BENCHMARK.md 与 docs/BASELINES.md（黄金靶场矩阵）

安全注意：本靶场故意包含可利用漏洞，仅供本地检测基准测试，严禁部署到公网。
"""

import argparse
import json
import os
import subprocess
import time

from flask import Flask, Response, request

app = Flask(__name__)
app.url_map.strict_slashes = False  # 扫描器会把端点补尾斜杠,两种形态都必须可路由

# OA 靶标独立 Flask 实例（与主靶场互不污染指纹）
oa_app = Flask("benchmark_lab_oa")
oa_app.url_map.strict_slashes = False
OA_VERSION = "1.3.2"

# 简单访问控制：仅允许本机来源
_ALLOWED = {"127.0.0.1", "::1", "localhost"}


@app.before_request
def _guard():
    if request.remote_addr not in _ALLOWED:
        return Response("forbidden", status=403)


@oa_app.before_request
def _oa_guard():
    if request.remote_addr not in _ALLOWED:
        return Response("forbidden", status=403)


@app.after_request
def _strip_server(resp):
    """剥离 Werkzeug 版本头：api 模块的 Server Version Disclosure 会在每个端点刷屏，
    黄金矩阵的 api 期望保持精确（版本泄露能力由其单测覆盖）。"""
    resp.headers.pop("Server", None)
    return resp


@oa_app.after_request
def _oa_strip_server(resp):
    resp.headers.pop("Server", None)
    return resp


def _hint(default_type="text/html; charset=utf-8"):
    def deco(fn):
        def wrapper(*a, **kw):
            resp = fn(*a, **kw)
            if isinstance(resp, Response):
                return resp  # 路由直接返回 Response(自定义头场景)时透传,避免嵌套 500
            if isinstance(resp, tuple):
                body, code = resp
            else:
                body, code = resp, 200
            ctype = default_type
            if isinstance(body, (dict, list)):
                body = json.dumps(body)
                ctype = "application/json"
            return Response(body, status=code, content_type=ctype)

        wrapper.__name__ = fn.__name__
        return wrapper

    return deco


# ── SQLi ──────────────────────────────────────────────────────────


@app.route("/sqli/error")
@_hint()
def sqli_error():
    v = request.args.get("id", "")
    if "'" in v or "or" in v.lower():
        return (
            "<html><body>SQLSTATE[42000]: Syntax error or access violation: "
            "1064 You have an error in your SQL syntax near '" + v[:40] + "' at line 1</body></html>"
        )
    return "<html><body>user id=%s not found</body></html>" % v


@app.route("/sqli/union")
@_hint()
def sqli_union():
    v = request.args.get("id", "")
    if "union" in v.lower():
        return "<html><body>1|admin|5f4dcc3b5aa765d61d8327deb882cf99</body></html>"
    return "<html><body>user 1</body></html>"


@app.route("/sqli/blind")
@_hint()
def sqli_blind():
    import re as _re

    v = request.args.get("id", "")
    # boolean 差异：通用数值等值判断（1=1 → admin，1=2 → guest）——
    # 兼容检测器的多组 True/False payload 对与二次验证
    m = _re.search(r"(\d+)\s*=\s*(\d+)", v)
    if m and m.group(1) == m.group(2):
        return "<html><body>Hello admin</body></html>"
    # 兼容 verify 用 payload：' OR '1'='1 / " OR "1"="1 / 'a'='a / 1=1
    if any(k in v for k in ("1=1", "'a'='a", "1'='1", '1"="1')):
        return "<html><body>Hello admin</body></html>"
    return "<html><body>Hello guest</body></html>"


@app.route("/sqli/time")
@_hint()
def sqli_time():
    v = request.args.get("id", "")
    if "sleep" in v.lower():
        time.sleep(2)
        return "<html><body>slow response</body></html>"
    return "<html><body>fast</body></html>"


# ── XSS ───────────────────────────────────────────────────────────


@app.route("/xss/reflected")
@_hint()
def xss_reflected():
    q = request.args.get("q", "")
    return "<html><body>search result: %s</body></html>" % q


# ── CMDi ──────────────────────────────────────────────────────────


@app.route("/cmdi")
@_hint()
def cmdi():
    host = request.args.get("host", "127.0.0.1")
    # 命令拼接注入点（本地靶场专用）
    out = subprocess.run(
        "ping -n 1 " + host if os.name == "nt" else "ping -c 1 " + host,
        shell=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    return "<html><body><pre>%s</pre></body></html>" % (out.stdout + out.stderr)


# ── LFI ───────────────────────────────────────────────────────────


@app.route("/lfi")
@_hint()
def lfi():
    f = request.args.get("file", "index.html")
    try:
        with open(f, "r", errors="replace") as fh:
            content = fh.read(2000)
        return "<html><body><pre>%s</pre></body></html>" % content
    except OSError:
        return "<html><body>file not found</body></html>"


# ── RCE ───────────────────────────────────────────────────────────


@app.route("/rce")
@_hint()
def rce():
    cmd = request.args.get("cmd", "echo hi")
    out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
    return "<html><body><pre>%s</pre></body></html>" % (out.stdout + out.stderr)


# ── XXE ───────────────────────────────────────────────────────────


@app.route("/xxe", methods=["POST"])
@_hint()
def xxe():
    import xml.etree.ElementTree as ET

    body = request.get_data(as_text=True)
    try:
        root = ET.fromstring(body)
        return "<html><body>parsed: %s</body></html>" % (root.findtext("name") or "")
    except ET.ParseError as e:
        # 外部实体展开失败的解析器错误特征
        return "<html><body>failed to load external entity: %s</body></html>" % e, 200


# 模拟"支持外部实体展开"的解析器（Python ET 默认拒绝展开）：
# DOCTYPE 声明 SYSTEM 实体时按路径返回模拟文件内容 —— 检测器视角等价于真实 XXE 文件读取
_SIMULATED_FILES = {
    "passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin/nologin\n",
    "hosts": "127.0.0.1\tlocalhost\n::1\tlocalhost\n",
    "win.ini": "[fonts]\n[extensions]\n[Mail]\n",
}


@app.route("/xxe_get")
@_hint()
def xxe_get():
    import re

    xml = request.args.get("xml", "")
    m = re.search(r'<!ENTITY[^>]*SYSTEM\s+"([^"]+)"', xml, re.I)
    if m:
        path = m.group(1).lower()
        for key, content in _SIMULATED_FILES.items():
            if key in path:
                return content, 200
        return "<html><body>file not found</body></html>", 200
    return "<html><body>parsed xml ok</body></html>", 200


# ── SPA mock（第五轮：--js-render 验证用，模拟 Angular 形态） ─────

_SPA_HTML = """<!DOCTYPE html>
<html><head><title>SPA App</title></head>
<body><div id="app"></div>
<script>
fetch('/rest/products/search?q=test').then(function(r){return r.json();}).then(function(d){
  document.getElementById('app').innerText = JSON.stringify(d);
});
fetch('/rest/user/login', {method:'POST', headers:{'Content-Type':'application/json'},
  body: JSON.stringify({email:'admin@example.com', password:'x'})});
</script></body></html>"""


@app.route("/spa")
@_hint()
def spa():
    return _SPA_HTML, 200


@app.route("/rest/products/search")
@_hint()
def rest_search():
    q = request.args.get("q", "")
    # 反射 q 的 JSON 响应（Juice Shop 形态）
    return {"data": [{"name": "result for %s" % q}]}, 200


@app.route("/rest/user/login", methods=["POST"])
@_hint()
def rest_login():
    import re as _re

    body = request.get_json(silent=True) or {}
    email = body.get("email", "")
    # SQLi 模拟（精确等值语义）：' OR '1'='1 → 真；' OR '1'='2 → 假（boolean 差异）
    m = _re.search(r"['\"]?(\w+)['\"]?\s*=\s*['\"]?(\w+)['\"]?", email)
    if m and m.group(1) == m.group(2):
        return {"authentication": {"token": "fake-token-abc123", "user": {"email": email}}}, 200
    return {"message": "Invalid email or password."}, 401


@app.route("/")
def index():
    links = [
        "/sqli/error?id=1",
        "/sqli/union?id=1",
        "/sqli/blind?id=1",
        "/sqli/time?id=1",
        "/xss/reflected?q=test",
        "/cmdi?host=127.0.0.1",
        "/lfi?file=index.html",
        "/rce?cmd=echo%20hi",
        "/ssti?name=world",
        "/ssrf?url=http://127.0.0.1/",
        "/xxe",
        "/xxe_get?xml=<xml>",
        "/.env",
        "/backup/backup.sql",
        "/spa",
        "/api/invoice?id=1001",
        "/api/secure-invoice?id=3001",
        "/api/users",
        "/safe/api?code=1",
        "/login",
        "/user/login",
        "/api/cors-open",
        "/api/cors-strict",
        "/api/debug-info",
        "/jsapp",
        "/jsapp-clean",
    ]
    body = '<html><head><title>Benchmark Lab</title><script src="/static/app.js"></script></head><body><h1>Benchmark Lab</h1><ul>'
    for link in links:
        body += f'<li><a href="{link}">{link}</a></li>'
    body += "</ul></body></html>"
    return Response(body, content_type="text/html; charset=utf-8")


# ── SSRF ──────────────────────────────────────────────────────────


@app.route("/ssrf")
@_hint()
def ssrf():
    import urllib.request

    url = request.args.get("url", "")
    if not url.startswith(("http://", "https://")):
        return "<html><body>bad url</body></html>"
    # 模拟云 metadata 服务（真实云环境 169.254.169.254 返回字段列表）
    if "169.254.169.254" in url:
        return (
            "ami-id\ninstance-id\npublic-ipv4\nsecurity-credentials\niam/\nplacement/\nmeta-data/\n",
            200,
        )
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = resp.read(500).decode("utf-8", "replace")
        return "<html><body><pre>%s</pre></body></html>" % data
    except Exception as e:
        return "<html><body>fetch error: %s</body></html>" % e


# ── SSTI（真实模板引擎渲染，跨平台真阳性） ─────────────────────


@app.route("/ssti")
@_hint()
def ssti():
    from jinja2 import Template

    name = request.args.get("name", "world")
    try:
        # 用户输入作为模板本体 —— 真实 SSTI 场景（{{7*7}} 求值为 49）
        return "<html><body>hello %s</body></html>" % Template(name).render()
    except Exception:
        # 模板语法错误时回显原始输入（非渲染结果）
        return "<html><body>hello %s</body></html>" % name, 200


# ── Sensitive ─────────────────────────────────────────────────────


@app.route("/.env")
@_hint()
def env_leak():
    return "DB_PASSWORD=secret123\nAPI_KEY=sk-benchmark-abc\n", 200


@app.route("/backup/backup.sql")
@_hint()
def backup_leak():
    return "INSERT INTO users VALUES (1,'admin','5f4dcc3b5aa765d61d8327deb882cf99');\n", 200


# ── IDOR（业务逻辑，v2.2 黄金靶场） ──────────────────────────────


@app.route("/api/invoice")
@_hint()
def idor_invoice():
    """漏洞靶标：任意数字 id 均返回同结构发票页 → 对象替换(±1/+100)应检出。

    页面满足判定条件：≥100 字节、HTML 标签结构 >5、两个替换值响应一致。
    故意不回显 id（静态内容）：保持 idor 单一漏洞语义，不引入反射型
    sqli/xss 噪音（黄金矩阵将本端点同时用作 sqli/xss 误报护栏）。
    """
    request.args.get("id", "1001")
    body = (
        "<html><head><title>Invoice Detail</title></head><body>"
        "<h1>Invoice 1001</h1>"
        "<p>customer: cust-1001</p><p>amount: 128.50</p><p>status: paid</p>"
        "<table><tr><th>item</th><th>qty</th></tr><tr><td>license</td><td>1</td></tr></table>"
        "</body></html>"
    )
    return body, 200


@app.route("/api/secure-invoice")
@_hint()
def idor_secure_invoice():
    """良性靶标：非属主 id 一律 403 → 对象替换不应检出（越权护栏）。"""
    iid = request.args.get("id", "3001")
    if iid != "3001":
        return "<html><body>Access Denied</body></html>", 403
    body = (
        "<html><head><title>Invoice Detail</title></head><body>"
        "<h1>Invoice 3001</h1><p>customer: cust-3001</p><p>amount: 88.00</p><p>status: open</p>"
        "</body></html>"
    )
    return body, 200


@app.route("/api/users")
@app.route("/api/users/")
@_hint()
def idor_bulk_users():
    """漏洞靶标：page=all 返回含敏感字段的批量数据 → 批量接口探测应检出。

    双路由注册（含尾斜杠）：扫描器会对目录形端点补尾斜杠，缺省路由会 404。
    """
    if request.args.get("page") == "all" or request.args.get("export") == "all":
        data = {
            "users": [
                {
                    "id": i,
                    "email": f"user{i}@corp.test",
                    "phone": "1380000000%d" % i,
                    "password_hash": "5f4dcc3b5aa765d61d8327deb882cf9%d" % i,
                    "id_card": "11010119900101001%d" % i,
                }
                for i in range(5)
            ]
        }
        return json.dumps(data), 200
    return {"users": [{"id": 1, "email": "user1@corp.test"}]}, 200


@app.route("/safe/api")
@_hint()
def safe_api():
    """误报护栏：success:false JSON（sqli success 子串误报回归防线）。"""
    return {"success": False, "message": "record not found"}, 200


# ── weakpass（弱口令） ────────────────────────────────────────────


@app.route("/login", methods=["GET", "POST"])
@_hint()
def login_form():
    """漏洞靶标：admin/admin123 可登录（weakpass 前 10 组合内）→ 弱口令应检出。

    成功响应含 success 标记（welcome/dashboard/logout）且不含 fail 标记
    （invalid/failed/error/incorrect/wrong）；失败响应含 fail 标记。
    """
    if request.method == "GET":
        return (
            "<html><head><title>Login</title></head><body><h1>Login</h1>"
            '<form method="post"><input name="username"/><input name="password" type="password"/>'
            '<button type="submit">Login</button></form></body></html>'
        )
    username = request.values.get("username") or request.values.get("log") or request.values.get("user_login") or ""
    password = request.values.get("password") or request.values.get("pwd") or request.values.get("user_pass") or ""
    if username == "admin" and password == "admin123":
        return (
            "<html><head><title>Dashboard</title></head><body>"
            "<h1>Welcome admin</h1><p>dashboard ready</p>"
            '<a href="/logout">logout</a></body></html>'
        )
    return "<html><body>Invalid username or password</body></html>", 200


@app.route("/user/login", methods=["GET", "POST"])
@_hint()
def login_hardened():
    """误报护栏：强口令端点，任何凭据都返回含 fail 标记的响应 → weakpass 不应报。"""
    if request.method == "GET":
        return "<html><body>Login</body></html>"
    return "<html><body>Incorrect username or password, please retry</body></html>", 200


# ── webshell ──────────────────────────────────────────────────────


@app.route("/cmd.php")
@_hint()
def fake_webshell():
    """漏洞靶标：一句话木马特征页（eval($_POST[)）→ webshell 路径探测应检出。"""
    return "<?php @eval($_POST['cmd']); ?>", 200


# ── api（CORS / 敏感信息） ────────────────────────────────────────


@app.route("/api/cors-open")
@_hint()
def cors_open():
    """漏洞靶标：任意 Origin 反射 + 允许凭据 → api 模块 CORS 配置错误应检出。"""
    origin = request.headers.get("Origin", "*")
    return Response(
        json.dumps({"user": "alice", "role": "member"}),
        status=200,
        content_type="application/json",
        headers={"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"},
    )


@app.route("/api/cors-strict")
@_hint()
def cors_strict():
    """误报护栏：固定可信 Origin（不反射）→ CORS 不应报。"""
    return Response(
        json.dumps({"user": "alice"}),
        status=200,
        content_type="application/json",
        headers={"Access-Control-Allow-Origin": "https://trusted.example"},
    )


@app.route("/api/debug-info")
@_hint()
def api_debug_info():
    """漏洞靶标：响应含 secret_key（16+ 字符）→ api 敏感信息泄露应检出。"""
    return {"debug": True, "secret_key": "supersecretkey12345678"}, 200


# ── js_analysis / jspathfinder（JS 信息提取） ─────────────────────


@app.route("/jsapp")
@_hint()
def jsapp():
    """漏洞靶标：引用含敏感信息/隐藏路径的 app.js。"""
    return '<html><head><title>JS App</title></head><body><script src="/static/app.js"></script></body></html>'


@app.route("/static/app.js")
@_hint(default_type="application/javascript")
def app_js():
    return (
        'var api_key = "raylab1234567890abcdefgh";\n'
        'var db_url = "mysql://admin:pw@10.0.0.5:3306/app";\n'
        'var backup_path = "/backup/backup.sql";\n'
        "fetch(backup_path);\n"
    ), 200


@app.route("/jsapp-clean")
@_hint()
def jsapp_clean():
    """误报护栏：引用无敏感信息的 clean.js → js_analysis 不应报。"""
    return '<html><head><title>Clean App</title></head><body><script src="/static/clean.js"></script></body></html>'


@app.route("/static/clean.js")
@_hint(default_type="application/javascript")
def clean_js():
    """无引号字符串/无路径/无密钥的纯逻辑 JS → 任何 pattern 都不应命中。"""
    return "var a = 1;\nvar b = 2;\nfunction add(x, y) { return x + y; }\n", 200


# ── waf（WAF 指纹） ───────────────────────────────────────────────


@app.route("/waf-protected")
def waf_protected():
    """漏洞靶标：Cloudflare 形态拦截页（server: cloudflare + cf-ray）→ waf 应识别。"""
    return Response(
        "<html><head><title>Attention Required! | Cloudflare</title></head>"
        "<body>Sorry, you have been blocked. Ray ID: 7abc123</body></html>",
        status=403,
        headers={
            "Server": "cloudflare",
            "cf-ray": "raylab-7abc123",
            "Set-Cookie": "__cfduid=raylab1234567890; Path=/; HttpOnly",
            "Content-Type": "text/html; charset=utf-8",
        },
    )


# ── authbypass（JWT 弱密钥，独立靶标路径） ────────────────────────


@app.route("/jwt/profile", methods=["GET"])
@_hint()
def jwt_profile():
    """靶标：校验 Bearer JWT 的 HMAC-SHA256 签名（弱密钥 "secret"）。

    扫描器注入弱密钥签发的 token → 200（弱密钥可伪造,authbypass 应检出
    jwt-weak-secret）；无/坏 token → 401（认证头移除重放路径因此不误报）。
    """
    import base64
    import hashlib
    import hmac as _hmac

    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return {"error": "unauthorized"}, 401
    token = auth[7:].strip()
    parts = token.split(".")
    if len(parts) != 3:
        return {"error": "unauthorized"}, 401
    try:
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        expected = (
            base64.urlsafe_b64encode(_hmac.new(b"secret", signing_input, hashlib.sha256).digest()).rstrip(b"=").decode()
        )
        if not _hmac.compare_digest(expected, parts[2]):
            return {"error": "unauthorized"}, 401
    except Exception:
        return {"error": "unauthorized"}, 401
    return {"profile": "lab-user", "role": "member"}, 200


# ── OA 靶标（独立 oa_app，Nacos 形态） ────────────────────────────

_NACOS_HOME = """<!DOCTYPE html>
<html><head><title>Nacos console</title></head>
<body><div id="root"></div>
<script>window.nacos_version = "%(version)s";</script>
<script>console.nacos = true;</script>
</body></html>"""

_NACOS_USERS = (
    '{"code":200,"message":null,"data":null,'
    '"pageItems":[{"username":"nacos","password":"$2a$10$EuWPZHzz32dJN7jexM34MOeYirDdFAZm2kuWj7VEOJhhZkDrxfvUu",'
    '"enabled":true}],"totalCount":1}'
)


@oa_app.route("/")
@_hint()
def oa_index():
    return _NACOS_HOME % {"version": OA_VERSION}, 200


@oa_app.route("/nacos/v1/auth/users")
@_hint()
def oa_users():
    """漏洞响应：与版本无关地返回 pageItems（修复版靠版本过滤跳过，检验过滤器本身）。"""
    return _NACOS_USERS, 200


@oa_app.route("/nacos/v1/cs/configs")
@_hint()
def oa_configs():
    """无 evidence 的通用检查项：404 JSON → 不应报（防通用检查项误报）。"""
    return {"code": 404, "message": "config not found"}, 404


@oa_app.route("/nacos/v1/console/server/state")
@_hint()
def oa_state():
    return {"version": OA_VERSION}, 200


def main():
    from werkzeug.serving import WSGIRequestHandler

    class _LabRequestHandler(WSGIRequestHandler):
        """隐藏 Werkzeug/Python 版本串。

        Werkzeug 开发服务器会在 WSGI 层之后覆写 Server 头,导致:
        1) api 模块 Server Version Disclosure 在每个端点刷屏
        2) /waf-protected 的 Server: cloudflare 签名被覆盖 → waf 永不匹配
        """

        def version_string(self) -> str:
            return "benchmark-lab"

    parser = argparse.ArgumentParser(description="RayScan benchmark lab")
    parser.add_argument("--port", type=int, default=18099)
    parser.add_argument("--oa-port", type=int, default=None, help="OA 靶标端口（指定则只运行 OA 应用）")
    parser.add_argument("--oa-version", default="1.3.2", help="OA 靶标 Nacos 版本号（默认 1.3.2 漏洞版）")
    args = parser.parse_args()

    if args.oa_port:
        global OA_VERSION
        OA_VERSION = args.oa_version
        print(f"[BenchmarkLab] OA 靶标 http://127.0.0.1:{args.oa_port}/  (Nacos {OA_VERSION} 形态, 仅本机访问)")
        oa_app.run(
            host="127.0.0.1", port=args.oa_port, debug=False, use_reloader=False, request_handler=_LabRequestHandler
        )
        return

    print(f"[BenchmarkLab] http://127.0.0.1:{args.port}/  (仅本机访问)")
    app.run(host="127.0.0.1", port=args.port, debug=False, use_reloader=False, request_handler=_LabRequestHandler)


if __name__ == "__main__":
    main()
