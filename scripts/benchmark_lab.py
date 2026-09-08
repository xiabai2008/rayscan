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

# OA 靶标独立 Flask 实例（与主靶场互不污染指纹）
oa_app = Flask("benchmark_lab_oa")
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


def _hint(default_type="text/html; charset=utf-8"):
    def deco(fn):
        def wrapper(*a, **kw):
            resp = fn(*a, **kw)
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
    ]
    body = "<html><head><title>Benchmark Lab</title></head><body><h1>Benchmark Lab</h1><ul>"
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
    parser = argparse.ArgumentParser(description="RayScan benchmark lab")
    parser.add_argument("--port", type=int, default=18099)
    parser.add_argument("--oa-port", type=int, default=None, help="OA 靶标端口（指定则只运行 OA 应用）")
    parser.add_argument("--oa-version", default="1.3.2", help="OA 靶标 Nacos 版本号（默认 1.3.2 漏洞版）")
    args = parser.parse_args()

    if args.oa_port:
        global OA_VERSION
        OA_VERSION = args.oa_version
        print(f"[BenchmarkLab] OA 靶标 http://127.0.0.1:{args.oa_port}/  (Nacos {OA_VERSION} 形态, 仅本机访问)")
        oa_app.run(host="127.0.0.1", port=args.oa_port, debug=False, use_reloader=False)
        return

    print(f"[BenchmarkLab] http://127.0.0.1:{args.port}/  (仅本机访问)")
    app.run(host="127.0.0.1", port=args.port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
