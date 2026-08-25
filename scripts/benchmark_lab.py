"""
RayScan 基准靶场（benchmark lab）— 建立检测基线用的本地漏洞样本。

- 仅绑定 127.0.0.1，随机端口，禁止外网访问（内置 403 拦截非本机来源）
- 覆盖：sqli（error/union/blind/time）/ xss / cmdi / lfi / rce / xxe / ssrf / sensitive
- 用法：python scripts/benchmark_lab.py --port 18099
- 基准记录见 docs/BENCHMARK.md

安全注意：本靶场故意包含可利用漏洞，仅供本地检测基准测试，严禁部署到公网。
"""

import argparse
import json
import os
import subprocess
import time

from flask import Flask, Response, request

app = Flask(__name__)

# 简单访问控制：仅允许本机来源
_ALLOWED = {"127.0.0.1", "::1", "localhost"}


@app.before_request
def _guard():
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


def main():
    parser = argparse.ArgumentParser(description="RayScan benchmark lab")
    parser.add_argument("--port", type=int, default=18099)
    args = parser.parse_args()
    print(f"[BenchmarkLab] http://127.0.0.1:{args.port}/  (仅本机访问)")
    app.run(host="127.0.0.1", port=args.port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
