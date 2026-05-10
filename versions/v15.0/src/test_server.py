"""WVS v18.0 本地测试靶场

一个简单的 Flask 服务器，包含常见 Web 漏洞，用于验证扫描器功能。
运行方式: python test_server.py
"""
from flask import Flask, request, render_template_string, redirect, make_response
import sqlite3
import os

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "test.db")

# ============== 初始化数据库 ==============
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    """)
    c.execute("DELETE FROM users")
    c.executemany("INSERT INTO users (username, password) VALUES (?, ?)", [
        ("admin", "admin123"),
        ("test", "test456"),
        ("user", "password")
    ])
    conn.commit()
    conn.close()

init_db()

# ============== SQL 注入漏洞页面 ==============

@app.route("/sqli/less-1")
def sqli_less1():
    """经典的 SQLi 注入点 - URL 参数未经处理直接拼接到 SQL"""
    id = request.args.get("id", "1")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    query = f"SELECT username, password FROM users WHERE id = {id}"
    try:
        c.execute(query)
        rows = c.fetchall()
        result = "<br>".join([f"User: {r[0]}, Pass: {r[1]}" for r in rows])
    except Exception as e:
        result = f"Error: {e}"
    conn.close()
    return f"<html><body><h1>SQL Injection - Less 1</h1><p>Query: {query}</p><p>Result: {result}</p><p><a href='?id=1'>Normal</a> | <a href='?id=1 UNION SELECT 1,2'>SQLi</a></p></body></html>"

@app.route("/sqli/less-2")
def sqli_less2():
    """数字型 SQL 注入"""
    id = request.args.get("id", "1")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute(f"SELECT username FROM users WHERE id = {id}")
        result = c.fetchall()
    except Exception as e:
        result = str(e)
    conn.close()
    return f"<html><body><h1>SQL Injection - Less 2 (Numeric)</h1><p>Result: {result}</p></body></html>"

@app.route("/sqli/login", methods=["GET", "POST"])
def sqli_login():
    """SQL 注入登录绕过"""
    error = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        c.execute(query)
        if c.fetchone():
            error = "Login successful!"
        else:
            error = "Login failed."
        conn.close()
    return f"""
    <html><body>
    <h1>SQL Injection - Login Bypass</h1>
    <form method="POST">
        <input name="username" placeholder="username">
        <input name="password" type="password" placeholder="password">
        <button type="submit">Login</button>
    </form>
    <p>Test: username=<code>admin' OR '1'='1</code> password=<code>anything</code></p>
    <p>{error}</p>
    </body></html>
    """

# ============== XSS 漏洞页面 ==============

@app.route("/xss/反射型")
def xss_reflected():
    """反射型 XSS - URL 参数直接输出到页面"""
    name = request.args.get("name", "")
    return f"""
    <html><body>
    <h1>XSS - Reflected</h1>
    <p>Hello, {name}</p>
    <p><a href="?name=admin">Normal</a> | <a href="?name=<script>alert('XSS')</script>">XSS</a></p>
    </body></html>
    """

@app.route("/xss/存储型", methods=["GET", "POST"])
def xss_stored():
    """存储型 XSS - 评论系统"""
    comments = []
    if request.method == "POST":
        comment = request.form.get("comment", "")
        with open(os.path.join(os.path.dirname(__file__), "comments.txt"), "a") as f:
            f.write(comment + "\n")
    try:
        with open(os.path.join(os.path.dirname(__file__), "comments.txt"), "r") as f:
            comments = f.readlines()
    except:
        pass
    return f"""
    <html><body>
    <h1>XSS - Stored (Comments)</h1>
    <form method="POST">
        <textarea name="comment" placeholder="Your comment"></textarea>
        <button type="submit">Submit</button>
    </form>
    <h2>Comments:</h2>
    {''.join([f'<div class="comment">{c.strip()}</div>' for c in comments])}
    <p>Test XSS: <code>&lt;script&gt;alert(document.cookie)&lt;/script&gt;</code></p>
    </body></html>
    """

@app.route("/xss/dom")
def xss_dom():
    """DOM XSS - JavaScript 直接读取 URL 参数"""
    name = request.args.get("name", "")
    html = f"""
    <html><body>
    <h1>XSS - DOM Based</h1>
    <div id="output"></div>
    <script>
        var name = new URLSearchParams(window.location.search).get("name");
        document.getElementById("output").innerHTML = "Hello, " + name;
    </script>
    <p><a href="?name=admin">Normal</a> | <a href="?name=<img src=x onerror=alert('XSS')>">DOM XSS</a></p>
    </body></html>
    """
    return html

# ============== 命令注入页面 ==============

@app.route("/cmdi")
def cmdi():
    """命令注入 - ping 命令"""
    cmd = request.args.get("cmd", "127.0.0.1")
    import subprocess
    result = ""
    try:
        r = subprocess.run(f"ping -n 1 {cmd}", capture_output=True, text=True, timeout=5)
        result = r.stdout + r.stderr
    except Exception as e:
        result = str(e)
    return f"""
    <html><body>
    <h1>Command Injection</h1>
    <form>
        <input name="cmd" value="{cmd}" placeholder="IP or command">
        <button type="submit">Ping</button>
    </form>
    <pre>{result}</pre>
    <p>Test: <code>127.0.0.1 & whoami</code></p>
    </body></html>
    """

# ============== 敏感文件暴露 ==============

@app.route("/.env")
def env_file():
    """.env 文件（配置泄露）"""
    return "DATABASE_URL=sqlite:///test.db\nSECRET_KEY=mysecret123\nAPI_KEY=sk-12345678"

@app.route("/config.php")
def config_php():
    """config.php 备份"""
    return "<?php\n$db_host = 'localhost';\n$db_user = 'root';\n$db_pass = 'password123';\n?>"

@app.route("/.git/config")
def git_config():
    """.git/config"""
    return "[core]\n\trepositoryformatversion = 0"

@app.route("/debug")
def debug():
    """调试页面"""
    return f"""
    <html><body>
    <h1>Debug Info</h1>
    <p>Server: Flask Dev</p>
    <p>Python: {os.sys.version}</p>
    <p>DB: {DB_PATH}</p>
    <p>Remote Addr: {request.remote_addr}</p>
    </body></html>
    """

@app.route("/robots.txt")
def robots():
    """robots.txt"""
    return "User-agent: *\nDisallow: /admin\nDisallow: /.git"

# ============== 正常页面 ==============

@app.route("/")
def index():
    return """
    <html><body>
    <h1>WVS Test Server</h1>
    <h2>SQL Injection:</h2>
    <ul>
        <li><a href="/sqli/less-1?id=1">/sqli/less-1</a> - GET 参数 SQLi</li>
        <li><a href="/sqli/less-2?id=1">/sqli/less-2</a> - 数字型 SQLi</li>
        <li><a href="/sqli/login">/sqli/login</a> - 登录绕过</li>
    </ul>
    <h2>XSS:</h2>
    <ul>
        <li><a href="/xss/反射型?name=admin">/xss/反射型</a></li>
        <li><a href="/xss/存储型">/xss/存储型</a></li>
        <li><a href="/xss/dom?name=admin">/xss/dom</a> - DOM XSS</li>
    </ul>
    <h2>Command Injection:</h2>
    <ul>
        <li><a href="/cmdi?cmd=127.0.0.1">/cmdi</a></li>
    </ul>
    <h2>Sensitive Files:</h2>
    <ul>
        <li><a href="/.env">/.env</a></li>
        <li><a href="/config.php">/config.php</a></li>
        <li><a href="/.git/config">/.git/config</a></li>
        <li><a href="/robots.txt">/robots.txt</a></li>
    </ul>
    </body></html>
    """

if __name__ == "__main__":
    print("=" * 60)
    print("WVS Test Server - http://127.0.0.1:8888")
    print("=" * 60)
    print("Vulnerabilities:")
    print("  SQLi: /sqli/less-1?id=1")
    print("  XSS:  /xss/反射型?name=test")
    print("  CMDi: /cmdi?cmd=127.0.0.1")
    print("  Config: /.env")
    print("=" * 60)
    app.run(host="0.0.0.0", port=8888, debug=False)
