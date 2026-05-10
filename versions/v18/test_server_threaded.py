"""WVS v18.0 本地测试服务器 - threading 版"""
import threading
import sqlite3
import os
from flask import Flask, request

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "test.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    c.execute("DELETE FROM users")
    c.executemany("INSERT INTO users VALUES (?,?,?)", [(1,"admin","admin123"),(2,"test","test456"),(3,"user","password")])
    conn.commit()
    conn.close()

init_db()

@app.route("/")
def index():
    return """<html><body>
    <h1>WVS Test Server</h1>
    <ul>
    <li><a href="/sqli/less-1?id=1">/sqli/less-1?id=1</a> - SQL Injection</li>
    <li><a href="/xss/reflected?name=admin">/xss/reflected?name=admin</a> - XSS</li>
    <li><a href="/cmdi?cmd=127.0.0.1">/cmdi?cmd=127.0.0.1</a> - Command Injection</li>
    <li><a href="/.env">/.env</a></li>
    <li><a href="/debug">/debug</a></li>
    </ul></body></html>"""

@app.route("/sqli/less-1")
def sqli_less1():
    id = request.args.get("id", "1")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute(f"SELECT username, password FROM users WHERE id = {id}")
        rows = c.fetchall()
        result = "<br>".join([f"User: {r[0]}, Pass: {r[1]}" for r in rows])
    except Exception as e:
        result = f"Error: {e}"
    conn.close()
    return f"<html><body><h1>SQLi - Less 1</h1><p>Query: {id}</p><p>{result}</p></body></html>"

@app.route("/xss/reflected")
def xss_reflected():
    name = request.args.get("name", "")
    return f'<html><body><h1>XSS - Reflected</h1><p>Hello, {name}</p></body></html>'

@app.route("/cmdi")
def cmdi():
    cmd = request.args.get("cmd", "127.0.0.1")
    import subprocess
    try:
        r = subprocess.run(f"ping -n 1 {cmd}", capture_output=True, text=True, timeout=5)
        result = r.stdout
    except Exception as e:
        result = str(e)
    return f"<html><body><h1>CMDi</h1><pre>{result}</pre></body></html>"

@app.route("/.env")
def env_file():
    return "DATABASE_URL=sqlite:///test.db\nSECRET_KEY=secret123\nAPI_KEY=sk-12345678"

@app.route("/debug")
def debug():
    return "<html><body><h1>Debug</h1><p>Server: Flask Dev</p></body></html>"

def run_server():
    app.run(host="127.0.0.1", port=8888, debug=False, use_reloader=False, threaded=True)

# 启动服务器
server_thread = threading.Thread(target=run_server, daemon=True)
server_thread.start()
print("Server started on http://127.0.0.1:8888")
print("Waiting for server to be ready...")
import time; time.sleep(2)
print("Ready!")
