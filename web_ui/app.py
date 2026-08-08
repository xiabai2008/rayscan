"""
RayScan 2.1.0 — Web UI (Flask + SSE 实时日志)
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import secrets  # noqa: E402  (用于 CSRF token 与可选 API token)

import asyncio
import json
import logging
import queue
import re
import threading
import time as time_module
from datetime import datetime
from pathlib import Path

from flask import (
    Flask,
    Response,
    abort,
    jsonify,
    render_template,
    request,
    session,
    stream_with_context,
)

from wvs.config import ConfigManager
from wvs.core import HTTPPool, WAVScanner
from wvs.core.result_merger import ResultMerger
from wvs.integrations import NucleiIntegration, SqlmapIntegration
from wvs.models import ScanTarget

app = Flask(__name__)

# ── 鉴权 + CSRF 配置 ──
# SECRET_KEY：必需（生产环境请用环境变量覆盖）。仅在缺失时给一个进程内随机值，
# 这意味着每次重启会让已有 session 失效 — 配合 CSRF 重新签发即可。
_app_secret = os.environ.get("RAYSCAN_WEB_SECRET")
if _app_secret:
    app.secret_key = _app_secret
else:
    app.secret_key = secrets.token_hex(32)
    print(
        "[WARN] 未设置 RAYSCAN_WEB_SECRET；Web UI 使用进程内随机 secret key。"
        "重启后所有 session/CSRF token 失效。生产请设置该环境变量。"
    )

# 简单的 API token（与登录 session 二选一）。默认生成一个并打印到终端，
# 用户可以 RAYSCAN_WEB_TOKEN=xxx 覆盖。
_DEFAULT_TOKEN = secrets.token_urlsafe(24)
API_TOKEN = os.environ.get("RAYSCAN_WEB_TOKEN") or _DEFAULT_TOKEN
print(f"[INFO] RayScan Web UI API token (header 'X-Api-Token'): {API_TOKEN}")
print("[INFO] 访问 /login 页面用此 token 登录；或 curl 调用时带 X-Api-Token。")


def _is_authorized() -> bool:
    """校验当前请求是否已通过鉴权（session 或 API token 任一即可）"""
    if session.get("authenticated"):
        return True
    token = request.headers.get("X-Api-Token", "")
    if token and secrets.compare_digest(token, API_TOKEN):
        return True
    return False


def _get_or_create_csrf_token() -> str:
    """返回当前 session 的 CSRF token（缺失时生成）"""
    tok = session.get("csrf_token")
    if not tok:
        tok = secrets.token_urlsafe(32)
        session["csrf_token"] = tok
    return tok


def _require_csrf():
    """校验 POST/PUT/DELETE 是否带有效 CSRF token（API token 用户不受限）"""
    if request.headers.get("X-Api-Token") and secrets.compare_digest(
        request.headers.get("X-Api-Token", ""), API_TOKEN
    ):
        return  # API token 用户已通过 _is_authorized，跳过 CSRF
    sent = request.headers.get("X-CSRF-Token", "")
    expected = session.get("csrf_token", "")
    if not expected or not sent or not secrets.compare_digest(sent, expected):
        abort(403, description="CSRF token missing or invalid")

# ── 扫描会话管理 ──
class ScanSession:
    def __init__(self):
        self.queue = queue.Queue()
        self.scanning = False
        self._thread = None
        self._result = None
        self._start_time = None
        self._found_vulns = []
        self._module_order = []

    def _setup_log_capture(self):
        """劫持扫描器所有模块的 logger，输出实时发到 SSE 队列"""
        class QueueHandler(logging.Handler):
            def __init__(self, q):
                super().__init__()
                self.q = q
                self.setFormatter(logging.Formatter("%(message)s"))
            def emit(self, record):
                try:
                    msg = self.format(record)
                    msg = re.sub(r'\033\[[0-9;]*m', '', msg)
                    if msg.strip():
                        self.q.put(("log", {
                            "level": record.levelname,
                            "text": msg,
                            "time": datetime.now().strftime("%H:%M:%S"),
                        }))
                    # 解析日志里的漏洞发现 → 即时推送到结果表
                    m = re.search(r'Found\s+(\S+)\s+in\s+(\S+)', msg, re.I)
                    m2 = re.search(r'🔴\s+发现\s+\[(\w+)\]\s+(\S+)', msg)
                    m3 = re.search(r'injection|XSS|LFI|SSRF|RCE|CMDi|XXE|sensitive|WAF', msg, re.I)
                    if m or m2 or m3:
                        self.q.put(("found", {"text": msg}))
                except Exception:
                    pass

        self._log_handler = QueueHandler(self.queue)
        for name in ["wvs.core.scanner", "wvs.core.crawler",
                      "wvs.modules", "wvs.core.session", "wvs"]:
            lg = logging.getLogger(name)
            lg.setLevel(logging.INFO)
            lg.addHandler(self._log_handler)
            lg.propagate = False

    def start(self, url: str, modules: list, config: dict):
        self.scanning = True
        self._start_time = time_module.time()
        self._found_vulns = []
        self._module_order = modules
        self._setup_log_capture()
        # 捕获 scanner 的 print() 输出
        self._orig_stdout = sys.stdout
        sys.stdout = self._StdoutCapture(self.queue, self._orig_stdout)
        self._thread = threading.Thread(
            target=self._worker, args=(url, modules, config), daemon=True
        )
        self._thread.start()

    class _StdoutCapture:
        """劫持 print() 输出发到 SSE 队列 + 同时保持终端显示"""
        def __init__(self, q, original_stdout):
            self.q = q
            self.orig = original_stdout
            self._buffer = ""
        def write(self, text):
            self.orig.write(text)
            self.orig.flush()
            self._buffer += text
            if "\n" in self._buffer or "\r" in self._buffer:
                lines = self._buffer.replace("\r\n", "\n").replace("\r", "\n").split("\n")
                for line in lines[:-1]:
                    clean = re.sub(r'\033\[[0-9;]*m', '', line).strip()
                    if clean:
                        self.q.put(("log", {
                            "level": "INFO",
                            "text": clean,
                            "time": datetime.now().strftime("%H:%M:%S"),
                        }))
                self._buffer = lines[-1]
        def flush(self):
            self.orig.flush()

    def stop(self):
        self.scanning = False

    def events(self):
        """SSE 事件生成器"""
        while True:
            try:
                typ, data = self.queue.get(timeout=1)
                yield f"event: {typ}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"
            except queue.Empty:
                if not self.scanning and self.queue.empty():
                    # 扫描结束且队列空了，发 done 后退出
                    yield f"event: done\ndata: {json.dumps({'msg': 'scan finished'})}\n\n"
                    break
                yield ": keepalive\n\n"  # SSE 心跳

    def _worker(self, url, modules, cfg):
        try:
            config = ConfigManager()
            for k, v in cfg.items():
                config.set(k, v)

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self._run_scan(url, modules, config))
            loop.close()
        except Exception as e:
            self._log("ERROR", f"扫描异常: {e}")
            import traceback
            for line in traceback.format_exc().split("\n"):
                if line.strip():
                    self._log("ERROR", line)
        finally:
            # 恢复 stdout
            sys.stdout = self._orig_stdout
            self.scanning = False
            self.queue.put(("done", {"msg": "扫描结束"}))

    async def _run_scan(self, url, modules, config):
        session = HTTPPool(config)
        scanner = WAVScanner(config, session)
        scanner._progress_callback = self._progress_cb

        for mod in modules:
            scanner.load_module(mod)

        self._log("INFO", "=" * 50)
        self._log("INFO", f"▶ 目标: {url}")
        self._log("INFO", f"▶ 模块: {', '.join(modules)}")
        self._log("INFO", "=" * 50)
        self._progress(5)

        target = ScanTarget(url=url)
        try:
            result = await asyncio.wait_for(
                scanner.scan(target),
                timeout=config.get("max_scan_time", 7200),
            )
        except asyncio.TimeoutError:
            self._log("ERROR", "扫描超时")
            return None

        elapsed = time_module.time() - self._start_time
        self._progress(100)
        self._log("INFO", f"✅ 完成！耗时 {elapsed:.0f}s")
        self._log("INFO",
            f"   端点: {result.endpoints_found}  |  请求: {result.requests_made}  |  漏洞: {len(result.vulnerabilities)}")

        sev_count = {}
        for v in result.vulnerabilities:
            sev = v.severity.value if hasattr(v.severity, "value") else str(v.severity)
            sev_count[sev] = sev_count.get(sev, 0) + 1
        for s in ["critical", "high", "medium", "low", "info"]:
            if s in sev_count:
                self._log("INFO", f"   [{s.upper()}] {sev_count[s]} 个")

        self.queue.put(("result", {
            "vulnerabilities": [
                {
                    "severity": v.severity.value if hasattr(v.severity, "value") else str(v.severity),
                    "type": v.type.value if hasattr(v.type, "value") else str(v.type),
                    "url": v.url,
                    "parameter": v.parameter or "",
                    "evidence": v.evidence or "",
                } for v in result.vulnerabilities
            ],
            "stats": {
                "endpoints": result.endpoints_found,
                "requests": result.requests_made,
                "elapsed": round(elapsed, 1),
            }
        }))
        self._result = result

    def _progress(self, pct):
        self.queue.put(("progress", {"pct": pct}))

    def _progress_cb(self, module_name, done, total, pct):
        if not self.scanning:
            return
        if module_name in set(m.lower() for m in self._module_order):
            total_m = len(self._module_order)
            try:
                idx = [m.lower() for m in self._module_order].index(module_name.lower())
            except ValueError:
                idx = 0
            base = 10 + (idx / max(total_m, 1)) * 75
            share = 75 / max(total_m, 1)
            val = int(base + (done / max(total, 1)) * share)
            self.queue.put(("progress", {"pct": min(val, 90)}))
            self.queue.put(("action", {
                "module": module_name,
                "done": done,
                "total": total,
                "text": f"检测 {module_name.upper()}... ({done}/{total})",
            }))
        elif module_name == "crawl":
            self.queue.put(("progress", {"pct": min(3 + (done / max(total, 1)) * 7, 10)}))
            self.queue.put(("action", {"text": f"爬虫 {done}/{total} 页面"}))

    def _log(self, level, text):
        self.queue.put(("log", {
            "level": level,
            "text": text,
            "time": datetime.now().strftime("%H:%M:%S"),
        }))

# 全局会话
scan_session = ScanSession()


# ── 路由 ──

@app.route("/")
def index():
    if not _is_authorized():
        return _redirect_to_login()
    return render_template("index.html", csrf_token=_get_or_create_csrf_token())


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        submitted = (request.form.get("token") or "").strip()
        if submitted and secrets.compare_digest(submitted, API_TOKEN):
            session["authenticated"] = True
            return _redirect_to_index()
        return render_template("login.html", error="Token 无效"), 401
    return render_template("login.html", error=None)


@app.route("/logout")
def logout():
    session.clear()
    return _redirect_to_login()


def _redirect_to_login():
    from flask import redirect, url_for
    return redirect(url_for("login"))


def _redirect_to_index():
    from flask import redirect, url_for
    return redirect(url_for("index"))


@app.route("/api/scan", methods=["POST"])
def api_scan():
    if not _is_authorized():
        return jsonify({"error": "未授权"}), 401
    _require_csrf()
    if scan_session.scanning:
        return jsonify({"error": "已有扫描正在运行"}), 400

    data = request.get_json() or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "请输入 URL"}), 400

    modules = data.get("modules") or []
    if not modules:
        return jsonify({"error": "至少选择一个模块"}), 400

    cfg = {
        "rate": int(data.get("rate", 15)),
        "timeout": int(data.get("timeout", 15)),
        "crawl_depth": int(data.get("crawl_depth", 2)),
        "crawl_max_urls": int(data.get("crawl_max_urls", 50)),
        "concurrent_endpoints": int(data.get("concurrent_endpoints", 10)),
    }
    if data.get("insecure"):
        cfg["verify_ssl"] = False

    scan_session.start(url, modules, cfg)
    return jsonify({"status": "started"})


@app.route("/api/stop", methods=["POST"])
def api_stop():
    if not _is_authorized():
        return jsonify({"error": "未授权"}), 401
    _require_csrf()
    scan_session.stop()
    return jsonify({"status": "stopped"})


@app.route("/api/stream")
def api_stream():
    if not _is_authorized():
        return jsonify({"error": "未授权"}), 401
    return Response(
        stream_with_context(scan_session.events()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.route("/api/export/<fmt>")
def api_export(fmt):
    if not _is_authorized():
        return jsonify({"error": "未授权"}), 401
    result = scan_session._result
    vulns = scan_session._found_vulns
    if not result and not vulns:
        return jsonify({"error": "没有结果"}), 400

    target_vulns = vulns if vulns else (
        result.vulnerabilities if result else []
    )

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    if fmt == "json":
        report = {
            "scan_time": ts,
            "total": len(target_vulns),
            "vulnerabilities": [
                {
                    "type": v.type.value if hasattr(v.type, "value") else str(v.type),
                    "severity": v.severity.value if hasattr(v.severity, "value") else str(v.severity),
                    "url": v.url,
                    "parameter": v.parameter or "",
                    "evidence": v.evidence or "",
                    "description": v.description or "",
                    "recommendation": v.recommendation or "",
                } for v in target_vulns
            ],
        }
        return jsonify(report)
    else:
        return jsonify({"error": "不支持格式"}), 400


# ── 扫描历史存储 ──────────────────────────────────────
SCAN_HISTORY: list = []  # [{id, target, time, duration, vulns, severity_counts}]


@app.route("/api/history")
def api_scan_history():
    """获取扫描历史"""
    if not _is_authorized():
        abort(401)
    limit = request.args.get("limit", 50, type=int)
    history = sorted(SCAN_HISTORY, key=lambda x: x.get("time", ""), reverse=True)[:limit]
    return jsonify(history)


@app.route("/api/stats")
def api_stats():
    """获取统计概览"""
    if not _is_authorized():
        abort(401)
    total_scans = len(SCAN_HISTORY)
    total_vulns = sum(h.get("total_vulns", 0) for h in SCAN_HISTORY)
    severity_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for h in SCAN_HISTORY:
        for sev, count in h.get("severity_counts", {}).items():
            if sev in severity_totals:
                severity_totals[sev] += count
    return jsonify({
        "total_scans": total_scans,
        "total_vulns": total_vulns,
        "severity_totals": severity_totals,
        "engines_available": {
            "nuclei": True,
            "sqlmap": True,
        }
    })


def _record_scan(target: str, vulns: list, duration: float) -> dict:
    """记录一次扫描到历史"""
    severity_counts = {}
    for v in vulns:
        sev = v.get("severity", "info") if isinstance(v, dict) else (v.severity.value if hasattr(v, "severity") else "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    record = {
        "id": len(SCAN_HISTORY) + 1,
        "target": target,
        "time": datetime.now().isoformat(),
        "duration": round(duration, 1),
        "total_vulns": len(vulns),
        "severity_counts": severity_counts,
    }
    SCAN_HISTORY.append(record)
    if len(SCAN_HISTORY) > 200:
        SCAN_HISTORY[:] = SCAN_HISTORY[-200:]
    return record


if __name__ == "__main__":
    # ── 默认仅本机绑定，避免无认证状态下对外暴露 ──
    # 需要对外服务时：RAYSCAN_WEB_HOST=0.0.0.0 python app.py
    bind_host = os.environ.get("RAYSCAN_WEB_HOST", "127.0.0.1")
    bind_port = int(os.environ.get("RAYSCAN_WEB_PORT", "5000"))
    print("=" * 50)
    print("  RayScan 2.1.0 — Web UI")
    print(f"  http://{bind_host}:{bind_port}")
    if bind_host in ("0.0.0.0", "::"):
        print("  [WARN] 监听所有网卡 — 请确保已启用鉴权 (RAYSCAN_WEB_TOKEN)")
    print("=" * 50)
    app.run(debug=False, host=bind_host, port=bind_port, threaded=True)
