"""
RayScan 1.0.2 — Web UI (Flask + SSE 实时日志)
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import asyncio
import json
import logging
import queue
import re
import threading
import time as time_module
from datetime import datetime
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request, stream_with_context

from wvs.config import ConfigManager
from wvs.core import HTTPPool, WAVScanner
from wvs.models import ScanTarget

app = Flask(__name__)

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

    def start(self, url: str, modules: list, config: dict):
        self.scanning = True
        self._start_time = time_module.time()
        self._found_vulns = []
        self._module_order = modules
        self._thread = threading.Thread(
            target=self._worker, args=(url, modules, config), daemon=True
        )
        self._thread.start()

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
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    if scan_session.scanning:
        return jsonify({"error": "已有扫描正在运行"}), 400

    data = request.get_json()
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "请输入 URL"}), 400

    modules = data.get("modules", [])
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
    scan_session.stop()
    return jsonify({"status": "stopped"})


@app.route("/api/stream")
def api_stream():
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


if __name__ == "__main__":
    print("=" * 50)
    print("  RayScan 1.0.2 — Web UI")
    print(f"  http://localhost:5000")
    print("=" * 50)
    app.run(debug=False, host="0.0.0.0", port=5000, threaded=True)
