"""Web UI 扫描会话（v2.3 T3.5）。

从 app.py 抽出:线程/事件循环管理、SSE 事件队列、结果序列化、
认证装配（共享 wvs.plugins.auth）、被动队列联动（共享 wvs.core.passive.queue_scan）。
"""

from __future__ import annotations

import asyncio
import json
import logging
import queue
import re
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from wvs.config import ConfigManager
from wvs.core import HTTPPool, WAVScanner
from wvs.core.passive import ProxyCaptureQueue
from wvs.core.passive.queue_scan import apply_gentle_rate_cap, scan_proxy_queue
from wvs.models import ScanResult, ScanTarget
from wvs.plugins.auth import AuthManager, authenticate_and_apply, configure_from_options

logger = logging.getLogger(__name__)


def serialize_vuln(v: Any) -> Dict[str, Any]:
    """漏洞 → SSE/导出 JSON 字典（含 evidence_chain）。"""
    severity = v.severity.value if hasattr(v.severity, "value") else str(v.severity)
    vuln_type = v.type.value if hasattr(v.type, "value") else str(v.type)
    return {
        "severity": severity,
        "type": vuln_type,
        "title": v.title or "",
        "url": v.url or "",
        "method": v.method or "GET",
        "parameter": v.parameter or "",
        "parameter_type": v.parameter_type or "",
        "payload": v.payload or "",
        "evidence": v.evidence or "",
        "description": v.description or "",
        "recommendation": v.recommendation or "",
        "module": v.module or "",
        "evidence_chain": list(v.evidence_chain or []),
    }


class ScanSession:
    """单次扫描会话:worker 线程 + SSE 事件队列 + 结果暂存。"""

    def __init__(self):
        self.queue: queue.Queue = queue.Queue()
        self.scanning = False
        self._thread: Optional[threading.Thread] = None
        self._result: Optional[ScanResult] = None
        self._start_time: Optional[float] = None
        self._module_order: List[str] = []
        self._log_handlers: List[Any] = []
        self._orig_stdout: Any = None

    # ── 日志捕获 ──
    def _setup_log_capture(self) -> None:
        """劫持扫描器模块 logger，输出实时发到 SSE 队列。"""

        class QueueHandler(logging.Handler):
            def __init__(self, q):
                super().__init__()
                self.q = q
                self.setFormatter(logging.Formatter("%(message)s"))

            def emit(self, record):
                try:
                    msg = self.format(record)
                    msg = re.sub(r"\033\[[0-9;]*m", "", msg)
                    if msg.strip():
                        self.q.put(
                            (
                                "log",
                                {
                                    "level": record.levelname,
                                    "text": msg,
                                    "time": datetime.now().strftime("%H:%M:%S"),
                                },
                            )
                        )
                    m = re.search(r"Found\s+(\S+)\s+in\s+(\S+)", msg, re.I)
                    m2 = re.search(r"🔴\s+发现\s+\[(\w+)\]\s+(\S+)", msg)
                    m3 = re.search(r"injection|XSS|LFI|SSRF|RCE|CMDi|XXE|sensitive|WAF", msg, re.I)
                    if m or m2 or m3:
                        self.q.put(("found", {"text": msg}))
                except Exception:  # noqa: BLE001
                    pass

        self._log_handlers = []
        for name in ["wvs.core.scanner", "wvs.core.crawler", "wvs.modules", "wvs.core.session", "wvs"]:
            lg = logging.getLogger(name)
            lg.setLevel(logging.INFO)
            handler = QueueHandler(self.queue)
            lg.addHandler(handler)
            lg.propagate = False
            self._log_handlers.append((lg, handler))

    def _teardown_log_capture(self) -> None:
        for lg, handler in self._log_handlers:
            try:
                lg.removeHandler(handler)
            except Exception:  # noqa: BLE001
                pass
        self._log_handlers = []

    class _StdoutCapture:
        """劫持 print() 输出发到 SSE 队列 + 同时保持终端显示。"""

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
                    clean = re.sub(r"\033\[[0-9;]*m", "", line).strip()
                    if clean:
                        self.q.put(
                            (
                                "log",
                                {"level": "INFO", "text": clean, "time": datetime.now().strftime("%H:%M:%S")},
                            )
                        )
                self._buffer = lines[-1]

        def flush(self):
            self.orig.flush()

    # ── 生命周期 ──
    def start(
        self,
        payload: Dict[str, Any],
        config: ConfigManager,
        modules: List[str],
        from_proxy_queue_path: Optional[Path] = None,
        on_finish: Optional[Callable[[Optional[ScanResult], float, Dict[str, Any]], None]] = None,
    ) -> None:
        self.scanning = True
        self._start_time = time.time()
        self._module_order = list(modules or [])
        self._setup_log_capture()
        self._orig_stdout = sys.stdout
        sys.stdout = self._StdoutCapture(self.queue, self._orig_stdout)
        self._thread = threading.Thread(
            target=self._worker,
            args=(payload, config, modules, from_proxy_queue_path, on_finish),
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self.scanning = False

    def events(self):
        """SSE 事件生成器。"""
        while True:
            try:
                typ, data = self.queue.get(timeout=1)
                yield f"event: {typ}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"
            except queue.Empty:
                if not self.scanning and self.queue.empty():
                    yield f"event: done\ndata: {json.dumps({'msg': 'scan finished'})}\n\n"
                    break
                yield ": keepalive\n\n"

    # ── 执行 ──
    def _worker(self, payload, config, modules, from_proxy_queue_path, on_finish) -> None:
        result: Optional[ScanResult] = None
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(self._run_scan(payload, config, modules, from_proxy_queue_path))
            finally:
                loop.close()
        except Exception as e:  # noqa: BLE001
            self._log("ERROR", f"扫描异常: {e}")
            import traceback

            for line in traceback.format_exc().split("\n"):
                if line.strip():
                    self._log("ERROR", line)
        finally:
            elapsed = time.time() - (self._start_time or time.time())
            if on_finish:
                try:
                    on_finish(result, elapsed, payload)
                except Exception as e:  # noqa: BLE001
                    logger.warning("on_finish 回调失败: %s", e)
            self._teardown_log_capture()
            if self._orig_stdout is not None:
                sys.stdout = self._orig_stdout
            self.scanning = False
            self.queue.put(("done", {"msg": "扫描结束"}))

    async def _run_scan(
        self,
        payload: Dict[str, Any],
        config: ConfigManager,
        modules: List[str],
        from_proxy_queue_path: Optional[Path],
    ) -> Optional[ScanResult]:
        if self._start_time is None:
            self._start_time = time.time()
        url = str(payload.get("url") or "")
        session = HTTPPool(config)
        scanner = WAVScanner(config, session)
        scanner._progress_callback = self._progress_cb
        for mod in modules or []:
            scanner.load_module(mod)

        self._log("INFO", "=" * 50)
        self._log("INFO", f"▶ 目标: {url}")
        self._log("INFO", f"▶ 模块: {', '.join(modules) if modules else '默认'}")
        self._log("INFO", "=" * 50)
        self._progress(5)

        target = ScanTarget(url=url)
        result: Optional[ScanResult] = None
        try:
            auth_payload = payload.get("auth") or {}
            if auth_payload:
                auth_manager = AuthManager(config)
                ok, err = configure_from_options(auth_manager, auth_payload)
                if not ok:
                    self._log("ERROR", f"认证配置错误: {err}")
                    return None
                self._log("INFO", f"[AUTH] 正在执行认证 ({auth_manager.provider_name})...")
                ok, err = await authenticate_and_apply(auth_manager, target, session)
                if not ok:
                    self._log("ERROR", f"认证失败: {err}")
                    return None
                self._log("INFO", "认证成功，已启用登录态维持")

            if payload.get("from_proxy"):
                result = await self._run_from_proxy(scanner, session, target, config, from_proxy_queue_path)
            else:
                try:
                    result = await asyncio.wait_for(scanner.scan(target), timeout=config.get("max_scan_time", 7200))
                except asyncio.TimeoutError:
                    self._log("ERROR", "扫描超时")
                    return None
        finally:
            await session.close()

        if result is None:
            return None

        elapsed = time.time() - (self._start_time or time.time())
        self._progress(100)
        self._log("INFO", f"✅ 完成！耗时 {elapsed:.0f}s")
        self._log(
            "INFO",
            f"   端点: {result.endpoints_found}  |  请求: {result.requests_made}  |  漏洞: {len(result.vulnerabilities)}",
        )
        severity_count: Dict[str, int] = {}
        for v in result.vulnerabilities:
            sev = v.severity.value if hasattr(v.severity, "value") else str(v.severity)
            severity_count[sev] = severity_count.get(sev, 0) + 1
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in severity_count:
                self._log("INFO", f"   [{sev.upper()}] {severity_count[sev]} 个")

        self.queue.put(
            (
                "result",
                {
                    "vulnerabilities": [serialize_vuln(v) for v in result.vulnerabilities],
                    "stats": {
                        "endpoints": result.endpoints_found,
                        "requests": result.requests_made,
                        "elapsed": round(elapsed, 1),
                    },
                },
            )
        )
        self._result = result
        return result

    async def _run_from_proxy(
        self,
        scanner: WAVScanner,
        session: HTTPPool,
        target: ScanTarget,
        config: ConfigManager,
        queue_path: Optional[Path],
    ) -> Optional[ScanResult]:
        if not queue_path or not Path(queue_path).exists():
            self._log("ERROR", "没有可用的被动捕获队列")
            return None
        try:
            capture_queue = ProxyCaptureQueue.load(Path(queue_path))
        except Exception as e:  # noqa: BLE001
            self._log("ERROR", f"队列文件解析失败: {e}")
            return None
        endpoints = capture_queue.filter_for_target(target.url)
        if not endpoints:
            self._log("ERROR", "队列中没有属于该目标域的端点")
            return None
        effective_rate = apply_gentle_rate_cap(config)
        self._log("INFO", f"被动队列定向扫描: {len(endpoints)} 端点, 速率上限 {effective_rate} req/s")
        queue_result = ScanResult(target=target)
        await scan_proxy_queue(
            scanner,
            session,
            endpoints,
            target.url,
            config.get("concurrent_endpoints", 10),
            queue_result,
        )
        return queue_result

    # ── 进度 / 日志 ──
    def _progress(self, pct: int) -> None:
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
            self.queue.put(
                (
                    "action",
                    {
                        "module": module_name,
                        "done": done,
                        "total": total,
                        "text": f"检测 {module_name.upper()}... ({done}/{total})",
                    },
                )
            )
        elif module_name == "crawl":
            self.queue.put(("progress", {"pct": min(3 + (done / max(total, 1)) * 7, 10)}))
            self.queue.put(("action", {"text": f"爬虫 {done}/{total} 页面"}))

    def _log(self, level: str, text: str) -> None:
        self.queue.put(("log", {"level": level, "text": text, "time": datetime.now().strftime("%H:%M:%S")}))
