"""
RayScan 1.0.2 GUI — ttkbootstrap 主题化 + 响应式布局
"""
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from tkinter import scrolledtext
import threading
import queue
import asyncio
import json
import logging
import sys
import os
import re
import time as time_module
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wvs.config import ConfigManager
from wvs.core import HTTPPool, WAVScanner
from wvs.models import ScanTarget

# ── ttkbootstrap 主题 ──
try:
    from ttkbootstrap import Style, Window
    HAS_TTKB = True
except ImportError:
    HAS_TTKB = False
    import tkinter as tk
    Window = tk.Tk

# ── 颜色映射 ──
SEVERITY_COLORS = {
    "critical": "#DC143C", "high": "#FF4500", "medium": "#FF8C00",
    "low": "#1E90FF", "info": "#6B7280",
}
MODULE_ICONS = {
    "sqli": "[SQLi]", "xss": "[XSS]", "cmdi": "[CMDi]", "lfi": "[LFI]",
    "rce": "[RCE]", "ssrf": "[SSRF]", "xxe": "[XXE]", "api": "[API]",
    "sensitive": "[SENSE]", "waf": "[WAF]", "crawl": "[CRAWL]",
    "jspathfinder": "[JSPATH]",
}
MODULE_INFO = {
    "sqli": "SQL注入（报错/布尔/时间/联合查询）",
    "xss": "跨站脚本（反射型/存储型/DOM型）",
    "cmdi": "命令注入",
    "lfi": "本地文件包含 + 路径遍历",
    "rce": "远程代码执行",
    "ssrf": "服务端请求伪造",
    "xxe": "XML外部实体注入",
    "api": "API安全（JWT/CORS/鉴权绕过）",
    "sensitive": "敏感信息泄露（Git/备份/默认凭据）",
    "waf": "WAF检测与绕过",
}

# 主题列表
THEMES = {
    "🌙 Darkly": "darkly",
    "☀️ Flatly": "flatly",
    "🦇 Superhero": "superhero",
    "🌞 Solar": "solar",
    "🤖 Cyborg": "cyborg",
    "🌊 Cosmo": "cosmo",
    "🌿 Minty": "minty",
    "📰 Litera": "litera",
    "🎨 Morph": "morph",
    "💜 Vapor": "vapor",
    "🔮 Pulse": "pulse",
}
DEFAULT_THEME = "darkly"


class QueueLogHandler(logging.Handler):
    """劫持 Python logger → GUI 队列"""

    def __init__(self, msg_queue: queue.Queue):
        super().__init__()
        self.msg_queue = msg_queue
        self.setFormatter(logging.Formatter("%(message)s"))

    def emit(self, record):
        try:
            msg = self.format(record)
            msg = re.sub(r'\033\[[0-9;]*m', '', msg)
            if msg.strip():
                self.msg_queue.put(("log", (record.levelname, msg)))
        except Exception:
            pass


class RayScanGUI:
    def __init__(self):
        self._theme_name = DEFAULT_THEME
        self._build_window()

        self.scanning = False
        self.msg_queue = queue.Queue()
        self.scan_result = None
        self._start_time = None
        self._found_vulns = []
        self._module_order = []

        self._setup_log_capture()
        self._build_ui()
        self._poll_queue()

    # ── 窗口构建 ──
    def _build_window(self):
        if HAS_TTKB:
            self.style = Style(theme=self._theme_name)
            self.root = Window(themename=self._theme_name)
        else:
            self.style = ttk.Style()
            self.root = tk.Tk()
        self.root.title("RayScan 1.0.2 — Web Vulnerability Scanner")
        self.root.geometry("1200x800")
        self.root.minsize(960, 640)

    def _retheme(self, theme_name: str):
        """切换主题"""
        if HAS_TTKB:
            self.style.theme_use(theme_name)
            self._theme_name = theme_name

    def _setup_log_capture(self):
        handler = QueueLogHandler(self.msg_queue)
        for name in ["wvs.core.scanner", "wvs.core.crawler",
                      "wvs.modules", "wvs.core.session", "wvs"]:
            lg = logging.getLogger(name)
            lg.setLevel(logging.INFO)
            lg.addHandler(handler)
            lg.propagate = False

    # ==================== UI 构建 ====================

    def _build_ui(self):
        # ── 整体 grid 布局 ──
        self.root.grid_rowconfigure(0, weight=0)   # toolbar
        self.root.grid_rowconfigure(1, weight=0)   # url bar
        self.root.grid_rowconfigure(2, weight=1)   # main area
        self.root.grid_rowconfigure(3, weight=0)   # status bar
        self.root.grid_columnconfigure(0, weight=1)

        self._build_toolbar()
        self._build_urlbar()
        self._build_main()
        self._build_statusbar()

    def _build_toolbar(self):
        bar = ttk.Frame(self.root, padding=(10, 6))
        bar.grid(row=0, column=0, sticky="ew")

        # Logo + 标题
        ttk.Label(bar, text="RayScan", font=("Segoe UI", 15, "bold")).pack(side=tk.LEFT)
        ttk.Label(bar, text="1.0.2", font=("Segoe UI", 9),
                  foreground="gray").pack(side=tk.LEFT, padx=(4, 20))

        # 主题选择器
        ttk.Label(bar, text="主题:", font=("", 9)).pack(side=tk.LEFT)
        self.theme_var = tk.StringVar(value="🌙 Darkly")
        theme_menu = ttk.Combobox(bar, textvariable=self.theme_var,
                                  values=list(THEMES.keys()), state="readonly",
                                  width=14, font=("", 9))
        theme_menu.pack(side=tk.LEFT, padx=(4, 0))
        theme_menu.bind("<<ComboboxSelected>>", self._on_theme_change)

        # Scan log count
        self.vuln_count_label = ttk.Label(bar, text="漏洞: 0",
                                          font=("", 9, "bold"))
        self.vuln_count_label.pack(side=tk.RIGHT)

    def _on_theme_change(self, event=None):
        name = self.theme_var.get()
        if name in THEMES:
            self._retheme(THEMES[name])

    def _build_urlbar(self):
        bar = ttk.Frame(self.root, padding=(10, 2, 10, 6))
        bar.grid(row=1, column=0, sticky="ew")
        bar.grid_columnconfigure(1, weight=1)

        ttk.Label(bar, text="目标 URL:", font=("", 10)).grid(row=0, column=0, padx=(0, 5))
        self.url_entry = ttk.Entry(bar, font=("Consolas", 11))
        self.url_entry.grid(row=0, column=1, sticky="ew", padx=(0, 5))
        self.url_entry.insert(0, "http://")
        self.url_entry.bind('<Return>', lambda e: self.start_scan())

        self.scan_btn = ttk.Button(bar, text="▶ 开始", style="success.TButton",
                                   command=self.start_scan, width=8)
        self.scan_btn.grid(row=0, column=2, padx=2)
        self.stop_btn = ttk.Button(bar, text="■ 停止", style="danger.TButton",
                                   command=self.stop_scan, state=tk.DISABLED, width=8)
        self.stop_btn.grid(row=0, column=3, padx=2)

    def _build_main(self):
        """主区域：左侧配置 + 右侧内容（响应式）"""
        main = ttk.Frame(self.root, padding=(10, 4, 10, 4))
        main.grid(row=2, column=0, sticky="nsew")
        main.grid_columnconfigure(1, weight=1)  # 右侧展开
        main.grid_rowconfigure(0, weight=1)

        self._build_left_panel(main)
        self._build_right_panel(main)

    # ── 左侧配置面板 ──
    def _build_left_panel(self, parent):
        left = ttk.Frame(parent, width=210)
        left.grid(row=0, column=0, sticky="ns", padx=(0, 8))
        left.grid_propagate(False)

        # 模块选择
        mod_f = ttk.LabelFrame(left, text="检测模块", padding=6)
        mod_f.pack(fill=tk.X, pady=(0, 4))

        self.module_vars = {}
        for mid in MODULE_INFO:
            var = tk.BooleanVar(value=True)
            self.module_vars[mid] = var
            ttk.Checkbutton(mod_f, text=mid.upper(), variable=var).pack(anchor=tk.W, pady=1)

        btnr = ttk.Frame(mod_f)
        btnr.pack(fill=tk.X, pady=(4, 0))
        ttk.Button(btnr, text="全选", width=7,
                   command=lambda: self._toggle_all(True)).pack(side=tk.LEFT, padx=1)
        ttk.Button(btnr, text="取消", width=7,
                   command=lambda: self._toggle_all(False)).pack(side=tk.LEFT, padx=1)

        # 扫描配置
        cfg_f = ttk.LabelFrame(left, text="扫描配置", padding=6)
        cfg_f.pack(fill=tk.X, pady=(4, 4))

        self.cfg_entries = {}
        for label, key, default in [
            ("速率 (req/s)", "rate", "15"),
            ("超时 (秒)", "timeout", "15"),
            ("爬虫深度", "crawl_depth", "2"),
            ("最大URL数", "crawl_max_urls", "50"),
            ("并发端点", "concurrent_endpoints", "10"),
        ]:
            r = ttk.Frame(cfg_f)
            r.pack(fill=tk.X, pady=1)
            ttk.Label(r, text=label, width=12, anchor=tk.W).pack(side=tk.LEFT)
            e = ttk.Entry(r, width=7, justify=tk.CENTER)
            e.insert(0, default)
            e.pack(side=tk.RIGHT)
            self.cfg_entries[key] = e

        self.insecure_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(cfg_f, text="跳过 SSL 验证",
                        variable=self.insecure_var).pack(anchor=tk.W, pady=(4, 0))

        # 版本信息
        ver_f = ttk.LabelFrame(left, text="版本", padding=6)
        ver_f.pack(fill=tk.X, side=tk.BOTTOM, pady=(4, 0))
        ttk.Label(ver_f, text="RayScan 1.0.2").pack(anchor=tk.W)
        ttk.Label(ver_f, text="MIT License", foreground="gray").pack(anchor=tk.W)
        ttk.Label(ver_f, text="github.com/xiabai2004",
                  foreground="gray", font=("", 7)).pack(anchor=tk.W)

    # ── 右侧主内容区 ──
    def _build_right_panel(self, parent):
        right = ttk.Frame(parent)
        right.grid(row=0, column=1, sticky="nsew")
        right.grid_rowconfigure(2, weight=1)  # 日志区域伸缩
        right.grid_columnconfigure(0, weight=1)

        # 进度区
        prog_f = ttk.LabelFrame(right, text="扫描进度", padding=6)
        prog_f.grid(row=0, column=0, sticky="ew", pady=(0, 4))

        # 状态文字
        self.status_label = ttk.Label(prog_f, text="就绪 ✓ 输入目标 URL 后开始",
                                      font=("", 9))
        self.status_label.pack(anchor=tk.W)

        # 当前模块
        self.module_label = ttk.Label(prog_f, text="", font=("Consolas", 9))
        self.module_label.pack(anchor=tk.W, pady=(2, 0))

        # 进度条
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(prog_f, variable=self.progress_var,
                                            maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=(5, 0))

        # 统计行
        stats = ttk.Frame(prog_f)
        stats.pack(fill=tk.X, pady=(4, 0))
        items = [
            ("端点:", "endpoint_label"),
            ("请求:", "request_label"),
            ("用时:", "time_label"),
        ]
        for text, attr in items:
            lbl = ttk.Label(stats, text="0", font=("Consolas", 9, "bold"))
            setattr(self, attr, lbl)
            ttk.Label(stats, text=text, font=("", 8)).pack(side=tk.LEFT)
            lbl.pack(side=tk.LEFT, padx=(0, 12))

        # 当前动作
        self.action_label = ttk.Label(stats, text="", font=("", 8))
        self.action_label.pack(side=tk.RIGHT)

        # ── 实时日志区域（带颜色） ──
        log_f = ttk.LabelFrame(right, text="实时扫描日志", padding=4)
        log_f.grid(row=1, column=0, sticky="nsew", pady=(0, 4))
        log_f.grid_rowconfigure(0, weight=1)
        log_f.grid_columnconfigure(0, weight=1)

        self.log_area = tk.Text(log_f, height=8, state=tk.DISABLED,
                                font=("Consolas", 9), wrap=tk.WORD,
                                padx=6, pady=4,
                                bg="#1a1a2e" if DEFAULT_THEME == "darkly" else "#f8f9fa",
                                fg="#e0e0e0" if DEFAULT_THEME == "darkly" else "#212529",
                                insertbackground="white")
        log_scroll = ttk.Scrollbar(log_f, orient=tk.VERTICAL,
                                    command=self.log_area.yview)
        self.log_area.configure(yscrollcommand=log_scroll.set)
        self.log_area.grid(row=0, column=0, sticky="nsew")
        log_scroll.grid(row=0, column=1, sticky="ns")

        # 日志 tag 颜色（明暗自适应）
        fg_light = "#10B981"
        fg_dark = "#059669"
        self.log_area.tag_configure("INFO", foreground=fg_light)
        self.log_area.tag_configure("WARNING", foreground="#F59E0B")
        self.log_area.tag_configure("ERROR", foreground="#EF4444")
        self.log_area.tag_configure("time", foreground="#6B7280")

        # ── 结果表格（实时更新） ──
        res_f = ttk.LabelFrame(right, text="发现结果（实时更新）", padding=4)
        res_f.grid(row=2, column=0, sticky="nsew")
        res_f.grid_rowconfigure(0, weight=1)
        res_f.grid_columnconfigure(0, weight=1)

        columns = ("severity", "type", "url", "parameter", "evidence")
        self.result_tree = ttk.Treeview(res_f, columns=columns,
                                         show="headings", height=5)
        self.result_tree.heading("severity", text="严重度")
        self.result_tree.heading("type", text="类型")
        self.result_tree.heading("url", text="URL")
        self.result_tree.heading("parameter", text="参数")
        self.result_tree.heading("evidence", text="证据")
        self.result_tree.column("severity", width=70, anchor=tk.CENTER)
        self.result_tree.column("type", width=100)
        self.result_tree.column("url", width=300)
        self.result_tree.column("parameter", width=80)
        self.result_tree.column("evidence", width=200)

        for sev, c in SEVERITY_COLORS.items():
            self.result_tree.tag_configure(sev.upper(), foreground=c)

        tree_scroll = ttk.Scrollbar(res_f, orient=tk.VERTICAL,
                                     command=self.result_tree.yview)
        self.result_tree.configure(yscrollcommand=tree_scroll.set)
        self.result_tree.grid(row=0, column=0, sticky="nsew")
        tree_scroll.grid(row=0, column=1, sticky="ns")
        self.result_tree.bind('<Double-Button-1>', lambda e: self._view_detail())

        # 结果底部按钮
        btn_f = ttk.Frame(res_f)
        btn_f.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(4, 0))
        for text, cmd in [
            ("📥 JSON", lambda: self._export("json")),
            ("📥 HTML", lambda: self._export("html")),
            ("🗑 清空", self._clear_results),
            ("📋 详情", self._view_detail),
        ]:
            ttk.Button(btn_f, text=text, command=cmd).pack(side=tk.LEFT, padx=2)

    def _build_statusbar(self):
        bar = ttk.Frame(self.root, padding=(10, 2))
        bar.grid(row=3, column=0, sticky="ew")
        ttk.Label(bar, text="RayScan 1.0.2 | MIT License",
                  font=("", 7), foreground="gray").pack(side=tk.LEFT)
        ttk.Label(bar, text="github.com/xiabai2004/RayScan",
                  font=("", 7), foreground="gray").pack(side=tk.RIGHT)

    # ==================== 扫描控制 ====================

    def _toggle_all(self, state):
        for v in self.module_vars.values():
            v.set(state)

    def start_scan(self):
        url = self.url_entry.get().strip()
        if not url or url == "http://":
            messagebox.showwarning("提示", "请输入目标 URL")
            return

        enabled = [m for m, v in self.module_vars.items() if v.get()]
        if not enabled:
            messagebox.showwarning("提示", "至少选择一个模块")
            return

        self._module_order = [m for m in MODULE_INFO if m in enabled]
        self._found_vulns = []
        self.scanning = True
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self._clear_results()
        self._start_time = time_module.time()

        self._log("INFO", "=" * 55)
        self._log("INFO", f"▶ 扫描目标: {url}")
        self._log("INFO", f"▶ 检测模块: {', '.join(enabled)}")
        self._log("INFO", "=" * 55)
        self.status_label.config(text="扫描进行中...")
        self.module_label.config(text="初始化...")
        self.action_label.config(text="准备中")
        self.progress_var.set(2)

        self._update_stats_loop()

        t = threading.Thread(target=self._scan_worker,
                             args=(url, enabled), daemon=True)
        t.start()

    def _update_stats_loop(self):
        if self._start_time and self.scanning:
            t = time_module.time() - self._start_time
            self.time_label.config(text=f"{t:.0f}s")
            self.root.after(1000, self._update_stats_loop)

    def stop_scan(self):
        self.scanning = False
        self.stop_btn.config(state=tk.DISABLED)
        self._log("WARNING", "用户中止扫描")
        self.status_label.config(text="已中止")
        self.module_label.config(text="")
        self.action_label.config(text="")
        self.scan_btn.config(state=tk.NORMAL)

    def _scan_worker(self, url, enabled):
        try:
            config = self._build_config()
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(self._run_scan(url, enabled, config))
            loop.close()
        except Exception as e:
            self.msg_queue.put(("log", ("ERROR", f"扫描异常: {e}")))
            import traceback
            for line in traceback.format_exc().split("\n"):
                if line.strip():
                    self.msg_queue.put(("log", ("ERROR", line)))
        finally:
            self.msg_queue.put(("done", None))

    async def _run_scan(self, url, enabled, config):
        from wvs.core import HTTPPool, WAVScanner

        session = HTTPPool(config)
        scanner = WAVScanner(config, session)
        scanner._progress_callback = self._scan_progress_cb

        for mod in enabled:
            scanner.load_module(mod)

        target = ScanTarget(url=url)

        self.msg_queue.put(("progress", 5))
        self.msg_queue.put(("action", "扫描中..."))

        try:
            result = await asyncio.wait_for(
                scanner.scan(target),
                timeout=config.get("max_scan_time", 7200),
            )
        except asyncio.TimeoutError:
            self.msg_queue.put(("log", ("ERROR", "扫描超时")))
            return None

        elapsed = time_module.time() - self._start_time
        self.msg_queue.put(("progress", 100))
        self.msg_queue.put(("action", "扫描完成"))
        self.msg_queue.put(("log", ("INFO", f"✅ 完成！耗时 {elapsed:.0f}s")))
        self.msg_queue.put(("log", ("INFO",
            f"   端点: {result.endpoints_found}  |  请求: {result.requests_made}  |  漏洞: {len(result.vulnerabilities)}")))

        sev_count = {}
        for v in result.vulnerabilities:
            sev = v.severity.value if hasattr(v.severity, "value") else str(v.severity)
            sev_count[sev] = sev_count.get(sev, 0) + 1
        for s in ["critical", "high", "medium", "low", "info"]:
            if s in sev_count:
                self.msg_queue.put(("log", ("INFO", f"   [{s.upper()}] {sev_count[s]} 个")))

        self.msg_queue.put(("stats", {
            "endpoints": result.endpoints_found,
            "requests": result.requests_made,
            "elapsed": elapsed,
        }))
        self.msg_queue.put(("result", result))
        return result

    def _scan_progress_cb(self, module_name, done, total, pct):
        if not self.scanning:
            return
        icon = MODULE_ICONS.get(module_name, f"[{module_name}]")
        label = f"{icon} {module_name}"
        if total > 0:
            label += f"  {done}/{total}"
        self.msg_queue.put(("module", label))

        if module_name in MODULE_INFO:
            total_m = len(self._module_order)
            try:
                idx = self._module_order.index(module_name)
            except ValueError:
                idx = 0
            base = 10 + (idx / max(total_m, 1)) * 75
            share = 75 / max(total_m, 1)
            val = int(base + (done / max(total, 1)) * share)
            self.msg_queue.put(("progress", min(val, 90)))
            self.msg_queue.put(("action", f"检测 {module_name.upper()}... ({done}/{total})"))
        elif module_name == "crawl":
            self.msg_queue.put(("progress", min(3 + (done / max(total, 1)) * 7, 10)))
            self.msg_queue.put(("action", f"爬虫 {done}/{total} 页面"))

    def _build_config(self):
        config = ConfigManager()
        for key in ["rate", "timeout", "crawl_depth", "crawl_max_urls", "concurrent_endpoints"]:
            try:
                config.set(key, int(self.cfg_entries[key].get()))
            except ValueError:
                pass
        if self.insecure_var.get():
            config.set("verify_ssl", False)
        return config

    # ==================== 消息循环 ====================

    def _poll_queue(self):
        try:
            while True:
                typ, data = self.msg_queue.get_nowait()
                if typ == "log":
                    self._log(*data)
                elif typ == "action":
                    self.action_label.config(text=data)
                elif typ == "module":
                    self.module_label.config(text=data)
                elif typ == "progress":
                    self.progress_var.set(data)
                elif typ == "stats":
                    if "endpoints" in data:
                        self.endpoint_label.config(text=str(data["endpoints"]))
                    if "requests" in data:
                        self.request_label.config(text=str(data["requests"]))
                    if "elapsed" in data:
                        self.time_label.config(text=f"{data['elapsed']:.0f}s")
                elif typ == "vuln":
                    self._add_vuln_row(data)
                elif typ == "result":
                    self._display_results(data)
                elif typ == "done":
                    self._on_done()
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)

    def _log(self, level, text):
        self.log_area.config(state=tk.NORMAL)
        t = datetime.now().strftime("%H:%M:%S")
        tag = level if level in ("INFO", "WARNING", "ERROR") else "INFO"
        self.log_area.insert(tk.END, f"{t} ", "time")
        self.log_area.insert(tk.END, f"{text}\n", tag)
        self.log_area.see(tk.END)
        self.log_area.config(state=tk.DISABLED)

    def _add_vuln_row(self, v):
        sev = v.severity.value if hasattr(v.severity, "value") else str(v.severity)
        vtype = v.type.value if hasattr(v.type, "value") else str(v.type)
        url = (v.url or "")[:80]
        param = v.parameter or ""
        evidence = (v.evidence or "")[:100]
        self.result_tree.insert("", tk.END, values=(sev, vtype, url, param, evidence),
                                 tags=(sev.upper(),))
        self._found_vulns.append(v)
        self.vuln_count_label.config(text=f"漏洞: {len(self._found_vulns)}")
        self._log("INFO", f"  🔴 发现 [{sev.upper()}] {vtype} @ {url}")

    def _on_done(self):
        self.scanning = False
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress_var.set(100)
        self.status_label.config(text="就绪 ✓ 扫描完成")
        self.module_label.config(text="")

    def _display_results(self, result):
        self.scan_result = result
        existing = set()
        for child in self.result_tree.get_children():
            v = self.result_tree.item(child, "values")
            existing.add((v[1], v[2], v[3]))
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for v in sorted(result.vulnerabilities,
                        key=lambda vv: sev_order.get(
                            vv.severity.value if hasattr(vv.severity, "value") else str(vv.severity), 5)):
            vt = v.type.value if hasattr(v.type, "value") else str(v.type)
            key = (vt, (v.url or "")[:80], v.parameter or "")
            if key not in existing:
                self._add_vuln_row(v)

    def _clear_results(self):
        self.result_tree.delete(*self.result_tree.get_children())
        self._found_vulns = []
        self.scan_result = None
        self.progress_var.set(0)
        self.endpoint_label.config(text="0")
        self.request_label.config(text="0")
        self.time_label.config(text="0s")
        self.vuln_count_label.config(text="漏洞: 0")
        self.log_area.config(state=tk.NORMAL)
        self.log_area.delete(1.0, tk.END)
        self.log_area.config(state=tk.DISABLED)
        self.module_label.config(text="")
        self.action_label.config(text="")

    # ==================== 导出 & 详情 ====================

    def _export(self, fmt):
        vulns = self._found_vulns or (
            self.scan_result.vulnerabilities if self.scan_result else []
        )
        if not vulns:
            messagebox.showwarning("提示", "没有结果可导出")
            return
        os.makedirs("scan_reports", exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        if fmt == "json":
            path = f"scan_reports/report_{ts}.json"
            report = {
                "scan_time": ts, "total": len(vulns),
                "vulnerabilities": [{
                    "type": v.type.value if hasattr(v.type, "value") else str(v.type),
                    "severity": v.severity.value if hasattr(v.severity, "value") else str(v.severity),
                    "url": v.url, "parameter": v.parameter,
                    "evidence": v.evidence, "title": v.title,
                    "description": v.description, "recommendation": v.recommendation,
                } for v in vulns],
            }
            with open(path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
        else:
            path = f"scan_reports/report_{ts}.html"
            sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            sv = sorted(vulns, key=lambda vv: sev_order.get(
                vv.severity.value if hasattr(vv.severity, "value") else str(vv.severity), 5))
            rows = ""
            for v in sv:
                s = v.severity.value if hasattr(v.severity, "value") else "info"
                c = SEVERITY_COLORS.get(s, "#000")
                rows += f"""<tr><td style="color:{c};font-weight:bold">{s.upper()}</td>
                <td>{v.type.value if hasattr(v.type,'value') else str(v.type)}</td>
                <td>{v.url or ''}</td><td>{v.parameter or ''}</td>
                <td>{v.evidence or ''}</td></tr>\n"""
            html = f"""<!DOCTYPE html><html lang="zh">
<head><meta charset="utf-8"><title>RayScan Report</title>
<style>
body{{font-family:Arial,sans-serif;margin:20px;background:#f5f5f5}}
h1{{color:#2563EB}} table{{border-collapse:collapse;width:100%;background:#fff}}
th,td{{padding:8px 12px;border:1px solid #ddd;text-align:left;font-size:13px}}
th{{background:#2563EB;color:#fff}} tr:hover{{background:#f0f0f0}}
.summary{{background:#fff;padding:15px;margin-bottom:20px;border-radius:5px}}
</style></head><body>
<h1>RayScan 1.0.2 扫描报告</h1>
<div class="summary"><p>时间: {datetime.now().isoformat()}</p>
<p>漏洞: {len(sv)}</p></div>
<table><tr><th>严重度</th><th>类型</th><th>URL</th><th>参数</th><th>证据</th></tr>
{rows}</table></body></html>"""
            with open(path, "w", encoding="utf-8") as f:
                f.write(html)
        self._log("INFO", f"✅ 报告保存: {path}")
        messagebox.showinfo("导出完成", f"已保存:\n{path}")

    def _view_detail(self):
        sel = self.result_tree.selection()
        if not sel:
            return
        v = self.result_tree.item(sel[0], "values")
        messagebox.showinfo("漏洞详情",
            f"严重度: {v[0]}\n类型: {v[1]}\nURL: {v[2]}\n参数: {v[3]}\n\n证据:\n{v[4]}")

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    app = RayScanGUI()
    app.run()
