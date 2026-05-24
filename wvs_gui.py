"""
RayScan 1.0.2 GUI — Web Vulnerability Scanner
实时扫描日志 + 即时结果显示
"""
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
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
from wvs.models import ScanTarget, Severity, Confidence

# ── 颜色方案 ──
SEVERITY_COLORS = {
    "critical": "#DC143C",
    "high": "#FF4500",
    "medium": "#FF8C00",
    "low": "#1E90FF",
    "info": "#6B7280",
}

MODULE_ICONS = {
    "sqli": "[SQLi]", "xss": "[XSS]", "cmdi": "[CMDi]",
    "lfi": "[LFI]", "rce": "[RCE]", "ssrf": "[SSRF]",
    "xxe": "[XXE]", "api": "[API]", "sensitive": "[SENSE]",
    "waf": "[WAF]", "crawl": "[CRAWL]", "jspathfinder": "[JSPATH]",
}

MODULE_INFO = {
    "sqli": ("SQL 注入", "检测 SQL 注入漏洞（报错/布尔/时间盲注/联合查询）"),
    "xss": ("跨站脚本", "检测反射型/存储型/DOM型 XSS"),
    "cmdi": ("命令注入", "检测命令注入（回显/时间/带外）"),
    "lfi": ("文件包含", "本地文件包含 + 路径遍历"),
    "rce": ("远程代码执行", "代码注入、反序列化漏洞"),
    "ssrf": ("SSRF", "服务端请求伪造，支持带外验证"),
    "xxe": ("XXE", "XML 外部实体注入"),
    "api": ("API 安全", "JWT 弱点、CORS 配置错误、鉴权绕过"),
    "sensitive": ("敏感信息", "Git/SVN 泄露、备份文件、配置文件、默认凭据"),
    "waf": ("WAF 检测", "识别 15+ 种 WAF/CDN，生成绕过载荷"),
}

ALL_MODULES = list(MODULE_INFO.keys())

# ── 日志级别颜色 ──
LOG_COLORS = {
    "INFO": "#10B981",
    "WARNING": "#F59E0B",
    "ERROR": "#EF4444",
    "DEBUG": "#6B7280",
    "CRITICAL": "#DC143C",
}


class QueueLogHandler(logging.Handler):
    """把 Python logger 输出实时发到 GUI 队列"""

    def __init__(self, msg_queue: queue.Queue):
        super().__init__()
        self.msg_queue = msg_queue
        self.setFormatter(logging.Formatter("%(message)s"))

    def emit(self, record):
        try:
            msg = self.format(record)
            level = record.levelname
            # 清理 ANSI 转义码
            msg = re.sub(r'\033\[[0-9;]*m', '', msg)
            if msg.strip():
                self.msg_queue.put(("log", (level, msg)))
        except Exception:
            pass


class RayScanGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("RayScan 1.0.2 — Web Vulnerability Scanner")
        self.root.geometry("1100x780")
        self.root.minsize(960, 640)

        self.scanning = False
        self.msg_queue = queue.Queue()
        self.scan_result = None
        self._start_time = None
        self._found_vulns = []

        # 劫持扫描器日志
        self._setup_log_capture()

        self._build_ui()
        self._poll_queue()

    # ── 日志劫持 ──
    def _setup_log_capture(self):
        handler = QueueLogHandler(self.msg_queue)
        for logger_name in ["wvs.core.scanner", "wvs.core.crawler",
                             "wvs.modules", "wvs.core.session",
                             "wvs"]:
            logger = logging.getLogger(logger_name)
            logger.setLevel(logging.INFO)
            logger.addHandler(handler)
            logger.propagate = False  # 阻止重复输出到终端

    # ==================== UI 构建 ====================

    def _build_ui(self):
        style = ttk.Style()
        try:
            style.theme_use("vista")  # Windows 原生主题
        except tk.TclError:
            pass

        # ── 顶部：标题 + URL 输入 ──
        header = ttk.Frame(self.root, padding=(15, 10, 15, 5))
        header.pack(fill=tk.X)

        ttk.Label(header, text="RayScan", font=("Segoe UI", 16, "bold"),
                  foreground="#2563EB").pack(side=tk.LEFT)
        ttk.Label(header, text="1.0.2", font=("Segoe UI", 10),
                  foreground="#6B7280").pack(side=tk.LEFT, padx=(4, 15))

        # URL 行
        url_frame = ttk.Frame(header)
        url_frame.pack(fill=tk.X, pady=(5, 0))
        ttk.Label(url_frame, text="目标 URL:", font=("", 10)).pack(side=tk.LEFT)
        self.url_entry = ttk.Entry(url_frame, font=("Consolas", 10))
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.url_entry.insert(0, "http://")
        self.url_entry.bind('<Return>', lambda e: self.start_scan())

        self.scan_btn = ttk.Button(url_frame, text="▶ 开始扫描",
                                   command=self.start_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=2)
        self.stop_btn = ttk.Button(url_frame, text="■ 停止",
                                   command=self.stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT)

        # ── 主区域：左(配置) | 中(日志+结果) | 右(帮助) ──
        main = ttk.Frame(self.root, padding=(15, 5, 15, 10))
        main.pack(fill=tk.BOTH, expand=True)

        # === 左侧：配置面板 ===
        left = ttk.Frame(main, width=200)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        left.pack_propagate(False)

        # 模块选择
        mod_frame = ttk.LabelFrame(left, text="检测模块", padding=8)
        mod_frame.pack(fill=tk.X)

        self.module_vars = {}
        for mod_id, (mod_name, mod_desc) in MODULE_INFO.items():
            var = tk.BooleanVar(value=True)
            self.module_vars[mod_id] = var
            cb = ttk.Checkbutton(mod_frame, text=mod_name, variable=var)
            cb.pack(anchor=tk.W, pady=1)

        btn_row = ttk.Frame(mod_frame)
        btn_row.pack(fill=tk.X, pady=(5, 0))
        ttk.Button(btn_row, text="全选", width=7,
                   command=lambda: self._toggle_all(True)).pack(side=tk.LEFT, padx=1)
        ttk.Button(btn_row, text="取消", width=7,
                   command=lambda: self._toggle_all(False)).pack(side=tk.LEFT, padx=1)

        # 扫描配置
        cfg_frame = ttk.LabelFrame(left, text="扫描配置", padding=8)
        cfg_frame.pack(fill=tk.X, pady=(8, 0))

        configs = [
            ("速率 (req/s):", "rate", "15"),
            ("超时 (秒):", "timeout", "15"),
            ("爬虫深度:", "crawl_depth", "2"),
            ("最大URL数:", "crawl_max_urls", "50"),
            ("并发端点:", "concurrent_endpoints", "10"),
        ]
        self.cfg_entries = {}
        for label, key, default in configs:
            row = ttk.Frame(cfg_frame)
            row.pack(fill=tk.X, pady=2)
            ttk.Label(row, text=label, width=12, anchor=tk.W).pack(side=tk.LEFT)
            entry = ttk.Entry(row, width=7, justify=tk.CENTER)
            entry.insert(0, default)
            entry.pack(side=tk.RIGHT)
            self.cfg_entries[key] = entry

        self.insecure_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(cfg_frame, text="跳过 SSL 验证",
                        variable=self.insecure_var).pack(anchor=tk.W, pady=(5, 0))

        # 版本信息
        ver_frame = ttk.LabelFrame(left, text="版本信息", padding=8)
        ver_frame.pack(fill=tk.X, pady=(8, 0))
        ttk.Label(ver_frame, text="RayScan 1.0.2",
                  font=("", 9, "bold")).pack(anchor=tk.W)
        ttk.Label(ver_frame, text="MIT License",
                  font=("", 8), foreground="#888").pack(anchor=tk.W)
        ttk.Label(ver_frame, text="github.com/xiabai2004/RayScan",
                  font=("", 7), foreground="#aaa").pack(anchor=tk.W)

        # === 中间：状态 + 日志 + 结果 ===
        center = ttk.Frame(main)
        center.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # 状态栏
        status_frame = ttk.LabelFrame(center, text="扫描状态", padding=8)
        status_frame.pack(fill=tk.X)

        top_status = ttk.Frame(status_frame)
        top_status.pack(fill=tk.X)
        self.status_label = ttk.Label(top_status, text="就绪 ✓  输入目标 URL 后点击「开始扫描」",
                                      foreground="#6B7280", font=("", 9))
        self.status_label.pack(side=tk.LEFT)

        self.vuln_count_label = ttk.Label(top_status, text="漏洞: 0",
                                          foreground="#6B7280", font=("", 9, "bold"))
        self.vuln_count_label.pack(side=tk.RIGHT)

        # 实时模块名 + 进度条
        self.module_label = ttk.Label(status_frame, text="", foreground="#2563EB",
                                      font=("Consolas", 9))
        self.module_label.pack(anchor=tk.W, pady=(3, 0))

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(status_frame, variable=self.progress_var,
                                            maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=(5, 0))

        # 实时统计行
        stats_row = ttk.Frame(status_frame)
        stats_row.pack(fill=tk.X, pady=(5, 0))
        self.endpoint_label = ttk.Label(stats_row, text="0", foreground="#2563EB")
        self._make_stat(stats_row, "端点:", self.endpoint_label)
        self.request_label = ttk.Label(stats_row, text="0", foreground="#2563EB")
        self._make_stat(stats_row, "请求:", self.request_label)
        self.time_label = ttk.Label(stats_row, text="0s", foreground="#2563EB")
        self._make_stat(stats_row, "用时:", self.time_label)
        self.mod_stat_label = ttk.Label(stats_row, text="-", foreground="#2563EB")
        self._make_stat(stats_row, "模块:", self.mod_stat_label)
        self.current_action_label = ttk.Label(stats_row, text="", foreground="#6B7280", font=("", 8))
        self._make_stat(stats_row, "当前:", self.current_action_label)

        # 日志区域
        log_frame = ttk.LabelFrame(center, text="实时扫描日志", padding=5)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=(5, 5))

        self.log_area = tk.Text(log_frame, height=12, state=tk.DISABLED,
                                font=("Consolas", 9), bg="#1E1E1E", fg="#D4D4D4",
                                insertbackground="white", wrap=tk.WORD,
                                padx=5, pady=5)
        log_scroll = ttk.Scrollbar(log_frame, orient=tk.VERTICAL,
                                    command=self.log_area.yview)
        self.log_area.configure(yscrollcommand=log_scroll.set)
        self.log_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        # 日志标签配置
        for level, color in LOG_COLORS.items():
            self.log_area.tag_configure(level.lower(), foreground=color)
        self.log_area.tag_configure("time", foreground="#6B7280")
        self.log_area.tag_configure("bold", font=("Consolas", 9, "bold"))

        # 结果表格
        result_frame = ttk.LabelFrame(center, text="发现结果 (实时更新)", padding=5)
        result_frame.pack(fill=tk.BOTH, pady=(0, 0))

        columns = ("severity", "type", "url", "parameter", "evidence")
        self.result_tree = ttk.Treeview(result_frame, columns=columns,
                                         show="headings", height=6)
        self.result_tree.heading("severity", text="严重度")
        self.result_tree.heading("type", text="类型")
        self.result_tree.heading("url", text="URL")
        self.result_tree.heading("parameter", text="参数")
        self.result_tree.heading("evidence", text="证据")
        self.result_tree.column("severity", width=70, anchor=tk.CENTER)
        self.result_tree.column("type", width=100)
        self.result_tree.column("url", width=280)
        self.result_tree.column("parameter", width=80)
        self.result_tree.column("evidence", width=200)
        for sev, color in SEVERITY_COLORS.items():
            self.result_tree.tag_configure(sev.upper(), foreground=color)

        tree_scroll = ttk.Scrollbar(result_frame, orient=tk.VERTICAL,
                                     command=self.result_tree.yview)
        self.result_tree.configure(yscrollcommand=tree_scroll.set)
        self.result_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.result_tree.bind('<Double-Button-1>', lambda e: self._view_detail())

        # 底部按钮
        btn_frame = ttk.Frame(result_frame)
        btn_frame.pack(fill=tk.X, pady=(5, 0))
        ttk.Button(btn_frame, text="📥 导出 JSON",
                   command=lambda: self._export("json")).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="📥 导出 HTML",
                   command=lambda: self._export("html")).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="🗑 清空",
                   command=self._clear_results).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="📋 查看详情",
                   command=self._view_detail).pack(side=tk.RIGHT, padx=2)

        # === 右侧：帮助面板 ===
        right = ttk.Frame(main, width=200)
        right.pack(side=tk.RIGHT, fill=tk.Y, padx=(10, 0))
        right.pack_propagate(False)

        help_frame = ttk.LabelFrame(right, text="使用说明", padding=8)
        help_frame.pack(fill=tk.X)
        helps = [
            ("① 输入目标 URL", "支持 http/https"),
            ("② 勾选检测模块", "默认全开，可按需关闭"),
            ("③ 点击开始扫描", "实时查看扫描进度"),
            ("④ 查看即时结果", "发现漏洞立刻展示"),
            ("⑤ 双击查看详情", "导出 JSON/HTML 报告"),
        ]
        for title, desc in helps:
            row = ttk.Frame(help_frame)
            row.pack(fill=tk.X, pady=3)
            ttk.Label(row, text=title, font=("", 9, "bold"),
                      foreground="#333").pack(anchor=tk.W)
            ttk.Label(row, text=desc, font=("", 8),
                      foreground="#666").pack(anchor=tk.W)

        note_frame = ttk.LabelFrame(right, text="注意事项", padding=8)
        note_frame.pack(fill=tk.X, pady=(8, 0))
        for note in [
            "• 仅扫描您有权测试的目标",
            "• 扫描结果实时显示在表格中",
            "• 日志区可看到完整的扫描过程",
            "• HTTPS 证书问题可关闭 SSL 验证",
            "• 本工具仅用于授权安全测试",
        ]:
            ttk.Label(note_frame, text=note, font=("", 8),
                      foreground="#888", wraplength=180).pack(anchor=tk.W, pady=1)

    @staticmethod
    def _make_stat(parent, label, widget):
        f = ttk.Frame(parent)
        f.pack(side=tk.LEFT, padx=(0, 15))
        ttk.Label(f, text=label, font=("", 8), foreground="#6B7280").pack(side=tk.LEFT)
        widget.pack(side=tk.LEFT, padx=2)

    # ==================== 扫描控制 ====================

    def _toggle_all(self, state):
        for var in self.module_vars.values():
            var.set(state)

    def start_scan(self):
        url = self.url_entry.get().strip()
        if not url or url == "http://":
            messagebox.showwarning("提示", "请输入目标 URL")
            return

        enabled_modules = [m for m, v in self.module_vars.items() if v.get()]
        if not enabled_modules:
            messagebox.showwarning("提示", "请至少选择一个检测模块")
            return

        self._module_order = [m for m in ALL_MODULES if m in enabled_modules]
        self._found_vulns = []
        self.scanning = True
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self._clear_results()
        self._start_time = time_module.time()

        self._log_gui("INFO", "=" * 55)
        self._log_gui("INFO", f"▶ 开始扫描: {url}")
        self._log_gui("INFO", f"▶ 模块: {', '.join(enabled_modules)}")
        self._log_gui("INFO", "=" * 55)
        self._set_status("扫描进行中...", "green")
        self.module_label.config(text="初始化...")
        self.current_action_label.config(text="准备中")
        self.progress_var.set(2)

        # 实时计时
        self._update_stats()

        thread = threading.Thread(
            target=self._scan_worker,
            args=(url, enabled_modules),
            daemon=True
        )
        thread.start()

    def _update_stats(self):
        if self._start_time and self.scanning:
            elapsed = time_module.time() - self._start_time
            self.time_label.config(text=f"{elapsed:.0f}s")
            self.root.after(1000, self._update_stats)

    def stop_scan(self):
        self.scanning = False
        self.stop_btn.config(state=tk.DISABLED)
        self._log_gui("WARNING", "用户中止扫描")
        self._set_status("已中止", "red")
        self.module_label.config(text="")
        self.current_action_label.config(text="")
        self.scan_btn.config(state=tk.NORMAL)

    def _scan_worker(self, url, enabled_modules):
        try:
            config = self._build_config()
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(
                self._run_scan(url, enabled_modules, config)
            )
            loop.close()
        except Exception as e:
            self.msg_queue.put(("log", ("ERROR", f"扫描异常: {e}")))
            import traceback
            for line in traceback.format_exc().split("\n"):
                if line.strip():
                    self.msg_queue.put(("log", ("ERROR", line)))
        finally:
            self.msg_queue.put(("done", None))

    async def _run_scan(self, url, enabled_modules, config):
        session = HTTPPool(config)
        scanner = WAVScanner(config, session)

        # 挂载进度回调
        scanner._progress_callback = self._scan_progress_cb

        for mod in enabled_modules:
            scanner.load_module(mod)

        target = ScanTarget(url=url)

        self.msg_queue.put(("progress", 5))
        self.msg_queue.put(("action", "正在扫描..."))

        try:
            result = await asyncio.wait_for(
                scanner.scan(target),
                timeout=config.get("max_scan_time", 7200)
            )
        except asyncio.TimeoutError:
            self.msg_queue.put(("log", ("ERROR", "扫描超时")))
            return None

        elapsed = time_module.time() - self._start_time
        self.msg_queue.put(("progress", 100))
        self.msg_queue.put(("action", "扫描完成"))
        self.msg_queue.put(("log", ("INFO", f"✅ 扫描完成！耗时 {elapsed:.0f}s")))
        self.msg_queue.put(("log", ("INFO", f"   端点: {result.endpoints_found}  |  请求: {result.requests_made}  |  漏洞: {len(result.vulnerabilities)}")))

        # 按严重度统计
        sev_count = {}
        for v in result.vulnerabilities:
            sev = v.severity.value if hasattr(v.severity, 'value') else str(v.severity)
            sev_count[sev] = sev_count.get(sev, 0) + 1
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in sev_count:
                color = SEVERITY_COLORS.get(sev, "#000")
                self.msg_queue.put(("log", ("INFO",
                    f"   [{sev.upper()}] {sev_count[sev]} 个")))

        self.msg_queue.put(("stats", {
            "endpoints": result.endpoints_found,
            "requests": result.requests_made,
            "elapsed": elapsed,
        }))
        self.msg_queue.put(("result", result))
        return result

    def _scan_progress_cb(self, module_name, done, total, pct):
        """来自扫描引擎的进度回调"""
        if not self.scanning:
            return

        icon = MODULE_ICONS.get(module_name, f"[{module_name}]")
        label_text = f"{icon} {module_name}"
        if total > 0:
            label_text += f"  {done}/{total}"
        self.msg_queue.put(("module", label_text))

        # 实时计算进度
        if module_name in ALL_MODULES:
            total_mods = len(self._module_order)
            try:
                mod_idx = self._module_order.index(module_name)
            except ValueError:
                mod_idx = 0
            base = 10 + (mod_idx / max(total_mods, 1)) * 75
            mod_share = 75 / max(total_mods, 1)
            pct_val = int(base + (done / max(total, 1)) * mod_share)
            self.msg_queue.put(("progress", min(pct_val, 90)))
            self.msg_queue.put(("action",
                f"检测 {module_name.upper()}... ({done}/{total})"))
        elif module_name == "crawl":
            crawl_pct = 3 + (done / max(total, 1)) * 7
            self.msg_queue.put(("progress", min(crawl_pct, 10)))
            self.msg_queue.put(("action", f"爬虫 {done}/{total} 页面"))
        elif module_name == "report":
            self.msg_queue.put(("progress", 95))
            self.msg_queue.put(("action", "生成报告..."))

    def _build_config(self):
        config = ConfigManager()
        for key in ["rate", "timeout", "crawl_depth", "crawl_max_urls", "concurrent_endpoints"]:
            try:
                val = int(self.cfg_entries[key].get())
                config.set(key, val)
            except ValueError:
                pass
        if self.insecure_var.get():
            config.set("verify_ssl", False)
        return config

    # ==================== 消息轮询 ====================

    def _poll_queue(self):
        try:
            while True:
                msg_type, msg_data = self.msg_queue.get_nowait()
                if msg_type == "log":
                    level, text = msg_data
                    self._log_gui(level, text)
                elif msg_type == "status":
                    self._set_status(*msg_data)
                elif msg_type == "action":
                    self.current_action_label.config(text=msg_data)
                elif msg_type == "module":
                    self.module_label.config(text=msg_data)
                elif msg_type == "progress":
                    self.progress_var.set(msg_data)
                elif msg_type == "stats":
                    if "endpoints" in msg_data:
                        self.endpoint_label.config(text=str(msg_data["endpoints"]))
                    if "requests" in msg_data:
                        self.request_label.config(text=str(msg_data["requests"]))
                    if "elapsed" in msg_data:
                        self.time_label.config(text=f"{msg_data['elapsed']:.0f}s")
                elif msg_type == "vuln":
                    # 即时添加单个漏洞到表格
                    self._add_vuln_row(msg_data)
                elif msg_type == "result":
                    self._display_results(msg_data)
                elif msg_type == "done":
                    self._on_done()
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)

    def _log_gui(self, level, text):
        """在终端风格的日志区输出"""
        self.log_area.config(state=tk.NORMAL)
        t = datetime.now().strftime("%H:%M:%S")
        tag = level.lower()
        if tag not in LOG_COLORS:
            tag = "info"
        self.log_area.insert(tk.END, f"{t} ", "time")
        self.log_area.insert(tk.END, f"{text}\n", tag)
        self.log_area.see(tk.END)
        self.log_area.config(state=tk.DISABLED)

    def _set_status(self, text, fg="black"):
        self.status_label.config(text=text, foreground=fg)

    def _add_vuln_row(self, v):
        """发现漏洞时即时添加到表格"""
        sev = v.severity.value if hasattr(v.severity, 'value') else str(v.severity)
        vtype = v.type.value if hasattr(v.type, 'value') else str(v.type)
        url = (v.url or "")[:80]
        param = v.parameter or ""
        evidence = (v.evidence or "")[:100]
        tag = sev.upper()
        self.result_tree.insert("", tk.END, values=(sev, vtype, url, param, evidence),
                                 tags=(tag,))
        # 更新漏洞计数
        self._found_vulns.append(v)
        self.vuln_count_label.config(text=f"漏洞: {len(self._found_vulns)}",
                                      foreground="#DC143C")
        # 日志里也标记
        self._log_gui("INFO", f"  🔴 发现 [{sev.upper()}] {vtype} @ {url}")

    def _on_done(self):
        self.scanning = False
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress_var.set(100)
        if self.status_label.cget("text") != "已中止":
            self._set_status("就绪 ✓  扫描完成", "green")
        self.module_label.config(text="")

    def _display_results(self, result):
        """最终结果（补充可能漏掉的漏洞）"""
        self.scan_result = result
        # 去重
        existing = set()
        for child in self.result_tree.get_children():
            vals = self.result_tree.item(child, "values")
            existing.add((vals[1], vals[2], vals[3]))
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_vulns = sorted(
            result.vulnerabilities,
            key=lambda v: sev_order.get(
                v.severity.value if hasattr(v.severity, 'value') else str(v.severity), 5
            )
        )
        for v in sorted_vulns:
            vtype = v.type.value if hasattr(v.type, 'value') else str(v.type)
            url = (v.url or "")[:80]
            param = v.parameter or ""
            key = (vtype, url, param)
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
        self.mod_stat_label.config(text="-")
        self.vuln_count_label.config(text="漏洞: 0", foreground="#6B7280")
        self.log_area.config(state=tk.NORMAL)
        self.log_area.delete(1.0, tk.END)
        self.log_area.config(state=tk.DISABLED)
        self.module_label.config(text="")
        self.current_action_label.config(text="")

    # ==================== 导出 ====================

    def _export(self, fmt):
        if not self.scan_result and not self._found_vulns:
            messagebox.showwarning("提示", "没有扫描结果可导出")
            return
        os.makedirs("scan_reports", exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        vulns = self._found_vulns or (self.scan_result.vulnerabilities if self.scan_result else [])
        if fmt == "json":
            path = f"scan_reports/report_{ts}.json"
            report = {
                "scan_time": ts,
                "total_vulnerabilities": len(vulns),
                "vulnerabilities": [
                    {
                        "type": v.type.value if hasattr(v.type, 'value') else str(v.type),
                        "severity": v.severity.value if hasattr(v.severity, 'value') else str(v.severity),
                        "url": v.url, "parameter": v.parameter,
                        "evidence": v.evidence, "title": v.title,
                        "description": v.description,
                        "recommendation": v.recommendation,
                    } for v in vulns
                ],
            }
            with open(path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
        else:
            path = f"scan_reports/report_{ts}.html"
            sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            sorted_v = sorted(vulns, key=lambda v: sev_order.get(
                v.severity.value if hasattr(v.severity, 'value') else str(v.severity), 5
            ))
            rows = ""
            for v in sorted_v:
                sev = v.severity.value if hasattr(v.severity, 'value') else "info"
                c = SEVERITY_COLORS.get(sev, "#000")
                rows += f"""<tr><td style="color:{c};font-weight:bold">{sev.upper()}</td>
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
<h1>🔍 RayScan 1.0.2 扫描报告</h1>
<div class="summary"><p>扫描时间: {datetime.now().isoformat()}</p>
<p>漏洞总数: {len(sorted_v)}</p></div>
<table><tr><th>严重度</th><th>类型</th><th>URL</th><th>参数</th><th>证据</th></tr>
{rows}</table></body></html>"""
            with open(path, "w", encoding="utf-8") as f:
                f.write(html)
        self._log_gui("INFO", f"✅ 报告已保存: {path}")
        messagebox.showinfo("导出完成", f"已保存到:\n{path}")

    def _view_detail(self):
        sel = self.result_tree.selection()
        if not sel:
            return
        values = self.result_tree.item(sel[0], "values")
        text = f"严重度: {values[0]}\n类型: {values[1]}\nURL: {values[2]}\n参数: {values[3]}\n\n证据:\n{values[4]}"
        messagebox.showinfo("漏洞详情", text)


if __name__ == '__main__':
    root = tk.Tk()
    app = RayScanGUI(root)
    root.mainloop()
