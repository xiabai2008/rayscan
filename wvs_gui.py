"""
RayScan 1.0 GUI — Web Vulnerability Scanner
"""
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import queue
import asyncio
import json
import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from wvs.config import ConfigManager
from wvs.core import HTTPPool, WAVScanner
from wvs.models import ScanTarget

SEVERITY_COLORS = {
    "critical": "#8B0000",
    "high": "#FF0000",
    "medium": "#FF8C00",
    "low": "#0066CC",
    "info": "#666666",
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


class WVSGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("RayScan 1.0 — Web Vulnerability Scanner")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)

        self.scanning = False
        self.msg_queue = queue.Queue()
        self.scan_result = None
        self._start_time = None
        self._progress_timer = None

        self._build_ui()
        self._poll_queue()

    # ==================== UI 构建 ====================

    def _build_ui(self):
        top = ttk.Frame(self.root, padding=10)
        top.pack(fill=tk.X)
        ttk.Label(top, text="目标 URL：", font=("", 10, "bold")).pack(side=tk.LEFT)
        self.url_entry = ttk.Entry(top, width=50)
        self.url_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.url_entry.insert(0, "http://")
        self.url_entry.bind('<Return>', lambda e: self.start_scan())

        self.scan_btn = ttk.Button(top, text="开始扫描", command=self.start_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=5)
        self.stop_btn = ttk.Button(top, text="停止", command=self.stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT)

        left = ttk.Frame(self.root, padding=5)
        left.pack(side=tk.LEFT, fill=tk.Y)

        mod_frame = ttk.LabelFrame(left, text="检测模块", padding=5)
        mod_frame.pack(fill=tk.X, pady=(0, 5))
        self.module_vars = {}
        for mod_id, (mod_name, mod_desc) in MODULE_INFO.items():
            var = tk.BooleanVar(value=True)
            self.module_vars[mod_id] = var
            cb = ttk.Checkbutton(mod_frame, text=mod_name, variable=var)
            cb.pack(anchor=tk.W)

        btn_row = ttk.Frame(mod_frame)
        btn_row.pack(fill=tk.X, pady=(5, 0))
        ttk.Button(btn_row, text="全选", command=lambda: self._toggle_all(True)).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_row, text="取消全选", command=lambda: self._toggle_all(False)).pack(side=tk.LEFT, padx=2)

        cfg_frame = ttk.LabelFrame(left, text="扫描配置", padding=5)
        cfg_frame.pack(fill=tk.X)
        configs = [
            ("请求速率 (req/s)：", "rate", "10"),
            ("超时 (秒)：", "timeout", "15"),
            ("爬虫深度：", "crawl_depth", "2"),
            ("最大 URL 数：", "crawl_max_urls", "50"),
            ("并发端点：", "concurrent_endpoints", "10"),
        ]
        self.cfg_entries = {}
        for label, key, default in configs:
            row = ttk.Frame(cfg_frame)
            row.pack(fill=tk.X, pady=1)
            ttk.Label(row, text=label, width=15).pack(side=tk.LEFT)
            entry = ttk.Entry(row, width=8)
            entry.insert(0, default)
            entry.pack(side=tk.LEFT)
            self.cfg_entries[key] = entry

        self.insecure_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(cfg_frame, text="禁用 SSL 验证", variable=self.insecure_var).pack(anchor=tk.W, pady=(5, 0))

        # ---- 右侧：使用说明 ----
        right = ttk.Frame(self.root, padding=5)
        right.pack(side=tk.RIGHT, fill=tk.Y)

        help_frame = ttk.LabelFrame(right, text="使用说明", padding=8)
        help_frame.pack(fill=tk.X)

        help_texts = [
            ("\u2460 输入目标", "输入要扫描的网址，支持 http/https"),
            ("\u2461 选择模块", "勾选要启用的检测模块，默认全开"),
            ("\u2462 调整参数", "根据目标性能调整请求速率和超时"),
            ("\u2463 开始扫描", "点击\u201c开始扫描\u201d，等待结果"),
            ("\u2464 查看结果", "双击漏洞行查看详情，可导出报告"),
        ]
        for title, desc in help_texts:
            row = ttk.Frame(help_frame)
            row.pack(fill=tk.X, pady=3)
            ttk.Label(row, text=title, font=("", 9, "bold"), foreground="#333").pack(anchor=tk.W)
            ttk.Label(row, text=desc, font=("", 8), foreground="#666", wraplength=180).pack(anchor=tk.W)

        note_frame = ttk.LabelFrame(right, text="注意事项", padding=8)
        note_frame.pack(fill=tk.X, pady=(10, 0))

        note_items = [
            "\u2022 仅扫描您有权测试的目标",
            "\u2022 高并发可能影响目标服务器",
            "\u2022 扫描时间取决于目标响应速度",
            "\u2022 HTTPS 证书问题可关闭 SSL 验证",
            "\u2022 结果可导出 JSON / HTML 报告",
            "\u2022 本工具仅用于授权安全测试",
        ]
        for note in note_items:
            ttk.Label(note_frame, text=note, font=("", 8), foreground="#888", wraplength=190).pack(anchor=tk.W, pady=1)

        # 版本信息
        ver_frame = ttk.LabelFrame(right, text="版本信息", padding=8)
        ver_frame.pack(fill=tk.X, pady=(10, 0))
        ttk.Label(ver_frame, text="RayScan 1.0", font=("", 9, "bold")).pack(anchor=tk.W)
        ttk.Label(ver_frame, text="RayScan 1.0.2", font=("", 8), foreground="#888").pack(anchor=tk.W)
        ttk.Label(ver_frame, text="MIT License", font=("", 8), foreground="#888").pack(anchor=tk.W)
        ttk.Label(ver_frame, text="github.com/xiabai2004/RayScan", font=("", 7), foreground="#aaa", wraplength=190).pack(anchor=tk.W)

        center = ttk.Frame(self.root, padding=5)
        center.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        status_frame = ttk.LabelFrame(center, text="扫描状态", padding=5)
        status_frame.pack(fill=tk.X, pady=(0, 5))

        self.status_label = ttk.Label(status_frame, text="就绪，请输入目标 URL", foreground="gray")
        self.status_label.pack(anchor=tk.W)

        self.current_action_label = ttk.Label(status_frame, text="", foreground="#888")
        self.current_action_label.pack(anchor=tk.W, pady=(2, 0))

        info_row = ttk.Frame(status_frame)
        info_row.pack(fill=tk.X, pady=2)
        ttk.Label(info_row, text="端点：").pack(side=tk.LEFT)
        self.endpoint_label = ttk.Label(info_row, text="-", foreground="blue")
        self.endpoint_label.pack(side=tk.LEFT, padx=(0, 20))
        ttk.Label(info_row, text="请求：").pack(side=tk.LEFT)
        self.request_label = ttk.Label(info_row, text="-", foreground="blue")
        self.request_label.pack(side=tk.LEFT, padx=(0, 20))
        ttk.Label(info_row, text="用时：").pack(side=tk.LEFT)
        self.time_label = ttk.Label(info_row, text="-", foreground="blue")
        self.time_label.pack(side=tk.LEFT)

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(center, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=(0, 5))

        log_frame = ttk.LabelFrame(center, text="扫描日志", padding=5)
        log_frame.pack(fill=tk.BOTH, expand=True)
        self.log_area = scrolledtext.ScrolledText(log_frame, height=10, state=tk.DISABLED, font=("Consolas", 9))
        self.log_area.pack(fill=tk.BOTH, expand=True)

        result_frame = ttk.LabelFrame(self.root, text="扫描结果", padding=5)
        result_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=(0, 10))

        columns = ("severity", "type", "url", "parameter", "evidence")
        self.result_tree = ttk.Treeview(result_frame, columns=columns, show="headings", height=8)
        self.result_tree.heading("severity", text="严重度")
        self.result_tree.heading("type", text="类型")
        self.result_tree.heading("url", text="URL")
        self.result_tree.heading("parameter", text="参数")
        self.result_tree.heading("evidence", text="证据")
        self.result_tree.column("severity", width=70)
        self.result_tree.column("type", width=120)
        self.result_tree.column("url", width=250)
        self.result_tree.column("parameter", width=80)
        self.result_tree.column("evidence", width=200)
        for sev, color in SEVERITY_COLORS.items():
            self.result_tree.tag_configure(sev.upper(), foreground=color)

        scrollbar = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=self.result_tree.yview)
        self.result_tree.configure(yscrollcommand=scrollbar.set)
        self.result_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        btn_frame = ttk.Frame(result_frame)
        btn_frame.pack(fill=tk.X, pady=(5, 0))
        ttk.Button(btn_frame, text="导出 JSON", command=lambda: self._export("json")).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="导出 HTML", command=lambda: self._export("html")).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="清空结果", command=self._clear_results).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="查看详情", command=self._view_detail).pack(side=tk.RIGHT, padx=2)
        self.result_tree.bind('<Double-Button-1>', lambda e: self._view_detail())

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

        self._module_order = [m for m in ["sqli","xss","cmdi","lfi","rce","ssrf","xxe","api","sensitive","waf"] if m in enabled_modules]

        self.scanning = True
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self._clear_results()
        self._log("=" * 50)
        self._log("开始扫描：{}".format(url))
        self._log("模块：{}".format(', '.join(enabled_modules)))
        self._set_status("正在初始化...")
        self.current_action_label.config(text="")
        self._start_time = datetime.now()

        # 启动定时器定期刷新用时
        self._update_elapsed()

        thread = threading.Thread(target=self._scan_worker, args=(url, enabled_modules), daemon=True)
        thread.start()

    def _update_elapsed(self):
        if self._start_time and self.scanning:
            elapsed = (datetime.now() - self._start_time).total_seconds()
            self.time_label.config(text="{:.0f}s".format(elapsed))
            self.root.after(1000, self._update_elapsed)

    def stop_scan(self):
        self.scanning = False
        self.stop_btn.config(state=tk.DISABLED)
        self._set_status("正在停止...")
        self.current_action_label.config(text="")
        self._log("用户中止扫描")

    def _scan_worker(self, url, enabled_modules):
        try:
            config = self._build_config()
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(self._run_scan(url, enabled_modules, config))
            loop.close()
        except Exception as e:
            self.msg_queue.put(("log", "扫描异常：{}".format(e)))
            import traceback
            self.msg_queue.put(("log", traceback.format_exc()))
        finally:
            self.msg_queue.put(("done", None))

    async def _run_scan(self, url, enabled_modules, config):
        session = HTTPPool(config)
        scanner = WAVScanner(config, session)

        for mod in enabled_modules:
            scanner.load_module(mod)

        target = ScanTarget(url=url)

        # 爬取阶段
        self.msg_queue.put(("log", "正在爬取目标网站..."))
        self.msg_queue.put(("action", "正在爬取页面..."))
        self.msg_queue.put(("progress", 5))
        await asyncio.sleep(0.5)  # 让 GUI 有机会刷新

        t0 = __import__('time').time()

        # 扫描阶段
        self.msg_queue.put(("action", "检测模块运行中..."))
        self.msg_queue.put(("progress", 10))

        # 把 scanner 挂载到 msg_queue 上，这样模块可以发进度
        scanner._progress_callback = self._scan_progress_cb

        try:
            result = await asyncio.wait_for(scanner.scan(target), timeout=config.get("max_scan_time", 7200))
        except asyncio.TimeoutError:
            self.msg_queue.put(("log", "扫描超时"))
            return None

        elapsed = __import__('time').time() - t0
        self.msg_queue.put(("progress", 95))
        self.msg_queue.put(("action", "正在生成报告..."))
        self.msg_queue.put(("log", "扫描完成！耗时 {:.0f}s".format(elapsed)))

        self.msg_queue.put(("log", "发现端点：{}".format(result.endpoints_found)))
        self.msg_queue.put(("log", "发送请求：{}".format(result.requests_made)))
        self.msg_queue.put(("log", "发现漏洞：{} 个".format(len(result.vulnerabilities))))
        self.msg_queue.put(("stats", {
            "endpoints": result.endpoints_found,
            "requests": result.requests_made,
            "elapsed": elapsed,
        }))

        sev_count = {}
        for v in result.vulnerabilities:
            sev = v.severity.value if hasattr(v.severity, 'value') else str(v.severity)
            sev_count[sev] = sev_count.get(sev, 0) + 1
        for sev, count in sorted(sev_count.items()):
            self.msg_queue.put(("log", "  [{}] {} 个".format(sev.upper(), count)))

        self.msg_queue.put(("result", result))
        return result

    def _scan_progress_cb(self, module_name, done, total, pct):
        """从扫描引擎回调的真实进度"""
        # 计算整体进度：crawl(0-10) + jspathfinder(10-15) + detectors(15-85)
        if module_name in ["sqli","xss","lfi","cmdi","rce","ssrf","xxe","api","sensitive","waf"]:
            total_mods = len(self._module_order)
            try:
                mod_idx = self._module_order.index(module_name)
            except ValueError:
                mod_idx = 0
            # 模块内进度: 15-85% 之间按模块分配
            base = 15 + (mod_idx / max(total_mods, 1)) * 70
            mod_share = 70 / max(total_mods, 1)
            pct = int(base + (done / max(total, 1)) * mod_share)
            pct = min(pct, 85)
        elif module_name == "crawl":
            pct = int(5 + (done / max(total, 1)) * 5)
        elif module_name == "jspathfinder":
            pct = 12
        elif module_name == "integrations":
            pct = 87
        elif module_name == "dedup":
            pct = 92
        elif module_name == "report":
            pct = 95
        else:
            # 使用扫描器传过来的百分比
            pct = min(pct, 85)
        self.msg_queue.put(("progress", pct))
        if module_name:
            action_text = "正在检测 [{}]... ({}/{})".format(module_name, done, total)
            self.msg_queue.put(("action", action_text))

    def _build_config(self):
        config = ConfigManager()
        try: config.set("rate", int(self.cfg_entries["rate"].get()))
        except ValueError: pass
        try: config.set("timeout", int(self.cfg_entries["timeout"].get()))
        except ValueError: pass
        try: config.set("crawl_depth", int(self.cfg_entries["crawl_depth"].get()))
        except ValueError: pass
        try: config.set("crawl_max_urls", int(self.cfg_entries["crawl_max_urls"].get()))
        except ValueError: pass
        try: config.set("concurrent_endpoints", int(self.cfg_entries["concurrent_endpoints"].get()))
        except ValueError: pass
        if self.insecure_var.get():
            config.set("verify_ssl", False)
        return config

    # ==================== 消息轮询 ====================

    def _poll_queue(self):
        try:
            while True:
                msg_type, msg_data = self.msg_queue.get_nowait()
                if msg_type == "log":
                    self._log(msg_data)
                elif msg_type == "status":
                    self._set_status(msg_data)
                elif msg_type == "action":
                    self.current_action_label.config(text=msg_data)
                elif msg_type == "progress":
                    self.progress_var.set(msg_data)
                elif msg_type == "stats":
                    self.endpoint_label.config(text=str(msg_data.get("endpoints", "-")))
                    self.request_label.config(text=str(msg_data.get("requests", "-")))
                    self.time_label.config(text="{:.0f}s".format(msg_data.get('elapsed', 0)))
                elif msg_type == "result":
                    self._display_results(msg_data)
                elif msg_type == "done":
                    self._on_done()
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)

    def _log(self, text):
        self.log_area.config(state=tk.NORMAL)
        now = datetime.now().strftime("%H:%M:%S")
        self.log_area.insert(tk.END, "[{}] {}\n".format(now, text))
        self.log_area.see(tk.END)
        self.log_area.config(state=tk.DISABLED)

    def _set_status(self, text):
        self.status_label.config(text=text, foreground="black")

    def _on_done(self):
        self.scanning = False
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress_var.set(100)
        self.current_action_label.config(text="")
        if self.status_label.cget("text") != "用户中止扫描":
            self._set_status("就绪 — 扫描完成")

    def _display_results(self, result):
        self.scan_result = result
        self.result_tree.delete(*self.result_tree.get_children())
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_vulns = sorted(
            result.vulnerabilities,
            key=lambda v: sev_order.get(
                v.severity.value if hasattr(v.severity, 'value') else str(v.severity), 5
            )
        )
        for v in sorted_vulns:
            sev = v.severity.value if hasattr(v.severity, 'value') else str(v.severity)
            vtype = v.type.value if hasattr(v.type, 'value') else str(v.type)
            url = (v.url or "")[:80]
            param = v.parameter or ""
            evidence = (v.evidence or "")[:100]
            tag = sev.upper()
            self.result_tree.insert("", tk.END, values=(sev, vtype, url, param, evidence), tags=(tag,))
        self._log("结果已加载，共 {} 个漏洞".format(len(sorted_vulns)))

    def _clear_results(self):
        self.result_tree.delete(*self.result_tree.get_children())
        self.scan_result = None
        self.progress_var.set(0)
        self.endpoint_label.config(text="-")
        self.request_label.config(text="-")
        self.time_label.config(text="-")

    def _export(self, fmt):
        if not self.scan_result:
            messagebox.showwarning("提示", "没有扫描结果可导出")
            return
        os.makedirs("scan_reports", exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        if fmt == "json":
            path = "scan_reports/report_{}.json".format(ts)
            vulns = []
            for v in self.scan_result.vulnerabilities:
                vulns.append({
                    "type": v.type.value if hasattr(v.type, 'value') else str(v.type),
                    "severity": v.severity.value if hasattr(v.severity, 'value') else str(v.severity),
                    "url": v.url,
                    "parameter": v.parameter,
                    "evidence": v.evidence,
                    "title": v.title,
                    "description": v.description,
                    "recommendation": v.recommendation,
                })
            report = {
                "scan_time": ts,
                "endpoints_found": getattr(self.scan_result, 'endpoints_found', 0),
                "requests_made": getattr(self.scan_result, 'requests_made', 0),
                "total_vulnerabilities": len(vulns),
                "vulnerabilities": vulns,
            }
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            self._log("JSON 报告已保存：{}".format(path))
            messagebox.showinfo("导出完成", "已保存到：{}".format(path))
        elif fmt == "html":
            path = "scan_reports/report_{}.html".format(ts)
            self._export_html(path)
            self._log("HTML 报告已保存：{}".format(path))
            messagebox.showinfo("导出完成", "已保存到：{}".format(path))

    def _export_html(self, path):
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        vulns = sorted(
            self.scan_result.vulnerabilities,
            key=lambda v: sev_order.get(
                v.severity.value if hasattr(v.severity, 'value') else str(v.severity), 5
            )
        )
        rows = ""
        for v in vulns:
            sev = v.severity.value if hasattr(v.severity, 'value') else "info"
            color = SEVERITY_COLORS.get(sev, "#000")
            rows += """<tr>
                <td style="color:{};font-weight:bold">{}</td>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
            </tr>\n""".format(color, sev.upper(), v.type.value if hasattr(v.type,'value') else str(v.type), v.url or '', v.parameter or '', v.evidence or '')
        html = """<!DOCTYPE html>
<html lang="zh">
<head><meta charset="utf-8"><title>RayScan Scan Report</title>
<style>
body{{font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5}}
h1{{color: #333}} table{{border-collapse: collapse; width: 100%; background: #fff}}
th,td{{padding: 8px 12px; border: 1px solid #ddd; text-align: left; font-size: 13px}}
th{{background: #333; color: #fff}} tr:hover{{background: #f0f0f0}}
.summary{{background: #fff; padding: 15px; margin-bottom: 20px; border-radius: 5px}}
</style></head>
<body>
<h1>RayScan 1.0 扫描报告</h1>
<div class="summary">
    <p>扫描时间：{}</p>
    <p>端点发现：{} | 请求数：{} | 漏洞总数：{}</p>
</div>
<table>
<tr><th>严重度</th><th>类型</th><th>URL</th><th>参数</th><th>证据</th></tr>
{}
</table>
</body></html>""".format(
            datetime.now().isoformat(),
            getattr(self.scan_result, 'endpoints_found', 0),
            getattr(self.scan_result, 'requests_made', 0),
            len(vulns), rows)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html)

    def _view_detail(self):
        sel = self.result_tree.selection()
        if not sel:
            return
        values = self.result_tree.item(sel[0], "values")
        text = "严重度: {}\n类型: {}\nURL: {}\n参数: {}\n\n证据:\n{}".format(values[0], values[1], values[2], values[3], values[4])
        messagebox.showinfo("漏洞详情", text)


if __name__ == '__main__':
    root = tk.Tk()
    app = WVSGUI(root)
    root.mainloop()
