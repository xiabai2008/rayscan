"""
WVS v19.2 GUI — Web Vulnerability Scanner 图形界面
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

# 确保 wvs 包在导入路径中
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
        self.root.title("WVS v19.2 — Web Vulnerability Scanner")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)

        self.scanning = False
        self.msg_queue = queue.Queue()
        self.scan_result = None

        self._build_ui()
        self._poll_queue()

    # ==================== UI 构建 ====================

    def _build_ui(self):
        # ---- 顶部：目标输入 ----
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

        # ---- 左侧面板：模块 + 配置 ----
        left = ttk.Frame(self.root, padding=5)
        left.pack(side=tk.LEFT, fill=tk.Y)

        # 模块选择
        mod_frame = ttk.LabelFrame(left, text="检测模块", padding=5)
        mod_frame.pack(fill=tk.X, pady=(0, 5))
        self.module_vars = {}
        for mod_id, (mod_name, mod_desc) in MODULE_INFO.items():
            var = tk.BooleanVar(value=True)
            self.module_vars[mod_id] = var
            cb = ttk.Checkbutton(mod_frame, text=mod_name, variable=var)
            cb.pack(anchor=tk.W)

        # 全选/取消
        btn_row = ttk.Frame(mod_frame)
        btn_row.pack(fill=tk.X, pady=(5, 0))
        ttk.Button(btn_row, text="全选", command=lambda: self._toggle_all(True)).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_row, text="取消全选", command=lambda: self._toggle_all(False)).pack(side=tk.LEFT, padx=2)

        # 配置参数
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

        # ---- 中间：状态 + 进度 ----
        center = ttk.Frame(self.root, padding=5)
        center.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        status_frame = ttk.LabelFrame(center, text="扫描状态", padding=5)
        status_frame.pack(fill=tk.X, pady=(0, 5))

        self.status_label = ttk.Label(status_frame, text="就绪，请输入目标 URL", foreground="gray")
        self.status_label.pack(anchor=tk.W)

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

        # 进度条
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(center, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=(0, 5))

        # 日志区
        log_frame = ttk.LabelFrame(center, text="扫描日志", padding=5)
        log_frame.pack(fill=tk.BOTH, expand=True)
        self.log_area = scrolledtext.ScrolledText(log_frame, height=10, state=tk.DISABLED, font=("Consolas", 9))
        self.log_area.pack(fill=tk.BOTH, expand=True)

        # ---- 底部：结果表格 ----
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

        # 为严重度设置颜色
        for sev, color in SEVERITY_COLORS.items():
            self.result_tree.tag_configure(sev.upper(), foreground=color)

        scrollbar = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=self.result_tree.yview)
        self.result_tree.configure(yscrollcommand=scrollbar.set)
        self.result_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 结果操作按钮
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

        self.scanning = True
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self._clear_results()
        self._log(f"=" * 50)
        self._log(f"开始扫描：{url}")
        self._log(f"模块：{', '.join(enabled_modules)}")
        self._set_status("正在初始化...")

        thread = threading.Thread(target=self._scan_worker, args=(url, enabled_modules), daemon=True)
        thread.start()

    def stop_scan(self):
        self.scanning = False
        self.stop_btn.config(state=tk.DISABLED)
        self._set_status("正在停止...")
        self._log("用户中止扫描")

    def _scan_worker(self, url, enabled_modules):
        """后台扫描线程"""
        try:
            config = self._build_config()

            # 在后台线程中运行 asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            result = loop.run_until_complete(self._run_scan(url, enabled_modules, config))
            loop.close()

        except Exception as e:
            self.msg_queue.put(("log", f"扫描异常：{e}"))
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
        self.msg_queue.put(("log", "正在爬取目标网站..."))
        self.msg_queue.put(("status", "正在爬取..."))
        self.msg_queue.put(("progress", 10))

        t0 = __import__('time').time()

        try:
            result = await asyncio.wait_for(scanner.scan(target), timeout=config.get("max_scan_time", 7200))
        except asyncio.TimeoutError:
            self.msg_queue.put(("log", "扫描超时"))
            return

        elapsed = __import__('time').time() - t0

        self.msg_queue.put(("progress", 90))
        self.msg_queue.put(("status", "正在生成报告..."))
        self.msg_queue.put(("log", f"扫描完成！耗时 {elapsed:.0f}s"))
        self.msg_queue.put(("log", f"发现端点：{result.endpoints_found}"))
        self.msg_queue.put(("log", f"发送请求：{result.requests_made}"))
        self.msg_queue.put(("log", f"发现漏洞：{len(result.vulnerabilities)} 个"))
        self.msg_queue.put(("stats", {
            "endpoints": result.endpoints_found,
            "requests": result.requests_made,
            "elapsed": elapsed,
        }))

        # 按严重度统计
        sev_count = {}
        for v in result.vulnerabilities:
            sev = v.severity.value if hasattr(v.severity, 'value') else str(v.severity)
            sev_count[sev] = sev_count.get(sev, 0) + 1
        for sev, count in sorted(sev_count.items()):
            self.msg_queue.put(("log", f"  [{sev.upper()}] {count} 个"))

        self.msg_queue.put(("result", result))

    def _build_config(self):
        config = ConfigManager()
        # 应用 GUI 中的配置
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

    # ==================== 消息轮询 (GUI 线程) ====================

    def _poll_queue(self):
        try:
            while True:
                msg_type, msg_data = self.msg_queue.get_nowait()
                if msg_type == "log":
                    self._log(msg_data)
                elif msg_type == "status":
                    self._set_status(msg_data)
                elif msg_type == "progress":
                    self.progress_var.set(msg_data)
                elif msg_type == "stats":
                    self.endpoint_label.config(text=str(msg_data.get("endpoints", "-")))
                    self.request_label.config(text=str(msg_data.get("requests", "-")))
                    self.time_label.config(text=f"{msg_data.get('elapsed', 0):.0f}s")
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
        self.log_area.insert(tk.END, f"[{now}] {text}\n")
        self.log_area.see(tk.END)
        self.log_area.config(state=tk.DISABLED)

    def _set_status(self, text):
        self.status_label.config(text=text, foreground="black")

    def _on_done(self):
        self.scanning = False
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress_var.set(100)
        if self.status_label.cget("text") != "用户中止扫描":
            self._set_status("就绪 — 扫描完成")

    def _display_results(self, result):
        """显示扫描结果到表格"""
        self.scan_result = result
        self.result_tree.delete(*self.result_tree.get_children())

        # 按严重度排序
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
            url = v.url[:80] if v.url else ""
            param = v.parameter or ""
            evidence = (v.evidence or "")[:100]

            tag = sev.upper()
            self.result_tree.insert("", tk.END, values=(sev, vtype, url, param, evidence), tags=(tag,))

        self._log(f"结果已加载，共 {len(sorted_vulns)} 个漏洞")

    def _clear_results(self):
        self.result_tree.delete(*self.result_tree.get_children())
        self.scan_result = None
        self.progress_var.set(0)
        self.endpoint_label.config(text="-")
        self.request_label.config(text="-")
        self.time_label.config(text="-")

    # ==================== 导出和详情 ====================

    def _export(self, fmt):
        if not self.scan_result:
            messagebox.showwarning("提示", "没有扫描结果可导出")
            return

        os.makedirs("scan_reports", exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        if fmt == "json":
            path = f"scan_reports/report_{ts}.json"
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
                "endpoints_found": self.scan_result.endpoints_found,
                "requests_made": self.scan_result.requests_made,
                "total_vulnerabilities": len(vulns),
                "vulnerabilities": vulns,
            }
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            self._log(f"JSON 报告已保存：{path}")
            messagebox.showinfo("导出完成", f"已保存到：{path}")

        elif fmt == "html":
            path = f"scan_reports/report_{ts}.html"
            self._export_html(path)
            self._log(f"HTML 报告已保存：{path}")
            messagebox.showinfo("导出完成", f"已保存到：{path}")

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
            rows += f"""<tr>
                <td style="color:{color};font-weight:bold">{sev.upper()}</td>
                <td>{v.type.value if hasattr(v.type,'value') else str(v.type)}</td>
                <td>{v.url or ''}</td>
                <td>{v.parameter or ''}</td>
                <td>{v.evidence or ''}</td>
            </tr>\n"""

        html = f"""<!DOCTYPE html>
<html lang="zh">
<head><meta charset="utf-8"><title>WVS Scan Report</title>
<style>
body{{font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5}}
h1{{color: #333}} table{{border-collapse: collapse; width: 100%; background: #fff}}
th,td{{padding: 8px 12px; border: 1px solid #ddd; text-align: left; font-size: 13px}}
th{{background: #333; color: #fff}} tr:hover{{background: #f0f0f0}}
.summary{{background: #fff; padding: 15px; margin-bottom: 20px; border-radius: 5px}}
</style></head>
<body>
<h1>WVS v19.2 扫描报告</h1>
<div class="summary">
    <p>扫描时间：{datetime.now().isoformat()}</p>
    <p>端点发现：{self.scan_result.endpoints_found} | 请求数：{self.scan_result.requests_made} | 漏洞总数：{len(vulns)}</p>
</div>
<table>
<tr><th>严重度</th><th>类型</th><th>URL</th><th>参数</th><th>证据</th></tr>
{rows}
</table>
</body></html>"""

        with open(path, 'w', encoding='utf-8') as f:
            f.write(html)

    def _view_detail(self):
        sel = self.result_tree.selection()
        if not sel:
            return
        values = self.result_tree.item(sel[0], "values")
        text = f"严重度: {values[0]}\n类型: {values[1]}\nURL: {values[2]}\n参数: {values[3]}\n\n证据:\n{values[4]}"
        messagebox.showinfo("漏洞详情", text)


if __name__ == '__main__':
    root = tk.Tk()
    app = WVSGUI(root)
    root.mainloop()
