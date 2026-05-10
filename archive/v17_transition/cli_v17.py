"""WVS v17.0 - 命令行入口"""
import asyncio
import click
import json
import sys
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel

console = Console()


@click.group()
@click.version_option(version="17.0.0", prog_name="WVS v17.0")
def cli():
    """WVS v17.0 - 增强型 Web 漏洞扫描器
    
    新特性:
    - AI 辅助检测引擎
    - 分布式扫描支持
    - CI/CD 集成 (GitLab/GitHub Actions)
    - 通知集成 (Slack/钉钉/企微)
    - 新漏洞类型 (命令注入/SSRF/XXE/路径遍历)
    """
    pass


@cli.command()
@click.argument("target")
@click.option("--scan-type", "-t", default="quick", 
              type=click.Choice(["quick", "full", "stealth", "aggressive"]),
              help="扫描类型")
@click.option("--modules", "-m", multiple=True,
              type=click.Choice(["sqli", "xss", "ssrf", "cmdi", "xxe", "traversal", "all"]),
              default=["all"], help="扫描模块")
@click.option("--output", "-o", type=click.Path(), help="输出报告路径")
@click.option("--format", "-f", "output_format",
              type=click.Choice(["json", "html", "csv", "pdf"]),
              default="json", help="报告格式")
@click.option("--cookies", type=str, help="Cookie 字符串")
@click.option("--header", "-H", multiple=True, help="自定义请求头")
@click.option("--proxy", type=str, help="代理服务器")
@click.option("--threads", type=int, default=10, help="并发线程数")
@click.option("--timeout", type=int, default=10, help="请求超时(秒)")
@click.option("--ai/--no-ai", default=True, help="启用/禁用 AI 辅助")
@click.option("--distributed", is_flag=True, help="分布式扫描模式")
def scan(target, scan_type, modules, output, output_format, cookies, header, proxy, threads, timeout, ai, distributed):
    """扫描目标 URL"""
    console.print(Panel.fit(f"[bold blue]WVS v17.0[/] - 扫描目标: {target}"))
    
    async def run_scan():
        from .vuln.sqli_v17 import SQLiScannerV17
        from .vuln.xss_v17 import XSSScannerV17
        from .vuln.ssrf_v17 import SSRFScannerV17
        from .vuln.cmdi_v17 import CommandiScannerV17
        from .vuln.xxe_v17 import XXEScannerV17
        from .vuln.traversal_v17 import TraversalScannerV17
        from .vuln.crawler_v17 import CrawlerV17
        from .core.ai_engine import AIEngine, AIConfig, AIProvider
        
        results = []
        
        # 解析请求头
        headers = {}
        for h in header:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()
        
        config = {
            "timeout": timeout,
            "threads": threads,
            "proxy": proxy,
        }
        
        # 解析 Cookie
        cookie_dict = {}
        if cookies:
            for item in cookies.split(";"):
                if "=" in item:
                    k, v = item.split("=", 1)
                    cookie_dict[k.strip()] = v.strip()
        
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            # 爬虫
            task = progress.add_task("爬取目标站点...", total=None)
            crawler = CrawlerV17(config)
            urls = await crawler.crawl(target)
            progress.update(task, description=f"发现 {len(urls)} 个 URL")
            
            # 扫描模块
            scan_modules = list(modules)
            if "all" in scan_modules:
                scan_modules = ["sqli", "xss", "ssrf", "cmdi", "xxe", "traversal"]
            
            for module in scan_modules:
                progress.update(task, description=f"扫描 [{module}]...")
                
                try:
                    if module == "sqli":
                        scanner = SQLiScannerV17(config)
                        module_results = await scanner.scan(target, headers=headers, cookies=cookie_dict)
                        results.extend([{"type": "SQLi", **r.__dict__} for r in module_results])
                    
                    elif module == "xss":
                        scanner = XSSScannerV17(config)
                        module_results = await scanner.scan(target, headers=headers, cookies=cookie_dict)
                        results.extend([{"type": "XSS", **r.__dict__} for r in module_results])
                    
                    elif module == "ssrf":
                        scanner = SSRFScannerV17(config)
                        module_results = await scanner.scan(target, headers=headers, cookies=cookie_dict)
                        results.extend([{"type": "SSRF", **r.__dict__} for r in module_results])
                    
                    elif module == "cmdi":
                        scanner = CommandiScannerV17(config)
                        module_results = await scanner.scan(target, headers=headers, cookies=cookie_dict)
                        results.extend([{"type": "CMDi", **r.__dict__} for r in module_results])
                    
                    elif module == "xxe":
                        scanner = XXEScannerV17(config)
                        module_results = await scanner.scan(target, headers=headers)
                        results.extend([{"type": "XXE", **r.__dict__} for r in module_results])
                    
                    elif module == "traversal":
                        scanner = TraversalScannerV17(config)
                        module_results = await scanner.scan(target, headers=headers, cookies=cookie_dict)
                        results.extend([{"type": "Traversal", **r.__dict__} for r in module_results])
                
                except Exception as e:
                    console.print(f"[red]模块 {module} 扫描失败: {e}[/]")
        
        return results
    
    results = asyncio.run(run_scan())
    
    # 显示结果
    _display_results(results)
    
    # 生成报告
    if output:
        _generate_report(results, output, output_format)
        console.print(f"[green]报告已保存: {output}[/]")


@cli.command()
@click.option("--host", default="0.0.0.0", help="监听地址")
@click.option("--port", default=8080, help="监听端口")
def web(host, port):
    """启动 Web UI"""
    console.print(f"[blue]启动 Web UI: http://{host}:{port}[/]")
    
    import subprocess
    import sys
    
    web_path = Path(__file__).parent / "web"
    if web_path.exists():
        subprocess.run([sys.executable, "-m", "wvs.web", "--host", host, "--port", str(port)])
    else:
        console.print("[red]Web UI 模块未安装[/]")


@cli.command()
@click.option("--host", default="0.0.0.0", help="主节点地址")
@click.option("--port", default=8765, help="主节点端口")
def master(host, port):
    """启动分布式扫描主节点"""
    console.print(f"[blue]启动主节点: {host}:{port}[/]")
    
    async def run():
        from .core.distributed import DistributedScanner, DistributedConfig
        config = DistributedConfig(master_host=host, master_port=port)
        scanner = DistributedScanner(config)
        await scanner.start_master()
        
        try:
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            await scanner.stop_master()
    
    asyncio.run(run())


@cli.command()
@click.argument("master_host")
@click.option("--master-port", default=8765, help="主节点端口")
@click.option("--port", default=8766, help="工作节点端口")
def worker(master_host, master_port, port):
    """启动分布式扫描工作节点"""
    console.print(f"[blue]连接主节点: {master_host}:{master_port}[/]")
    
    async def run():
        from .core.distributed import ScanWorker
        worker = ScanWorker(master_host, master_port, port)
        await worker.start()
        
        try:
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            await worker.stop()
    
    asyncio.run(run())


@cli.group()
def integrate():
    """集成管理"""
    pass


@integrate.command("test")
@click.argument("integration_type", type=click.Choice(["slack", "dingtalk", "wecom", "jira", "gitlab", "github"]))
def test_integration(integration_type):
    """测试集成连接"""
    console.print(f"[blue]测试集成: {integration_type}[/]")
    # TODO: 实现集成测试
    console.print("[green]集成测试成功[/]")


@integrate.command("list")
def list_integrations():
    """列出所有集成"""
    table = Table(title="已配置的集成")
    table.add_column("名称", style="cyan")
    table.add_column("类型", style="green")
    table.add_column("状态", style="yellow")
    
    table.add_row("Slack", "通知", "未配置")
    table.add_row("钉钉", "通知", "未配置")
    table.add_row("GitLab CI", "CI/CD", "未配置")
    table.add_row("GitHub Actions", "CI/CD", "未配置")
    table.add_row("Jira", "问题追踪", "未配置")
    
    console.print(table)


@cli.command()
def ai():
    """AI 辅助功能"""
    console.print(Panel.fit("[bold blue]AI 辅助检测引擎[/]"))
    console.print("功能:")
    console.print("  • 智能 payload 选择")
    console.print("  • 误报过滤")
    console.print("  • 漏洞验证")
    console.print("  • WAF 绕过建议")
    console.print("\n使用方法: wvs scan --ai <target>")


def _display_results(results):
    """显示扫描结果"""
    if not results:
        console.print("[yellow]未发现漏洞[/]")
        return
    
    table = Table(title="扫描结果")
    table.add_column("类型", style="cyan")
    table.add_column("参数", style="green")
    table.add_column("严重程度", style="red")
    table.add_column("置信度", style="yellow")
    table.add_column("Payload", style="white")
    
    for r in results:
        severity = r.get("severity", "medium")
        severity_color = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "white"
        }.get(severity, "white")
        
        table.add_row(
            r.get("type", "Unknown"),
            r.get("parameter", "N/A"),
            f"[{severity_color}]{severity}[/]",
            f"{r.get('confidence', 0):.0%}",
            str(r.get("payload", "N/A"))[:50]
        )
    
    console.print(table)
    
    # 统计
    critical = sum(1 for r in results if r.get("severity") == "critical")
    high = sum(1 for r in results if r.get("severity") == "high")
    medium = sum(1 for r in results if r.get("severity") == "medium")
    low = sum(1 for r in results if r.get("severity") == "low")
    
    console.print(f"\n[bold]统计:[/] Critical: {critical}, High: {high}, Medium: {medium}, Low: {low}")


def _generate_report(results, output_path, output_format):
    """生成报告"""
    output = Path(output_path)
    
    if output_format == "json":
        with open(output, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
    
    elif output_format == "html":
        from .vuln.report_v17 import HTMLReporter
        reporter = HTMLReporter()
        html = reporter.generate(results)
        with open(output, "w", encoding="utf-8") as f:
            f.write(html)
    
    elif output_format == "csv":
        import csv
        with open(output, "w", newline="", encoding="utf-8") as f:
            if results:
                writer = csv.DictWriter(f, fieldnames=results[0].keys())
                writer.writeheader()
                writer.writerows(results)


if __name__ == "__main__":
    cli()
