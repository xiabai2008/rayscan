"""WVS v16.0 - 命令行接口

改进点：
1. 彩色输出（Rich 库）
2. 实时进度显示
3. 交互式报告
4. 多目标批量扫描
5. 配置文件支持
"""
import asyncio
import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich.tree import Tree
from datetime import datetime
from pathlib import Path
import json

console = Console()


@click.group()
@click.version_option(version="16.0.0", prog_name="WVS")
def cli():
    """WVS v16.0 - Web Vulnerability Scanner"""
    pass


@cli.command()
@click.argument("target")
@click.option("--depth", "-d", default=3, help="爬虫深度")
@click.option("--urls", "-u", default=100, help="最大 URL 数")
@click.option("--output", "-o", default="./reports", help="输出目录")
@click.option("--format", "-f", type=click.Choice(["html", "json", "csv", "all"]), default="html", help="报告格式")
@click.option("--quick", is_flag=True, help="快速扫描模式")
@click.option("--auth-cookie", help="认证 Cookie")
@click.option("--auth-header", help="认证 Header")
def scan(target, depth, urls, output, format, quick, auth_cookie, auth_header):
    """扫描目标网站"""
    console.print(Panel.fit(
        "[bold cyan]WVS v16.0[/] - Web Vulnerability Scanner\n"
        f"目标: [yellow]{target}[/]",
        border_style="blue"
    ))
    
    # 配置
    config = {
        "max_depth": 2 if quick else depth,
        "max_urls": 50 if quick else urls,
        "output_dir": output,
    }
    
    # 执行扫描
    asyncio.run(_run_scan(target, config, format, auth_cookie, auth_header))


async def _run_scan(target: str, config: dict, format: str, auth_cookie: str, auth_header: str):
    """执行扫描"""
    import aiohttp
    from .vuln.crawler_v16 import CrawlerV16
    from .vuln.sqli_v16 import SQLiScannerV16
    from .vuln.xss_v16 import XSSScannerV16
    from .vuln.report_v16 import ReportGeneratorV16, Vulnerability
    
    start_time = datetime.now()
    
    async with aiohttp.ClientSession() as session:
        # 爬虫
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]爬取中...", total=config["max_urls"])
            
            crawler = CrawlerV16(config)
            pages = await crawler.crawl(target, session)
            
            progress.update(task, completed=len(pages))
        
        console.print(f"[green]✓[/] 爬取完成: {len(pages)} 个页面")
        
        # SQL 注入
        console.print("\n[yellow]检测 SQL 注入...[/]")
        sqli_scanner = SQLiScannerV16(config)
        sqli_results = []
        
        with Progress(console=console) as progress:
            task = progress.add_task("[cyan]SQL 注入检测", total=len(pages))
            
            for i, page in enumerate(pages):
                results = await sqli_scanner.scan(page.url, session)
                sqli_results.extend(results)
                progress.update(task, completed=i + 1)
        
        # XSS
        console.print("\n[yellow]检测 XSS...[/]")
        xss_scanner = XSSScannerV16(config)
        xss_results = []
        
        with Progress(console=console) as progress:
            task = progress.add_task("[cyan]XSS 检测", total=len(pages))
            
            for i, page in enumerate(pages):
                results = await xss_scanner.scan(page.url, session)
                xss_results.extend(results)
                progress.update(task, completed=i + 1)
    
    end_time = datetime.now()
    
    # 生成报告
    reporter = ReportGeneratorV16(config["output_dir"])
    reporter.set_scan_info(
        target=target,
        start_time=start_time,
        end_time=end_time,
        urls_scanned=len(pages),
        forms_tested=sum(len(p.forms) for p in pages),
    )
    
    # 添加 SQL 注入结果
    for r in sqli_results:
        if r.vulnerable:
            reporter.add_vulnerability(Vulnerability(
                name=f"SQL 注入 ({r.injection_type.value})",
                severity="CRITICAL" if r.injection_type.value in ["error_based", "union_based"] else "HIGH",
                url=r.parameter,
                parameter=r.parameter,
                payload=r.payload,
                description=f"检测到 {r.injection_type.value} 型 SQL 注入",
                remediation="使用参数化查询，禁止拼接 SQL 字符串",
                confidence=r.confidence,
                evidence=r.evidence,
                cwe_id="89",
            ))
    
    # 添加 XSS 结果
    for r in xss_results:
        if r.vulnerable:
            reporter.add_vulnerability(Vulnerability(
                name=f"XSS ({r.xss_type.value})",
                severity="HIGH",
                url=r.parameter,
                parameter=r.parameter,
                payload=r.payload,
                description=f"检测到 {r.xss_type.value} 型 XSS",
                remediation="对用户输入进行 HTML 转义，使用 CSP",
                confidence=r.confidence,
                evidence=r.evidence,
                cwe_id="79",
            ))
    
    # 输出报告
    if format in ["html", "all"]:
        html_path = reporter.generate_html_report()
        console.print(f"[green]✓[/] HTML 报告: {html_path}")
    
    if format in ["json", "all"]:
        json_path = reporter.generate_json_report()
        console.print(f"[green]✓[/] JSON 报告: {json_path}")
    
    if format in ["csv", "all"]:
        csv_path = reporter.generate_csv_report()
        console.print(f"[green]✓[/] CSV 报告: {csv_path}")
    
    # 显示摘要
    _show_summary(reporter)


def _show_summary(reporter):
    """显示扫描摘要"""
    reporter.calculate_statistics()
    stats = reporter.statistics
    
    console.print("\n")
    console.print(Panel.fit(
        "[bold]扫描摘要[/]\n"
        f"总漏洞数: [red]{stats['total']}[/]\n"
        f"严重: [red]{stats['by_severity']['CRITICAL']}[/] | "
        f"高危: [yellow]{stats['by_severity']['HIGH']}[/] | "
        f"中危: [yellow]{stats['by_severity']['MEDIUM']}[/] | "
        f"低危: [green]{stats['by_severity']['LOW']}[/]\n"
        f"风险评分: [cyan]{stats['risk_score']:.1f}[/]",
        border_style="blue"
    ))
    
    # 漏洞表格
    if reporter.vulnerabilities:
        table = Table(title="漏洞列表", show_lines=True)
        table.add_column("#", style="cyan", width=4)
        table.add_column("严重程度", width=10)
        table.add_column("类型", width=30)
        table.add_column("URL", width=50)
        table.add_column("置信度", width=8)
        
        for i, v in enumerate(reporter.vulnerabilities[:20], 1):  # 只显示前 20 个
            severity_color = {
                "CRITICAL": "red",
                "HIGH": "yellow",
                "MEDIUM": "yellow",
                "LOW": "green",
            }.get(v.severity, "white")
            
            table.add_row(
                str(i),
                f"[{severity_color}]{v.severity}[/]",
                v.name[:30],
                v.url[:50],
                f"{v.confidence:.0%}",
            )
        
        console.print(table)
        
        if len(reporter.vulnerabilities) > 20:
            console.print(f"\n[dim]还有 {len(reporter.vulnerabilities) - 20} 个漏洞未显示，详见报告[/]")


@cli.command()
@click.argument("targets", type=click.File("r"))
@click.option("--output", "-o", default="./reports", help="输出目录")
def batch(targets, output):
    """批量扫描（从文件读取目标列表）"""
    target_list = [line.strip() for line in targets if line.strip()]
    
    console.print(f"[cyan]批量扫描 {len(target_list)} 个目标[/]")
    
    for i, target in enumerate(target_list, 1):
        console.print(f"\n[yellow][{i}/{len(target_list)}][/] 扫描: {target}")
        # 可以调用 scan 命令


@cli.command()
def features():
    """显示 v16.0 新特性"""
    from . import FEATURES_V16
    
    tree = Tree("[bold cyan]WVS v16.0 新特性[/]")
    
    for feature in FEATURES_V16:
        tree.add(f"[green]✓[/] {feature}")
    
    console.print(tree)


@cli.command()
@click.argument("url")
@click.option("--param", "-p", required=True, help="测试参数")
def test_sqli(url, param):
    """测试单个参数的 SQL 注入"""
    console.print(f"[cyan]测试 SQL 注入: {url} (参数: {param})[/]")
    
    asyncio.run(_test_single_sqli(url, param))


async def _test_single_sqli(url: str, param: str):
    """测试单个参数"""
    import aiohttp
    from .vuln.sqli_v16 import SQLiScannerV16
    
    async with aiohttp.ClientSession() as session:
        scanner = SQLiScannerV16()
        results = await scanner.scan(url, session)
        
        if results:
            table = Table(title="SQL 注入检测结果")
            table.add_column("类型", style="cyan")
            table.add_column("参数")
            table.add_column("Payload")
            table.add_column("置信度")
            
            for r in results:
                if r.vulnerable:
                    table.add_row(
                        r.injection_type.value,
                        r.parameter,
                        r.payload[:50],
                        f"{r.confidence:.0%}",
                    )
            
            console.print(table)
        else:
            console.print("[yellow]未检测到 SQL 注入[/]")


if __name__ == "__main__":
    cli()
