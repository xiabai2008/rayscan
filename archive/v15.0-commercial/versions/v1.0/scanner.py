"""WVS 主扫描协调器 (v2.0)"""
import asyncio
import uuid
from typing import List, Dict
from datetime import datetime
from pathlib import Path

try:
    import aiohttp
except ImportError:
    aiohttp = None

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from .config import ScanConfig
from .deduplicator import VulnDeduplicator, VulnFilter
from ..network.port_scanner import PortScanner, ServiceRecognizer
from ..web.crawler import WebCrawler
from ..vuln.xss import XSSScanner
from ..vuln.sqli import SQLiScanner
from ..vuln.info_disclosure import InfoDisclosureScanner
from ..vuln.dir_traversal import DirectoryTraversalScanner
from ..vuln.base import Vulnerability
from ..report.html_gen import HTMLReportGenerator
from ..report.json_csv_gen import JSONReportGenerator, CSVReportGenerator


console = Console() if RICH_AVAILABLE else None


class WVSScanner:
    """Web 漏洞扫描器主类 v2.0"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.scan_id = f"WVS-{uuid.uuid4().hex[:8].upper()}"
        self.vulnerabilities: List[Vulnerability] = []
        self.start_time = None
        self.end_time = None
    
    async def scan(self) -> Dict:
        """执行完整扫描流程"""
        self.start_time = datetime.now()
        
        if RICH_AVAILABLE:
            console.print(Panel.fit(
                f"[bold blue]Web Vulnerability Scanner v2.0[/bold blue]\n"
                f"扫描ID: [cyan]{self.scan_id}[/cyan]\n"
                f"目标: [yellow]{self.config.target}[/yellow]",
                title="启动扫描",
                border_style="blue"
            ))
        else:
            print(f"\n{'='*60}")
            print(f"[+] 启动漏洞扫描 v2.0")
            print(f"[*] 扫描ID: {self.scan_id}")
            print(f"[*] 目标: {self.config.target}")
            print(f"{'='*60}\n")
        
        # 1. 端口扫描
        await self._port_scan()
        
        # 2. Web 爬虫
        crawl_result = await self._crawl()
        
        # 3. 漏洞检测
        await self._vulnerability_scan(crawl_result)
        
        # 4. 生成报告
        report_paths = self._generate_reports()
        
        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds()
        
        result = {
            "scan_id": self.scan_id,
            "target": self.config.target,
            "duration": duration,
            "vulnerabilities": len(self.vulnerabilities),
            "report_paths": report_paths,
            "details": [v.to_dict() for v in self.vulnerabilities],
        }
        
        self._print_summary(result)
        return result
    
    async def _port_scan(self):
        """端口扫描阶段"""
        self._log("[1/4] 端口扫描中...", "info")
        host = self.config.target.replace("http://", "").replace("https://", "").split("/")[0]
        
        scanner = PortScanner(
            concurrency=self.config.concurrency,
            timeout=self.config.timeout
        )
        ports = list(range(self.config.port_range[0], self.config.port_range[1] + 1))
        open_ports = await scanner.scan_range(host, ports)
        
        if open_ports and RICH_AVAILABLE:
            table = Table(title=f"开放端口 ({len(open_ports)}个)")
            table.add_column("端口", style="cyan")
            table.add_column("服务", style="green")
            for port in open_ports[:10]:
                table.add_row(str(port), ServiceRecognizer.recognize(port))
            console.print(table)
        elif open_ports:
            print(f"      发现 {len(open_ports)} 个开放端口:")
            for port in open_ports[:10]:
                print(f"        - Port {port}: {ServiceRecognizer.recognize(port)}")
    
    async def _crawl(self) -> Dict:
        """Web 爬虫阶段"""
        self._log("[2/4] Web 爬虫启动...", "info")
        
        crawler = WebCrawler(
            max_depth=self.config.max_depth,
            max_urls=self.config.max_urls,
            concurrency=self.config.concurrency
        )
        
        result = await crawler.crawl(self.config.target)
        
        if RICH_AVAILABLE:
            stats = Table.grid()
            stats.add_row("URL 数量:", str(len(result['urls'])))
            stats.add_row("表单数量:", str(len(result['forms'])))
            stats.add_row("JS 文件:", str(len(result['js_files'])))
            console.print(Panel(stats, title="爬取结果", border_style="green"))
        else:
            print(f"      URL: {len(result['urls'])}, 表单: {len(result['forms'])}, JS: {len(result['js_files'])}")
        
        return result
    
    async def _vulnerability_scan(self, crawl_result: Dict):
        """漏洞检测阶段"""
        self._log("[3/4] 漏洞检测中...", "info")
        
        # 认证信息
        if self.config.auth.is_authenticated():
            self._log(f"      使用 {self.config.auth.auth_type} 认证", "info")
        
        # 使用连接池优化
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        headers = self.config.auth.get_headers()
        
        # TCP 连接器配置（连接池）
        connector = aiohttp.TCPConnector(
            limit=self.config.concurrency * 2,  # 总连接数限制
            limit_per_host=30,  # 单主机连接限制
            ttl_dns_cache=300,  # DNS 缓存时间
            use_dns_cache=True,
            enable_cleanup_closed=True,
            force_close=False,
        )
        
        async with aiohttp.ClientSession(
            timeout=timeout, 
            headers=headers,
            connector=connector,
        ) as session:
            context = {
                **crawl_result,
                "session": session,
                "target": self.config.target,
            }
            
            scanners = []
            
            if self.config.check_xss:
                scanners.append(("XSS", XSSScanner()))
            if self.config.check_sqli:
                scanners.append(("SQL注入", SQLiScanner()))
            if getattr(self.config, 'check_info', True):
                scanners.append(("敏感信息", InfoDisclosureScanner()))
            if getattr(self.config, 'check_traversal', True):
                scanners.append(("目录遍历", DirectoryTraversalScanner()))
            
            for name, scanner in scanners:
                self._log(f"      执行 {name} 扫描...", "debug")
                try:
                    results = await scanner.check(self.config.target, context)
                    self.vulnerabilities.extend(results)
                except Exception as e:
                    self._log(f"      {name} 扫描出错: {e}", "warning")
        
        # 去重处理
        if self.config.deduplicate:
            self._log("      漏洞去重...", "debug")
            deduplicator = VulnDeduplicator()
            self.vulnerabilities = deduplicator.deduplicate(self.vulnerabilities)
        
        # 过滤和排序
        vuln_filter = VulnFilter(min_confidence=self.config.min_confidence)
        self.vulnerabilities = vuln_filter.filter(self.vulnerabilities)
        self.vulnerabilities = vuln_filter.sort_by_severity(self.vulnerabilities)
        
        # POC 验证
        if self.config.verify_poc and self.vulnerabilities:
            self._log("      POC 验证中...", "info")
            from .poc_verifier import POCVerifier
            verifier = POCVerifier(timeout=self.config.timeout)
            
            verified_count = 0
            for vuln in self.vulnerabilities:
                vuln_type = self._get_vuln_type(vuln.name)
                if vuln_type:
                    is_verified = await verifier.verify_vulnerability(
                        vuln_type=vuln_type,
                        url=vuln.url,
                        payload=vuln.payload,
                        session=session
                    )
                    if is_verified:
                        vuln.name = f"[已验证] {vuln.name}"
                        verified_count += 1
            
            verify_summary = verifier.get_verification_summary()
            self._log(f"      POC 验证完成: {verified_count}/{len(self.vulnerabilities)} 个已验证", "success")
        
        self._log(f"      共发现 {len(self.vulnerabilities)} 个漏洞", "success")
        
        # 保存到数据库
        try:
            from .database import db
            db.save_scan(
                scan_id=self.scan_id,
                target=self.config.target,
                duration=0,  # 将在最后更新
                vulnerabilities=[v.to_dict() for v in self.vulnerabilities],
                profile=getattr(self.config, 'profile', 'standard'),
            )
        except Exception as e:
            self._log(f"      数据库保存失败: {e}", "warning")
    
    def _get_vuln_type(self, name: str) -> str:
        """从漏洞名称获取类型"""
        name_lower = name.lower()
        if "xss" in name_lower:
            return "xss"
        elif "sql" in name_lower or "注入" in name_lower:
            return "sqli"
        elif "目录" in name_lower or "遍历" in name_lower:
            return "traversal"
        return None
    
    def _generate_reports(self) -> Dict[str, Path]:
        """生成多格式报告"""
        self._log("[4/4] 生成报告中...", "info")
        
        paths = {}
        
        # HTML 报告
        html_gen = HTMLReportGenerator()
        paths['html'] = html_gen.save(
            self.scan_id, self.config.target, 
            self.vulnerabilities, self.config.output_dir
        )
        
        # JSON 报告
        json_gen = JSONReportGenerator()
        paths['json'] = json_gen.save(
            self.scan_id, self.config.target,
            self.vulnerabilities, self.config.output_dir
        )
        
        # CSV 报告
        csv_gen = CSVReportGenerator()
        paths['csv'] = csv_gen.save(
            self.scan_id, self.config.target,
            self.vulnerabilities, self.config.output_dir
        )
        
        # PDF 报告
        try:
            from ..report.pdf_gen import PDFReportGenerator
            pdf_gen = PDFReportGenerator()
            pdf_path = Path(self.config.output_dir) / f"{self.scan_id}.pdf"
            paths['pdf'] = pdf_gen.generate(
                self.scan_id, self.config.target,
                [v.to_dict() for v in self.vulnerabilities],
                pdf_path
            )
        except Exception as e:
            self._log(f"      PDF 生成失败: {e}", "warning")
        
        for fmt, path in paths.items():
            self._log(f"      {fmt.upper()}: {path}", "debug")
        
        return paths
    
    def _print_summary(self, result: Dict):
        """打印扫描摘要"""
        duration = result['duration']
        vuln_count = result['vulnerabilities']
        
        if RICH_AVAILABLE:
            # 漏洞统计表
            severity_count = {"严重": 0, "高危": 0, "中危": 0, "低危": 0, "信息": 0}
            for v in self.vulnerabilities:
                severity_count[v.severity.label_cn] = severity_count.get(v.severity.label_cn, 0) + 1
            
            table = Table(title="扫描摘要", show_header=True)
            table.add_column("指标", style="cyan")
            table.add_column("数值", style="yellow")
            table.add_row("扫描耗时", f"{duration:.2f} 秒")
            table.add_row("漏洞总数", str(vuln_count))
            table.add_row("严重", str(severity_count["严重"]))
            table.add_row("高危", str(severity_count["高危"]))
            table.add_row("中危", str(severity_count["中危"]))
            
            console.print(Panel(table, border_style="green"))
            console.print(f"[green]报告已保存:[/green]")
            for fmt, path in result['report_paths'].items():
                console.print(f"  - {fmt.upper()}: [cyan]{path}[/cyan]")
        else:
            print(f"\n{'='*60}")
            print("[+] 扫描完成!")
            print(f"{'='*60}")
            print(f"[*] 耗时: {duration:.2f} 秒")
            print(f"[*] 漏洞: {vuln_count} 个")
            for fmt, path in result['report_paths'].items():
                print(f"[*] {fmt.upper()}: {path}")
            print(f"{'='*60}\n")
    
    def _log(self, message: str, level: str = "info"):
        """统一日志输出"""
        if RICH_AVAILABLE:
            colors = {
                "info": "blue",
                "success": "green", 
                "warning": "yellow",
                "error": "red",
                "debug": "dim"
            }
            console.print(f"[{colors.get(level, 'white')}]{message}[/{colors.get(level, 'white')}]")
        else:
            print(message)
