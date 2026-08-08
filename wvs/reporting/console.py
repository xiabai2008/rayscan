"""
Console Reporter
Outputs color-formatted scan results using the Rich library
"""

import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .. import __version__
from ..models import Confidence, ScanResult, Severity, Vulnerability

# Severity color mapping
SEV_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}

# Windows GBK 终端不支持 emoji，使用 ASCII 安全字符
_SAFE_EMOJI = False
try:
    "\u2600".encode(sys.stdout.encoding or "utf-8")
    _SAFE_EMOJI = True
except (UnicodeEncodeError, UnicodeDecodeError, AttributeError):
    _SAFE_EMOJI = False

_SEV_BADGES = {
    Severity.CRITICAL: "CRIT",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MED",
    Severity.LOW: "LOW",
    Severity.INFO: "INFO",
}
SEV_ICONS = {
    Severity.CRITICAL: ("!!" if not _SAFE_EMOJI else "\U0001f480"),
    Severity.HIGH: ("[H]" if not _SAFE_EMOJI else "\U0001f534"),
    Severity.MEDIUM: ("[M]" if not _SAFE_EMOJI else "\U0001f7e1"),
    Severity.LOW: ("[L]" if not _SAFE_EMOJI else "\U0001f535"),
    Severity.INFO: ("[I]" if not _SAFE_EMOJI else "\u26aa"),
}


class ConsoleReporter:
    """
    Console Color Reporter

    Supports:
    - Real-time progress output (stage-based)
    - Vulnerability table (sorted by severity)
    - Individual vulnerability detail expansion
    - Save to text file
    """

    def __init__(self, verbose: bool = False, quiet: bool = False):
        self.console = Console()
        self._err_console = Console(stderr=True)
        self.verbose = verbose
        self.quiet = quiet

    # ─────────────────────────────────────────────────────────────
    # Scan phase progress
    # ─────────────────────────────────────────────────────────────

    def phase(self, step: int, total: int, label: str, detail: str = ""):
        """Output scan phase information"""
        if self.quiet:
            return
        self.console.print(
            f"\n[bold cyan][{step}/{total}][/bold cyan] [bold]{label}[/bold]"
            + (f" [dim]{detail}[/dim]" if detail else "")
        )

    def _icon(self, name: str) -> str:
        """返回安全图标（非 Windows 用 emoji，Windows 用 ASCII）"""
        icons = {
            "info": ("[i]" if not _SAFE_EMOJI else "\u2139"),
            "ok": ("[v]" if not _SAFE_EMOJI else "\u2713"),
            "warn": ("[!]" if not _SAFE_EMOJI else "\u26a0"),
            "err": ("[x]" if not _SAFE_EMOJI else "\u2717"),
        }
        return icons.get(name, "[*]")

    def info(self, msg: str):
        """Output information message"""
        if not self.quiet:
            self.console.print(f"  [dim]{self._icon('info')}[/dim]  {msg}")

    def success(self, msg: str):
        if not self.quiet:
            self.console.print(f"  [green]{self._icon('ok')}[/green]  {msg}")

    def warning(self, msg: str):
        if not self.quiet:
            self.console.print(f"  [yellow]{self._icon('warn')}[/yellow]  {msg}")

    def error(self, msg: str):
        self._err_console.print(f"  [red]✗[/red]  {msg}")

    def debug(self, msg: str):
        if self.verbose:
            self.console.print(f"  [dim]DEBUG:[/dim]  {msg}")

    # ─────────────────────────────────────────────────────────────
    # Scan results report
    # ─────────────────────────────────────────────────────────────

    def report(self, result: ScanResult, save_path: Optional[Path] = None):
        """
        Generate and output a complete scan report

        Args:
            result: ScanResult object
            save_path: Optional path to save the text report
        """
        # Header
        self._print_header(result)

        if not result.vulnerabilities:
            self._print_no_vulns(result)
        else:
            self._print_vuln_summary(result)
            self._print_vuln_table(result.vulnerabilities)
            self._print_top_vulns_detail(result.vulnerabilities[:3])

        self._print_footer(result)

        # Save text report
        if save_path:
            self._save_text_report(result, save_path)

    def _print_header(self, result: ScanResult):
        """Print report header"""
        self.console.print()
        border = "cyan" if not result.vulnerabilities else "red"
        self.console.print(
            Panel.fit(
                f"[bold cyan]RayScan {__version__}[/bold cyan]  "
                f"[dim]扫描报告[/dim]\n"
                f"{'─' * 40}\n"
                f"[bold]目标 URL:[/bold] {result.target.url}\n"
                f"[bold]扫描时间:[/bold] {result.scan_time.strftime('%Y-%m-%d %H:%M:%S') if result.scan_time else datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"[bold]总耗时:[/bold]   {result.duration:.1f}s\n"
                f"[bold]请求数:[/bold]   {result.requests_made}",
                border_style=border,
                padding=(1, 2),
            )
        )

    def _print_no_vulns(self, result: ScanResult):
        """Print when no vulnerabilities are found"""
        self.console.print()
        self.console.print(
            Panel.fit(
                f"[bold green]✅ 扫描完成，未发现漏洞[/bold green]\n端点扫描: {result.endpoints_found or '?'} | 耗时: {result.duration:.1f}s",
                border_style="green",
                padding=(1, 2),
            )
        )

    def _print_vuln_summary(self, result: ScanResult):
        """Vulnerability summary"""
        counts = result.severity_count
        parts = []
        sev_labels = {
            "critical": (
                "[bold red]",
                f"{SEV_ICONS.get(Severity.CRITICAL, '')} {counts.get('critical', 0)} 严重[/bold red]",
            ),
            "high": ("[red]", f"{SEV_ICONS.get(Severity.HIGH, '')} {counts.get('high', 0)} 高危[/red]"),
            "medium": ("[yellow]", f"{SEV_ICONS.get(Severity.MEDIUM, '')} {counts.get('medium', 0)} 中危[/yellow]"),
            "low": ("[blue]", f"{SEV_ICONS.get(Severity.LOW, '')} {counts.get('low', 0)} 低危[/blue]"),
            "info": ("[dim]", f"{SEV_ICONS.get(Severity.INFO, '')} {counts.get('info', 0)} 信息[/dim]"),
        }
        parts = []
        for sev in ["critical", "high", "medium", "low", "info"]:
            if counts.get(sev):
                parts.append(f"{sev_labels[sev][0]}{sev_labels[sev][1]}")

        total = len(result.vulnerabilities)
        self.console.print()
        self.console.print(
            Panel.fit(
                f"[bold red]⚠ 发现 {total} 个漏洞[/bold red]\n" + "  |  ".join(parts),
                border_style="red",
                padding=(1, 2),
            )
        )

    def _print_vuln_table(self, vulns: List[Vulnerability]):
        """Vulnerability details table"""
        table = Table(
            title="漏洞列表",
            show_lines=True,
            header_style="bold cyan",
            border_style="dim",
        )
        table.add_column("#", justify="right", style="dim", width=3)
        table.add_column("严重", style="bold", width=7)
        table.add_column("类型", style="cyan", width=16)
        table.add_column("URL", width=40)
        table.add_column("参数", width=16)
        table.add_column("置信", width=8)

        for i, v in enumerate(vulns, 1):
            style = SEV_COLORS.get(v.severity, "")
            url_short = v.url[:38] + ".." if len(v.url) > 40 else v.url
            conf_color = "green" if v.confidence in (Confidence.HIGH, Confidence.CERTAIN) else "yellow"

            table.add_row(
                str(i),
                f"[{style}]{v.severity.value.upper()}[/]",
                f"[cyan]{v.type.value}[/]",
                url_short,
                v.parameter or "-",
                f"[{conf_color}]{v.confidence.value}[/]",
            )

        self.console.print()
        self.console.print(table)

    def _print_top_vulns_detail(self, vulns: List[Vulnerability]):
        """Individual vulnerability details"""
        if not vulns:
            return

        self.console.print()
        self.console.print("[bold cyan]━━━ Top 漏洞详情 ━━━[/bold cyan]\n")

        for i, v in enumerate(vulns, 1):
            sev = SEV_COLORS.get(v.severity, "")
            self.console.print(
                Panel.fit(
                    f"[{sev}][bold]{i}. [{v.severity.value.upper()}] {v.title}[/bold][/{sev}]\n"
                    f"[bold]URL:[/bold] {v.url}\n"
                    f"[bold]参数:[/bold] {v.parameter or '-'} ({v.parameter_type or 'query'})\n"
                    + (f"[bold]Payload:[/bold] [red]{v.payload or '-'}[/red]\n" if v.payload else "")
                    + (f"[bold]证据:[/bold] {v.evidence[:200]}\n" if v.evidence else "")
                    + f"[bold]描述:[/bold] {v.description[:300] if v.description else '-'}\n"
                    + (
                        f"[bold]修复建议:[/bold] {v.recommendation[:200] if v.recommendation else '-'}\n"
                        if v.recommendation
                        else ""
                    ),
                    border_style="red" if v.severity in (Severity.CRITICAL, Severity.HIGH) else "yellow",
                    padding=(1, 2),
                )
            )

            # Reference links
            if v.references:
                ref_table = Table(border_style="dim", show_header=False)
                ref_table.add_column("Key", style="dim")
                ref_table.add_column("Value", style="cyan")
                for ref in v.references[:5]:
                    ref_table.add_row("→", ref)
                self.console.print(ref_table)

            self.console.print()

    def _print_footer(self, result: ScanResult):
        """Footer"""
        self.console.print()
        self.console.print(
            f"[dim]{'─' * 60}[/dim]\n"
            f"[dim]RayScan {__version__} | "
            f"总耗时 {result.duration:.1f}s | "
            f"请求 {result.requests_made} | "
            f"端点 {result.endpoints_found or '?'} | "
            f"模块 {result.modules_run or '?'}[/dim]"
        )

    # ─────────────────────────────────────────────────────────────
    # Save report
    # ─────────────────────────────────────────────────────────────

    def _save_text_report(self, result: ScanResult, path: Path):
        """Save text format report"""
        path.parent.mkdir(parents=True, exist_ok=True)

        lines = [
            f"RayScan {__version__} 扫描报告",
            f"{'=' * 60}",
            f"目标: {result.target.url}",
            f"时间: {result.scan_time.strftime('%Y-%m-%d %H:%M:%S') if result.scan_time else 'N/A'}",
            f"耗时: {result.duration:.1f}s",
            f"请求数: {result.requests_made}",
            "",
            f"漏洞统计: {len(result.vulnerabilities)} 个",
        ]

        for sev in ["critical", "high", "medium", "low", "info"]:
            if result.severity_count.get(sev):
                lines.append(f"  [{sev.upper()}] {result.severity_count[sev]}")

        lines.append("")
        lines.append("漏洞详情:")
        lines.append("-" * 60)

        for i, v in enumerate(result.vulnerabilities, 1):
            lines.append(f"\n{i}. [{v.severity.value.upper()}] {v.title}")
            lines.append(f"   URL: {v.url}")
            lines.append(f"   参数: {v.parameter or '-'} ({v.parameter_type or 'query'})")
            if v.payload:
                lines.append(f"   Payload: {v.payload}")
            if v.evidence:
                lines.append(f"   证据: {v.evidence[:200]}")
            if v.description:
                lines.append(f"   描述: {v.description[:300]}")
            if v.recommendation:
                lines.append(f"   修复: {v.recommendation[:200]}")
            if v.references:
                lines.append(f"   引用: {' | '.join(v.references[:3])}")

        path.write_text("\n".join(lines), encoding="utf-8")
        self.console.print(f"\n[green]文本报告已保存: {path}[/green]")


def format_vuln_brief(v: Vulnerability) -> str:
    """Format vulnerability as a one-line summary"""
    sev_icon = SEV_ICONS.get(v.severity, "")
    url_short = v.url[:50] + ".." if len(v.url) > 52 else v.url
    return f"{sev_icon} [{v.severity.value.upper():8}] {v.type.value:20} {url_short:52} @{v.parameter or '-':15} [{v.confidence.value}]"
