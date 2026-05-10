"""WVS v18.0 - CLI Entry Point"""
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
@click.version_option(version="18.0.0", prog_name="WVS v18.0")
def cli():
    """WVS v18.0 - Enterprise Security Scanner
    
    Modules:
    - Web Scan: sqli, xss, ssrf, cmdi, xxe, traversal
    - Cloud Native: Docker, Kubernetes, AWS/Azure/GCP
    - Mobile: Android APK, iOS IPA, API
    - Compliance: PII, GDPR, China Data Security Law
    """
    pass


# ========== Batch Scan ==========

@cli.command("batch")
@click.argument("target_file", type=click.Path(exists=True))
@click.option("--modules", "-m", multiple=True,
              type=click.Choice(["sqli", "xss", "nuclei", "dom-xss", "all"]),
              default=["all"], help="Scan modules")
@click.option("--concurrency", "-c", type=int, default=3, help="Concurrent scans (default: 3)")
@click.option("--depth", "-d", type=int, default=2, help="Crawl depth (default: 2)")
@click.option("--output", "-o", type=click.Path(), help="Output report path")
@click.option("--format", "-f", "output_format",
              type=click.Choice(["html", "json", "csv"]),
              default="html", help="Report format")
@click.option("--no-basic", is_flag=True, help="Disable basic scanner")
@click.option("--no-sqlmap", is_flag=True, help="Disable SQLMap")
@click.option("--no-nuclei", is_flag=True, help="Disable Nuclei")
def batch_scan(target_file, modules, concurrency, depth, output, output_format,
               no_basic, no_sqlmap, no_nuclei):
    """Batch scan multiple targets from a file (one target per line)"""
    
    # Read targets
    with open(target_file, 'r') as f:
        lines = f.readlines()
    
    # Parse targets (support: url, ip/cidr, domain)
    targets = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # Add http:// if no scheme
        if not line.startswith('http'):
            line = 'http://' + line
        targets.append(line)
    
    if not targets:
        console.print("[red]No valid targets found![/]")
        return
    
    console.print(Panel.fit("[bold blue]WVS v18.0[/] - Batch Scan"))
    console.print(f"[yellow]Targets:[/] {len(targets)} | [yellow]Concurrency:[/] {concurrency}")
    console.print(f"[yellow]Modules:[/] {', '.join(modules)}")
    
    async def run_batch():
        from wvs.vuln.full_scanner import FullScanner
        import asyncio
        from datetime import datetime
        
        # Module list
        module_list = list(modules)
        if "all" in module_list:
            module_list = ["sqli", "xss", "nuclei"]
        
        # Results storage
        all_results = []
        semaphore = asyncio.Semaphore(concurrency)
        
        async def scan_with_semaphore(target):
            async with semaphore:
                console.print(f"[dim]Scanning:[/] {target}")
                scanner = FullScanner({
                    "max_depth": depth,
                    "max_urls": 100,
                    "timeout": 15,
                    "delay": 0.05,
                    "enable_basic": not no_basic,
                    "enable_sqlmap": not no_sqlmap,
                    "enable_nuclei": not no_nuclei,
                })
                try:
                    result = await scanner.scan(target, modules=module_list)
                    return result
                except Exception as e:
                    console.print(f"[red]Error scanning {target}:[/] {str(e)[:50]}")
                    return None
        
        # Run all scans
        from datetime import datetime
        start_time = datetime.now()
        tasks = [scan_with_semaphore(t) for t in targets]
        results = await asyncio.gather(*tasks)
        
        # Filter out None results
        all_results = [r for r in results if r is not None]
        
        return all_results
    
    # Run
    results = asyncio.run(run_batch())
    
    # Summary
    console.print(f"\n[bold]Batch Scan Complete![/]")
    console.print(f"  Scanned: {len(results)}/{len(targets)} targets")
    
    total_vulns = sum(len(r.vulnerabilities) for r in results)
    console.print(f"  Total vulnerabilities: {total_vulns}")
    
    # Severity summary
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for r in results:
        for v in r.vulnerabilities:
            sev = v.severity.lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
    
    console.print(f"\n[bold]Severity Summary:[/]")
    console.print(f"  [red]Critical:[/] {severity_counts['critical']}")
    console.print(f"  [red]High:[/] {severity_counts['high']}")
    console.print(f"  [yellow]Medium:[/] {severity_counts['medium']}")
    console.print(f"  [green]Low:[/] {severity_counts['low']}")
    console.print(f"  [blue]Info:[/] {severity_counts['info']}")
    
    # Show targets with vulns
    targets_with_vulns = [(r.target, len(r.vulnerabilities)) for r in results if r.vulnerabilities]
    if targets_with_vulns:
        console.print(f"\n[bold red]Targets with Vulnerabilities:[/]")
        for target, vuln_count in sorted(targets_with_vulns, key=lambda x: -x[1]):
            console.print(f"  [red]{vuln_count}[/] - {target}")
    
    # Export combined report
    if output:
        import json
        from datetime import datetime
        report_data = {
            "scan_time": datetime.now().isoformat(),
            "targets": len(targets),
            "scanned": len(results),
            "total_vulnerabilities": total_vulns,
            "severity": severity_counts,
            "results": []
        }
        for r in results:
            report_data["results"].append({
                "target": r.target,
                "urls": len(r.urls),
                "vulnerabilities": len(r.vulnerabilities),
                "vulns": [(v.type, v.url, v.severity, v.evidence[:50]) for v in r.vulnerabilities]
            })
        
        with open(output, 'w') as f:
            json.dump(report_data, f, indent=2)
        console.print(f"\n[green]Report saved to:[/] {output}")

# ========== Exploitation ==========

@cli.command("exploit")
@click.argument("vuln_file", type=click.Path(exists=True))
@click.option("--method", "-m", type=click.Choice(["auto", "sqlmap", "manual"]),
              default="auto", help="Exploitation method")
@click.option("--ip", "-i", default="127.0.0.1", help="Attacker IP for reverse shell")
@click.option("--port", "-p", type=int, default=4444, help="Attacker port for reverse shell")
@click.option("--output", "-o", type=click.Path(), help="Output file")
def exploit_vuln(vuln_file, method, ip, port, output):
    """Exploit a detected vulnerability (from JSON report)"""
    import json
    from datetime import datetime
    
    console.print(Panel.fit("[bold red]WVS v18.0[/] - Exploitation Module"))
    
    # Load vulnerability info
    with open(vuln_file, 'r') as f:
        vuln_data = json.load(f)
    
    # If it's a full report, extract vulnerabilities
    if 'results' in vuln_data:
        vulns = []
        for r in vuln_data['results']:
            for v in r.get('vulns', []):
                vulns.append({
                    'type': v[0],
                    'url': v[1],
                    'severity': v[2],
                    'evidence': v[3] if len(v) > 3 else ''
                })
    else:
        vulns = [vuln_data]
    
    console.print(f"[yellow]Found {len(vulns)} vulnerabilities to exploit")
    
    async def run_exploit():
        from wvs.modules.exploit import ExploitEngine
        
        engine = ExploitEngine(timeout=60)
        results = []
        
        for vuln in vulns:
            vuln_info = {
                'type': vuln['type'],
                'url': vuln['url'],
                'attacker_ip': ip,
                'attacker_port': port,
                'payload': vuln.get('evidence', '')
            }
            
            console.print(f"\\n[cyan]Exploiting:[/] {vuln['type']} @ {vuln['url']}")
            
            result = await engine.exploit(vuln_info)
            results.append({
                'vuln': vuln,
                'exploit': result
            })
            
            if result['success']:
                console.print(f"  [green]SUCCESS:[/] {result['result'][:100]}...")
            else:
                console.print(f"  [red]FAILED:[/] {result['result'][:100]}...")
        
        return results
    
    results = asyncio.run(run_exploit())
    
    # Summary
    success_count = sum(1 for r in results if r['exploit']['success'])
    console.print(f"\\n[bold]Exploitation Complete![/]")
    console.print(f"  Exploited: {success_count}/{len(results)} vulnerabilities")
    
    # Save results
    if output:
        with open(output, 'w') as f:
            json.dump(results, f, indent=2)
        console.print(f"\\n[green]Results saved to:[/] {output}")




# ========== Web Scan ==========

@cli.command("scan")
@click.argument("target")
@click.option("--modules", "-m", multiple=True,
              type=click.Choice(["sqli", "xss", "nuclei", "dom-xss", "all"]),
              default=["all"], help="Scan modules: sqli(SQL注入), xss, nuclei(CVE扫描), dom-xss(DOM XSS)")
@click.option("--depth", "-d", type=int, default=3, help="Crawl depth")
@click.option("--output", "-o", type=click.Path(), help="Output report path")
@click.option("--format", "-f", "output_format",
              type=click.Choice(["html", "json", "csv", "pdf", "md"]),
              default="html", help="Report format")
@click.option("--cookies", type=str, help="Cookie string")
@click.option("--header", "-H", multiple=True, help="Custom headers")
@click.option("--no-basic", is_flag=True, help="Disable basic scanner")
@click.option("--no-sqlmap", is_flag=True, help="Disable SQLMap")
@click.option("--no-nuclei", is_flag=True, help="Disable Nuclei")
@click.option("--no-playwright", is_flag=True, help="Disable Playwright (JS rendering)")
def scan_web(target, modules, depth, output, output_format, cookies, header,
             no_basic, no_sqlmap, no_nuclei, no_playwright):
    """Full vulnerability scan with multiple engines"""
    console.print(Panel.fit(f"[bold blue]WVS v18.0[/] - Full Scan: {target}"))
    
    async def run():
        from wvs.vuln.full_scanner import FullScanner
        
        console.print("[yellow]Starting scan...[/]")
        
        # 模块列表
        module_list = list(modules)
        if "all" in module_list:
            module_list = ["sqli", "xss", "nuclei", "dom-xss"]
        
        scanner = FullScanner({
            "max_depth": depth,
            "max_urls": 200,
            "timeout": 15,
            "delay": 0.05,
            "enable_basic": not no_basic,
            "enable_sqlmap": not no_sqlmap,
            "enable_nuclei": not no_nuclei,
            "enable_playwright": not no_playwright,
        })
        
        if cookies:
            cookie_dict = {}
            for item in cookies.split(";"):
                if "=" in item:
                    k, v = item.split("=", 1)
                    cookie_dict[k.strip()] = v.strip()
            scanner.set_auth(cookies=cookie_dict)
        
        if header:
            headers = {}
            for h in header:
                if ":" in h:
                    k, v = h.split(":", 1)
                    headers[k.strip()] = v.strip()
            scanner.set_auth(headers=headers)
        
        result = await scanner.scan(target, modules=module_list)
        
        # Summary
        console.print(f"\n[bold]Scan Results:[/]")
        console.print(f"  Target: {result.target}")
        console.print(f"  Duration: {result.duration:.2f}s")
        console.print(f"  URLs crawled: {len(result.urls)}")
        console.print(f"  Forms found: {len(result.forms)}")
        console.print(f"  Vulnerabilities: {len(result.vulnerabilities)}")
        console.print(f"  Sources: {', '.join(result.sources)}")
        
        # Severity summary
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in result.vulnerabilities:
            sev = v.severity.lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        console.print(f"\n[bold]Severity Summary:[/]")
        console.print(f"  [red]Critical:[/] {severity_counts['critical']}")
        console.print(f"  [red]High:[/] {severity_counts['high']}")
        console.print(f"  [yellow]Medium:[/] {severity_counts['medium']}")
        console.print(f"  [green]Low:[/] {severity_counts['low']}")
        console.print(f"  [blue]Info:[/] {severity_counts['info']}")
        
        # Show vulnerabilities by source
        if result.vulnerabilities:
            console.print(f"\n[bold red]Vulnerabilities Found:[/]")
            
            for source in set(v.source for v in result.vulnerabilities):
                source_vulns = [v for v in result.vulnerabilities if v.source == source]
                console.print(f"\n[cyan]From {source}:[/] {len(source_vulns)} vulnerabilities")
                
                table = Table(title=f"Vulnerabilities - {source.upper()}")
                table.add_column("Type", style="cyan")
                table.add_column("URL", style="yellow")
                table.add_column("Severity", style="red")
                table.add_column("Conf", style="magenta")
                
                for v in source_vulns[:20]:
                    table.add_row(
                        v.type[:30],
                        v.url[:40],
                        v.severity,
                        f"{v.confidence:.0%}"
                    )
                
                console.print(table)
        
        # Show sensitive paths
        if result.sensitive_paths:
            console.print(f"\n[bold yellow]Sensitive Paths Found:[/]")
            table = Table(title="Sensitive Paths")
            table.add_column("URL", style="cyan")
            table.add_column("Type", style="yellow")
            table.add_column("Severity", style="red")
            
            for p in result.sensitive_paths[:10]:
                table.add_row(p["url"], p.get("type", "Unknown"), p.get("severity", "medium"))
            
            console.print(table)
        
        # Generate report
        from wvs.modules.report import ReportGenerator
        report_gen = ReportGenerator(output_dir=output or "./reports")
        report = report_gen.generate(result, target)
        
        if output_format == "json":
            report_path = report_gen.to_json(report)
        else:
            report_path = report_gen.to_html(report)
        
        console.print(f"\n[green]Report saved: {report_path}[/]")
        
        return result
    
    return asyncio.run(run())


# ========== Cloud Native ==========

@cli.group("cloud")
def cloud_group():
    """Cloud Native Security Scan"""
    pass


@cloud_group.command("dockerfile")
@click.argument("path", type=click.Path(exists=True))
def scan_dockerfile(path):
    """Scan Dockerfile"""
    from wvs.plugins.cloud.scanner import CloudNativeScanner
    
    console.print(f"[blue]Scanning Dockerfile: {path}[/]")
    scanner = CloudNativeScanner()
    findings = scanner.scan_dockerfile(path)
    
    if findings:
        table = Table(title="Dockerfile Security Issues")
        table.add_column("Line", style="cyan")
        table.add_column("Issue", style="yellow")
        table.add_column("Severity", style="red")
        for f in findings:
            table.add_row(str(f.get("line", 0)), f.get("issue", "")[:50], f.get("severity", ""))
        console.print(table)
    else:
        console.print("[green]No issues found[/]")


@cloud_group.command("image")
@click.argument("image_name")
def scan_image(image_name):
    """Scan Container Image"""
    from wvs.plugins.cloud.scanner import CloudNativeScanner
    
    console.print(f"[blue]Scanning image: {image_name}[/]")
    scanner = CloudNativeScanner()
    findings = scanner.scan_image(image_name)
    
    if findings:
        table = Table(title="Container Image Vulnerabilities")
        table.add_column("CVE", style="cyan")
        table.add_column("Package", style="yellow")
        table.add_column("Severity", style="red")
        for f in findings[:20]:
            table.add_row(f.get("cve", "N/A"), f.get("package", "N/A"), f.get("severity", "N/A"))
        console.print(table)
    else:
        console.print("[green]No vulnerabilities found[/]")


@cloud_group.command("k8s")
@click.option("--namespace", "-n", default="default", help="Namespace")
def scan_k8s(namespace):
    """Scan Kubernetes"""
    from wvs.plugins.cloud.scanner import CloudNativeScanner
    
    console.print(f"[blue]Scanning K8s namespace: {namespace}[/]")
    scanner = CloudNativeScanner()
    findings = scanner.scan_k8s(namespace)
    
    if findings:
        table = Table(title="K8s Security Issues")
        table.add_column("Resource", style="cyan")
        table.add_column("Issue", style="yellow")
        table.add_column("Severity", style="red")
        for f in findings[:20]:
            table.add_row(f.get("resource", "N/A"), f.get("issue", "N/A"), f.get("severity", "N/A"))
        console.print(table)
    else:
        console.print("[green]No issues found[/]")


# ========== Mobile Security ==========

@cli.group("mobile")
def mobile_group():
    """Mobile Security Scan"""
    pass


@mobile_group.command("apk")
@click.argument("apk_path", type=click.Path(exists=True))
def scan_apk(apk_path):
    """Scan Android APK"""
    from wvs.plugins.mobile.scanner import MobileScanner
    
    console.print(f"[blue]Scanning APK: {apk_path}[/]")
    scanner = MobileScanner()
    findings = scanner.scan_apk(apk_path)
    
    if findings:
        table = Table(title="APK Security Issues")
        table.add_column("Vulnerability", style="cyan")
        table.add_column("File", style="yellow")
        table.add_column("Severity", style="red")
        for f in findings[:20]:
            table.add_row(f.vulnerability[:40], f.file_path[:30], f.severity)
        console.print(table)
        console.print(f"\n[bold]Total:[/] {len(findings)} issues")
    else:
        console.print("[green]No issues found[/]")


@mobile_group.command("ipa")
@click.argument("ipa_path", type=click.Path(exists=True))
def scan_ipa(ipa_path):
    """Scan iOS IPA"""
    from wvs.plugins.mobile.scanner import MobileScanner
    
    console.print(f"[blue]Scanning IPA: {ipa_path}[/]")
    scanner = MobileScanner()
    findings = scanner.scan_ipa(ipa_path)
    
    if findings:
        console.print(f"[yellow]Found {len(findings)} issues[/]")
    else:
        console.print("[green]No issues found[/]")


# ========== Compliance ==========

@cli.group("compliance")
def compliance_group():
    """Data Compliance Scan"""
    pass


@compliance_group.command("pii")
@click.argument("content", type=str)
def scan_pii(content):
    """Detect PII (Personal Identifiable Information)"""
    from wvs.plugins.compliance.scanner import ComplianceScanner
    
    console.print("[blue]Detecting PII...[/]")
    scanner = ComplianceScanner()
    findings = scanner.scan_pii(content, "input")
    
    if findings:
        table = Table(title="PII Found")
        table.add_column("Type", style="cyan")
        table.add_column("Match", style="yellow")
        table.add_column("Severity", style="red")
        table.add_column("Regulation", style="green")
        for f in findings[:20]:
            table.add_row(f.data_type, f.pattern_matched[:30], f.severity, f.regulation[:40])
        console.print(table)
    else:
        console.print("[green]No PII found[/]")


@compliance_group.command("gdpr")
@click.option("--privacy-policy", is_flag=True, help="Has privacy policy")
@click.option("--purpose-limitation", is_flag=True, help="Clear data processing purpose")
@click.option("--data-minimization", is_flag=True, help="Only collect necessary data")
@click.option("--storage-limitation", is_flag=True, help="Has data retention policy")
@click.option("--security", is_flag=True, help="Has security measures")
@click.option("--encryption", is_flag=True, help="Encrypts personal data")
def check_gdpr(privacy_policy, purpose_limitation, data_minimization, storage_limitation, security, encryption):
    """GDPR Compliance Check"""
    from wvs.plugins.compliance.scanner import ComplianceScanner, ComplianceFramework
    
    console.print("[blue]GDPR Compliance Check...[/]")
    scanner = ComplianceScanner()
    
    assessment = {
        "privacy_policy": privacy_policy,
        "purpose_limitation": purpose_limitation,
        "data_minimization": data_minimization,
        "storage_limitation": storage_limitation,
        "security": security,
        "encryption": encryption,
    }
    
    violations = scanner.check_compliance(ComplianceFramework.GDPR, assessment)
    
    table = Table(title="GDPR Compliance Status")
    table.add_column("Article", style="cyan")
    table.add_column("Requirement", style="yellow")
    table.add_column("Status", style="green")
    
    for v in violations:
        status_color = "green" if v.status == "compliant" else "red"
        table.add_row(v.article, v.requirement, f"[{status_color}]{v.status}[/]")
    
    console.print(table)


@compliance_group.command("china")
@click.option("--classification", is_flag=True, help="Has data classification")
@click.option("--security-measures", is_flag=True, help="Has security measures")
@click.option("--risk-assessment", is_flag=True, help="Regular risk assessment")
@click.option("--important-data", is_flag=True, help="Important data protection")
def check_china(classification, security_measures, risk_assessment, important_data):
    """China Data Security Law Compliance Check"""
    from wvs.plugins.compliance.scanner import ComplianceScanner, ComplianceFramework
    
    console.print("[blue]China Data Security Law Check...[/]")
    scanner = ComplianceScanner()
    
    assessment = {
        "classification": classification,
        "security_measures": security_measures,
        "risk_assessment": risk_assessment,
        "important_data_protection": important_data,
    }
    
    violations = scanner.check_compliance(ComplianceFramework.CHINA_DS, assessment)
    
    table = Table(title="China Data Security Law Compliance")
    table.add_column("Article", style="cyan")
    table.add_column("Requirement", style="yellow")
    table.add_column("Status", style="green")
    
    for v in violations:
        status_color = "green" if v.status == "compliant" else "red"
        table.add_row(v.article, v.requirement, f"[{status_color}]{v.status}[/]")
    
    console.print(table)


# ========== Utils ==========

@cli.command("version")
def show_version():
    """Show version info"""
    console.print(Panel.fit("""
[bold blue]WVS v18.0[/] - Enterprise Security Scanner

Modules:
  - Web Scan (SQLi, XSS, SSRF, Cmdi, XXE, Traversal)
  - Cloud Native (Docker, K8s, AWS/Azure/GCP)
  - Mobile (Android, iOS, API)
  - Compliance (PII, GDPR, China Data Security Law)

Features:
  - PDF report support (fpdf2)
  - Fixed .git/HEAD false positives
  - Enhanced crawler depth & auth
  - Integrated v10-v17 all features
"""))


if __name__ == "__main__":
    cli()
