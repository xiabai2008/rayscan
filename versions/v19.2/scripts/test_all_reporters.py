#!/usr/bin/env python3
"""测试所有报告生成器"""
import sys
sys.path.insert(0, 'C:/Users/HZR/.openclaw/workspace/wvs-v19')

from pathlib import Path
from datetime import datetime

from wvs.models import ScanResult, ScanTarget, Vulnerability, Severity, Confidence, VulnerabilityType
from wvs.reporting import ConsoleReporter, HTMLReporter, MarkdownReporter, JSONReporter, CSVReporter

# 创建测试数据
target = ScanTarget(url="http://47.95.192.41:8081/dvwa/")

vulns = [
    Vulnerability(
        type=VulnerabilityType.SQL_INJECTION,
        title="SQL Injection (Error-based)",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        url="http://47.95.192.41:8081/vulnerabilities/sqli/?id=1",
        method="GET",
        parameter="id",
        parameter_type="query",
        payload="'",
        evidence="You have an error in your SQL syntax",
        description="SQL injection vulnerability in id parameter",
        recommendation="Use parameterized queries",
        cwe_id=89,
        module="sqli",
    ),
    Vulnerability(
        type=VulnerabilityType.XSS,
        title="Reflected XSS",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        url="http://47.95.192.41:8081/vulnerabilities/xss_r/?name=test",
        method="GET",
        parameter="name",
        parameter_type="query",
        payload="<script>alert(1)</script>",
        evidence="<script>alert(1)</script>",
        cwe_id=79,
        module="xss",
    ),
    Vulnerability(
        type=VulnerabilityType.COMMAND_INJECTION,
        title="Command Injection",
        severity=Severity.CRITICAL,
        confidence=Confidence.CERTAIN,
        url="http://47.95.192.41:8081/vulnerabilities/exec/",
        method="POST",
        parameter="ip",
        parameter_type="body",
        payload="; id",
        evidence="uid=33(www-data)",
        description="OS command injection vulnerability",
        recommendation="Use escapeshellarg() or escapeshellcmd()",
        cwe_id=78,
        module="cmdi",
    ),
    Vulnerability(
        type=VulnerabilityType.LFI,
        title="Local File Inclusion",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        url="http://47.95.192.41:8081/vulnerabilities/fi/?page=include.php",
        method="GET",
        parameter="page",
        parameter_type="query",
        payload="../../../etc/passwd",
        evidence="root:x:0:0:root:/root:/bin/bash",
        cwe_id=98,
        module="lfi",
    ),
]

result = ScanResult(
    target=target,
    vulnerabilities=vulns,
    scan_time=datetime.now(),
    duration=12.5,
    requests_made=156,
    endpoints_found=45,
    modules_run=4,
)

# 创建输出目录
output_dir = Path("C:/Users/HZR/.openclaw/workspace/wvs-v19/reports")
output_dir.mkdir(parents=True, exist_ok=True)

print("=" * 60)
print("测试报告生成器")
print("=" * 60)

# 1. JSON 标准格式
print("\n[1/5] JSON Reporter - Standard...")
json_reporter = JSONReporter()
json_path = output_dir / "test_standard.json"
json_reporter.generate(result, json_path)
print(f"  OK {json_path} ({json_path.stat().st_size} bytes)")

# 2. JSON SARIF 格式
print("\n[2/5] JSON Reporter - SARIF...")
sarif_path = output_dir / "test_sarif.sarif"
json_reporter.generate_sarif(result, sarif_path)
print(f"  OK {sarif_path} ({sarif_path.stat().st_size} bytes)")

# 3. CSV 格式
print("\n[3/5] CSV Reporter...")
csv_reporter = CSVReporter()
csv_path = output_dir / "test_vulnerabilities.csv"
csv_reporter.generate(result, csv_path)
print(f"  OK {csv_path} ({csv_path.stat().st_size} bytes)")

# 4. CSV Summary
csv_summary_path = output_dir / "test_summary.csv"
csv_reporter.generate_summary(result, csv_summary_path)
print(f"  OK {csv_summary_path} ({csv_summary_path.stat().st_size} bytes)")

# 5. HTML（已有）
print("\n[4/5] HTML Reporter...")
html_reporter = HTMLReporter()
html_path = output_dir / "test_html.html"
html_reporter.generate(result, html_path)
print(f"  OK {html_path} ({html_path.stat().st_size} bytes)")

# 6. Markdown（已有）
print("\n[5/5] Markdown Reporter...")
md_reporter = MarkdownReporter()
md_path = output_dir / "test_markdown.md"
md_reporter.generate(result, md_path)
print(f"  OK {md_path} ({md_path.stat().st_size} bytes)")

print("\n" + "=" * 60)
print("全部完成！")
print("=" * 60)

# 显示文件列表
print("\n生成的报告文件:")
for f in sorted(output_dir.glob("test_*")):
    print(f"  {f.name:30} {f.stat().st_size:>8} bytes")
