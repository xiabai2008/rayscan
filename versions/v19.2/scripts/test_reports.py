"""测试报告系统"""
import asyncio
import sys
sys.stdout.reconfigure(encoding='utf-8')

from pathlib import Path
from datetime import datetime

from wvs.models import ScanResult, ScanTarget, Vulnerability, VulnerabilityType, Severity, Confidence
from wvs.reporting.console import ConsoleReporter
from wvs.reporting.html_report import HTMLReporter
from wvs.reporting.markdown_report import MarkdownReporter

def create_mock_result() -> ScanResult:
    """创建模拟扫描结果"""
    target = ScanTarget(url="http://47.95.192.41:8081/dvwa/")
    
    vulns = [
        Vulnerability(
            type=VulnerabilityType.SQL_INJECTION,
            title="SQL Injection (Error-based)",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            url="http://47.95.192.41:8081/vulnerabilities/sqli/?id=1",
            parameter="id",
            parameter_type="query",
            method="GET",
            payload="'",
            evidence="You have an error in your SQL syntax",
            description="检测到 SQL 注入漏洞，攻击者可以通过注入恶意 SQL 语句获取数据库敏感信息",
            recommendation="使用参数化查询或预编译语句，对用户输入进行严格过滤",
            references=["https://owasp.org/www-community/attacks/SQL_Injection"],
            module="sqli",
        ),
        Vulnerability(
            type=VulnerabilityType.XSS,
            title="Cross-Site Scripting (Reflected)",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            url="http://47.95.192.41:8081/vulnerabilities/xss_r/?name=test",
            parameter="name",
            parameter_type="query",
            method="GET",
            payload="<script>alert(1)</script>",
            evidence="Script tag reflected in response",
            description="检测到反射型 XSS 漏洞，攻击者可以注入恶意脚本",
            recommendation="对用户输入进行 HTML 实体编码，使用 CSP 策略",
            references=["https://owasp.org/www-community/attacks/xss/"],
            module="xss",
        ),
        Vulnerability(
            type=VulnerabilityType.COMMAND_INJECTION,
            title="Command Injection",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            url="http://47.95.192.41:8081/vulnerabilities/exec/",
            parameter="ip",
            parameter_type="body",
            method="POST",
            payload="; id",
            evidence="uid=33(www-data) gid=33(www-data)",
            description="检测到命令注入漏洞，攻击者可以执行任意系统命令",
            recommendation="避免使用系统命令执行函数，使用安全的 API 替代",
            references=["https://owasp.org/www-community/attacks/Command_Injection"],
            module="cmdi",
        ),
        Vulnerability(
            type=VulnerabilityType.LFI,
            title="Local File Inclusion",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            url="http://47.95.192.41:8081/vulnerabilities/fi/?page=include.php",
            parameter="page",
            parameter_type="query",
            method="GET",
            payload="/etc/passwd",
            evidence="root:x:0:0:root:/root:/bin/bash",
            description="检测到本地文件包含漏洞，攻击者可以读取敏感文件",
            recommendation="避免将用户输入直接传递给文件包含函数",
            references=["https://owasp.org/www-community/attacks/File_Inclusion"],
            module="lfi",
        ),
    ]
    
    result = ScanResult(
        target=target,
        vulnerabilities=vulns,
        scan_time=datetime.now(),
        duration=12.5,
        requests_made=156,
        endpoints_found=24,
        modules_run=["sqli", "xss", "cmdi", "lfi"],
    )
    
    return result

def test_console_report():
    """测试控制台报告"""
    print("\n" + "="*60)
    print("控制台报告测试")
    print("="*60)
    
    result = create_mock_result()
    reporter = ConsoleReporter()
    reporter.report(result)

def test_html_report():
    """测试 HTML 报告"""
    print("\n" + "="*60)
    print("HTML 报告测试")
    print("="*60)
    
    result = create_mock_result()
    reporter = HTMLReporter()
    
    output_path = Path("reports/test_report.html")
    reporter.generate(result, output_path)
    print(f"HTML 报告已生成: {output_path}")
    
    # JSON 报告
    json_path = Path("reports/test_report.json")
    reporter.generate_json(result, json_path)
    print(f"JSON 报告已生成: {json_path}")

def test_markdown_report():
    """测试 Markdown 报告"""
    print("\n" + "="*60)
    print("Markdown 报告测试")
    print("="*60)
    
    result = create_mock_result()
    reporter = MarkdownReporter()
    
    output_path = Path("reports/test_report.md")
    reporter.generate(result, output_path)
    print(f"Markdown 报告已生成: {output_path}")

def main():
    print("="*60)
    print("WVS v19 报告系统测试")
    print("="*60)
    
    test_console_report()
    test_html_report()
    test_markdown_report()
    
    print("\n" + "="*60)
    print("测试完成！")
    print("="*60)
    print("\n生成的报告文件:")
    
    reports_dir = Path("reports")
    if reports_dir.exists():
        for f in reports_dir.iterdir():
            size = f.stat().st_size
            print(f"  - {f.name}: {size:,} bytes")

if __name__ == "__main__":
    main()
