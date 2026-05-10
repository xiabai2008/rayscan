"""测试报告生成器"""
import sys
sys.path.insert(0, "C:\\Users\\HZR\\.qclaw\\workspace-agent-b7ed571b\\wvs-v18")

from wvs.modules.report import ReportGenerator, ScanReport
from wvs.vuln.scanner_v18 import Vulnerability, ScanResult, URLInfo
import tempfile
import os


def test_report_generator():
    """测试报告生成器"""
    print("Testing ReportGenerator...")
    
    # 创建临时输出目录
    output_dir = tempfile.mkdtemp()
    gen = ReportGenerator(output_dir=output_dir)
    
    # 模拟扫描结果
    class MockScanResult:
        def __init__(self):
            self.urls = [URLInfo(url="http://example.com/page1"), URLInfo(url="http://example.com/page2")]
            self.forms = [{"url": "http://example.com/login", "method": "POST"}]
            self.vulnerabilities = [
                Vulnerability(
                    type="SQL Injection",
                    url="http://example.com/page?id=1",
                    parameter="id",
                    payload="' OR '1'='1",
                    severity="critical",
                    confidence=0.95,
                    evidence="SQL syntax error detected",
                    poc="http://example.com/page?id=%27%20OR%20%271%27%3D%271"
                ),
                Vulnerability(
                    type="XSS",
                    url="http://example.com/search?q=test",
                    parameter="q",
                    payload="<script>alert(1)</script>",
                    severity="high",
                    confidence=0.88,
                    evidence="Payload in attribute context",
                    poc="http://example.com/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
                ),
                Vulnerability(
                    type="Local File Inclusion",
                    url="http://example.com/view?file=test",
                    parameter="file",
                    payload="../../../etc/passwd",
                    severity="critical",
                    confidence=0.95,
                    evidence="root: in response",
                    poc="http://example.com/view?file=../../../etc/passwd"
                )
            ]
            self.js_files = ["http://example.com/app.js"]
            self.sensitive_paths = [
                {"url": "http://example.com/.env", "type": "Environment File", "severity": "critical"},
                {"url": "http://example.com/phpinfo.php", "type": "PHP Info", "severity": "high"}
            ]
            self.duration = 15.5
            self.total_requests = 42
    
    result = MockScanResult()
    
    # 生成报告
    report = gen.generate(result, "http://example.com")
    
    # 验证报告内容
    assert report.target == "http://example.com"
    assert report.urls_count == 2
    assert report.forms_count == 1
    assert len(report.vulnerabilities) == 3
    assert report.severity_stats["critical"] == 2
    assert report.severity_stats["high"] == 1
    print(f"  [OK] Report generated: {report.target}")
    print(f"  [OK] Severity stats: {report.severity_stats}")
    
    # 生成 JSON
    json_path = gen.to_json(report)
    assert os.path.exists(json_path)
    print(f"  [OK] JSON report: {json_path}")
    
    # 生成 HTML
    html_path = gen.to_html(report)
    assert os.path.exists(html_path)
    print(f"  [OK] HTML report: {html_path}")
    
    # 验证 HTML 内容
    with open(html_path, "r", encoding="utf-8") as f:
        html = f.read()
    assert "SQL Injection" in html
    assert "XSS" in html
    assert "critical" in html
    assert "example.com" in html
    print(f"  [OK] HTML content validated")
    
    # 清理
    import shutil
    shutil.rmtree(output_dir)
    
    print("\n[OK] All tests passed!")
    return True


if __name__ == "__main__":
    test_report_generator()
