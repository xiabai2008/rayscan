"""测试 SQLMap 集成"""
import sys
sys.path.insert(0, r"C:\Users\HZR\.qclaw\workspace-agent-b7ed571b\wvs-v18")

from wvs.integrations import SQLMapIntegration

print("Testing SQLMap integration...")

sqli = SQLMapIntegration()

# 测试简单 URL
url = "https://httpbin.org/get?id=1"
print(f"\nTesting: {url}")

results = sqli.scan(url)
print(f"Found {len(results)} SQL injection vulnerabilities")

if results:
    for r in results:
        print(f"  Type: {r.injection_type}")
        print(f"  Parameter: {r.parameter}")
        print(f"  Severity: {r.severity}")
        print(f"  Confidence: {r.confidence}")
else:
    print("  No SQL injection found (expected for httpbin.org)")

print("\nSQLMap integration test complete!")
