"""测试 Nuclei 模板检测"""
import sys
sys.path.insert(0, r"C:\Users\HZR\.qclaw\workspace-agent-b7ed571b\wvs-v18")

from wvs.integrations import NucleiIntegration

# 测试一些常见的网站
targets = [
    ("httpbin.org", "https://httpbin.org/"),
    ("example", "https://example.com/"),
]

for name, url in targets:
    print(f"\n{'='*60}")
    print(f"Testing: {name} ({url})")
    print('='*60)
    
    nuclei = NucleiIntegration()
    vulns = nuclei.scan(url, severity=["critical", "high", "medium", "low", "info"])
    
    print(f"\nFound {len(vulns)} issues:")
    for v in vulns:
        print(f"  [{v.severity.upper()}] {v.name}")
        print(f"    URL: {v.matched_at}")
        print(f"    Desc: {v.description}")
