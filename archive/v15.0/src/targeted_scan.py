import sys
sys.path.insert(0, r"C:\Users\HZR\.qclaw\workspace-agent-b7ed571b\wvs-v18")
from wvs.vuln.scanner_v18 import VulnerabilityScanner
import asyncio, aiohttp, json, time, os

TARGET = "http://192.168.18.132"

# 手动发现的端点
ENDPOINTS = [
    ("http://192.168.18.132/view.php", "page", "GET"),
    ("http://192.168.18.132/dbadmin/test_db.php", "password", "POST"),
]

async def targeted_scan():
    results = {"vulns": [], "start": time.strftime("%Y-%m-%d %H:%M:%S")}
    scanner = VulnerabilityScanner({"timeout": 15, "delay": 0.1})
    
    async with aiohttp.ClientSession() as session:
        for url, param, method in ENDPOINTS:
            print(f"\n=== Testing {url} [{param}] ===")
            
            # LFI
            print("  LFI...")
            try:
                for v in await scanner.test_lfi(session, url, param, method) or []:
                    print(f"    [LFI FOUND] {v.payload[:40]}")
                    results["vulns"].append({"type": "LFI", "url": url, "param": param, "evidence": v.evidence})
            except Exception as e:
                print(f"    Error: {e}")
            
            # SQLi
            print("  SQLi...")
            try:
                for v in await scanner.test_sqli(session, url, param, method) or []:
                    print(f"    [SQLi FOUND] {v.payload[:40]}")
                    results["vulns"].append({"type": "SQLi", "url": url, "param": param})
            except Exception as e:
                print(f"    Error: {e}")
            
            # XSS
            print("  XSS...")
            try:
                for v in await scanner.test_xss(session, url, param) or []:
                    print(f"    [XSS FOUND] {v.payload[:40]}")
                    results["vulns"].append({"type": "XSS", "url": url, "param": param})
            except Exception as e:
                print(f"    Error: {e}")
    
    results["total"] = len(results["vulns"])
    results["end"] = time.strftime("%Y-%m-%d %H:%M:%S")
    
    os.makedirs("C:/Users/HZR/.qclaw/workspace-agent-b7ed571b/wvs-v18/reports", exist_ok=True)
    with open("C:/Users/HZR/.qclaw/workspace-agent-b7ed571b/wvs-v18/reports/zico2_targeted.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\n=== Summary ===")
    print(f"Total vulnerabilities: {len(results['vulns'])}")
    for v in results["vulns"]:
        print(f"  [{v['type']}] {v['url']} param={v['param']}")

asyncio.run(targeted_scan())
