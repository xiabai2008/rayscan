"""直接验证目标站点的漏洞"""
import sys
sys.path.insert(0, r"C:\Users\HZR\.qclaw\workspace-agent-b7ed571b\wvs-v18")

import asyncio
import aiohttp
from wvs.vuln.scanner_v18 import VulnerabilityScanner
from wvs.integrations import NucleiIntegration

TARGET = "http://192.168.18.131"

async def scan_target():
    print(f"Scanning: {TARGET}")
    scanner = VulnerabilityScanner({"timeout": 15, "delay": 0.2})
    results = []
    
    # 1. 测试已知漏洞路径
    vuln_paths = [
        # DVWA
        "/dvwa/vulnerabilities/sqli/?id=1",
        "/dvwa/vulnerabilities/xss_r/?name=test",
        "/dvwa/vulnerabilities/sqli_blind/?id=1",
        "/dvwa/vulnerabilities/upload/?",
        # Mutillidae
        "/mutillidae/?page=client-side-filtering.php",
        "/mutillidae/?page=dns-lookup.php",
        # PhpMyAdmin
        "/phpmyadmin/",
        "/phpMyAdmin/",
        # TWiki
        "/twiki/bin/view/Main/",
        # Other
        "/tikiwiki/",
        "/phpinfo.php",
        "/cgi-bin/",
        "/examples/",
    ]
    
    print("\n[1] Testing known vulnerable paths...")
    async with aiohttp.ClientSession() as session:
        for path in vuln_paths:
            url = TARGET + path
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status in [200, 302, 401]:
                        print(f"  FOUND: {url} ({resp.status})")
                        results.append({"url": url, "status": resp.status})
            except:
                pass
    
    # 2. SQLi 测试
    print("\n[2] Testing SQL Injection...")
    sqli_params = [
        (f"{TARGET}/dvwa/vulnerabilities/sqli/", "id", "GET"),
        (f"{TARGET}/mutillidae/index.php?page=dns-lookup.php", "dns_lookup_hostname", "GET"),
    ]
    
    sqli_found = []
    async with aiohttp.ClientSession() as session:
        for url, param, method in sqli_params:
            print(f"  Testing: {url}?{param}=1")
            vulns = await scanner.test_sqli(session, url, param, method)
            if vulns:
                for v in vulns:
                    print(f"    [SQLi DETECTED] {v.type}")
                    print(f"    Payload: {v.payload[:60]}")
                    print(f"    Severity: {v.severity}, Confidence: {v.confidence:.0%}")
                    sqli_found.append(v)
            else:
                print(f"    Not found")
    
    # 3. XSS 测试
    print("\n[3] Testing XSS...")
    xss_params = [
        (f"{TARGET}/dvwa/vulnerabilities/xss_r/", "name", "GET"),
        (f"{TARGET}/mutillidae/index.php?page=add-to-your-blog.php", "add_to_your_blog", "POST"),
        (f"{TARGET}/twiki/bin/view/Main/", "topic", "GET"),
    ]
    
    xss_found = []
    async with aiohttp.ClientSession() as session:
        for url, param, method in xss_params:
            print(f"  Testing: {url}")
            vulns = await scanner.test_xss(session, url, param)
            if vulns:
                for v in vulns:
                    print(f"    [XSS DETECTED] {v.type}")
                    print(f"    Payload: {v.payload[:60]}")
                    print(f"    Severity: {v.severity}, Confidence: {v.confidence:.0%}")
                    xss_found.append(v)
            else:
                print(f"    Not found")
    
    # 4. Nuclei 模板检测
    print("\n[4] Running Nuclei template scan...")
    nuclei = NucleiIntegration()
    nuclei_results = nuclei.scan(f"{TARGET}/")
    print(f"  Nuclei found: {len(nuclei_results)}")
    for v in nuclei_results[:5]:
        print(f"    [{v.severity}] {v.name}: {v.description[:60]}")
    
    # 5. CMDi 测试
    print("\n[5] Testing Command Injection...")
    cmdi_params = [
        (f"{TARGET}/mutillidae/index.php?page=dns-lookup.php", "dns_lookup_hostname", "GET"),
    ]
    cmdi_found = []
    async with aiohttp.ClientSession() as session:
        for url, param, method in cmdi_params:
            print(f"  Testing: {url}")
            vulns = await scanner.test_cmdi(session, url, param)
            if vulns:
                for v in vulns:
                    print(f"    [CMDi DETECTED] {v.type}")
                    cmdi_found.append(v)
    
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Discovered URLs: {len(results)}")
    print(f"SQL Injection: {len(sqli_found)}")
    print(f"XSS: {len(xss_found)}")
    print(f"CMDi: {len(cmdi_found)}")
    print(f"Nuclei: {len(nuclei_results)}")
    
    return {
        "urls": results,
        "sqli": sqli_found,
        "xss": xss_found,
        "cmdi": cmdi_found,
        "nuclei": nuclei_results
    }

if __name__ == "__main__":
    asyncio.run(scan_target())
