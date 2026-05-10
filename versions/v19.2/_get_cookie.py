import httpx, re, asyncio

async def login():
    base = "http://172.17.43.129:8888/dvwa"
    async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as c:
        # Step 1: get login token
        r = await c.get(base + "/login.php")
        m = re.search(r"user_token' value='([^']+)'", r.text)
        if not m:
            print("FAIL: no login token")
            return

        # Step 2: login
        r = await c.post(base + "/login.php", data={
            "username": "admin", "password": "password",
            "Login": "Login", "user_token": m.group(1),
        })
        print(f"Login response: {len(r.text)} bytes, has DVWA: {'DVWA' in r.text}")

        # Step 3: navigate to security.php to get token
        r = await c.get(base + "/security.php")
        m2 = re.search(r"user_token' value='([^']+)'", r.text)
        if m2:
            print(f"Security token: {m2.group(1)[:10]}...")
            r = await c.post(base + "/security.php", data={
                "security": "low", "seclev_submit": "Submit",
                "user_token": m2.group(1),
            })
            print(f"Security response: {len(r.text)} bytes")
        else:
            print("FAIL: no security token")
            print(r.text[:500])

        # Step 4: verify
        r = await c.get(base + "/index.php")
        has_low = "low" in r.text.lower() and "security" in r.text.lower()
        print(f"Verify: {len(r.text)} bytes")
        
        cookies_str = "; ".join(f"{n}={v}" for n, v in c.cookies.items())
        print(f"Cookies: {cookies_str}")
        print(f"Has PHPSESSID: {any(n.startswith('PHPSESSID') for n in c.cookies)}")
        
        # Check session from response
        for h in r.headers.items():
            if 'set-cookie' in h[0].lower():
                print(f"Set-Cookie header: {h[1][:100]}")

asyncio.run(login())
