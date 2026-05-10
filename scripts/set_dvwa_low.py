import asyncio
import httpx
import re


async def set_dvwa_low():
    async with httpx.AsyncClient(follow_redirects=True, timeout=30) as c:
        # Step 1: Login
        resp = await c.get("http://192.168.18.131/dvwa/login.php")
        data = {"username": "admin", "password": "password", "Login": "Login"}
        resp = await c.post("http://192.168.18.131/dvwa/login.php", data=data)
        print(f"Login: {resp.status_code}, URL: {resp.url}")

        # Step 2: Set security to low
        # First GET the security page
        resp = await c.get("http://192.168.18.131/dvwa/security.php")
        print(f"Security page: {resp.status_code}")

        # Extract CSRF token if any
        m = re.search(r'name="user_token"\s+value="([^"]+)"', resp.text)
        token = m.group(1) if m else ""

        # POST to set security
        sec_data = {
            "security": "low",
            "seclev_submit": "Submit",
        }
        if token:
            sec_data["user_token"] = token

        resp = await c.post("http://192.168.18.131/dvwa/security.php", data=sec_data)
        print(f"Set security: {resp.status_code}, URL: {resp.url}")

        # Verify
        resp = await c.get("http://192.168.18.131/dvwa/security.php")
        if "Security level set to low" in resp.text or 'value="low"' in resp.text or "low" in resp.text.lower():
            print("Security set to LOW!")
        else:
            print(f"Security page content (first 500): {resp.text[:500]}")

        # Check cookies
        print(f"Cookies: {dict(c.cookies)}")


asyncio.run(set_dvwa_low())
