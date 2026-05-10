import asyncio
import httpx
from wvs.plugins.auth import FormLoginAuth


async def test():
    async with httpx.AsyncClient(follow_redirects=True, timeout=30) as c:
        auth = FormLoginAuth(
            login_url="http://192.168.18.131/dvwa/login.php",
            username="admin",
            password="password",
        )
        result = await auth.authenticate(c)
        print(f"authenticated: {result['authenticated']}")
        print(f"cookies: {result['cookies']}")
        print(f"error: {result['error']}")

        # Verify session works
        resp = await c.get("http://192.168.18.131/dvwa/vulnerabilities/sqli/")
        has_user_id = "User ID" in resp.text
        print(f"SQLi page has User ID: {has_user_id}")


asyncio.run(test())
