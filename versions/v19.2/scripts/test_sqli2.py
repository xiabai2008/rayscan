import asyncio
import httpx
import re


async def test():
    async with httpx.AsyncClient(follow_redirects=True, timeout=30) as c:
        # Login + security low
        await c.get("http://192.168.18.131/dvwa/login.php")
        await c.post("http://192.168.18.131/dvwa/login.php", data={"username": "admin", "password": "password", "Login": "Login"})
        await c.get("http://192.168.18.131/dvwa/security.php")
        await c.post("http://192.168.18.131/dvwa/security.php", data={"security": "low", "seclev_submit": "Submit"})

        # Baseline
        r = await c.get("http://192.168.18.131/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit")
        print(f"Baseline length: {len(r.text)}")

        # Error-based payload
        r2 = await c.get("http://192.168.18.131/dvwa/vulnerabilities/sqli/?id=1'&Submit=Submit")
        print(f"\nError payload length: {len(r2.text)}")
        # Search for SQL error
        text = r2.text.lower()
        for pattern_name, patterns in [
            ("mysql", [r"you have an error", r"mysql", r"sql syntax", r"near"]),
            ("generic", [r"error in your sql"]),
        ]:
            for p in patterns:
                m = re.search(p, text, re.IGNORECASE)
                if m:
                    print(f"  FOUND ({pattern_name}): ...{r2.text[max(0,m.start()-50):m.end()+100]}...")

        # What does the scanner's DB_ERROR_PATTERNS expect?
        from wvs.modules.sqli.payloads import DB_ERROR_PATTERNS
        for db, pats in DB_ERROR_PATTERNS.items():
            for pat in pats:
                m = re.search(pat, r2.text, re.IGNORECASE)
                if m:
                    print(f"  MATCHED DB_ERROR_PATTERNS[{db}] pattern '{pat}': found")
                    break

        # Print first part of response to see what's there
        print(f"\nResponse (first 2000 chars):\n{r2.text[:2000]}")


asyncio.run(test())
