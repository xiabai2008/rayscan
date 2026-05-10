import urllib.request, re, socket
socket.setdefaulttimeout(15)
base = "http://192.168.18.132"

print("=== Static URL Discovery ===")

# Fetch homepage
req = urllib.request.Request(base + "/", headers={"User-Agent": "Mozilla/5.0"})
resp = urllib.request.urlopen(req, timeout=10)
html = resp.read().decode("utf-8", errors="ignore")

# Extract all URLs
urls = set()
# href/src/action
urls.update(re.findall(r'href=["\x27]([^"\x27>\s]+)["\x27]', html))
urls.update(re.findall(r'src=["\x27]([^"\x27>\s]+)["\x27]', html))
urls.update(re.findall(r'action=["\x27]([^"\x27>\s]+)["\x27]', html))
# JavaScript URLs
urls.update(re.findall(r'location\.href\s*=\s*["\x27]([^"\x27]+)["\x27]', html))
urls.update(re.findall(r'window\.location\s*=\s*["\x27]([^"\x27]+)["\x27]', html))
# URL-like patterns in JS
urls.update(re.findall(r'["\x27]([^"\x27]*\.php[^"\x27]*)["\x27]', html))

print("Discovered URLs:")
internal = []
for url in sorted(urls):
    if url.startswith("/") or url.startswith("?") or url.startswith(base):
        if not url.startswith("#") and not url.startswith("mailto:") and not url.startswith("javascript:"):
            internal.append(url)
            print(f"  {url}")

# Build full URLs for scanning
print(f"\nTotal internal URLs: {len(internal)}")

# Test each discovered URL
print("\n=== Testing Discovered Endpoints ===")
for url in internal[:20]:
    full = base + url if url.startswith("/") else url
    if not full.startswith("http"):
        full = base + "/" + url
    try:
        req = urllib.request.Request(full.split("?")[0], headers={"User-Agent": "WVS/1.0"})
        resp = urllib.request.urlopen(req, timeout=5)
        print(f"  {url[:50]} -> 200 ({len(resp.read())} bytes)")
    except urllib.error.HTTPError as e:
        if e.code != 404:
            print(f"  {url[:50]} -> {e.code}")
    except Exception as e:
        pass
