import urllib.request, re, socket
socket.setdefaulttimeout(10)
base = "http://192.168.18.132"

req = urllib.request.Request(base + "/", headers={"User-Agent": "Mozilla/5.0"})
resp = urllib.request.urlopen(req, timeout=10)
html = resp.read().decode("utf-8", errors="ignore")

links = re.findall(r'href=["\x27]([^"\x27>\s]+)["\x27]', html, re.I)
links += re.findall(r'src=["\x27]([^"\x27>\s]+)["\x27]', html, re.I)

print("=== Homepage Links ===")
for link in sorted(set(links))[:30]:
    print(link)

print("\n=== Known zico2 Endpoints ===")
paths = ["/view.php", "/cart.php", "/login.php", "/view.php", "/rr.php",
         "/db.sql", "/db.sql.gz", "/robots.txt", "/phpinfo.php", "/.env"]

for p in paths:
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect(("192.168.18.132", 80))
        s.send(f"HEAD {p} HTTP/1.0\r\nHost: 192.168.18.132\r\n\r\n".encode())
        resp = s.recv(500).decode()
        code = resp.split()[1] if resp.startswith("HTTP") else "?"
        s.close()
        if code not in ("404", "403"):
            print(f"{p} -> {code}")
    except: pass
