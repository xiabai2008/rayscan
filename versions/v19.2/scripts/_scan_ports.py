import concurrent.futures, socket

ports = [21,22,23,25,53,80,110,111,135,139,143,445,512,513,514,1099,
         1524,2049,2121,3306,3632,5432,5900,6000,6667,6697,8009,
         8180,8888,9010,9090,10000,32768,49152,54322]

def check(p):
    try:
        s = socket.socket()
        s.settimeout(0.4)
        s.connect(('172.17.43.128', p))
        s.close()
        return p
    except:
        return None

with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
    open_ports = [p for p in ports if ex.submit(check, p).result()]

print('Open ports on 172.17.43.128:')
for p in sorted(open_ports):
    try:
        s = socket.socket()
        s.settimeout(0.5)
        s.connect(('172.17.43.128', p))
        banner = s.recv(100)
        s.close()
        b = banner.decode('utf-8', errors='replace').strip()
        print(f'  {p}: {b[:80]}')
    except:
        print(f'  {p}: open')
