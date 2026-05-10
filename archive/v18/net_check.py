import asyncio, aiohttp, sys
sys.path.insert(0, r'C:\\Users\\HZR\\.qclaw\\workspace-agent-b7ed571b\\wvs-v18')

async def check():
    # Quick TCP connect test - faster than HTTP
    import socket
    targets = [
        ('192.168.18.254', 80),
        ('192.168.18.131', 80),
    ]
    for host, port in targets:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        try:
            result = sock.connect_ex((host, port))
            sock.close()
            print(str(host) + ':' + str(port) + ' -> ' + ('OPEN' if result == 0 else 'CLOSED (' + str(result) + ')'))
        except Exception as e:
            print(str(host) + ':' + str(port) + ' -> ERROR: ' + str(e))

asyncio.run(asyncio.sleep(0))

import socket
for host, port in [('192.168.18.254', 80), ('192.168.18.131', 80)]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    try:
        r = sock.connect_ex((host, port))
        sock.close()
        print(host + ':' + str(port) + ' -> ' + ('OPEN' if r == 0 else 'CLOSED'))
    except Exception as e:
        print(host + ':' + str(port) + ' -> ' + str(e))
