"""用 Python http.client 测试本地服务器"""
import http.client
import time

def http_get(host, path, port=8888):
    """直接用 socket 发送 HTTP 请求"""
    try:
        conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.request("GET", path)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, data.decode('utf-8', errors='replace')
    except Exception as e:
        return None, str(e)

# 测试
print("Testing with 127.0.0.1...")
status, data = http_get("127.0.0.1", "/")
print(f"Status: {status}")
print(f"Length: {len(data)}")
if status == 200:
    print("First 300 chars:", data[:300])

# 测试 sqli 端点
print("\nTesting SQLi endpoint...")
status, data = http_get("127.0.0.1", "/sqli/less-1?id=1")
print(f"Status: {status}")
print(f"Length: {len(data)}")
if status == 200:
    print(data[:500])
