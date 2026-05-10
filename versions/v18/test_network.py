"""测试网络连接"""

import asyncio
import aiohttp

async def test_connection():
    """测试多个端点"""
    endpoints = [
        ("SQLi-Labs", "http://47.95.192.41:8083/"),
        ("Pikachu", "http://47.95.192.41:8082/"),
        ("DVWA", "http://47.95.192.41:8081/"),
        ("Example", "https://httpbin.org/get"),
        ("Baidu", "https://www.baidu.com"),
    ]
    
    timeout = aiohttp.ClientTimeout(total=10)
    
    async with aiohttp.ClientSession(timeout=timeout) as session:
        for name, url in endpoints:
            try:
                async with session.get(url) as resp:
                    content = await resp.text()
                    print(f"[{name}] Status: {resp.status}, Length: {len(content)}")
            except Exception as e:
                print(f"[{name}] Error: {type(e).__name__}: {e}")

if __name__ == "__main__":
    asyncio.run(test_connection())
