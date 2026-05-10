"""测试 aiohttp 连接 localhost"""
import asyncio
import aiohttp
import re

async def test():
    print("Testing localhost:8888...")
    
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get('http://127.0.0.1:8888/', timeout=aiohttp.ClientTimeout(total=5)) as r:
                print('Status:', r.status)
                text = await r.text()
                print('HTML length:', len(text))
                
                # 提取链接
                links = re.findall(r'href=["\']([^"\']+)["\']\s*>', text)
                print('Links found:', len(links))
                for l in links[:10]:
                    print(' ', l)
    except Exception as e:
        print('Error:', e)

asyncio.run(test())
