"""简单测试 - 诊断爬虫问题"""

import asyncio
import aiohttp
from bs4 import BeautifulSoup

async def test_basic_request():
    """测试基本 HTTP 请求"""
    url = "http://47.95.192.41:8083/"
    
    print(f"测试请求: {url}")
    
    try:
        timeout = aiohttp.ClientTimeout(total=5)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as resp:
                print(f"状态码: {resp.status}")
                content = await resp.text()
                print(f"内容长度: {len(content)}")
                
                # 解析 HTML
                soup = BeautifulSoup(content, 'lxml')
                links = soup.find_all('a', href=True)
                print(f"发现链接: {len(links)}")
                
                for link in links[:5]:
                    print(f"  - {link.get('href')}")
                
                return True
    except Exception as e:
        print(f"错误: {e}")
        return False

if __name__ == "__main__":
    result = asyncio.run(test_basic_request())
    print(f"\n测试结果: {'成功' if result else '失败'}")
