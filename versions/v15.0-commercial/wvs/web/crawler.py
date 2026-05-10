"""异步 Web 爬虫模块"""
import asyncio
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Set
from dataclasses import dataclass, field

try:
    import aiohttp
    from bs4 import BeautifulSoup
except ImportError:
    aiohttp = None
    BeautifulSoup = None


@dataclass
class Form:
    """表单数据类"""
    action: str
    method: str
    inputs: List[Dict] = field(default_factory=list)


class WebCrawler:
    """异步 Web 爬虫"""
    
    def __init__(self, max_depth: int = 3, max_urls: int = 100, concurrency: int = 20):
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.concurrency = concurrency
        self.visited: Set[str] = set()
        self.urls_queue: asyncio.Queue = asyncio.Queue()
        self.forms: List[Form] = []
        self.js_files: List[str] = []
    
    async def crawl(self, start_url: str) -> Dict:
        """爬取目标网站"""
        if aiohttp is None:
            raise ImportError("需要安装 aiohttp: pip install aiohttp")
        
        await self.urls_queue.put((start_url, 0))
        semaphore = asyncio.Semaphore(self.concurrency)
        
        tasks = []
        while len(self.visited) < self.max_urls:
            try:
                url, depth = await asyncio.wait_for(self.urls_queue.get(), timeout=1.0)
                if url in self.visited or depth > self.max_depth:
                    continue
                task = asyncio.create_task(self._crawl_url(url, depth, semaphore))
                tasks.append(task)
                if len(tasks) >= self.concurrency:
                    await asyncio.gather(*tasks)
                    tasks = []
            except asyncio.TimeoutError:
                break
        
        if tasks:
            await asyncio.gather(*tasks)
        
        return {
            "urls": list(self.visited),
            "forms": self.forms,
            "js_files": self.js_files,
        }
    
    async def _crawl_url(self, url: str, depth: int, semaphore: asyncio.Semaphore):
        """爬取单个 URL"""
        async with semaphore:
            try:
                timeout = aiohttp.ClientTimeout(total=10)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(url, ssl=False) as resp:
                        if resp.status == 200:
                            content_type = resp.headers.get("Content-Type", "")
                            if "text/html" in content_type:
                                html = await resp.text()
                                self.visited.add(url)
                                self._parse_html(html, url, depth)
            except Exception as e:
                pass  # 静默处理异常
    
    def _parse_html(self, html: str, base_url: str, depth: int):
        """解析 HTML 提取信息"""
        soup = BeautifulSoup(html, "html.parser")
        
        # 提取表单
        for form in soup.find_all("form"):
            inputs = []
            for inp in form.find_all("input"):
                inputs.append({
                    "name": inp.get("name", ""),
                    "type": inp.get("type", "text"),
                    "value": inp.get("value", ""),
                })
            action = urljoin(base_url, form.get("action", ""))
            method = form.get("method", "get").upper()
            self.forms.append(Form(action=action, method=method, inputs=inputs))
        
        # 提取 JS 文件
        for script in soup.find_all("script", src=True):
            js_url = urljoin(base_url, script["src"])
            self.js_files.append(js_url)
        
        # 提取链接
        for a in soup.find_all("a", href=True):
            next_url = urljoin(base_url, a["href"])
            if urlparse(next_url).netloc == urlparse(base_url).netloc:
                if next_url not in self.visited and next_url not in [u for u, d in list(self.urls_queue._queue)]:
                    self.urls_queue.put_nowait((next_url, depth + 1))
    

