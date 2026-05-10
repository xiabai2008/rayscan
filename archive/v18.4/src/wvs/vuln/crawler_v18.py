"""WVS v18.0 - 增强型爬虫

修复：
1. 爬取深度不足
2. 认证管理优化
3. URL 去重优化
4. .git/HEAD 误报修复
"""
import asyncio
import re
import hashlib
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from typing import Set, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
import aiohttp
from bs4 import BeautifulSoup

try:
    import aiohttp
except ImportError:
    aiohttp = None


@dataclass
class URLInfo:
    url: str
    method: str = "GET"
    params: Dict = field(default_factory=dict)
    form_data: Dict = field(default_factory=dict)
    headers: Dict = field(default_factory=dict)
    cookies: Dict = field(default_factory=dict)
    content_type: str = ""
    depth: int = 0
    parent: str = ""


@dataclass
class CrawlResult:
    urls: List[URLInfo]
    forms: List[Dict]
    js_files: List[str]
    sensitive_paths: List[str]
    duration: float
    total_requests: int


class CrawlerV18:
    """增强型爬虫 v18.0"""
    
    # 修复：敏感路径检测（排除误报）
    SENSITIVE_PATHS = {
        # 版本控制
        "/.git/config": {"type": "Git配置泄露", "severity": "high"},
        "/.git/HEAD": {"type": "Git HEAD泄露", "severity": "high"},
        "/.svn/entries": {"type": "SVN泄露", "severity": "high"},
        "/.hg/store/data": {"type": "Mercurial泄露", "severity": "high"},
        
        # 配置文件
        "/.env": {"type": "环境变量泄露", "severity": "critical"},
        "/config.php": {"type": "PHP配置泄露", "severity": "high"},
        "/wp-config.php": {"type": "WordPress配置泄露", "severity": "critical"},
        "/database.yml": {"type": "数据库配置泄露", "severity": "critical"},
        
        # 备份文件
        "/backup.sql": {"type": "SQL备份泄露", "severity": "critical"},
        "/backup.zip": {"type": "备份文件泄露", "severity": "high"},
        "/db.sql": {"type": "数据库备份泄露", "severity": "critical"},
        
        # 管理面板
        "/admin": {"type": "管理面板", "severity": "info"},
        "/admin/login": {"type": "管理登录页", "severity": "info"},
        "/phpmyadmin": {"type": "phpMyAdmin", "severity": "medium"},
        "/manager/html": {"type": "Tomcat Manager", "severity": "high"},
        
        # API文档
        "/swagger-ui.html": {"type": "Swagger UI", "severity": "medium"},
        "/api-docs": {"type": "API文档", "severity": "medium"},
        "/graphql": {"type": "GraphQL端点", "severity": "medium"},
    }
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.max_depth = self.config.get("max_depth", 3)  # 修复：默认深度3
        self.max_urls = self.config.get("max_urls", 500)
        self.concurrency = self.config.get("concurrency", 20)
        self.timeout = self.config.get("timeout", 10)
        self.verify_ssl = self.config.get("verify_ssl", False)
        
        # 认证管理
        self.session_cookies: Dict[str, str] = {}
        self.session_headers: Dict[str, str] = {}
        
        # URL 去重
        self.visited_urls: Set[str] = set()
        self.url_hashes: Set[str] = set()
    
    def set_auth(self, cookies: Dict[str, str] = None, headers: Dict[str, str] = None):
        """设置认证信息"""
        if cookies:
            self.session_cookies.update(cookies)
        if headers:
            self.session_headers.update(headers)
    
    def _normalize_url(self, url: str) -> str:
        """规范化 URL（用于去重）"""
        parsed = urlparse(url)
        # 移除 fragment，排序 query 参数
        query = parse_qs(parsed.query)
        sorted_query = urlencode(sorted(query.items()), doseq=True)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{sorted_query}"
    
    def _hash_url(self, url: URLInfo) -> str:
        """计算 URL 哈希（包含方法、参数）"""
        key = f"{url.method}:{url.url}:{sorted(url.params.items())}:{sorted(url.form_data.items())}"
        return hashlib.md5(key.encode()).hexdigest()
    
    def _is_valid_url(self, url: str, base_url: str) -> bool:
        """检查 URL 是否有效"""
        try:
            parsed = urlparse(url)
            base_parsed = urlparse(base_url)
            
            # 同域名检查
            if parsed.netloc != base_parsed.netloc:
                return False
            
            # 过滤静态资源
            static_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.css', '.ico', '.svg', '.woff', '.woff2', '.ttf', '.eot']
            if any(parsed.path.lower().endswith(ext) for ext in static_extensions):
                return False
            
            return True
        except:
            return False
    
    async def crawl(self, start_url: str) -> CrawlResult:
        """爬取网站"""
        import time
        start_time = time.time()
        
        all_urls: List[URLInfo] = []
        all_forms: List[Dict] = []
        all_js_files: Set[str] = set()
        sensitive_found: List[str] = []
        total_requests = 0
        
        # 初始化队列
        queue = asyncio.Queue()
        await queue.put(URLInfo(url=start_url, depth=0))
        
        connector = aiohttp.TCPConnector(ssl=self.verify_ssl, limit=self.concurrency)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            semaphore = asyncio.Semaphore(self.concurrency)
            
            async def process_url(url_info: URLInfo):
                nonlocal total_requests
                
                if len(self.visited_urls) >= self.max_urls:
                    return
                
                normalized = self._normalize_url(url_info.url)
                if normalized in self.visited_urls:
                    return
                
                self.visited_urls.add(normalized)
                total_requests += 1
                
                try:
                    async with semaphore:
                        # 合并认证信息
                        cookies = {**self.session_cookies, **url_info.cookies}
                        headers = {
                            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                            **self.session_headers,
                            **url_info.headers
                        }
                        
                        if url_info.method == "GET":
                            async with session.get(url_info.url, cookies=cookies, headers=headers) as resp:
                                content = await resp.text()
                                status = resp.status
                        else:
                            async with session.request(
                                url_info.method,
                                url_info.url,
                                data=url_info.form_data,
                                cookies=cookies,
                                headers=headers
                            ) as resp:
                                content = await resp.text()
                                status = resp.status
                        
                        if status == 200:
                            all_urls.append(url_info)
                            
                            # 解析 HTML
                            soup = BeautifulSoup(content, 'lxml')
                            
                            # 提取链接
                            if url_info.depth < self.max_depth:
                                for link in soup.find_all('a', href=True):
                                    href = link['href']
                                    full_url = urljoin(url_info.url, href)
                                    
                                    if self._is_valid_url(full_url, start_url):
                                        # 提取 URL 参数
                                        parsed = urlparse(full_url)
                                        params = parse_qs(parsed.query)
                                        params = {k: v[0] if len(v) == 1 else v for k, v in params.items()}
                                        
                                        new_url = URLInfo(
                                            url=parsed._replace(query="").geturl(),
                                            params=params,
                                            depth=url_info.depth + 1,
                                            parent=url_info.url
                                        )
                                        
                                        url_hash = self._hash_url(new_url)
                                        if url_hash not in self.url_hashes:
                                            self.url_hashes.add(url_hash)
                                            await queue.put(new_url)
                            
                            # 提取表单
                            for form in soup.find_all('form'):
                                action = form.get('action', '')
                                method = form.get('method', 'GET').upper()
                                inputs = {}
                                
                                for input_tag in form.find_all(['input', 'textarea', 'select']):
                                    name = input_tag.get('name')
                                    if name:
                                        inputs[name] = input_tag.get('value', '')
                                
                                form_url = urljoin(url_info.url, action)
                                all_forms.append({
                                    "url": form_url,
                                    "method": method,
                                    "inputs": inputs,
                                    "parent": url_info.url
                                })
                            
                            # 提取 JS 文件
                            for script in soup.find_all('script', src=True):
                                js_url = urljoin(url_info.url, script['src'])
                                all_js_files.add(js_url)
                
                except Exception as e:
                    pass
            
            # 并发爬取
            tasks = []
            while True:
                try:
                    url_info = queue.get_nowait()
                    tasks.append(process_url(url_info))
                    
                    if len(tasks) >= self.concurrency:
                        await asyncio.gather(*tasks)
                        tasks = []
                
                except asyncio.QueueEmpty:
                    if tasks:
                        await asyncio.gather(*tasks)
                    break
            
            # 检测敏感路径（修复误报）
            sensitive_tasks = []
            for path, info in self.SENSITIVE_PATHS.items():
                test_url = urljoin(start_url, path)
                async def check_sensitive(url, path_info):
                    try:
                        async with session.get(url, headers={"User-Agent": "Mozilla/5.0"}) as resp:
                            if resp.status == 200:
                                content = await resp.text()
                                # 验证内容有效性（排除误报）
                                if len(content) > 50 and not content.startswith("<!DOCTYPE"):
                                    sensitive_found.append({
                                        "url": url,
                                        **path_info
                                    })
                    except:
                        pass
                
                sensitive_tasks.append(check_sensitive(test_url, info))
            
            await asyncio.gather(*sensitive_tasks)
        
        duration = time.time() - start_time
        
        return CrawlResult(
            urls=all_urls,
            forms=all_forms,
            js_files=list(all_js_files),
            sensitive_paths=sensitive_found,
            duration=duration,
            total_requests=total_requests + len(sensitive_found)
        )
    
    def reset(self):
        """重置爬虫状态"""
        self.visited_urls.clear()
        self.url_hashes.clear()
        self.session_cookies.clear()
        self.session_headers.clear()
    
    @staticmethod
    def extract_url_patterns(html: str, base_url: str) -> List[URLInfo]:
        """从 HTML/JavaScript 中提取 URL 模式（静态分析）"""
        patterns = []
        
        # 1. 提取所有 href/src/action
        import re
        urls = set()
        urls.update(re.findall(r'href=["\x27]([^"\x27>\s]+)["\x27]', html))
        urls.update(re.findall(r'src=["\x27]([^"\x27>\s]+)["\x27]', html))
        urls.update(re.findall(r'action=["\x27]([^"\x27>\s]+)["\x27]', html))
        
        # 2. 提取 JavaScript 中的 URL
        urls.update(re.findall(r'location\.href\s*=\s*["\x27]([^"\x27]+)["\x27]', html))
        urls.update(re.findall(r'window\.location\s*=\s*["\x27]([^"\x27]+)["\x27]', html))
        urls.update(re.findall(r'["\x27]([^"\x27]*\.php[^"\x27]*)["\x27]', html))
        
        # 3. 提取 URL 模式 (path?param=...)
        url_pattern = re.compile(r'["\x27]([/\w\-\.]+\?\w+=)["\x27]')
        urls.update(url_pattern.findall(html))
        
        for url in urls:
            if url.startswith("#") or url.startswith("javascript:") or url.startswith("mailto:"):
                continue
            if url.startswith("/"):
                full_url = urljoin(base_url, url)
            elif url.startswith("http"):
                full_url = url
            else:
                full_url = urljoin(base_url + "/", url)
            
            parsed = urlparse(full_url)
            params = parse_qs(parsed.query)
            params = {k: v[0] if len(v) == 1 else v for k, v in params.items()}
            
            patterns.append(URLInfo(
                url=parsed._replace(query="").geturl(),
                params=params,
                depth=0
            ))
        
        return patterns
    
    @staticmethod
    def get_common_params() -> List[str]:
        """常见漏洞参数名"""
        return [
            "id", "file", "page", "path", "template", "include",
            "doc", "document", "folder", "root", "pg", "style",
            "pdf", "data", "code", "type", "action", "name",
            "user", "username", "pass", "password", "email",
            "search", "query", "q", "url", "link", "src",
            "dest", "redirect", "return", "next", "target",
        ]
