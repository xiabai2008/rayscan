"""WVS v16.0 - 增强型爬虫

改进点：
1. 智能表单识别和填充
2. JavaScript 渲染支持（可选）
3. 单页应用（SPA）爬取
4. API 端点自动发现
5. 认证态保持
"""
import asyncio
import re
from typing import List, Dict, Set, Optional
from urllib.parse import urljoin, urlparse, urldefrag
from dataclasses import dataclass
import json

try:
    import aiohttp
    from bs4 import BeautifulSoup
except ImportError:
    aiohttp = None
    BeautifulSoup = None


@dataclass
class CrawledPage:
    url: str
    depth: int
    content: str
    status_code: int
    content_type: str
    forms: List[Dict]
    links: List[str]
    scripts: List[str]
    api_endpoints: List[str]
    is_spam_page: bool = False


@dataclass
class FormInfo:
    action: str
    method: str
    inputs: List[Dict]
    enctype: str
    has_csrf: bool
    has_file_upload: bool


class CrawlerV16:
    """爬虫 v16.0 - 智能爬取 + API 发现"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.max_depth = self.config.get("max_depth", 3)
        self.max_urls = self.config.get("max_urls", 100)
        self.timeout = self.config.get("timeout", 10.0)
        self.concurrency = self.config.get("concurrency", 10)
        
        # 已访问 URL
        self.visited: Set[str] = set()
        self.to_visit: List[tuple] = []  # (url, depth)
        
        # 发现的资源
        self.pages: List[CrawledPage] = []
        self.forms: List[FormInfo] = []
        self.api_endpoints: Set[str] = set()
        
        # 认证
        self.auth_cookies = None
        self.auth_headers = None
        
        # SPA 检测
        self.is_spa = False
        self.framework = None
    
    async def crawl(self, start_url: str, session) -> List[CrawledPage]:
        """执行爬取"""
        self.to_visit = [(start_url, 0)]
        
        semaphore = asyncio.Semaphore(self.concurrency)
        
        while self.to_visit and len(self.visited) < self.max_urls:
            url, depth = self.to_visit.pop(0)
            
            if url in self.visited:
                continue
            
            if depth > self.max_depth:
                continue
            
            self.visited.add(url)
            
            async with semaphore:
                page = await self._crawl_page(url, depth, session)
                if page:
                    self.pages.append(page)
                    
                    # 发现新链接
                    if depth < self.max_depth:
                        for link in page.links:
                            if link not in self.visited:
                                self.to_visit.append((link, depth + 1))
        
        return self.pages
    
    async def _crawl_page(self, url: str, depth: int, session) -> Optional[CrawledPage]:
        """爬取单个页面"""
        try:
            headers = self.auth_headers or {}
            
            async with session.get(url, timeout=self.timeout, headers=headers, ssl=False) as resp:
                content_type = resp.headers.get("Content-Type", "")
                
                # 只处理 HTML
                if "text/html" not in content_type:
                    # 检测 API 端点
                    if "application/json" in content_type:
                        self.api_endpoints.add(url)
                    return None
                
                text = await resp.text()
                
                # 检测 SPA
                if depth == 0:
                    self._detect_spa(text)
                
                # 解析页面
                soup = BeautifulSoup(text, "lxml")
                
                # 提取链接
                links = self._extract_links(url, soup)
                
                # 提取表单
                forms = self._extract_forms(url, soup)
                
                # 提取脚本
                scripts = self._extract_scripts(url, soup)
                
                # 发现 API 端点
                api_endpoints = self._discover_api_endpoints(url, text, scripts)
                
                # 检测垃圾页面
                is_spam = self._detect_spam_page(text)
                
                return CrawledPage(
                    url=url,
                    depth=depth,
                    content=text,
                    status_code=resp.status,
                    content_type=content_type,
                    forms=forms,
                    links=links,
                    scripts=scripts,
                    api_endpoints=api_endpoints,
                    is_spam_page=is_spam,
                )
        except Exception as e:
            return None
    
    def _extract_links(self, base_url: str, soup) -> List[str]:
        """提取链接"""
        links = []
        
        for tag in soup.find_all(["a", "link", "area"]):
            href = tag.get("href")
            if href and not href.startswith(("#", "javascript:", "mailto:", "tel:")):
                full_url = urljoin(base_url, href)
                # 去除 fragment
                full_url, _ = urldefrag(full_url)
                # 只保留同源链接（可选）
                if self._is_same_domain(base_url, full_url):
                    links.append(full_url)
        
        return list(set(links))
    
    def _extract_forms(self, base_url: str, soup) -> List[Dict]:
        """提取表单"""
        forms = []
        
        for form in soup.find_all("form"):
            action = form.get("action", "")
            if action:
                action = urljoin(base_url, action)
            else:
                action = base_url
            
            method = form.get("method", "GET").upper()
            enctype = form.get("enctype", "application/x-www-form-urlencoded")
            
            inputs = []
            has_file = False
            has_csrf = False
            
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                
                inp_type = inp.get("type", "text")
                value = inp.get("value", "")
                
                inputs.append({
                    "name": name,
                    "type": inp_type,
                    "value": value,
                })
                
                if inp_type == "file":
                    has_file = True
                
                # 检测 CSRF token
                if any(csrf in name.lower() for csrf in ["csrf", "token", "_token", "authenticity_token"]):
                    has_csrf = True
            
            # 智能填充表单
            filled_data = self._smart_fill_form(inputs)
            
            forms.append({
                "action": action,
                "method": method,
                "enctype": enctype,
                "inputs": inputs,
                "has_csrf": has_csrf,
                "has_file_upload": has_file,
                "test_data": filled_data,
            })
        
        return forms
    
    def _smart_fill_form(self, inputs: List[Dict]) -> Dict[str, str]:
        """智能填充表单"""
        data = {}
        
        for inp in inputs:
            name = inp["name"]
            inp_type = inp["type"]
            
            # 根据字段名推断值
            name_lower = name.lower()
            
            if inp_type == "email" or "email" in name_lower:
                data[name] = "test@example.com"
            elif inp_type == "password" or "pass" in name_lower:
                data[name] = "test123"
            elif inp_type == "number" or "age" in name_lower:
                data[name] = "25"
            elif inp_type == "tel" or "phone" in name_lower:
                data[name] = "13800138000"
            elif inp_type == "url" or "url" in name_lower or "website" in name_lower:
                data[name] = "http://example.com"
            elif inp_type == "date":
                data[name] = "2026-01-01"
            elif inp_type == "file":
                data[name] = "test.txt"  # 文件名
            elif inp_type in ["checkbox", "radio"]:
                data[name] = "1"
            elif inp_type == "hidden":
                data[name] = inp.get("value", "")
            else:
                # 默认填充
                data[name] = "test"
        
        return data
    
    def _extract_scripts(self, base_url: str, soup) -> List[str]:
        """提取脚本"""
        scripts = []
        
        for script in soup.find_all("script"):
            src = script.get("src")
            if src:
                scripts.append(urljoin(base_url, src))
        
        return scripts
    
    def _discover_api_endpoints(self, url: str, text: str, scripts: List[str]) -> List[str]:
        """发现 API 端点"""
        endpoints = set()
        
        # 从 HTML 内容中提取
        api_patterns = [
            r'["\']/(api|v\d|graphql)["\']',
            r'["\']https?://[^"\']+/api/[^"\']+["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.[a-z]+\(["\']([^"\']+)["\']',
            r'\$\.ajax\([^)]*url:\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in api_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                full_url = urljoin(url, match)
                endpoints.add(full_url)
        
        # 从脚本 URL 推断
        for script in scripts:
            if "/api/" in script:
                endpoints.add(script)
        
        return list(endpoints)
    
    def _detect_spa(self, text: str):
        """检测单页应用"""
        # React
        if "react" in text.lower() or "__NEXT_DATA__" in text:
            self.is_spa = True
            self.framework = "react"
        
        # Vue
        if "vue" in text.lower() or "__NUXT__" in text:
            self.is_spa = True
            self.framework = "vue"
        
        # Angular
        if "ng-version" in text.lower() or "angular" in text.lower():
            self.is_spa = True
            self.framework = "angular"
    
    def _detect_spam_page(self, text: str) -> bool:
        """检测垃圾页面（登录页、错误页等）"""
        spam_indicators = [
            "login",
            "sign in",
            "404",
            "not found",
            "error",
            "forbidden",
            "access denied",
        ]
        
        text_lower = text.lower()
        count = sum(1 for ind in spam_indicators if ind in text_lower)
        
        return count >= 3
    
    def _is_same_domain(self, url1: str, url2: str) -> bool:
        """检查是否同域"""
        try:
            return urlparse(url1).netloc == urlparse(url2).netloc
        except:
            return False
    
    def set_auth(self, cookies: Dict = None, headers: Dict = None):
        """设置认证信息"""
        self.auth_cookies = cookies
        self.auth_headers = headers
    
    def get_all_urls(self) -> List[str]:
        """获取所有爬取的 URL"""
        return [page.url for page in self.pages]
    
    def get_all_forms(self) -> List[Dict]:
        """获取所有表单"""
        all_forms = []
        for page in self.pages:
            all_forms.extend(page.forms)
        return all_forms
    
    def get_api_endpoints(self) -> List[str]:
        """获取所有 API 端点"""
        return list(self.api_endpoints)


# 认证保持
class AuthKeeper:
    """认证态保持器"""
    
    def __init__(self, session):
        self.session = session
        self.cookies = {}
        self.headers = {}
    
    async def login(self, login_url: str, credentials: Dict, method: str = "POST"):
        """执行登录"""
        try:
            if method.upper() == "POST":
                async with self.session.post(login_url, data=credentials, ssl=False) as resp:
                    self.cookies = {c.key: c.value for c in self.session.cookie_jar}
                    return resp.status == 200
            else:
                async with self.session.get(login_url, params=credentials, ssl=False) as resp:
                    self.cookies = {c.key: c.value for c in self.session.cookie_jar}
                    return resp.status == 200
        except Exception:
            return False
    
    def get_auth_headers(self) -> Dict:
        """获取认证头"""
        return self.headers
    
    def get_cookies(self) -> Dict:
        """获取 cookies"""
        return self.cookies
