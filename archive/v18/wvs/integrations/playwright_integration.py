"""WVS v18.0 - Playwright 集成模块

提供 JavaScript 渲染支持，用于爬取 SPA 应用和检测 DOM XSS。
需要安装: pip install playwright
"""
import os
import asyncio
import re
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from pathlib import Path

try:
    from playwright.async_api import async_playwright, Page, Browser, BrowserContext
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


@dataclass
class DiscoveredURL:
    url: str
    method: str = "GET"
    params: Dict = None
    forms: List[Dict] = None
    title: str = ""
    rendered: bool = True


@dataclass
class DOMXSSVulnerability:
    url: str
    source: str  # document.URL, location.hash, etc.
    sink: str  # eval, innerHTML, etc.
    payload: str
    severity: str = "high"


class PlaywrightIntegration:
    """Playwright 集成器 - JS 渲染和 DOM XSS 检测"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.browser = None
        self.context = None
        
        # 配置
        self.timeout = self.config.get("timeout", 30000)  # 页面超时
        self.wait_until = self.config.get("wait_until", "networkidle")  # 等待策略
        self.max_depth = self.config.get("max_depth", 2)  # 爬取深度
        self.max_urls = self.config.get("max_urls", 100)  # 最大 URL 数
        
        # DOM XSS 检测配置
        self.dom_xss_enabled = self.config.get("dom_xss", True)
        
        # 已知 sinks（危险函数）
        self.sinks = [
            "innerHTML", "outerHTML", "insertAdjacentHTML",
            "document.write", "document.writeln",
            "eval", "Function", "setTimeout", "setInterval",
            "execScript", "msWriteProfilerMark",
            "location.href", "location.assign", "location.replace",
            "expr", "globalExpr", "crypto.generateCRMFRequest"
        ]
        
        # 已知 sources（用户输入源）
        self.sources = [
            "location.hash", "location.href", "location.search",
            "location.pathname",
            "document.URL", "document.documentURI", "document.URLUnencoded",
            "document.referrer", "document.baseURI",
            "window.name", "history.pushState", "history.replaceState"
        ]
    
    async def init(self):
        """初始化浏览器"""
        if not PLAYWRIGHT_AVAILABLE:
            print("[!] Playwright not installed. Run: pip install playwright && python -m playwright install chromium")
            return False
        
        self.playwright = await async_playwright().start()
        
        # 尝试启动 Chromium
        try:
            # 使用系统 Chrome
            chrome_path = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
            if os.path.exists(chrome_path):
                self.browser = await self.playwright.chromium.launch(
                    headless=True,
                    executable_path=chrome_path,
                    args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-gpu", 
                          "--disable-software-rasterizer", "--disable-dev-shm-usage"]
                )
            else:
                # 尝试 Playwright 自带浏览器
                self.browser = await self.playwright.chromium.launch(
                    headless=True,
                    args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-gpu"]
                )
            self.context = await self.browser.new_context(
                viewport={"width": 1920, "height": 1080},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            )
            return True
        except Exception as e:
            print(f"[!] Failed to launch browser: {e}")
            await self.playwright.stop()
            return False
    
    async def close(self):
        """关闭浏览器"""
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
    
    async def crawl(self, url: str) -> List[DiscoveredURL]:
        """
        使用 Playwright 爬取网站（支持 JS 渲染）
        
        Args:
            url: 起始 URL
            
        Returns:
            发现的 URL 列表
        """
        discovered: List[DiscoveredURL] = []
        
        if not await self.init():
            print("[!] Browser init failed")
            return discovered
        
        try:
            page = await self.context.new_page()
            
            # 设置超时
            page.set_default_timeout(15000)
            
            print(f"[*] Navigating to {url}...")
            
            # 导航到首页
            response = await page.goto(
                url,
                timeout=20000,
                wait_until="domcontentloaded"
            )
            
            if response and response.status == 200:
                # 等待一小段时间让 JS 执行
                await asyncio.sleep(1)
                
                title = await page.title()
                print(f"[*] Page title: {title}")
                
                # 获取页面内容
                content = await page.content()
                print(f"[*] Page content length: {len(content)}")
                
                # 提取链接
                links = await page.eval_on_selector_all(
                    "a[href]",
                    "elements => elements.map(e => e.href)"
                )
                
                discovered_urls = [url]
                for link in links:
                    if link.startswith("http") and len(discovered_urls) < self.max_urls:
                        discovered_urls.append(link)
                
                print(f"[*] Found {len(discovered_urls)} URLs")
                
                # 添加到结果
                for discovered_url in discovered_urls:
                    discovered.append(DiscoveredURL(
                        url=discovered_url,
                        params={},
                        forms=[],
                        title=title,
                        rendered=True
                    ))
            
            await page.close()
            
        except Exception as e:
            print(f"[!] Error crawling {url}: {e}")
            import traceback
            traceback.print_exc()
        finally:
            await self.close()
        
        return discovered
    
    async def _extract_links(self, page: Page, base_url: str) -> List[str]:
        """提取页面中的链接"""
        links = []
        
        try:
            # 使用 JavaScript 提取所有链接
            hrefs = await page.eval_on_selector_all(
                "a[href]",
                "elements => elements.map(e => e.href)"
            )
            
            for href in hrefs:
                if href and href.startswith("http"):
                    links.append(href)
            
            # 也检查 JavaScript 动态生成的链接
            js_links = await page.evaluate("""
                () => {
                    const links = [];
                    // 检查 location 和 history
                    const loc = window.location;
                    // 检查常见的 JS 框架路由
                    document.querySelectorAll('[data-href], [data-link], [onclick*="location"]').forEach(el => {
                        const href = el.dataset.href || el.dataset.link || '';
                        if (href) links.push(href);
                    });
                    return [...new Set(links)];
                }
            """)
            
            links.extend(js_links)
            links = list(set(links))
            
        except Exception as e:
            print(f"[!] Link extraction error: {e}")
        
        return links
    
    async def _extract_forms(self, page: Page) -> List[Dict]:
        """提取页面中的表单"""
        forms = []
        
        try:
            forms_data = await page.evaluate("""
                () => {
                    const forms = [];
                    document.querySelectorAll('form').forEach(form => {
                        const inputs = {};
                        form.querySelectorAll('input, textarea, select').forEach(input => {
                            inputs[input.name || input.id || 'unknown'] = {
                                type: input.type || 'text',
                                value: input.value || '',
                                required: input.required || false
                            };
                        });
                        forms.push({
                            action: form.action || window.location.href,
                            method: form.method || 'GET',
                            inputs: inputs
                        });
                    });
                    return forms;
                }
            """)
            
            forms = forms_data
            
        except Exception as e:
            print(f"[!] Form extraction error: {e}")
        
        return forms
    
    async def test_dom_xss(self, url: str) -> List[DOMXSSVulnerability]:
        """
        测试 DOM XSS 漏洞
        
        Args:
            url: 目标 URL
            
        Returns:
            发现的 DOM XSS 漏洞
        """
        vulns = []
        
        if not await self.init():
            return vulns
        
        # DOM XSS 测试 payloads
        dom_xss_payloads = [
            ("#<script>alert(1)</script>", "location.hash", "innerHTML"),
            ("#<img src=x onerror=alert(1)>", "location.hash", "innerHTML"),
            ("#<svg onload=alert(1)>", "location.hash", "innerHTML"),
            ("#'><script>alert(1)</script>", "location.hash", "innerHTML"),
            ("#javascript:alert(1)", "location.hash", "eval"),
            ("?q=<script>alert(1)</script>", "location.search", "innerHTML"),
            ("?q=<img src=x onerror=alert(1)>", "location.search", "innerHTML"),
        ]
        
        try:
            page = await self.context.new_page()
            
            for payload, source, sink in dom_xss_payloads:
                test_url = url + payload
                
                try:
                    # 导航到测试 URL
                    response = await page.goto(
                        test_url,
                        timeout=self.timeout,
                        wait_until="domcontentloaded"
                    )
                    
                    # 等待一小段时间让 JS 执行
                    await asyncio.sleep(0.5)
                    
                    # 检查是否触发了警告
                    dialog_caught = []
                    
                    def handle_dialog(dialog):
                        dialog_caught.append(dialog.message)
                        asyncio.create_task(dialog.dismiss())
                    
                    page.on("dialog", handle_dialog)
                    
                    # 检查页面是否包含注入的内容
                    content = await page.content()
                    
                    if "<script>alert(1)</script>" in content or "alert(1)" in content:
                        # 进一步验证
                        alert_triggered = await page.evaluate("""
                            () => {
                                // 检查是否有未转义的脚本标签
                                return document.body.innerHTML.includes('<script>alert(1)</script>') ||
                                       window.alertCalled ||
                                       false;
                            }
                        """)
                        
                        if alert_triggered:
                            vulns.append(DOMXSSVulnerability(
                                url=test_url,
                                source=source,
                                sink=sink,
                                payload=payload,
                                severity="high"
                            ))
                    
                    # 检查 event handler 是否被触发
                    if "onerror=alert(1)" in content or "onload=alert(1)" in content:
                        vulns.append(DOMXSSVulnerability(
                            url=test_url,
                            source=source,
                            sink=sink,
                            payload=payload,
                            severity="high"
                        ))
                
                except Exception as e:
                    continue
            
            await page.close()
            
        finally:
            await self.close()
        
        return vulns
    
    async def screenshot(self, url: str, output_path: str = None) -> Optional[str]:
        """
        截图
        
        Args:
            url: 目标 URL
            output_path: 输出路径
            
        Returns:
            截图文件路径
        """
        if not await self.init():
            return None
        
        if not output_path:
            output_path = f"screenshots/screenshot_{hash(url)}.png"
        
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        
        try:
            page = await self.context.new_page()
            await page.goto(url, timeout=self.timeout, wait_until=self.wait_until)
            await page.screenshot(path=output_path, full_page=True)
            await page.close()
            return output_path
            
        except Exception as e:
            print(f"[!] Screenshot error: {e}")
            return None
        finally:
            await self.close()
    
    def _normalize_url(self, url: str) -> str:
        """规范化 URL"""
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(url)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))


class EnhancedCrawlerWithJS:
    """增强型爬虫 - 支持 JS 渲染"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.playwright = PlaywrightIntegration(config)
        self.traditional_crawler = None  # 备用传统爬虫
    
    async def crawl(self, url: str) -> List[DiscoveredURL]:
        """爬取网站，优先使用 Playwright"""
        
        # 尝试 Playwright
        if PLAYWRIGHT_AVAILABLE:
            print(f"[*] Using Playwright to crawl: {url}")
            return await self.playwright.crawl(url)
        
        # 回退到传统爬虫
        print(f"[*] Playwright not available, using traditional crawler")
        from wvs.vuln.scanner_v18 import EnhancedCrawler
        
        crawler = EnhancedCrawler(self.config)
        result = await crawler.crawl(url)
        
        return [
            DiscoveredURL(
                url=u.url,
                params=u.params,
                forms=[],
                title="",
                rendered=False
            )
            for u in result.urls
        ]


# 便捷函数
async def crawl_with_js(url: str, config: Dict = None) -> List[DiscoveredURL]:
    """使用 Playwright 爬取"""
    crawler = EnhancedCrawlerWithJS(config)
    return await crawler.crawl(url)


async def test_dom_xss_async(url: str) -> List[DOMXSSVulnerability]:
    """测试 DOM XSS"""
    playwright = PlaywrightIntegration()
    return await playwright.test_dom_xss(url)


def test_dom_xss(url: str) -> List[Dict]:
    """同步测试 DOM XSS"""
    return asyncio.run(test_dom_xss_async(url))
