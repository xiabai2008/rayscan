"""测试 Playwright DOM XSS"""
import sys
sys.path.insert(0, r"C:\Users\HZR\.qclaw\workspace-agent-b7ed571b\wvs-v18")

import asyncio
from wvs.integrations.playwright_integration import PlaywrightIntegration

async def test():
    print("Testing Playwright with system Chrome...")
    
    pw = PlaywrightIntegration()
    
    # 测试 JS 渲染爬取
    print("\n[*] Testing JS rendering crawl...")
    urls = await pw.crawl("https://example.com")
    print(f"    Found {len(urls)} URLs")
    for u in urls:
        print(f"      - {u.url} (rendered: {u.rendered})")
    
    # 测试 DOM XSS
    print("\n[*] Testing DOM XSS detection...")
    vulns = await pw.test_dom_xss("https://example.com")
    print(f"    Found {len(vulns)} DOM XSS vulnerabilities")
    
    # 测试截图
    print("\n[*] Testing screenshot...")
    import os
    import asyncio
    screenshot_path = "test_screenshot.png"
    path = await pw.screenshot("https://example.com", screenshot_path)
    if path and os.path.exists(path):
        size = os.path.getsize(path)
        print(f"    Screenshot saved: {path} ({size/1024:.1f} KB)")
    else:
        print(f"    Screenshot failed")
    
    print("\n[+] Playwright test complete!")

try:
    asyncio.run(test())
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
