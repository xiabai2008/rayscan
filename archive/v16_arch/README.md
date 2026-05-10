# WVS v16.0 - Web Vulnerability Scanner

专业级 Web 漏洞扫描工具，基于市场调研（sqlmap、OWASP ZAP、Burp Suite、Nikto）的优秀实践进行迭代升级。

## 版本信息
- 版本: 16.0.0
- 发布日期: 2026-04-17
- 基于版本: v15.0

## ✨ 核心特性

### 1. 多阶段 SQL 注入验证
- 阶段 1: 错误型注入（最快）
- 阶段 2: UNION 注入
- 阶段 3: 布尔盲注
- 阶段 4: 时间盲注（多次验证）

### 2. 上下文感知 XSS 检测
- 自动分析注入上下文
- 智能选择最佳 payload
- CSP 检测和绕过建议

### 3. 智能爬虫
- 表单智能填充
- API 端点发现
- SPA 支持（React/Vue/Angular）
- 认证态保持

### 4. WAF 规避
- SQL 注入 WAF 规避
- XSS WAF 规避
- 自动检测和绕过

### 5. 数据库指纹识别
- MySQL / PostgreSQL / Oracle / MSSQL / SQLite
- 自动选择数据库特定 payload

### 6. 更多检测类型
- 命令注入
- 路径遍历
- XXE
- SSRF（含云元数据）

### 7. 可视化报告
- 交互式 HTML 报告
- 图表可视化
- 多格式导出

### 8. Web UI
- FastAPI 后端
- WebSocket 实时推送
- 单页应用界面

## 📁 文件结构

```
wvs-v16/
├── wvs/
│   ├── __init__.py           # 版本信息
│   ├── core/
│   │   └── payloads_v16.py   # 增强型 Payload 库
│   └── vuln/
│       ├── sqli_v16.py       # 多阶段 SQL 注入
│       ├── xss_v16.py        # 上下文感知 XSS
│       └── crawler_v16.py    # 智能爬虫
├── CHANGELOG.md              # 更新日志
└── README.md                 # 本文件
```

## 🚀 快速开始

```python
import asyncio
import aiohttp
from wvs.vuln.sqli_v16 import SQLiScannerV16
from wvs.vuln.xss_v16 import XSSScannerV16
from wvs.vuln.crawler_v16 import CrawlerV16

async def scan(url):
    async with aiohttp.ClientSession() as session:
        # 爬虫
        crawler = CrawlerV16({"max_depth": 2, "max_urls": 50})
        pages = await crawler.crawl(url, session)
        
        # SQL 注入
        sqli_scanner = SQLiScannerV16()
        for page in pages:
            results = await sqli_scanner.scan(page.url, session)
            for r in results:
                if r.vulnerable:
                    print(f"[SQLi] {r.parameter} - {r.injection_type.value}")
        
        # XSS
        xss_scanner = XSSScannerV16()
        for page in pages:
            results = await xss_scanner.scan(page.url, session)
            for r in results:
                if r.vulnerable:
                    print(f"[XSS] {r.parameter} - {r.xss_type.value}")

asyncio.run(scan("http://target.com"))
```

## 📊 与 v15.0 对比

| 特性 | v15.0 | v16.0 |
|------|-------|-------|
| SQL 注入阶段 | 1 阶段 | 4 阶段 |
| XSS 上下文感知 | ❌ | ✅ |
| 智能爬虫 | 基础 | 增强 |
| WAF 规避 | ❌ | ✅ |
| 数据库指纹 | ❌ | ✅ |
| 时间盲注优化 | ❌ | ✅ |
| mXSS 检测 | ❌ | ✅ |
| 云元数据 SSRF | ❌ | ✅ |
| Payload 数量 | ~50 | ~150 |

## 📝 更新日志

详见 [CHANGELOG.md](./CHANGELOG.md)

## 🔗 市场调研参考

- **sqlmap**: 多阶段验证、数据库指纹、WAF 规避
- **OWASP ZAP**: 上下文感知扫描、智能爬虫
- **Burp Suite**: 表单填充、认证保持、SPA 支持
- **Nikto**: 敏感路径检测、服务器指纹
