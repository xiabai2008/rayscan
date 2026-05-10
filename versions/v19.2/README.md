# WVS v19.2 — Web Vulnerability Scanner

> 实用架构派 Web 漏洞扫描器。v19.1 重构底座 + v19.2 集成增强。

## 🎯 v19.2 更新

基于 v19 的模块化架构，堆了五个开源工具集成和一个自研 JS 分析引擎：

| 模块 | 状态 | 说明 |
|------|------|------|
| **JSPathfinder** | ✅ 已接入 | JS 端点发现 + 24 类敏感信息 + 7 类漏洞线索 + 路径 FUZZ |
| **sqlmap** | ✅ 已接入 | SQLi 终极方案，subprocess 调 API 模式 |
| **ffuf** | ✅ 已接入 | 目录/文件爆破，JSON 输出解析 |
| **Wappalyzer** | ✅ 已接入 | 技术栈指纹识别，优先 python-Wappalyzer |
| **Nuclei** | ✅ 已有 | 模板化漏洞扫描（v19 原有） |

### 扫描流程 (v19.2)
```
Phase 1   → 爬虫 (Crawler)
Phase 1.5 → JS 分析 (JSPathfinder) — secrets + endpoints + fuzz
Phase 2   → 检测器并发 (SQLi / XSS / CMDi / LFI / RCE / SSRF / XXE / API / Sensitive / WAF)
Phase 2b  → 外部集成并发 (Wappalyzer + ffuf + sqlmap + Nuclei)
Phase 3   → 去重 + 置信度
Phase 4   → 报告
```

## ✨ 核心特性

### 🛡️ 检测模块（10 个内置）
| 模块 | 检测类型 |
|------|----------|
| sqli | Error-based / Boolean-blind / Time-based / Union |
| xss | Reflected / Stored / DOM-based，7 层置信度 |
| cmdi | Echo 回显 / Time-based / OOB（Interactsh） |
| lfi | 本地文件包含 + 路径穿越 |
| rce | 代码注入 / 反序列化 (PHP/Python/Java) |
| ssrf | 服务端请求伪造 + OOB 验证 |
| xxe | XML 外部实体注入 |
| api | API 安全（JWT / CORS / Auth bypass） |
| sensitive | 敏感信息泄露（Git/SVN/备份/配置/默认凭证） |
| waf | WAF 检测与绕过（Cloudflare/AWS/Azure/ModSecurity 等 15+） |

### 🔌 集成工具（5 个）
| 工具 | 触发策略 | 产出 |
|------|----------|------|
| JSPathfinder | 始终运行 | 密钥/Token/密码、API 端点、漏洞线索 |
| Wappalyzer | 始终运行 | 技术栈指纹 → 推送 WAF 模块 |
| ffuf | 始终运行（工具可用时） | 隐藏目录/文件发现 |
| sqlmap | SQLi 检测器有发现时触发 | 注入点深度验证 |
| Nuclei | 始终运行 | 模板化漏洞扫描 |

### 🏗️ 架构优势
- **模块化设计**：每个检测器独立模块，统一 `DetectionModule` 基类
- **统一数据模型**：`Vulnerability` / `ScanTarget` / `ScanResult` 贯穿全链路
- **并发调度**：asyncio + Semaphore + 模块优先级排序 + 提前退出
- **断点续扫**：Checkpoint 自动保存，超时/崩溃后可续扫
- **实验靶场适配**：`lab_profiles.py` 自动识别 DVWA/Mutillidae/phpMyAdmin 等

## 🚀 快速开始

### 安装
```bash
# 克隆 (实际在本地)
cd wvs-v19.2

# 安装核心依赖
pip install -e .

# 安装集成工具 (可选)
pip install python-Wappalyzer    # Wappalyzer
# sqlmap, ffuf, nuclei 需要单独安装 CLI

# 安装 Playwright (JSPathfinder 浏览器渲染，可选)
pip install playwright && playwright install chromium
```

### 基本使用
```python
from wvs.core.scanner import WAVScanner
from wvs.models import ScanTarget

scanner = WAVScanner()
target = ScanTarget(url="http://example.com")
result = await scanner.scan(target)

for v in result.vulnerabilities:
    print(f"[{v.severity.value}] {v.title}")
```

### 命令行使用
```bash
# 基本扫描
python examples/full_scan.py http://example.com

# 指定模块
python examples/full_scan.py http://example.com --modules sqli,xss

# 输出 JSON
python examples/full_scan.py http://example.com --output report.json
```

## 📁 项目结构

```
wvs-v19.2/
├── wvs/
│   ├── __init__.py              # 版本号 19.2.0
│   ├── config.py                # 统一配置管理
│   ├── models.py                # Vulnerability / ScanTarget / ScanResult
│   ├── constants.py             # 全局常量
│   ├── exceptions.py            # 异常定义
│   ├── core/
│   │   ├── scanner.py           # 主扫描引擎 (Phase 1→4)
│   │   ├── crawler.py           # Web 爬虫 (含参数发现)
│   │   ├── session.py           # HTTP 连接池 (aiohttp)
│   │   └── lab_profiles.py      # 实验靶场配置
│   ├── modules/
│   │   ├── base.py              # DetectionModule 基类
│   │   ├── __init__.py          # 模块注册
│   │   ├── sqli/                # SQL 注入检测
│   │   ├── xss/                 # XSS 检测
│   │   ├── cmdi/                # 命令注入检测
│   │   ├── lfi/                 # 文件包含检测
│   │   ├── rce/                 # 远程代码执行检测
│   │   ├── ssrf/                # SSRF 检测
│   │   ├── xxe/                 # XXE 检测
│   │   ├── api/                 # API 安全检测
│   │   ├── sensitive/           # 敏感信息检测
│   │   ├── waf/                 # WAF 检测与绕过
│   │   └── jspathfinder/        # ☆v19.2 JS 端点发现与敏感信息分析
│   ├── integrations/            # ☆v19.2 外部工具集成
│   │   ├── __init__.py
│   │   ├── sqlmap_integration.py
│   │   ├── ffuf_integration.py
│   │   └── wappalyzer_integration.py
│   ├── plugins/                 # 认证插件
│   └── reporting/               # 报告系统
├── examples/
├── docs/
├── pyproject.toml               # v19.2.0
└── README.md
```

## ⚙️ 配置

```python
# wvs/config.py — DEFAULT_CONFIG 片段
DEFAULT_CONFIG = {
    "timeout": 30,
    "threads": 5,
    "crawl_depth": 4,
    "crawl_max_urls": 300,
    "concurrent_endpoints": 6,
    "enable_waf_detection": True,
    "modules": {
        "sqli": {"enabled": True, "timeout": 30, "threads": 2, ...},
        # ... 其他检测模块
        "jspathfinder": {           # ☆v19.2
            "enabled": True,
            "timeout": 15,
            "threads": 10,
            "custom_params": {"fuzz": True, "use_playwright": False},
        },
    },
    "integrations": {               # ☆v19.2
        "enabled": True,
        "nuclei": {"enabled": True, "timeout": 300, "rate_limit": 20},
        "sqlmap": {"enabled": True, "timeout": 600, "level": 2, "risk": 1},
        "ffuf":   {"enabled": True, "timeout": 120, "rate": 30},
        "wappalyzer": {"enabled": True, "timeout": 30},
    },
}
```

## 🧪 JSPathfinder 规则覆盖

| 类别 | 数量 | 示例 |
|------|------|------|
| 敏感信息正则 | 24 类 | Google API Key / GitHub Token / AWS Key / Stripe / JWT / 身份证 / DB 连接串 |
| 端点提取模式 | 10 组 | `/api/*` / `/v1/*` / `/graphql` / Swagger / WebSocket / `/admin/*` |
| 漏洞关键字 | 7 类 | SQLi / XSS / SSRF / LFI/RFI / RCE / Debug Mode / Source Map |
| 路径 FUZZ | 25+ 条 | `/.git/config` / `/.env` / `/backup/` / `/wp-admin/` / `WEB-INF/web.xml` |
| 已知库过滤 | 10 个 | jQuery / Vue / React / Bootstrap / Angular / Lodash / Moment |

## 🔧 开发

```bash
# 安装开发依赖
pip install -e ".[dev]"

# 运行测试
pytest

# 测试 JSPathfinder 单独
python -c "from wvs.modules.jspathfinder import JSPathfinderDetector; print(JSPathfinderDetector.get_info())"
```

## 📊 v19 vs v19.2

| 维度 | v19 | v19.2 |
|------|-----|-------|
| 检测模块 | 10 个 | 10 个 + 1 个(JSPathfinder) |
| 外部集成 | 1 个(Nuclei) | 5 个(+sqlmap/ffuf/Wappalyzer/JSPathfinder) |
| 扫描阶段 | 4 Phase | 5 Phase(含 Phase 1.5) |
| 敏感信息检测 | sensitive 模块 | + JSPathfinder 24 类 JS 密钥检测 |
| 端点发现 | crawler | + JSPathfinder JS 端点提取 |
| 路径爆破 | ❌ | ✅ ffuf + JSPathfinder FUZZ |

## 📄 许可证

MIT License

---

**注意**：本工具仅用于授权的安全测试。未经授权的使用可能违反法律。
