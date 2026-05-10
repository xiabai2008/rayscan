# RayScan 1.0 🚀

> **前身：WVS v19.2** | 一个功能强大的 Web 漏洞扫描器
>
> *RayScan 是 WVS 系列正式开源后的新名字，致敬过去 19 个版本的迭代积累。*

## 📋 功能特性

- **SQL 注入检测** — error-based / union / boolean-blind / time-based / stacked
- **XSS 检测** — 反射型 / 存储型 / DOM 型
- **命令注入 (CMDi) 检测**
- **文件包含 (LFI) 检测**
- **SSRF / XXE 检测**
- **RCE 检测**
- **敏感信息泄露检测**
- **WAF 检测与绕过**
- **API 安全扫描**
- **JSPathFinder** — JavaScript 端点发现
- **第三方工具集成**（Nuclei, sqlmap, ffuf, Wappalyzer）
- **多种报告格式**（HTML, JSON, CSV, Markdown, Console）

## 🚀 快速开始

### 1. 环境准备

```bash
# Python 3.8+ 安装依赖
pip install -r requirements-dev.txt
```

### 2. 快速扫描

```bash
# 最简单的用法 —— 给个URL就行
python quick_scan.py -u http://example.com
```

### 3. 全量扫描

```bash
# 深度爬取 + 全部检测模块 + 外部集成
python full_scan.py -u http://example.com --profile full
```

### 4. GUI 界面

```bash
# 带图形界面的交互式扫描
python wvs_gui.py
```

### 5. 特定模块扫描

```bash
# 配置文件修改：在 quick_scan.py 或 full_scan.py 中的
# config.set("crawl_depth", 2) 等参数可按需调整
```

## 📖 详细使用说明

### 🎯 快速扫描 (`quick_scan.py`)

适合快速摸清目标安全状况。

| 参数 | 说明 | 默认值 |
|------|------|:-----:|
| `-u / --url` | 目标URL | 必填 |
| 爬取深度 | 页面层级 | 2 层 |
| 爬取上限 | 最大URL数 | 25 |
| 超时 | 请求超时(s) | 15s |
| 重试 | 失败重试次数 | 0次 |

**输出：** 控制台打印漏洞列表 + JSON 报告文件

---

### 🌊 全量扫描 (`full_scan.py`)

适合深度安全审计。

| 参数 | 说明 | 默认值 |
|------|------|:-----:|
| 爬取深度 | 页面层级 | 3 层 |
| 爬取上限 | 最大URL数 | 500 |
| 并发端点 | 同时检测数 | 12 |
| 模块 | 全部检测模块 | 全部启用 |
| 报告格式 | 输出格式 | JSON / 控制台 |

**输出：** 详细的漏洞清单，包含类型、严重等级、URL、置信度

---

### 🖥️ GUI 模式 (`wvs_gui.py`)

适合不想敲命令的用户，图形化操作。

---

### 📁 扫描报告

扫描完成后，结果保存在 `scan_reports/` 目录，格式为 JSON。

查看历史报告：
```bash
# scan_reports/ 目录下存放了之前的扫描记录
ls scan_reports/
```

---

### 🛠️ 配置说明

核心配置在 `wvs/config.py` 中，常用可调参数：

```python
config.set("crawl_depth", 2)           # 爬取深度
config.set("crawl_max_urls", 100)       # 最大爬取URL数
config.set("concurrent_endpoints", 10)  # 并发检测数
config.set("timeout", 15)              # 请求超时(s)
config.set("verify_ssl", False)        # 是否验证SSL证书
config.set("retry_count", 1)           # 失败重试次数
```

### 🔧 自定义扫描脚本

如果你需要自定义扫描目标，可以参考 `quick_scan.py` 的写法创建自己的脚本：

```python
import asyncio
from wvs.config import ConfigManager
from wvs.core import HTTPPool, WAVScanner
from wvs.models import ScanTarget

async def my_scan():
    config = ConfigManager()
    config.set("crawl_depth", 2)
    
    session = HTTPPool(config)
    scanner = WAVScanner(config, session)
    scanner.load_all_modules()
    
    target = ScanTarget(url="http://your-target.com")
    result = await scanner.scan(target)
    
    print(f"Found {len(result.vulnerabilities)} vulnerabilities")

asyncio.run(my_scan())
```

## 🤖 支持的检测模块

| 模块 | 检测类型 |
|------|----------|
| `sqli` | SQL 注入 (error-based / union / boolean-blind / time-based / stacked) |
| `xss` | 跨站脚本 (反射型/存储型) |
| `cmdi` | 命令注入 |
| `lfi` | 本地文件包含 |
| `rce` | 远程代码执行 |
| `ssrf` | 服务端请求伪造 |
| `xxe` | XML 外部实体注入 |
| `api` | API 安全检测 |
| `sensitive` | 敏感信息泄露 |
| `waf` | WAF 检测与绕过 |
| `jspathfinder` | JavaScript 端点发现 |

## 🔗 外部工具集成

| 工具 | 用途 | 安装方式 |
|------|------|----------|
| Nuclei | 漏洞模板扫描 | `pip install nuclei-python` |
| sqlmap | SQL 注入深度利用 | 需单独安装 |
| ffuf | 模糊测试 | 需单独安装 |
| Wappalyzer | 技术栈识别 | `pip install python-Wappalyzer` |

## 📂 项目结构

```
RayScan/
├── wvs/                       # 核心扫描库
├── scripts/                   # 扫描脚本
├── scan_reports/              # 扫描报告
├── examples/                  # 示例代码
├── analysis/                  # 项目分析文档
├── docs/                      # 技术文档
├── archive/                   # 📦 WVS 历史版本归档
│   ├── v19/
│   ├── v18.4/
│   ├── v18/
│   ├── ...
├── shared_components/         # 共享组件
├── tools/                     # 工具脚本
├── version_diffs/             # 版本差异分析
├── full_scan.py               # 全量扫描入口
├── quick_scan.py              # 快速扫描入口
├── wvs_gui.py                 # GUI 界面
├── pyproject.toml             # 项目配置
├── LICENSE                    # MIT 许可证
├── RENAMED_TO_RAYSCAN.md      # 更名记
└── .gitignore
```

## 📊 检测能力

| 能力 | 状态 |
|------|------|
| SQL 注入 | ✅ error-based / union / boolean-blind / time-based |
| XSS | ✅ 反射型 / 存储型 |
| 命令注入 | ✅ 高精度 |
| LFI | ✅ 支持 |
| SSRF | ✅ 支持 |
| XXE | ✅ 支持 |
| RCE | ✅ 支持 |
| 敏感信息泄露 | ✅ 高覆盖 |
| WAF 绕过 | ✅ 多策略 |
| API 扫描 | ✅ 支持 |
| 第三方集成 | ✅ Nuclei, sqlmap, ffuf, Wappalyzer |

## ⚙️ 版本历史

| 版本 | 说明 |
|------|------|
| **RayScan 1.0** | **正式开源版（基于 WVS v19.2）** |
| WVS v19 / v19.2 | 扫描引擎重构，集成框架升级 |
| WVS v18 / v18.4 | 高级检测模块 + 企业级扫描能力 |
| WVS v17 | 模块化架构重构 |
| WVS v16 | 插件系统 + 多报告格式 |
| WVS v15 | 基础扫描框架搭建 |
| WVS v1~14 | 早期版本开发迭代 |

详见 [更名记](RENAMED_TO_RAYSCAN.md)

## ⚠️ 免责声明

本工具**仅供**获得明确授权的安全测试、渗透测试及漏洞研究使用。
**未经授权扫描、攻击他人系统属于违法行为，使用者需自行承担一切法律责任。**

使用本工具即表示您已阅读并同意上述条款。

## 📄 License

MIT License — Copyright (c) 2026 xiabai2004
