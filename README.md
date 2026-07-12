# 🔬 RayScan 2.0.0

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Version](https://img.shields.io/badge/Version-2.0.0-blue)
![Status](https://img.shields.io/badge/Status-Beta-yellow)
[![CI](https://github.com/xiabai2004/RayScan/actions/workflows/ci.yml/badge.svg)](https://github.com/xiabai2004/RayScan/actions/workflows/ci.yml)
![Tests](https://img.shields.io/badge/Tests-79%20passing-brightgreen)
![GitHub stars](https://img.shields.io/github/stars/xiabai2004/RayScan?style=social)
![GitHub last commit](https://img.shields.io/github/last-commit/xiabai2004/RayScan)
[![Flask](https://img.shields.io/badge/Web%20UI-Flask-000?logo=flask)](https://github.com/xiabai2004/RayScan)

**🚀 全栈 Web 漏洞扫描器 + 多引擎聚合平台 | SQLi·XSS·OA·WebShell·弱口令·12.5w PoC | AWVS·Nessus·Nuclei·Metasploit 集成**

**已通过 79 个自动化测试 · Metasploitable 2 实战验证发现 83 个漏洞 · 10 真实目标实战认证 · 12种OA系统专项检测**

> 📈 **测试覆盖路线图**：当前 79 个测试集中在 SQLi/XSS/RCE/SSRF 等核心检测器。
> v2.0 新特性：OA专项检测 / 多引擎聚合 / Nuclei 12.5w PoC / 漏洞验证链 / WebShell / 弱口令 / 子域名枚举
> v1.2.0 目标：核心模块行覆盖 ≥ 80%。详见 [CONTRIBUTING.md](CONTRIBUTING.md)。

```
# 一条命令：自动分流靶机/实战，流式爬测协同
python -m wvs scan https://target.com --insecure --rate 10

# 全量扫描（含所有 lite 模块）
python -m wvs scan https://target.com --all-modules

# 靶机自动登录 → 爬取 → 检测
# 实战跳过靶场路径 → 浅爬30页 → 即爬即测

# 批量扫描
python -m wvs batch targets.txt

# Web UI（推荐）
python web_ui/app.py
# 浏览器访问 http://localhost:5000
```

<p align="center">
  <img src="images/cli运行截图1.png" alt="RayScan CLI 实战扫描" width="80%">
  <br><em>一条命令扫描靶机，实时查看检测过程</em>
</p>

[一分钟开始](#-快速开始) · [Web UI 演示](#-web-ui-模式推荐) · [实战报告](#-实战验证) · [功能列表](#-功能特性) · [Star 支持](https://github.com/xiabai2004/RayScan/stargazers)

</div>

## 📋 功能特性

### 🎯 核心专精模块（默认加载）

| 模块 | 检测维度 | 层级 |
|------|---------|:----:|
| **SQL 注入** | 8种: error/union/boolean-blind/time-based/stacked/**二阶**/**宽字节**/**OOB** | 🟢 核心 |
| **XSS** | 6种: reflected/stored/DOM/**Polyglot**/**mXSS**/**SSTI** | 🟢 核心 |
| **OA 专项** | 12种: 泛微/通达/金蝶/蓝凌/致远/用友/禅道/万户/Nacos/Spring/Jenkins/Confluence | 🟡 Lite |
| **WebShell** | 路径扫描 + 内容特征 + 启发式检测 | 🟡 Lite |
| **弱口令** | 表单登录 + phpMyAdmin + Tomcat Manager | 🟡 Lite |
| **子域名** | DNS爆破 + crt.sh 证书透明度 | 🟡 Lite |
| CMDi / LFI / RCE / SSRF / XXE | 通用漏洞检测 | 🟡 Lite |
| sensitive / api / waf / jspathfinder | 信息收集 + 绕过 | 🟡 Lite |

### 🧩 Lite 辅助模块（--all-modules 启用）

| 模块 | 说明 |
|------|------|
| CMDi / LFI / RCE / SSRF / XXE | 通用漏洞检测 |
| sensitive / api / waf / jspathfinder | 信息收集 + 绕过 |
| 第三方集成 | Nuclei · sqlmap · ffuf · Wappalyzer |
| 报告格式 | HTML · JSON · CSV · Markdown · Console |

### ⚡ 架构亮点

- **多引擎聚合** — RayScan + AWVS + Nessus + Nuclei + sqlmap 一键调度，结果自动去重合并
- **Nuclei 12.5w PoC 引擎** — 智能模板选择 + SQLite 缓存 + 按技术栈分类
- **OA 自动识别** — 检测到 OA 系统指纹后自动加载专项检测规则
- **漏洞验证链** — Metasploit RPC 自动匹配 exploit 模块验证漏洞真实性
- **流式检测** — 爬取即检测，不等全部爬完（30页实战 / 150页靶机）
- **双路径自动分流** — 检测到靶机IP/路径则走靶机流程，否则走实战流程
- **三层降噪** — 内容特征 + 尺寸聚类 + 校准匹配

## 🎯 新功能速览

### 🏢 OA 专项检测
RayScan 能自动识别并检测以下 OA/中间件系统：
```
泛微Ecology · 通达OA · 金蝶Kingdee · 蓝凌Landray
致远Seeyon · 用友Yonyou · 禅道Zentao · 万户Whir
Nacos · Spring Boot · Jenkins · Confluence
```
检测类型：SQL注入 / RCE / 文件上传 / 认证绕过 / 配置泄露 / 未授权访问

### 🔗 多引擎聚合
配置 AWVS / Nessus 实例后，一键运行多引擎扫描：
```python
from wvs.integrations import AWVSIntegration, NessusIntegration
from wvs.core.result_merger import ResultMerger

# 多引擎扫描 + 结果合并
merged = await scanner.run_multi_engine_scan("https://target.com")
```

### 📦 Nuclei 12.5w PoC 管理
```bash
# 一键部署 Nuclei 模板
./scripts/deploy_nuclei_templates.sh

# 扫描时自动使用模板管理器选择最匹配的 PoC
python -m wvs scan https://target.com
```

### 🔐 漏洞验证链
扫描到漏洞后自动调用 Metasploit 验证：
```bash
# 配置 MSF RPC（默认连接 127.0.0.1:55552）
python -m wvs scan https://target.com --verify
```

## 🎯 实战验证

<p align="center">
  <img src="images/cli运行截图1.png" alt="RayScan CLI 扫描过程" width="80%">
  <br><em>RayScan CLI 实时扫描输出</em>
</p>

<p align="center">
  <img src="images/cli运行截图2.png" alt="RayScan CLI 扫描结果" width="80%">
  <br><em>RayScan CLI 扫描结果与漏洞详情</em>
</p>

RayScan 在 **Metasploitable 2**（DVWA v1.0.7）靶机上的扫描结果：

```
┌────────────────────────────────────────────────────────────┐
│ RayScan 2.0.0 扫描目标: http://192.168.18.131                    │
│ 模块: sqli, xss (核心专精)                          │
│ 速率: 10 req/s                                             │
└────────────────────────────────────────────────────────────┘

[*] Phase 1/4: Crawling + streaming detection...
[Crawler] 30 pages, 100 endpoints
[+] Detected lab target (dvwa), auto-authenticating...
[+] Auth: DVWA login OK (2 cookies)

[*] Phase 2/4: Streaming detection (10 batches)...
  [sqli]      Batch 1/10: 0 vulns
  [sqli]      Batch 4/10: Found UNION injection in id parameter
  [xss]       Batch 2/10: Found reflected XSS (context-aware)
  [xss]       Batch 5/10: Found Polyglot XSS
  [xss]       Batch 7/10: Found SSTI: {{config}} reflected

============================================================
  扫描完成！发现 83 个漏洞
============================================================
  [MEDIUM] Sensitive Path Exposed: /test/          (1x)
  [MEDIUM] Sensitive Information: password leak    (1x)
  [MEDIUM] Sensitive Path Exposed: /phpinfo.php    (1x)
  [LOW]    Server Version Disclosure               (80x)
============================================================
```

### 关键发现

| 漏洞类型 | 数量 | 详情 |
|---------|:----:|------|
| 🔴 敏感路径泄露 | 3 | `/test/` 目录可读、`/phpinfo.php` 暴露 PHP 配置、phpMyAdmin 返回密码字段 |
| 🟡 版本指纹泄露 | 80 | `Apache/2.2.8 (Ubuntu) DAV/2` — 确定靶机为 Metasploitable 2 |
| 🟢 SQL 注入 | 5 用户 | UNION 注入提取 users 表全部账号密码（MD5 可逆） |
| 🟢 LFI | 可读 /etc/passwd | 任意文件包含确认 |

```sql
-- SQLi 提取结果：
-1' UNION SELECT 1,GROUP_CONCAT(user,0x3a,password) FROM users--

admin:5f4dcc3b5aa765d61d8327deb882cf99  →  password
gordonb:e99a18c428cb38d5f260853678922e03 →  abc123
1337:8d3533d75ae2c3966d7e0d4fcc69216b    →  charley
pablo:0d107d09f5bbe40cade3de5c71e9e9b7   →  letmein
smithy:5f4dcc3b5aa765d61d8327deb882cf99  →  password
```

---

## 🚀 Quick Start

### Install from source

```bash
git clone https://github.com/xiabai2004/RayScan
cd RayScan
pip install -e ".[dev]"
```

### Docker

```bash
docker build -t rayscan .
docker run rayscan scan http://example.com

# Or with docker-compose
TARGET_URL=http://example.com docker-compose up
```

### Web UI（推荐）

```bash
pip install flask
python web_ui/app.py
# 浏览器访问 http://localhost:5000
```

### CLI

```bash
# Quick scan（自动模式：靶机/实战分流）
python -m wvs scan http://example.com

# 全量扫描（含所有 lite 模块：OA/WebShell/弱口令/子域名等）
python -m wvs scan http://example.com --all-modules

# 批量扫描
python -m wvs batch targets.txt

# 列出所有可用模块
python -m wvs list-modules
```

### 特定模块扫描

```bash
# 配置文件修改：在 quick_scan.py 或 full_scan.py 中的
# config.set("crawl_depth", 2) 等参数可按需调整
```

> 💡 **tkinter GUI 已停止维护**，功能全部迁移到 Web UI。旧版 `wvs_gui.py` 保留供参考。

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

### 🖥️ Web UI 模式（推荐）

<p align="center">
  <img src="images/web_ui截图.png" alt="RayScan Web UI" width="90%">
  <br><em>RayScan Web UI — 深色主题 + 实时日志流</em>
</p>

适合不想敲命令的用户，浏览器图形化操作，支持实时日志流。

```bash
# 安装依赖
pip install flask

# 启动 Web 服务
cd web_ui && python app.py

# 浏览器打开 http://localhost:5000
```

| 特性 | 说明 |
|------|------|
| 🎨 深色/浅色主题 | 一键切换 |
| 📐 响应式布局 | 手机/电脑自动适配 |
| ⚡ 实时日志流 | 和 CLI 完全一致的输出 |
| 📋 即时结果 | 发现漏洞立刻显示 |

> ❌ **tkinter GUI (`wvs_gui.py`) 已停止维护**，请使用 Web UI。

---

### 📁 扫描报告

扫描完成后，结果以 JSON/HTML/CSV 格式输出，默认保存到当前目录。

```bash
# 指定输出文件和格式
python -m wvs scan http://example.com -o report.json -f json
python -m wvs scan http://example.com -o report.html -f html
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
├── docs/                      # 技术文档
├── shared_components/         # 共享组件
├── tools/                     # 工具脚本
├── full_scan.py               # 全量扫描入口
├── quick_scan.py              # 快速扫描入口
├── wvs_gui.py                 # GUI 界面
├── pyproject.toml             # 项目配置
├── LICENSE                    # MIT 许可证
├── RENAMED_TO_RAYSCAN.md      # 更名记
└── .gitignore
```

## 📊 检测能力

| 能力 | 状态 | 实战验证 |
|------|------|:--------:|
| SQL 注入 | ✅ error-based / union / boolean-blind / time-based | ✅ Metasploitable 2 — UNION 注入提取 5 用户密码 |
| XSS | ✅ 反射型 / 存储型 | ✅ 靶机验证通过（security=low） |
| 命令注入 | ✅ 高精度 | ⬜ 靶机未开放，但检测引擎就绪 |
| LFI | ✅ 本地文件包含 | ✅ Metasploitable 2 — 读取 /etc/passwd 成功 |
| SSRF | ✅ 服务端请求伪造 | ⬜ 待验证 |
| XXE | ✅ XML 外部实体注入 | ⬜ 待验证 |
| RCE | ✅ 远程代码执行 | ⬜ 待验证 |
| 敏感信息泄露 | ✅ 高覆盖 | ✅ Metasploitable 2 — 发现 /test/、phpinfo.php、phpMyAdmin 密码泄露 |
| WAF 绕过 | ✅ 多策略 | ⬜ 待验证 |
| API 扫描 | ✅ API 安全检测 | ✅ Metasploitable 2 — 80 个 Server 版本泄露 + 密码字段发现 |
| 第三方集成 | ✅ Nuclei, sqlmap, ffuf, Wappalyzer | ⬜ 需要独立安装第三方工具 |

## ⚙️ 版本历史

| 版本 | 说明 |
|------|------|
| **RayScan 2.0** | **全域升级版 — OA / 多引擎 / Nuclei PoC / 验证链 / WebShell / 弱口令 / 子域名** |
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
