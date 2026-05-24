# RayScan 架构概览

## 项目结构

```
RayScan/
├── wvs/                          # 核心扫描库 (22,013 行 Python)
│   ├── __init__.py               # 包入口
│   ├── __main__.py               # python -m wvs 入口
│   ├── cli.py                    # CLI 命令行接口 (scan/batch/list-modules)
│   ├── config.py                 # 配置管理 (YAML/JSON/环境变量)
│   ├── models.py                 # 数据模型 (Vulnerability / ScanTarget / ScanResult)
│   ├── constants.py              # 全局常量定义
│   ├── exceptions.py             # 异常体系 (15+ 自定义异常)
│   ├── core/                     # 扫描引擎
│   │   ├── scanner.py            # 主扫描器 (934 行)
│   │   ├── crawler.py            # 爬虫引擎 (987 行)
│   │   ├── session.py            # HTTP 会话池 (637 行)
│   │   ├── cache.py              # 缓存系统 (513 行)
│   │   ├── rate_limiter.py       # 速率限制 (519 行)
│   │   ├── scheduler.py          # 任务调度器 (344 行)
│   │   ├── oob.py                # OOB 检测 (~950 行)
│   │   └── ...
│   ├── modules/                  # 检测模块
│   │   ├── base.py               # 模块基类
│   │   ├── sqli/                 # SQL 注入检测 (1586 行)
│   │   ├── xss/                  # XSS 检测 (719 行)
│   │   ├── cmdi/                 # 命令注入检测 (682 行)
│   │   ├── lfi/                  # 文件包含检测 (596 行)
│   │   ├── rce/                  # 远程代码执行 (1138 行)
│   │   ├── ssrf/                 # SSRF 检测 (777 行)
│   │   ├── xxe/                  # XXE 检测 (634 行)
│   │   ├── api/                  # API 安全检测 (415 行)
│   │   ├── sensitive/            # 敏感信息泄露 (789 行)
│   │   ├── waf/                  # WAF 检测与绕过 (801 行)
│   │   └── jspathfinder/         # JS 端点发现 (543 行)
│   ├── integrations/             # 第三方工具集成
│   │   ├── nuclei_runner.py      # Nuclei 集成 (430 行)
│   │   ├── sqlmap_runner.py      # sqlmap 集成 (330 行)
│   │   ├── ffuf_runner.py        # ffuf 集成 (321 行)
│   │   └── wappalyzer_runner.py  # Wappalyzer 集成 (351 行)
│   ├── reporting/                # 报告系统
│   │   ├── console.py            # 控制台报告
│   │   ├── html_report.py        # HTML 报告 (451 行)
│   │   ├── json_reporter.py      # JSON 报告
│   │   ├── csv_reporter.py       # CSV 报告
│   │   └── markdown_report.py    # Markdown 报告
│   ├── exploit/                  # 漏洞利用模块
│   ├── plugins/                  # 插件 (auth 认证等)
│   └── gui/                      # GUI 界面
├── tests/                        # 测试套件 (2279 行, 16 文件)
├── scan_reports/                 # 扫描报告输出目录
├── full_scan.py                  # 全量扫描入口
├── quick_scan.py                 # 快速扫描入口
├── wvs_gui.py                    # GUI 入口
├── Dockerfile                    # Docker 构建
├── docker-compose.yml            # Docker Compose
├── pyproject.toml                # 项目配置
└── CHANGELOG.md                  # 更新日志
```

## 分层架构

```
┌──────────────────────────────────────────────────┐
│                   CLI / GUI                       │  ← 用户接口
├──────────────────────────────────────────────────┤
│              Authentication Layer                 │  ← 认证插件
├──────────────────────────────────────────────────┤
│  ┌──────────┐  ┌──────────┐  ┌───────────────┐   │
│  │ Scanner   │  │ Crawler  │  │   Scheduler   │   │  ← 核心引擎
│  └────┬─────┘  └────┬─────┘  └───────┬───────┘   │
├───────┼──────────────┼────────────────┼──────────┤
│  ┌────┴──────────────┴────────────────┴───────┐   │
│  │            Module  Registry                 │   │  ← 模块注册
│  └────┬──────────┬──────────┬──────────┬──────┘   │
│  ┌────┴──┐ ┌────┴──┐ ┌────┴──┐ ┌────┴───┐       │
│  │ SQLi  │ │ XSS   │ │ CMDi  │ │ ... 11 │       │  ← 检测模块
│  └───────┘ └───────┘ └───────┘ └────────┘       │
├──────────────────────────────────────────────────┤
│        Integrations (Nuclei / sqlmap / ffuf)      │  ← 外部工具
├──────────────────────────────────────────────────┤
│           Reporting (HTML/JSON/CSV/MD)            │  ← 报告输出
└──────────────────────────────────────────────────┘
```

## 核心数据流

```
用户输入 URL
    │
    ▼
┌────────┐   ┌──────────┐   ┌─────────┐
│ Crawler │──▶│ Scanner  │──▶│ Modules │
│ 爬页面  │   │ 调度模块 │   │ 执行检测 │
└────────┘   └──────────┘   └────┬────┘
                                 │
    ┌────────────────────────────┼──────────┐
    │                            ▼          │
    │  ┌──────┐  ┌──────┐  ┌─────────┐     │
    │  │ SQLi │  │ XSS  │  │ CMDi... │     │
    │  └──┬───┘  └──┬───┘  └────┬────┘     │
    │     └─────────┼───────────┘           │
    │               ▼                       │
    │      ┌──────────────┐                 │
    │      │   Reporter   │                 │
    │      │ (Console/    │                 │
    │      │  HTML/JSON)  │                 │
    │      └──────────────┘                 │
    └───────────────────────────────────────┘
```

## 关键设计决策

1. **异步驱动** — 基于 `asyncio` + `aiohttp`，支持高并发 HTTP 请求
2. **模块化检测** — 每个漏洞类型独立模块，继承统一基类，可插拔
3. **配置分层** — 默认值 → 配置文件 → CLI 参数，逐层覆盖
4. **统一数据模型** — `Vulnerability` / `ScanTarget` / `ScanResult` 贯穿全流程
5. **插件化认证** — `AuthManager` 支持 5 种认证方式，可扩展
6. **自动速率限制** — 智能调整请求频率，避免被 WAF 封禁
