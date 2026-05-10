# WVS v17.0

增强型 Web 漏洞扫描器 - 基于市场最佳实践构建

## 新特性

### 🔍 核心扫描引擎
- **SQLi v17**: 多阶段验证、数据库指纹、WAF 规避
- **XSS v17**: 上下文感知、DOM XSS、CSP 绕过
- **SSRF v17**: 云元数据检测、内网扫描、绕过技术
- **命令注入 v17**: Unix/Windows 双平台、时间盲注
- **XXE v17**: 文件读取、SSRF、OOB 检测
- **路径遍历 v17**: 多种编码、空字节、包装器

### 🤖 AI 辅助检测
- 智能 payload 选择
- 误报过滤
- 漏洞验证
- WAF 绕过建议
- 支持多种 LLM (OpenAI/Claude/本地模型)

### 🌐 分布式扫描
- 主节点/工作节点架构
- 任务分发与负载均衡
- 断线重连与任务重分配
- 实时进度监控

### 🔗 CI/CD 集成
- GitLab CI 流水线触发
- GitHub Actions 工作流集成
- 自动漏洞报告

### 📢 通知集成
- Slack Webhook
- 钉钉机器人
- 企业微信
- 自定义 Webhook

### 📊 问题追踪
- Jira Issue 自动创建
- GitHub Issues 集成

## 快速开始

```bash
# 安装依赖
pip install -r requirements.txt

# 基础扫描
python -m wvs scan https://example.com

# 指定模块
python -m wvs scan https://example.com -m sqli xss

# 启用 AI 辅助
python -m wvs scan https://example.com --ai

# 分布式模式
python -m wvs master --port 8765  # 主节点
python -m wvs worker localhost --port 8766  # 工作节点

# Web UI
python -m wvs web --port 8080
```

## 目录结构

```
wvs-v17/
├── wvs/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli_v17.py           # CLI 入口
│   ├── core/
│   │   ├── payloads_v17.py  # Payload 库
│   │   ├── ai_engine.py     # AI 引擎
│   │   └── distributed.py   # 分布式扫描
│   ├── vuln/
│   │   ├── sqli_v17.py      # SQL 注入
│   │   ├── xss_v17.py       # XSS
│   │   ├── ssrf_v17.py      # SSRF
│   │   ├── cmdi_v17.py      # 命令注入
│   │   ├── xxe_v17.py       # XXE
│   │   ├── traversal_v17.py # 路径遍历
│   │   ├── crawler_v17.py   # 爬虫
│   │   └── report_v17.py    # 报告生成
│   ├── integrations/
│   │   └── manager.py       # 集成管理
│   └── web/                 # Web UI
├── requirements.txt
├── PROGRESS.md
└── README.md
```

## 版本历史

- **v17.0** (2026-04-17): AI 辅助、分布式扫描、新漏洞类型
- **v16.0** (2026-04-17): 核心引擎重写、Web UI
- **v11.0**: CI/CD 集成、插件系统
