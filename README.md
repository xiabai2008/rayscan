# WVS - Web Vulnerability Scanner 🚀

> **最新版本：v19.2** | 一个功能强大的 Web 漏洞扫描器

## 📋 功能特性

- **SQL 注入检测** - 支持多种注入类型和payload
- **XSS 检测** - 反射型/存储型/DOM型
- **命令注入 (CMDi) 检测**
- **文件包含 (LFI/RFI) 检测**
- **SSRF/XXE 检测**
- **敏感信息泄露检测**
- **WAF 绕过**
- **API 扫描**
- **JSPathFinder** - JavaScript 端点发现
- **RCE 检测**
- **第三方工具集成**（Nuclei, sqlmap, ffuf, Wappalyzer）
- **多种报告格式**（HTML, JSON, CSV, Markdown, Console）

## 🚀 快速开始

```bash
# 安装依赖
pip install -r requirements-dev.txt

# 快速扫描
python quick_scan.py -u https://example.com

# 全量扫描
python full_scan.py -u https://example.com --profile full

# GUI 模式
python wvs_gui.py
```

## 📂 项目结构

```
WVS_all/
├── wvs/                       # 核心扫描库（v19.2）
├── scripts/                   # 扫描脚本
├── scan_reports/              # 扫描报告
├── examples/                  # 示例代码
├── analysis/                  # 项目分析文档
├── docs/                      # 技术文档
├── archive/                   # 📦 历史版本归档
│   ├── v19/
│   ├── v18.4/
│   ├── v18/
│   ├── v17/
│   ├── v16/
│   ├── v15.0/
│   ├── v1_v15_complete/
│   └── ...
├── shared_components/         # 共享组件
├── tools/                     # 工具脚本
├── version_diffs/             # 版本差异分析
├── full_scan.py               # 全量扫描入口
├── quick_scan.py              # 快速扫描入口
├── scan_dvwa.py               # DVWA 靶场扫描
├── scan_dvwa_v19.2.py         # DVWA 扫描（v19.2 优化版）
├── wvs_gui.py                 # GUI 界面
├── pyproject.toml             # 项目配置
└── .gitignore
```

## 📊 检测能力

| 能力 | 状态 |
|------|------|
| SQL 注入 | ✅ 高精度 |
| XSS | ✅ 高精度 |
| 命令注入 | ✅ 高精度 |
| LFI/RFI | ✅ 高精度 |
| SSRF | ✅ 支持 |
| XXE | ✅ 支持 |
| 敏感信息 | ✅ 高覆盖 |
| WAF 绕过 | ✅ 多策略 |
| API 扫描 | ✅ 支持 |
| RCE | ✅ 支持 |
| 第三方集成 | ✅ Nuclei, sqlmap, ffuf |

## ⚙️ 版本历史

| 版本 | 说明 |
|------|------|
| **v19.2** | **当前最新版** - 性能优化 + bug修复 + 新检测模块 |
| v19 | 扫描引擎重构，集成框架升级 |
| v18.4 | 企业级扫描能力完善 |
| v18 | 高级检测模块 + 性能优化 |
| v17 | 模块化架构重构 |
| v16 | 插件系统 + 多报告格式 |
| v15 | 基础扫描框架搭建 |
| v1~14 | 早期版本开发迭代 |

## ⚠️ 免责声明

本工具仅供授权的安全测试和漏洞研究使用。未经授权扫描他人系统是违法行为。

## 📄 License

MIT License
