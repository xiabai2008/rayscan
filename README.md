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
