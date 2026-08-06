# RayScan 1.0 — 我花了大半年写的 Web 漏洞扫描器，今天开源了 🚀

> 一个拥有 11 个检测模块、覆盖 SQL 注入 / XSS / 命令注入 / LFI / SSRF / RCE 等主流漏洞的实用型扫描器。

## 🤔 为什么要写这个

半年前，我在做安全测试的时候发现，市面上的开源扫描器要么太重量级（跑一次半小时），要么检测能力单一。于是决定自己写一个，目标很简单：

- **开箱即用** —— pip install 完就能跑
- **检测要准** —— 不是瞎扫，要有真凭实据
- **模块化** —— 想加新检测类型，写一个模块就行

从 v1 到 v19，从单文件脚本到 800KB 代码的扫描引擎……大半年过去了，它长成了今天的样子。

## 🔬 能扫什么

目前内置 11 个检测模块：

| 模块 | 检测能力 |
|------|----------|
| **SQL 注入** | error-based / union / boolean-blind / time-based / stacked queries |
| **XSS** | 反射型 / 存储型 |
| **命令注入** | 高精度，带并发 time-based 优化 |
| **LFI** | 本地文件包含 |
| **RCE** | 远程代码执行检测 |
| **SSRF** | 服务端请求伪造 |
| **XXE** | XML 外部实体注入 |
| **API 安全** | REST API 安全检测 |
| **敏感信息** | 信息泄露扫描 |
| **WAF** | WAF 检测与绕过 |
| **JSPathFinder** | JavaScript 端点自动发现 |

## 📊 实战表现

在 DVWA 靶场测试中，成功检出 **7 种漏洞类型**，包括：

- SQL 注入（68次检出）
- XSS（54次检出）
- 命令注入（16次检出）
- LFI（36次检出）
- SSRF（14次检出）

## 🚀 3 秒上手

```bash
pip install -r requirements-dev.txt

# 扫个站看看
python quick_scan.py -u http://example.com

# 深度扫描
python full_scan.py -u http://example.com

# 有桌面的话还能用 GUI
python wvs_gui.py
```

## 🏗️ 技术架构

```
Crawler → 参数发现 → 并发检测 → 去重 → 报告
```

全程 async 异步，支持并发检测，内置限速机制避免把目标打挂。

## 📦 为什么叫 RayScan

之前它叫 WVS（Web Vulnerability Scanner），走过了 19 个大版本。开源之际改名为 RayScan，寓意像射线一样精准穿透。

旧版本完整保留在 `archive/` 目录——这既是对过去的尊重，也是成长的记录。

## 🔗 开源地址

**GitHub：** https://github.com/xiabai2008/rayscan

**License：** MIT —— 随便用，随便改，保留版权声明就行。

## 💬 写在最后

这个项目目前还是 Beta 阶段，肯定有很多不完善的地方。但我相信，**好的工具是在使用中打磨出来的**。

如果你试了觉得有用，点个 Star 🌟 就是对我最大的鼓励。
如果你发现 bug 或者有建议，直接提 Issue，每条我都会看。

---

*—— xiabai2008, 2026*
