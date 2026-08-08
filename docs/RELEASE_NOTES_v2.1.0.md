# RayScan v2.1.0 — Release Notes

> 发布日期:2026-08-07
> GitHub: [xiabai2008/rayscan](https://github.com/xiabai2008/rayscan) · License: MIT

---

## 🎉 欢迎使用 RayScan 2.1

RayScan 是一个**比 Nuclei 更深、比 AWVS 更轻**的开源 Web 漏洞扫描器——自研深度检测引擎(不是模板匹配)+ 多引擎聚合 + SRC 场景开箱即用。

v2.1.0 在 v2.0(OA 专项 + Nuclei 接入 + 误报治理)之上新增:可解释检测、被动扫描、业务逻辑检测、规则管理、一键演示、合规预设。

---

## 🚀 三大亮点

### 1. 🧪 一键演示 — 5 秒看到效果

```bash
pip install rayscan
rayscan demo
```

内置本地靶场(SQLi/XSS,仅监听 127.0.0.1),启动即自动扫描,**实测检出 12 个漏洞**,每条附证据链。不配靶机、不写配置,装完就能看。

### 2. 🔍 可解释检测 — 漏洞不是"报出来"而是"讲清楚"

```bash
rayscan scan https://target.com --explain
```

```text
[SQLi] id 参数 | UNION-based | confidence=high
  ├ baseline: 200/2,431B (3 samples, σ=0.02s)
  ├ test:     200/8,912B  响应长度 +267%
  └ evidence: "You have an error in your SQL syntax" (MySQL)
```

每条漏洞给出**证据链**(基线差异/命中特征/置信度依据),JSON/SARIF 报告同步输出,**可直接作 SRC 提交证据**。

### 3. 🚦 被动扫描 + 业务逻辑 — 覆盖你的盲区

```bash
# 被动扫描:分析真实浏览器流量,覆盖登录后页面
rayscan passive --listen 127.0.0.1:8081 --target https://target.com

# 业务逻辑检测(SRC 最大赏金,WAF 拦不住)
rayscan scan https://target.com --all-modules
```

新增模块:
- **IDOR/越权**:对象替换(±1/批量)对比 + 批量接口 + 管理端点探测
- **认证绕过**:认证头移除重放 + JWT none/弱密钥 + 默认凭据

---

## ✨ 完整更新清单

### Added(新功能)
| 功能 | 说明 |
|------|------|
| `rayscan demo` | 内置靶场一键演示 |
| `rayscan passive` | 零依赖轻量 MITM 被动扫描 |
| `rayscan rules` | 规则管理(status/init/update),增量更新无需发版 |
| `--explain` | 可解释检测证据链 |
| `--preset` | 5 种扫描预设(gentle 合规轻扫等) |
| `--concurrency` | 全局并发参数(跨模块共享信号量) |
| `idor` / `authbypass` 模块 | 业务逻辑/越权/认证绕过检测 |
| `ScanOrchestrator` | WAVScanner 编排层拆分(facade 模式) |
| 聚合报告视图 | multi 结果高亮 ★ 多引擎高可信漏洞 |
| CI 覆盖率门禁 | `--cov-fail-under=30` |

### Fixed(修复)
- `multi` 子命令不可达(重复定义 + 未接线)→ 已修复
- `--i-have-permission` exploit 空转 → 授权确认后真实执行
- `HTMLReporter.generate_json` 误用 → JSON 报告改走 `JSONReporter`
- `WAVScanner._vuln_seen` 未初始化崩溃 → 已修复
- 报告版本硬编码 → 动态读取 `__version__`
- 全局并发 Semaphore 不共享 → 已修复

### Kept(继承 v2.0 能力)
- OA 三级检测链路(12 种指纹 + 版本过滤 + 规则证据)
- Nuclei 主流程接入(默认启用 + 内置回退)
- 扫描断点恢复(--resume + checkpoint)
- S1-S3 误报治理(XXE/SSRF baseline 排除等)

---

## 🏗️ 工程现状

- **约 211 自动化测试**全绿(远程 v2.0 回归 + 本地 Phase 0-4 全量),CI 覆盖率门禁 30%+
- ruff + mypy 质量门禁,Docker 多阶段构建(git 已内置支持规则更新)
- 规则可贡献:detect → exploit → regression 三阶段流程,新人友好
- 合规内建:授权确认、gentle 预设、SSRF 拦截、元数据阻断

---

## 📥 安装

```bash
# pip 安装
pip install rayscan

# 或源码
git clone https://github.com/xiabai2008/rayscan
cd rayscan && pip install -e .

# Docker
docker build -t rayscan .
docker run rayscan demo
```

---

## 🙏 致谢

感谢每一位使用、测试、提 Issue、提 PR 的朋友。

- 贡献者名单见 [CONTRIBUTORS.md](https://github.com/xiabai2008/rayscan/blob/master/CONTRIBUTORS.md)
- 反馈承诺:Issue 48h 内回应 · PR 7 天内评审

**点个 Star ⭐ 支持我们,让 RayScan 走得更远。**
