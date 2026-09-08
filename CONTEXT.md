# CONTEXT — RayScan 领域词汇表

> 单上下文仓库的唯一领域词汇来源（约定见 `docs/agents/domain.md`）。issue、PR、测试名、文档命名请使用本表术语，勿用同义词列中的替代词。决策记录见 `docs/adr/`。

## 项目一句话

RayScan 是面向**中文 OA / 国产中间件**的专项 Web 漏洞检测器，以规则级证据链与低误报为差异化定位（ADR-0001）。通用漏洞检测由内置 Nuclei 阶段兜底。

## 术语表

| 术语 | 定义 | 避免的说法 |
|------|------|-----------|
| **靶机（Lab）** | 本地漏洞演练环境（DVWA / Metasploitable 2 / Mutillidae 等），`lab_profiles.py` 自动识别并自动认证 | 靶场、实验环境 |
| **实战（Real-world）** | 非靶机目标：浅爬、即爬即测、跳过靶场专属路径 | 生产环境、真实目标 |
| **双路径分流** | 扫描启动时按靶机/实战自动选择流程 | 自动模式（口语可，文档避免） |
| **流式检测** | 爬取分批进行，每批端点立即送检，不等全部爬完 | 边爬边扫 |
| **三级检测链路** | OA 专项检测的固定顺序：内容指纹识别 → 版本识别 → 规则级证据验证（+版本过滤） | 三步检测 |
| **闭环（Closure）** | 一条 OA 规则完成了真实/靶场样本的实测验证并在 `OA_RULES.md` §5 留下记录 | 验证完成（不完整义） |
| **闭环率** | 已闭环 OA 规则数 / 12（当前 0/12，S5 目标 ≥6/12，见 FF3） | 覆盖率（与代码覆盖率混淆） |
| **误报治理** | 判定必须基于响应证据（baseline 排除、内容特征、规则级 evidence），仅路径可达不报 | 降噪（口语可，文档避免） |
| **baseline** | 检测前先发的良性对照请求，用于排除目标自身响应差异造成的假阳性 | 对照组 |
| **OOB** | 带外验证（dnslog / interactsh），用于 blind 漏洞确认 | 带外（口语可） |
| **checkpoint / resume** | 扫描进度 30s 间隔落盘；`--resume` 合并已发现漏洞并跳过已完成模块 | 断点续传 |
| **core / optional / lite** | 模块三层级：core 默认加载（sqli/xss）、optional 按需（jspathfinder）、lite 需 `--all-modules`（其余 15 个）。由 `ModuleInfo.category` 决定 | 主模块/副模块 |
| **Nuclei 阶段** | 主流程 Phase 3.5：CLI 可用走模板扫描，不可用走内置内容特征回退（无"可达即报"） | nuclei 集成（指 integrations/ 层时才用） |
| **S 序列** | 项目迭代代号：S1 误报治理 → S2 链条接通 → S3 OA 深化 → S4 信任重建 → S5 OA 闭环 → S6 架构收敛 | 阶段（歧义） |
| **适应度函数（FF1–FF6）** | ADR-0001 定义的可测试架构不变量（CLI 行数 / 数字一致 / 闭环率 / 靶场回归 / 裸捕获递减 / 仓库卫生） | 质量门禁（指 CI 时才用） |

## 命名规则

- 迭代文档：`docs/audit/rayscan-sN-<主题>-<YYYY-MM-DD>.md`，版本 v1/v2 递增不覆盖
- ADR：`docs/adr/NNNN-kebab-case.md`，状态字段（Proposed/Accepted/Superseded）
- 决策冲突：新内容与既有 ADR 矛盾时，显式标注"Contradicts ADR-NNNN"而非静默覆盖
