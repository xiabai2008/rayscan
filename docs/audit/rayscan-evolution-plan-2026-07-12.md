# RayScan 技术演进规划方案（统一版）

> 版本：v1.2 ｜ 日期：2026-07-12（v1.1），2026-08-05（v1.2 战略修正）
> 编制：交付总监齐活林 汇总（产品路线图-许清楚 / 技术演进-高见远）
> 依据：代码库审计 `docs/audit/rayscan-codebase-audit-2026-07-12.md` + 2026-08-05 实战能力复审（检测引擎/主流程双路深度审查）
> 配套技术详档：`docs/rayscan_evolution_roadmap.md`（架构师原始方案 + 二次校准）
> 战略决策状态：**已修正**（v1.1 拍板"自研内核优先"，v1.2 于 2026-08-05 修正为"**OA 专项 + 工作流闭环**"，详见 §11）

---

## 0. 执行摘要（TL;DR）

RayScan 当前「**内核强、工程弱、接线断**」：检测内核插件化扎实、主流漏洞覆盖全，但存在一处 **P0 阻断级缺陷**（`httpx` 未声明依赖，导致安装/Docker/CI 全失败），且测试被排除出库、集成层未接入主流程、编排层膨胀。

本方案给出 **5 个 Phase、约 52 人天** 的演进路线，**先止血（P0）→ 工程化地基（P1）→ 架构解耦（P2）→ 能力扩展与接线（P3）→ 规模化安全与生态（P4）**，并补齐 IDOR/越权、SSTI、API 安全等高价值缺失能力。

**方向已定**：以「自研内核优先」构筑检测精度 + 合规安全护城河，先走开源，目标用户聚焦安全研究员 / 渗透测试；聚合（integrations）降级为可选增强。架构师据此完成二次校准（详见 `docs/rayscan_evolution_roadmap.md` §6）。

---

## 1. 产品愿景与定位

RayScan 定位为 **「自研检测内核 + 可选多引擎聚合」的异步 Web 漏洞扫描器**，而非纯调度平台。差异化护城河：

1. **合规安全**：默认只检测不利用（exploit 默认禁用）+ 扫描前授权确认门槛（开源发布前置条件）。
2. **精度可控**：`wvs/` 插件化抽象使新增漏洞类型成本极低，自研内核覆盖 SQLi/XSS/SSRF 等主流面，比纯调度器更可控。
3. **报告友好**：多格式报告（含 SARIF）贴合研究员出报告与开源社区集成；CLI 优先，契合渗透工作流。

**取舍**：不追工具广度（如 AWVS 商业套件），以「检测精度 + 合规安全 + 可扩展」构筑壁垒；聚合仅作可选增强，nuclei 默认开、其余需 `--enable`。

---

## 2. 目标使用者与诉求（侧重：安全研究员 / 渗透优先）

| 使用者 | 核心诉求 | 当前优先级 |
|--------|---------|-----------|
| 安全研究员 / 渗透（瑞哥侧） | 新增漏洞类型快、OOB/上下文感知精准、并发/Profile 可调、报告多格式 | **核心聚焦** |
| DevSecOps / 开发 | CLI/CI 可嵌入、安装可靠、gentle 速率、SARIF | 兼顾（非首要） |
| 社区 / 开源用户 | 安装可靠、文档清晰、合规默认行为 | 兼顾（开源发布驱动） |

---

## 3. 统一分期路线图（产品 × 技术对齐）

> 时间桶：近期 0–3 月（Phase 0–2）｜中期 3–6 月（Phase 3 + P4 前半）｜长期 6–12 月+（P4 后半 + 生态）
> 工作量合计 **52 人天**（P0 5 + P1 10 + P2 18 + P3 12 + P4 7）

| Phase | 周期/工作量 | 工程目标 | 产品能力交付 | 对应需求 |
|-------|-----------|---------|-------------|---------|
| **P0 止血** | ~1 sprint / 5 人天 | httpx/flask 入依赖、proxies→proxy、sqli `__init__` 漏透 session、删 dev 依赖冲突、import smoke test | 安装/Docker/CI 跑通（R-01） | R-01 |
| **P1 工程化地基** | ~2 sprint / 10 人天 | 单版本源(2.0.0)、uv.lock、CI(ruff+mypy+覆盖率)、Docker 多阶段、tests 入库 + sqli/xss 单测、sarif/csv 接线修复 | 可重复构建 + 基础测试网（R-02/R-03） | R-02, R-03 |
| **P2 架构解耦** | ~3 sprint / 18 人天 | 模块加载统一(ModuleFactory)、WAVScanner 拆分(Orchestrator+Auth/Dedup/Checkpoint)、统一 httpx(http2)、aiohttp 隔离默认禁用、concurrent_endpoints 真正生效、删硬编码路径/lab 分支(改 `--lab`) | 可维护核心 + 并发可调（R-08 基础） | R-08 |
| **P3 能力扩展与接线** | ~2–3 sprint / 12 人天 | integrations/ 接入主流程(可选增强)、补全 SARIF 实现 | **自研漏洞模块为绝对核心**：**IDOR/越权**(R-04)、**认证绕过**(R-05)、**API 安全增强 + GraphQL**(R-06)；多引擎生效(R-09，nuclei 默认开) | R-04, R-05, R-06, R-09 |
| **P4 规模化·安全·生态** | ~1.5 sprint / 7 人天 | 缓存/响应体/重定向约束、SSRF+profile 遍历+WebUI 加固、扫描前授权确认 + gentle 预设 | **SSTI/CSRF/开放重定向/RFI**(R-07)、**授权确认+合规预设**(R-10，**开源前置，升权**)；R-11/R-12/R-13 降权为可选/社区驱动（移出核心人天） | R-07, R-10 |

---

## 4. 需求池（P0/P1/P2，归一化）

**P0（近期必做，阻断级）**
- R-01 `httpx`/`flask` 依赖声明修复 —— 阻断安装（P0）
- R-02 测试纳入版本管理 + 补 sqli/xss 核心用例（P1）
- R-03 版本号统一(2.0.0) + SARIF/CSV 静默失效修复（P0/P1）

**P1（近期/中期，自研为核心）**
- R-04 IDOR / 越权检测（P3，企业最常漏，最高价值）⭐
- R-05 认证绕过检测（P3）⭐
- R-06 API 安全增强（越权/批量/速率）+ GraphQL（P3）⭐
- R-07 SSTI / CSRF / 开放重定向 / RFI（P4）
- R-08 并发可配置化（破除硬编码 2）（P2）
- R-09 integrations/ 接入主流程（P3，可选增强：nuclei 默认开、其余 `--enable`）
- R-10 授权确认 + gentle 合规预设（P4，开源发布前置，升权）

**P2（长期，降权为可选/社区驱动，不占核心人天）**
- R-11 Web UI 与 CLI 能力对齐（P4，**降权**：社区驱动/后续可选，最低优先）
- R-12 MSF 验证链落地（P4，**降权**：自研优先+开源下推迟）
- R-13 多引擎聚合深化（P4，**降权**：仅保留 nuclei 等已接部分，awvs/nessus/wappalyzer 维持 `--enable`）

> ⭐ = 自研内核优先方向下的核心交付

---

## 5. 关键架构决策（草图）

- **模块加载统一**：各 detector 顶部 `@register_module`；`ModuleFactory.create_all()` 遍历注册表实例化；删除 `WAVScanner.load_module()` 的 `__import__` 兜底与 `_MODULE_PRIORITY` 硬编码（改配置/Profile 驱动）。
- **流水线编排**：定义 `ScanStage` 接口 `async def run(ctx) -> StageResult`；`Orchestrator` 持 `List[ScanStage]`，`Auth`/`Dedup`/`Checkpoint` 为内建 stage，靶场逻辑抽为可选 `--lab` stage。
- **集成抽象**：`class Integration(ABC): name; async def run(target, ctx)` + `IntegrationRegistry`，引擎无关注入；**默认仅启用 nuclei，其余显式 `--enable`**（ffuf/sqlmap 默认关，贴合合规）。
- **HTTP 统一**：核心统一 `AsyncClient(http2=True, verify=config.verify_ssl)`；**aiohttp 隔离至外调适配层、默认禁用**，保留聚合选项（非全删）。
- **并发模型**：全局 `Semaphore(cfg.concurrency)` + `--concurrency` + 预设 `gentle≈2-3 / default≈5-10 / aggressive`，硬上限受速率合规约束（破除硬编码 15/12）。
- **缓存策略**：`LRUCache(maxsize=2000, ttl=300)` 存 `(status, headers_hash, body_hash)` 轻量元组，替代完整 `httpx.Response` 缓存。
- **安全加固**：目标 `scheme∈{http,https}` 且 IP 非私网/链路本地/`169.254.169.254`；Profile `name` 白名单 `^[A-Za-z0-9_-]+$`；`verify=False` 仅 `--insecure` 时允许并告警。

涉及核心文件：`wvs/core/scanner.py`、`wvs/core/base.py`、`wvs/modules/__init__.py`、`wvs/core/orchestrator.py`(新)、`wvs/core/auth_manager.py`(新)、`wvs/core/dedup.py`(新)、`wvs/core/checkpoint.py`(新)、`wvs/core/session.py`、`wvs/core/integrations/`(新抽象)、`wvs/cli.py`、`wvs/profiles/loader.py`、`wvs/web_ui/app.py`、`pyproject.toml`、`Dockerfile`、`.github/workflows/ci.yml`。

---

## 6. 依赖与工程化治理

- **`pyproject.toml`**：`[project.dependencies]` 补 `httpx>=0.27,<0.29`、`flask>=3`；`[project.optional-dependencies].dev` 仅 `ruff`/`mypy`/`pytest`；删除 `requirements-dev.txt`（black/isort/flake8 统一为 ruff）。
- **锁文件**：`uv` 生成 `uv.lock`，CI 校验可复现。
- **CI 门禁**：`ruff` + `mypy`（关键模块 `--strict`）+ `pytest` 覆盖率门槛（先 30%，逐步提升至 50%+）。
- **Docker**：builder 装 dev 依赖，runtime 仅 `dependencies`+`httpx`，非 root 运行。
- **版本单一源**：`wvs/__init__.__version__ = "2.0.0"` 为唯一来源，CLI/报告/pyproject 读取，勿单列外发版本。

---

## 7. 成功指标 / KPI（可量化）

| 指标 | 现状 | 目标 |
|------|------|------|
| 覆盖漏洞类 | ~22 类 | 近期 24 类 → 中期 ≥30 类 |
| 误报率 | 未建基线 | < 8%（先建基线测试集） |
| 漏报率（基准集） | 未建基线 | < 15% |
| 测试覆盖率 | 核心 sqli/xss 0% | sqli/xss ≥70%，总体 ≥50% |
| 安装成功率（pip/Docker/CI） | 失败 | 100% |
| 扫描吞吐 | 并发=2 | 并发可配后 ≥3× |

---

## 8. 里程碑 Timeline（Mermaid 甘特）

```mermaid
gantt
    title RayScan 技术演进里程碑（52 人天）
    dateFormat  YYYY-MM-DD
    axisFormat  %m/%d
    section P0 止血
    httpx/flask 依赖 + smoke test      :p0, 2026-07-15, 8d
    section P1 工程化地基
    单版本源 + 锁文件 + CI + Docker      :p1, after p0, 10d
    tests 入库 + sqli/xss 单测           :p1b, after p1, 5d
    section P2 架构解耦
    模块加载统一(ModuleFactory)          :p2a, after p1b, 6d
    拆 WAVScanner + Orchestrator         :p2b, after p2a, 12d
    统一 httpx(http2) + aiohttp 隔离     :p2c, after p2a, 8d
    section P3 能力扩展
    integrations 接入(可选增强)+SARIF    :p3a, after p2b, 8d
    IDOR/越权 + 认证绕过 + API/GraphQL   :p3b, after p3a, 12d
    section P4 规模化·安全·生态
    缓存/响应/重定向约束 + SSRF 加固      :p4a, after p3b, 8d
    SSTI/CSRF/开放重定向/RFI + 授权确认   :p4b, after p4a, 7d
    Web UI/MSF/聚合深化(可选,社区驱动)    :p4c, after p4b, 5d
```

---

## 9. 已定战略决策与校准结论（原"待确认事项"）

> 瑞哥已于 2026-07-12 拍板 4 项战略决策，架构师据此完成二次校准（详见 `docs/rayscan_evolution_roadmap.md` §6）。

**A. 已定战略决策**
1. **战略方向 = 自研内核优先** —— 聚焦检测精度 + 合规安全护城河；聚合仅作可选增强。
2. **商业模式 = 先开源** —— GitHub 开源，吸引社区与背书；MSF/Web UI 可在开源基础上迭代。
3. **目标用户 = 安全研究员 / 渗透优先** —— CLI/报告/文档贴合该群体，DevSecOps 降为兼顾。
4. **版本号 = 统一 2.0.0** —— pyproject 为单一事实源（SSOT），CLI/报告派生读取。

**B. Provisional 默认（经复核全部保留，与新决策一致）**
- 版本 SSOT = pyproject 2.0.0 ✅
- aiohttp 隔离至外调适配层、默认禁用（非全删）✅
- 集成默认策略 = nuclei 默认开、其余需 `--enable`、ffuf/sqlmap 默认关 ✅
- 并发 = Semaphore(cfg.concurrency) + `--concurrency` + 预设 gentle/default/aggressive，硬上限受合规约束 ✅
- 靶场逻辑改可选 `--lab` stage ✅

**C. 范围翻转（因决策 1/2/3）**
- **P3 升权**：IDOR/越权(R-04)、认证绕过(R-05)、API 安全+GraphQL(R-06) 列为绝对核心，经 `@register_module` 注册进 `ModuleFactory`。
- **P4 降权（移出核心人天）**：R-11 Web UI、R-12 MSF 验证链、R-13 聚合深化 → 可选/社区驱动。
- **P4 升权**：R-10 授权确认 + gentle 合规预设 → 开源发布前置条件，优先级靠前。
- **P4 人天 10 → 7**（总工期 55 → 52）。

**D. 仍开放的技术细节（非战略级，按合理默认推进，无需再拍板）**
- Python 版本下限：建议 `>=3.10`（asyncio 改进、httpx 对齐）。
- `concurrent_endpoints` 15/12：作为 `aggressive` 预设参考值，最终由 `--concurrency` 暴露。

---

## 10. 交付物索引

- 本统一规划：`docs/audit/rayscan-evolution-plan-2026-07-12.md`
- 架构师技术详档（含二次校准）：`docs/rayscan_evolution_roadmap.md`
- 审计原始报告：`docs/audit/rayscan-codebase-audit-2026-07-12.md`

---

## 11. 战略修正（v1.2 · 2026-08-05）— OA 专项 + 工作流闭环

### 11.1 修正背景：鸡肋诊断

v1.1 的「自研内核优先」执行 1 个月后，2026-08-05 实战能力复审（检测引擎 + 主流程双路深度审查）揭示结构性矛盾：

1. **差异化真空**：在通用扫描器赛道上，Nuclei（模板生态）/ ZAP（SPA 爬取 + 会话持久化）/ Burp（检测深度）均为免费代差级对手；RayScan 任何单一维度都打不赢。
2. **"自研内核优先"的假设不成立**：原假设"自研比纯调度更可控"，但审查证实自研内核正确性恰恰是最弱环节——OA"状态码即漏洞"、XXE/SSRF 无 baseline、DOM XSS 假阳性、Nuclei 回退"可达即报"，实战误报洪水。
3. **P3 绝对核心（IDOR/越权/认证绕过自研）是全行业最难的方向**：连商业扫描器都做不好逻辑漏洞检测，solo 团队 12 人天大概率产出高误报、不可验证的模块。
4. **卖点与能力脱节**：README 宣称"多引擎聚合"为死代码、OA 专项检测名不副实、MSF 验证链未闭环；v2.0.0 已满 1 个月未发版。

### 11.2 修正后的定位（2026-08-05 拍板）

> **RayScan = 中文 OA/国产应用专项检测器 + 一条命令的实战扫描工作流**
> 唯一差异化资产 = 12 种中文 OA 指纹/路径字典（Nuclei 覆盖稀疏、Xray 社区版无 OA 专项、AWVS 收费）
> 不追求任何单项超越免费竞品，而是修好"爬取 → 检测 → 聚合 → 报告"链条，兑现卖点。

**B. 修正后的范围取舍**

| 方向 | 决策 |
|------|------|
| OA/国产应用专项（指纹→版本→验证三级链路）| ⭐ 核心，投入 6 人天深化 |
| 工作流链条（nuclei 接入默认开 / checkpoint 复活 / 误报治理）| ⭐ 核心，投入 7~8 人天 |
| 自研 IDOR/越权/认证绕过/API+GraphQL（原 P3 绝对核心 R-04/05/06）| ❌ 砍掉，降为远期探索 |
| SPA 爬取 | ❌ 承认短板（ZAP 已有），不做 |
| MSF 验证链（R-12）、Web UI 深化（R-11）| ⏸️ 维持降权（可选/社区驱动）|
| Nuclei 模板生态 | 接入并使用，不自建（R-09 升为必做）|

**C. 修正后 3 个月执行计划（≈14~16 人天，替代原 P3/P4）**

| 阶段 | 投入 | 交付 | 验证指标 |
|------|------|------|---------|
| S1 发版前修复 | 3~4 人天 | ①Nuclei 回退"可达即报"加内容校验 ②OA 状态码判定改为特征验证 ③XXE/SSRF 加 baseline 排除 ④DOM XSS 降级 beta/移除 ⑤README 撤下未兑现卖点 | 误报源清零，复测通过 |
| S2 链条接通 | 3~4 人天 | ①nuclei 接入 `scan()` 默认开 ②修模板选择父目录 bug（nuclei_integration.py:207-218）③checkpoint/`--resume` 复活（scanner.py:610-643 + cli.py:167-173）| `--resume` 实测可恢复 |
| S3 OA 专项深化 | 6 人天 | 指纹识别→版本判定→漏洞特征验证三级链路；现有 12 种 OA 正确性修正；规则可扩展（YAML 规则文件候选）| 每种 OA ≥1 真实/靶场样本验证记录 |
| S4 发布与实测 | 2 人天 | 打 v2.0.0 tag 发 release；3~5 个授权目标实战误报/覆盖记录入 README | 社区可复现、误报率有据 |

**D. 已确认的代码级修复清单（源自 2026-08-05 双路审查）**

- 误报治理：`nuclei_integration.py:714-768`（可达即报）、`oa/detector.py:276-299/294-297`（状态码即漏洞 + 401/403 误判）、`xxe/detector.py:398-431`（无 baseline）、`ssrf/detector.py:414-418`（无 baseline）、`xss/detector.py:548-590`（DOM XSS 假阳性）
- 死代码：checkpoint（`scanner.py:610-643`、`cli.py:167-173`）、scanner 内建认证 `_do_authenticate`（`scanner.py:214-271`）、stacked-query time 死分支（`techniques_mixins.py:587-601`）、`cmdi/detector.py:517` echo-blind 死分支
- 实战限制：SPA 硬编码关闭（`crawler.py:360-365`）→ 改为 `--js-render` 可配置开启（保留但降级，社区驱动）、参数膨胀（`crawler.py:747-808`）→ 非反射参数移入盲测队列而非全量检测、公网 IP 误判靶机（`lab_profiles.py:370`）→ 私网网段精确匹配
- 接线：integrations 接入 `scan()`（nuclei 默认开，其余 `--enable`）、模板精筛修复（`nuclei_integration.py:207-218`）

**E. 对 v1.1 的继承与变更**
- 继承：P0/P1 已闭环 ✅；P2 架构解耦仍有效但顺延；授权确认 + gentle 合规预设（R-10）仍是开源发布前置；版本 SSOT = pyproject 2.0.0。
- 变更：R-04/05/06 从"绝对核心"降为远期探索；R-09 从"可选增强"升为 S2 必做；R-13 聚合深化维持降权。
