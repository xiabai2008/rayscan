# RayScan 升级路线规划（2026-09-07）

> 承接 `docs/audit/rayscan-evolution-plan-2026-07-12.md` §11 战略修正（**OA 专项 + 工作流闭环，替代自研内核优先**）与 `docs/rayscan_evolution_roadmap.md`（P0–P4 已基本落地）。
> 本版路线以 **检测可信度** 为唯一主线：扫描器的价值不在模块数量，而在**误报率（FP）/漏报率（FN）这两个数字**。

## 0. 当前基线（2026-09-07）

| 维度 | 现状 |
|---|---|
| 规模 | wvs/ 30,378 行，18 个检测模块，259+ 测试函数，CI 覆盖率门禁 30%（实测 33.5%） |
| 差异化 | OA 三级检测链路（指纹→版本→规则级证据+版本过滤）；`--explain` 证据链；gentle 合规预设 |
| 被动扫描 | **HTTPS 解密已打通**（本次 `--tls-intercept`），并修复 CONNECT 隧道回环历史 bug |
| 主要短板 | core 层单测薄弱；rules/ 近空；被动流量尚未联动主动验证；DOM XSS 无真实检测；多账号业务逻辑缺失；登录态维护缺失 |

今日已完成：真实扫描报告入库排查（证实未入库）、CI 覆盖率门禁做实 + format 门禁转绿、被动代理 TLS 拦截 + 隧道修复（commit `a68c6e1` / feat 提交）。

## 1. 战略判断（为什么这么排）

1. **可信度 > 功能数**。安全工具的口碑崩塌只需一次高调误报。S1 误报治理（baseline/证据验证）方向正确，但缺**制度化度量**：没有基线数字，每次重构都可能悄悄劣化。下一阶段的全部工作必须能回答"FP/FN 变好了还是变坏了"。
2. **OA 专项是护城河**（延续 §11 决策）：Nuclei 已覆盖通用漏洞，通用型扫描器没有差异；国产 OA/中间件的指纹库、版本-漏洞映射、规则级证据是真实痛点（护网、SRC、内网评估），且社区缺高质量开源实现。`docs/OA_RULES.md` 的"实战验证记录表"必须闭环。
3. **被动扫描刚从"能看"变成"能用"**：HTTPS 解密打通后，被动流量的价值在于**登录后业务深处的真实参数**——把它变成主动扫描的输入（passive→active 联动），才是闭环。
4. **证据链是 SRC 工作流的核心资产**：`--explain` 已产出 evidence_chain，差最后一公里——可直接提交/重放的证据包。
5. **先纵深后宽度**：不再新增通用漏洞类型模块（SSTI/CSRF 等小模块优先级降低），把现有 18 个模块做深做准。

## 2. 分阶段路线

> **执行状态（2026-09-09 更新）**：v2.2 的 T2.1/T2.2/T2.3/T2.4/T2.5 已全部落地
> （黄金矩阵 20/20、nightly 门禁、domxss headless、登录态维持、双账号 IDOR），
> 并额外修复 10 个矩阵暴露的真实缺陷（详见 CHANGELOG [Unreleased]）。
> **⑩ 已完成（2026-09-09）**：scan() 内联爬扫循环/checkpoint/resume 全部迁入编排器 Stage，
> scan() 收敛为单趟流水线 facade，编排层吞异常收紧为可观测（ctx.stage_failures → result.errors）；
> 410 测试全绿 + 黄金矩阵 sqli/idor 冒烟通过。
> **⑪ 已完成（2026-09-12）**：v2.3 四件全部落地（T3.1 联动 / T3.2 证据包 / T3.3 规则外部化 / T3.4 模板策展），
> 另完成 **T3.5 Web UI 对齐 CLI**（passive 捕获队列闭环 / explain 证据链 / profile 应用保存 / 五类认证）。
> v2.3 收尾，版本升 2.3.0。

### v2.2 — 实测闭环（检测可信度制度化）⏱ ≈2 周 ✅ 已完成

**目标：每个模块有可复现的 FP/FN 基线数字，且 CI 阻止劣化。**

| 任务 | 说明 | 验收标准 |
|---|---|---|
| T2.1 黄金靶场矩阵 | `demo_lab` 扩展为独立靶场集：DVWA/Pikachu（docker compose）+ 自建 OA 仿真站（Nacos/泛微样式页 + 版本头），覆盖全部 18 模块的"应有检出"用例 | `rayscan scan --lab` 一条命令跑完矩阵，输出 per-module 检出/误报矩阵 |
| T2.2 FP/FN 基线入库 | 基线数字写入 `docs/BASELINES.md`；CI 对黄金靶场结果做断言（检出集合不变、误报集合为空） | CI 新增 `lab-regression` job；基线变更需在 PR 说明原因 |
| T2.3 真实 DOM XSS | Playwright（新 extra `rayscan[headless]`）驱动 headless Chromium，hook `innerHTML/document.write/location` sink，替代被移除的伪检测 | 对含 DOM sink 的靶场页检出，良性页不报 |
| T2.4 登录态维持 | `HTTPPool` 会话层：401/302-to-login 自动重登（凭据由 auth profile 提供）、token 刷新 | 扫描全程不掉登录态（靶场验证：受保护页面持续可达） |
| T2.5 双账号 IDOR | idor 模块增加第二会话对比模式（A 账号资源 → B 账号访问 → 真实越权验证），替代当前的单会话对象替换（误报源） | 双账号下横权检出；单账号模式保留但标注"疑似" |

**工程伴随**：`WAVScanner.scan()` 内联的爬取-检测循环与 checkpoint/resume 迁入 Orchestrator stage（消灭最后的 god-class 残留）；core 层（crawler/session/rate_limiter）补单测，覆盖率门禁 30%→35%。

### v2.3 — 工作流闭环（从"扫出漏洞"到"交付报告"）⏱ ≈2 周

**目标：一次扫描的产出能直接进入 SRC 提交/渗透报告流程。**

| 任务 | 说明 | 验收标准 |
|---|---|---|
| T3.1 passive→active 联动 | 被动捕获的端点/参数入队，`--from-proxy` 对队列做定向主动验证（复用现有模块，限速合并） | 浏览器代理浏览 10 分钟后，主动扫描仅针对真实参数面，耗时 < 全量爬扫 |
| T3.2 证据包导出 | `rayscan report --pack`：每漏洞生成 markdown + curl 重放命令 + evidence_chain + SARIF，打包为可提交目录 | 每条漏洞可用导出的 curl 一键复现 |
| T3.3 OA 规则包 | `rules/` 从近空到可用：按 `docs/OA_RULES.md` 检测矩阵补齐规则文件（YAML 化，含 evidence/max_version 元数据），`rayscan rules update` 接 git 源 | OA 模块全部检测项由外部规则驱动；新增 OA 只需加规则不改代码 |
| T3.4 Nuclei 模板策展 | 按 OA 指纹（`OA_FINGERPRINTS` 已有 12 种）自动挑选对应 tags/路径模板，淘汰泛匹配 | 模板选择结果随报告输出（可审计） |
| T3.5 Web UI 对齐 CLI | ✅ web_ui 补 passive/explain/profile 三能力入口（社区可协作的显式切面） | UI 可发起带认证的扫描并查看证据链 |

### v3.0 — 规模化与生态 ⏱ ≈1 个月（可社区并行）

- **HTTP 栈统一**：核心统一 httpx(async)，requests/aiohttp 隔离至适配层（完成旧 P2-T2.3 遗留）。
- **批量/分布式**：`batch` 升级为队列驱动（redis/文件队列），checkpoint 可跨进程恢复。
- **mypy 渐进严格**：core/ 与 modules/base.py 先进 `disallow_untyped_defs`，CI types job 从 advisory 转 blocking（TD-003 关闭路径）。
- **覆盖率门禁爬坡**：35% → 45%，配合 TD-008（core 单测）整改。
- **社区规则生态**：规则仓库独立 + `rule_contribution.yml` 流程跑通；`CONTRIBUTING` 增加"一条 OA 规则的完整贡献示例"。

## 3. 度量（每个版本发布必须回答）

1. 黄金靶场 FP/FN 矩阵（per module，与上一版对比）。
2. OA 指纹覆盖率：12 → 目标 20+ 种（以 `docs/OA_RULES.md` 实测记录为准）。
3. 真实环境扫描时长中位数（gentle/default 档）与请求数 P95。
4. CI 门禁状态：coverage、ruff、format、（v3.0 起）mypy 全绿。

## 4. 明确不做（本轮）

- 自研漏洞内核替代 Nuclei（§11 决策维持）。
- AWVS/Nessus/MSF 集成接主流程（保持 Roadmap，等社区驱动）。
- 主动重放/改写用户流量的被动代理（保持单向，避免过度工程与合规风险）。
- HTTP/2、TLS 指纹伪装等对抗性增强（需求出现后再排期）。

## 5. 风险与缓解

| 风险 | 缓解 |
|---|---|
| 靶场矩阵维护成本高 | 靶场即测试夹具（tests 共用），单容器 compose 起停 |
| TLS 拦截被安全软件告警 | 文档明示授权使用边界；默认关闭，`--tls-intercept` 显式开启 |
| 被动→主动联动放大扫描强度 | 队列强制走 RateLimiter + gentle 预设上限，`--target` 过滤延续 |
| Playwright 重依赖 | 独立 extra `headless`，缺失时跳过 DOM XSS 并在报告中标注"未检测" |
