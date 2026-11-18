# ADR-0002：产品边界与可选能力

- 状态：Proposed（2026-11-18）
- 版本：v1
- 决策人：项目作者
- 关联：ADR-0001（OA 专项定位）、`docs/audit/rayscan-s4-trust-rebuild-2026-08-24.md`、`docs/TECH_DEBT.md`
- 目的：把 ADR-0001 的定位落到**可执行的边界**，结束“冻结但持续开发”的状态。

## 1. 背景

2026-08-24 的 ADR-0001 把 RayScan 收缩为“中文 OA / 国产中间件专项检测器”，并明确砍掉 Web UI 深化、IDOR/认证绕过、SPA 爬取、多引擎聚合、MSF 验证链。

但后续提交（v2.2 T2.3/T2.5、v2.3 T3.5）又持续投入了 DOM XSS、双账号 IDOR、Web UI 对齐 CLI；同时 v19.2 的 `scheduler/session_manager/cache/encoding_bypass`、v2.0 的多引擎集成层仍留在仓库，形成三类成本：

1. **理解成本**：21 个模块、7 个集成、2 套 UI、3 套配置来源，贡献者无法判断哪条是主线。
2. **维护成本**：没有调用方的代码持续被格式化、类型检查、版本号更新。
3. **信任成本**：README/架构文档与实际能力不一致，回归（resume/gentle/all-modules）长期未被发现。

本 ADR 不再重复“做什么”，而是定义**什么算核心、什么算可选、什么必须删除**，并把这些边界变成 CI 不变量。

## 2. 决策

### 2.1 核心产品

> RayScan 核心 = **中文 OA / 国产中间件专项检测 + Nuclei 通用兜底 + 证据包工作流**。

核心必须始终满足：

- 一条命令完成“扫描 → 证据 → 可重放报告”；
- 每条 finding 有 `evidence` 与 `replay`；
- 默认低干扰（gentle 预设真实生效）；
- 黄金矩阵 FP/FN 门禁通过。

### 2.2 核心依赖边界

核心（`wvs/kernel`、`wvs/domain`、`wvs/app`）只允许依赖：

- `httpx`、`pyyaml`、`beautifulsoup4`、`lxml`、`rich`、`aiohttp`（OOB/兼容适配）；
- Python 标准库。

以下能力**不得**成为核心依赖，只能作为 optional extra / 独立包：

| 能力 | 形态 | 约束 |
|---|---|---|
| Web UI | `pip install "rayscan[web]"` | 不进入核心 `dependencies`；`wvs/core` 不得 import `flask/web_ui` |
| AI 复核 | `pip install "rayscan[ai]"`（或纯配置开关） | 无 key 时静默跳过；不阻塞扫描 |
| MCP Server | `pip install "rayscan[mcp]"` | 不在 CLI 默认路径 |
| Exploit | `pip install "rayscan[exploit]"` / 独立包 | 默认不可导入；CLI 双重确认；不得被核心 import |
| Headless DOM XSS / SPA | `pip install "rayscan[jsrender]"` | 缺失时降级并标注“未检测” |

### 2.3 明确移除 / 冻结

| 资产 | 决策 | 理由 |
|---|---|---|
| `core/scheduler.py`、`core/session_manager.py`、`core/cache.py`、`core/encoding_bypass.py` | **删除** | v19.2 遗产，无生产调用方 |
| `modules/waf/bypass_payloads.py`、`modules/lite/` | **删除** | 无引用 / 注册入口已废弃 |
| `integrations/msf_integration.py` | **删除** | 仅 `check-engines` 探活，无扫描路径 |
| 多引擎聚合（AWVS/Nessus/sqlmap/ffuf） | **移出主线** | 与 OA 专项定位冲突；保留则必须作为独立包并补测试 |
| IDOR / AuthBypass | **冻结**（仅修 bug） | ADR-0001 已冻结；不再扩功能 |
| SPA / `--js-render` | **冻结** | 维护成本高，非 OA 差异化；仅保留既有能力 |
| Web UI 深化 | **暂停** | 先完成内核门禁；Web UI 只做与 CLI 对齐的必要修复 |
| Python 3.8 | **弃用** | EOL 且 CI 未覆盖；支持矩阵为 3.9–3.12 |

> “冻结”= 不再新增功能、不再扩测试面；出现安全/正确性缺陷仍修。

### 2.4 CLI 与内核

- `cli.py` 只做参数解析、输出、退出码；业务编排下沉到 `wvs/app/`。
- `WAVScanner` 保留为兼容 facade；新代码依赖 `ScanContext` + `Stage` 协议，不直接调用 scanner 私有方法。
- `wvs/core` 不得 import `web_ui/ai/mcp_server/exploit`；唯一允许的集成是 `integrations.nuclei_integration`。

## 3. 适应度函数（CI 可执行）

| ID | 不变量 | 阈值 | 检查 |
|---|---|---|---|
| FF1 | 核心不硬依赖可选层 | 0 违规 | `tests/test_architecture.py::test_core_does_not_hard_import_optional_layers` |
| FF2 | 已删除资产不复活 | 0 | `test_legacy_file_stays_removed` / `test_legacy_module_is_not_importable` |
| FF3 | 黄金矩阵 FP/FN | guardrail FP=0；must_detect FN=0 | nightly `run_golden_matrix.py` |
| FF4 | 每条 finding 可重放 | replay 成功=100% | `tests/test_evidence_pack.py` + 矩阵 |
| FF5 | gentle 预设真实限速 | ≤3 req/s | CLI/单元断言 `max_requests_per_second` |
| FF6 | 发布包完整 | wheel smoke 通过 | CI `Wheel smoke` |
| FF7 | CLI 不增长 | ≤1800 行（目标 600） | `test_cli_size_budget` |

> FF1/FF2/FF6/FF7 已落地；FF3/FF4/FF5 在 v2.3.1 修复后由现有测试与 nightly 覆盖。

## 4. 后果

正面：

- 贡献者只需理解一条主线：规则 → 证据 → 报告。
- 依赖面缩小，安装/打包/CI 更快，`pip install` 不再携带 Flask/Playwright。
- 删除无调用方代码后，重构/升级的回归面显著下降。

负面：

- Web UI/AI/MCP 不再是“开箱即用”，需要显式 extra。
- 多引擎用户需要改用 Nuclei 或独立编排。
- 短期内文档/入口需要同步，存在迁移成本。

## 5. 迁移与兼容

1. `wvs` 包名、`wvs-report-v1` 报告 schema、CLI 命令保持兼容。
2. `WVS_*` 环境变量进入弃用周期：保留读取 + 警告，下个 major 移除。
3. Web UI 改为 `rayscan[web]`；`python web_ui/app.py` 仍可用（源码安装）。
4. Exploit 改为显式 extra；库调用方必须显式 import 子模块，CLI 仍需 `--i-have-permission` + `RAYSCAN_ENABLE_EXPLOIT=1`。
5. 多引擎/IDOR/AuthBypass 的删除或冻结在 v2.3.x 内完成；需要恢复时先重开本 ADR。

## 6. 可逆性与重新考虑条件

本 ADR 是**双向门**：删除的是无调用方代码，恢复成本主要是重写适配层。满足任一条件应重开本 ADR：

1. OA 规则闭环连续两个版本无增长，且社区明确要求通用扫描能力；
2. 获得持续的多维护者投入，单人带宽约束消失；
3. Web UI 成为主要使用入口（有可验证的使用数据），且核心门禁已稳定；
4. Nuclei 社区系统性覆盖国产 OA，OA 差异化窗口关闭。

## 7. 责任

- 决策责任人：项目作者。
- 执行检查：CI 的 `architecture` / `package` / `nightly matrix` 三个 job；每季度回顾一次本 ADR 与 `docs/TECH_DEBT.md`。
- 冲突处理：新功能若违反 FF1/FF2，必须在本 ADR 中登记例外，否则 PR 不合并。
