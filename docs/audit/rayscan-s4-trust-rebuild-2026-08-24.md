# S4 信任重建执行清单

- 版本：v1（后续迭代另立 v2，不覆盖本文件）
- 日期：2026-08-24
- 依据：ADR-0001（`docs/adr/0001-oa-focused-repositioning.md`）+ 2026-08-24 三路项目审查
- 目标：把"宣称层"与"交付层"对齐。S4 完成前**不发新版本**。
- **执行状态（2026-08-24）**：T1–T5 已完成；T3 嵌套目录项已完成（2026-08-24 归档至 `C:\Users\HZR\Desktop\HZR_PROJECTS\RayScan-archive-2026-08-24\`，含完整 git 历史与 `delivery/` 独有设计文档）；T6 待办——v2.1.1 发布条件：①本地全绿 ②推送后 CI 五个 job 全绿。执行明细见 AGENTS.md Change Log 同日条目。附带发现并修复：`test_version_consistency` 依赖 tomllib（Py3.11+）与 `requires-python>=3.8` 矛盾，CI 3.9/3.10 job 必挂，已改正则解析。

## 背景摘要（为什么做 S4）

| 编号 | 问题 | 证据 |
|------|------|------|
| B1 | 宣称数字失真 | README 写 190 测试，实测 `pytest --collect-only` 收集 259；CHANGELOG 测试数在 281→190→211 间反复跳动，无单一事实源 |
| B2 | OA 专项闭环 0/12 | `docs/OA_RULES.md` §5 验证表全部"待实测"（S5 解决，本清单只修文档口径） |
| B3 | 仓库结构混乱 | 嵌套 `RayScan/` 旧副本（578 文件，未跟踪）、僵尸入口 ×3、文档与代码脱节（modules.md 写 11 模块，实际 18+） |
| B4 | CI 门禁缺口 | 无 pip-audit/CodeQL，无覆盖率阈值，mypy 非阻塞（`continue-on-error`） |

---

## 任务清单

> 约定：每项含【动作】【验收标准】【验证方式】。标 ⚠️ 的是破坏性操作（删文件/动 git），执行前需作者确认。

### T1 · README 宣称修正（FF2）

- [ ] 重新统计测试数：`python -m pytest tests --collect-only -q`，以**当次实测**为准（2026-08-24 审查时为 259，落笔前必须重跑）
- [ ] 修正 `Tests-190 passing` 徽章：改用动态徽章（CI 工作流徽章已具备），或如实更新数字并去掉静态 passing 字样（收集数 ≠ 通过数，除非 CI 全绿，否则不写 passing）
- [ ] 版本历史表排序修正：当前 2.1 排在 2.0 之前
- [ ] 顶部定位语按 ADR-0001 改写：「中文 OA / 国产中间件专项检测器」为第一定位，"全栈扫描器"降级为辅助描述
- [ ] "Metasploitable 2 实战验证发现 83 个漏洞"补链接到可复核的证据（报告文件/截图），否则降格为"靶机验证"措辞
- **验收**：README 中每一个可数字化的声明都有可复核来源；无静态夸大徽章
- **验证**：`git diff README.md` 逐行自查 + 对照本清单 B1 行

### T2 · 陈旧文档重写或删除（FF6）

- [ ] `docs/modules.md`：按实际 18+ 模块目录重写（补 oa/idor/authbypass/subdomain/weakpass/webshell/js_analysis/lite 及 core/oob、core/passive 子包），或直接删除并指向 README 模块表（二选一，推荐重写——它是贡献者的第一入口）
- [ ] `docs/architecture.md`：文件路径全部核对（`nuclei_runner.py` → `nuclei_integration.py` 等 4 处；补 awvs/nessus/msf 集成与 oob/passive 子目录）
- [ ] 新建 `CONTEXT.md`（仓库根，按 `docs/agents/domain.md` 约定）：领域词汇表（靶机/实战分流、三级检测链路、闭环率、误报治理、Lite 模块）——后续 issue/PR/测试命名统一用语
- **验收**：文档中出现的每个文件路径都能在仓库中找到；模块数与 `wvs/modules/` 目录一致
- **验证**：抽查文档中 5 个路径 `Test-Path` 均为 True；模块数与目录计数一致

### T3 · 僵尸资产出仓（FF6）⚠️

- [ ] ⚠️ 删除 `full_scan.py`——僵尸入口 + 第 30 行泄漏个人绝对路径（该路径已随历史公开，删文件止损；如需彻底清除需重写 git 历史，属重操作，单独立项决定）
- [ ] ⚠️ 删除 `quick_scan.py`（硬编码靶场地址 + 旧 API `load_all_modules()`）
- [ ] ⚠️ 删除 `wvs_gui.py`（README 已声明停止维护；29KB 死重量）——若想留档，移入 `docs/legacy/` 而非保留在根目录
- [ ] ⚠️ 本地嵌套 `RayScan/` 目录（578 文件的旧副本，未被 git 跟踪）：**由作者亲手**移出仓库目录归档（如移至 `~/Desktop/HZR_PROJECTS/RayScan-archive-2026/`），不使用 rm 递归删除
- [ ] README 项目结构图同步移除已删条目
- **验收**：根目录仅剩 `AGENTS.md`、`README.md`、`CHANGELOG.md`、`pyproject.toml` 等正式文件；`git ls-files` 无僵尸入口
- **验证**：`git ls-files | Select-String -Pattern "scan.py|gui"` 为空；嵌套目录不存在

### T4 · CHANGELOG 数字单一事实源（FF2）

- [ ] CHANGELOG 历史条目中的测试数**不回改**（历史就是历史），但在文件顶部加一行说明：「自 v2.1.0 起测试数以 CI collect-only 实测为准，历史数字为当时口径」
- [ ] 建立"宣称数字来源"规则：对外数字只允许出自 CI 产物（测试数、覆盖率），不手写
- **验收**：新增条目模板里包含"测试数（来源：CI）"字段
- **验证**：读 CHANGELOG 顶部说明存在

### T5 · CI 门禁加固（FF5 前置）

- [ ] `ci.yml` 增加 pip-audit job（push/PR 触发，扫 `requirements.lock.txt`）
- [ ] mypy job：`continue-on-error: true` 收窄为仅 `wvs/core/` 目录阻塞，其余仍 advisory（避免一次性修复全部类型问题）
- [ ] 覆盖率起步门禁：`--cov-fail-under` 设为**当前实测值取整减 2**（先止血下降趋势，不追 80% 目标——那是 v1.2.0 的事，需先跑一次拿基线）
- [ ] 增加仓库卫生检查 step：`git ls-files` 对照白名单（无 `.pyc`/`.coverage`/`scan_reports`/嵌套目录）
- **验收**：CI 红/绿有实际拦截力；pip-audit 在依赖有 CVE 时会红
- **验证**：推一个含 `except Exception: pass` 的临时提交看 FF5/门禁是否拦截（验证后回滚）

### T6 · 发布口径冻结

- [ ] S4 全部完成前不打 tag、不发 Release
- [ ] S4 完成后先发 **v2.1.1**（修补版本：文档修正 + 仓库清理 + CI 加固，无功能变更），作为"宣称=交付"的第一个锚点版本
- **验收**：v2.1.1 Release Notes 逐条对应本清单完成项

---

## 执行顺序与依赖

```
T3（清僵尸）→ T2（重写文档，路径才不会指向已删文件）→ T1（README 最后改，引用新文档）
T4、T5 独立，可穿插
T6 收尾
```

## 总验收标准（S4 Done 的定义）

1. FF2 达成：README 所有数字可复核
2. FF6 达成：`git ls-files` 无僵尸入口，嵌套目录消失
3. CI 具备：pip-audit + core 目录 mypy 阻塞 + 覆盖率下限 + 仓库卫生检查
4. `CONTEXT.md` 与 ADR-0001 存在且被 README 引用
5. 发布 v2.1.1

## 不在 S4 范围内（防蔓延）

- OA 规则实测闭环 → S5
- CLI 瘦身 / Stage 化 → S6
- git 历史重写（清除已泄漏路径）→ 单独立项评估
- Web UI 任何功能开发（含 CSRF 顺序修复可顺手做，但不展开）
