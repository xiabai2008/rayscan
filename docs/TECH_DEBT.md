# 技术债看板（Tech Debt Board）

本看板集中追踪 RayScan 已知的技术债与待整改项。目标是**让债务可见、可分配、可闭环**，避免散落在记忆里。

> 维护规则：
> - 严重度：🔴 高（影响正确性/安全/流程）｜🟡 中（质量/可维护性）｜🟢 低（整洁度）
> - 状态：📋 待办 / 🚧 进行中 / ✅ 已解决 / ⏸️ 暂缓
> - 关联 Issue：如有对应 GitHub Issue，填编号；否则由发现者建 Issue 并回链。
> - 每个 sprint 至少清理 1 条 🔴/🟡。

---

## 看板

| 编号 | 区域 | 问题 | 严重度 | 状态 | 负责人 | 关联 |
|------|------|------|--------|------|--------|------|
| TD-001 | 工程配置 | 行宽标准冲突（black=88 / isort=88 / ruff=120 / flake8=150） | 🟡 | ✅ 已解决 | @xiabai2008 | — |
| TD-002 | 工程配置 | `pyproject.toml` 版本漂移（写 1.1.0，实际 v2.0.0） | 🟡 | ✅ 已解决 | @xiabai2008 | — |
| TD-003 | 类型安全 | `mypy` 配置宽松：`disallow_untyped_defs=false` 且大片模块 `ignore_errors`，无类型保障 | 🟡 | 🚧 部分完成 | @xiabai2008 | 2026-08-08：新模块（ai/mcp_server/mcp/graphql）mypy 0 错误进 CI（advisory）；存量 212 错待渐进 |
| TD-004 | Lint 覆盖 | `sqli/payloads.py`、`sqli/techniques_mixins.py`、`rce/payloads.py` 被整体排除出 ruff | 🟢 | 📋 待办 | — | — |
| TD-005 | 流程/知识 | 历史 65 次提交几乎单人直推，无评审记录，知识单点集中 | 🔴 | 🚧 进行中 | @xiabai2008 | PR 流程已启用 |
| TD-006 | 测试 | CI 未接入 `pytest-cov`，无覆盖率基线/门禁 | 🟡 | ✅ 已解决 | @xiabai2008 | 2026-08-08：branch 覆盖门禁 fail_under=25（基线 ~27%），CI blocking |
| TD-007 | 可维护性 | 核心模块类型注解缺失，IDE 跳转/重构困难 | 🟡 | 🚧 部分完成 | — | 2026-08-08：新增代码全注解（见 TD-003） |
| TD-008 | 测试覆盖 | `wvs/core`（scanner/session/cache/rate_limiter）单元测试薄弱 | 🟡 | 🚧 部分完成 | — | 2026-08-08：+25 测试（scanner 去重/归一化、crawler URL 逻辑、session cookie/header）；cache/rate_limiter 仍薄 |
| TD-009 | 工程配置 | ruff select 与 CI 命令行覆盖不一致（本地 109 错 vs CI 0） | 🟡 | ✅ 已解决 | @xiabai2008 | 2026-08-08：select 收敛 E/F/W/I + ignore E402/E501，本地=CI |

---

## 如何新增一条

1. 在表格末尾追加一行，编号顺延（TD-00x）。
2. 严重度按上表评估；🔴 需在评审中优先讨论。
3. 建 GitHub Issue（标签 `tech-debt`），把编号填入「关联」列。
4. 领取后把状态改为 🚧 并填负责人；完成后改 ✅ 并附 PR 链接。

## 如何清理一条

- 修复并入 `master` 后，将状态置 ✅，并在「关联」列附上修复 PR/Issue 链接。
- 每季度回顾一次本看板，合并重复项、关闭已过时的项。
