# RayScan v2.1.0 发布报告

> 发布日期:2026-08-07 ｜ Release: [github.com/xiabai2008/rayscan/releases/tag/v2.1.0](https://github.com/xiabai2008/rayscan/releases/tag/v2.1.0)

---

## 一、发布成果

| 项目 | 状态 |
|------|------|
| **GitHub Release** | ✅ `RayScan v2.1.0`(非 draft,含完整 Release Notes) |
| **Tag** | ✅ `v2.1.0` 已推送 |
| **Docker 镜像** | ✅ Docker workflow 构建成功 |
| **Release workflow** | ✅ success |
| **测试套件** | ✅ 约 211 用例全绿 |
| **CI lint** | ✅ ruff (E/F/W/I 子集) 全绿 |

**Release URL**: https://github.com/xiabai2008/rayscan/releases/tag/v2.1.0

---

## 二、版本决策背景

### 2.1 发现的重大情况
远程仓库 `xiabai2008/rayscan` 在 2026-08-05/06 已发布 **v2.0.0 与 v2.0.1** 两个 Release,且与本地历史**完全分叉**(无共同祖先,97 提交 vs 本地 10 提交)。本地工作区是另一条开发线(含 Phase 0-4 升级,但不含远程的账号统一/文档清理/CI 严格化等 87 个提交)。

### 2.2 用户决策
经确认,用户选择 **"发布 v2.1.0"**:保留远程已发布的 v2.0.0/v2.0.1,将本地 Phase 0-4 升级作为新版本合并发布。

---

## 三、合并过程(远程基 + 本地增量)

### 3.1 采用远程 v2.0 基线的文件(含 v2.0 功能,不可丢)
| 文件 | 原因 |
|------|------|
| `wvs/modules/oa/detector.py` | OA 三级链路(12 指纹/版本过滤/规则证据,S3) |
| `wvs/modules/xxe/detector.py` | S1 baseline 误报治理 |
| `wvs/modules/ssrf/detector.py` | S1 baseline 排除 |
| `wvs/integrations/nuclei_integration.py` | S2 `.git/config` 特征修正 + 模板文件列表传递 |
| `wvs/profiles/builtin.py` | 远程新增 profile 数据 |
| `wvs/modules/subdomain/jspathfinder/awvs/nessus` | 远程微改进 |

### 3.2 采用本地升级版并补回远程功能的文件
| 文件 | 合并动作 |
|------|---------|
| `wvs/cli.py` | 本地版(+672 Phase 0-4 命令)**补回** `--no-nuclei` 参数与处理 |
| `wvs/core/scanner.py` | 本地版(Orchestrator/dedup/全局并发)**补回** nuclei 字段/`_run_nuclei`/checkpoint 原生实现/`_try_save_checkpoint`/resume 恢复 |
| `wvs/modules/base.py` | 本地版(evidence_chain)**补回** py3.9 懒加载锁修复 |

### 3.3 本地新增文件(Phase 0-4 成果,整体保留)
`demo_lab.py` / `passive/` / `orchestrator.py` / `stages.py` / `rule_updater.py` / `dedup.py` / `idor/` / `authbypass/` / `gentle.yaml` / `rules/` + 8 个新测试文件

### 3.4 关键 bug 修复(合并中发现)
- `WAVScanner` 缺 `_vuln_seen`/`_modules_done`/`_last_checkpoint_time` 初始化 → AttributeError
- `_run_nuclei` 调用签名与 NucleiIntegration.scan(url, cookies, severities) 不匹配
- checkpoint 原生文件实现(兼容 bare scanner 测试 + dedup 架构)
- pyproject tomli 语法(远程修复版)+ 版本号统一 2.1.0

---

## 四、v2.1.0 功能清单

**继承 v2.0**:OA 三级检测链路 / Nuclei 主流程接入(内置回退)/ 扫描断点恢复(--resume)/ S1-S3 误报治理

**新增(Phase 0-4)**:
- `--explain` 可解释检测证据链(JSON/SARIF 报告含 evidence_chain)
- `passive` 被动扫描(零依赖 MITM + 域名过滤)
- `idor`/`authbypass` 业务逻辑检测
- `demo` 一键演示(内置靶场,实测 12 漏洞)
- `rules` 规则管理(status/init/update)
- `--preset` 5 种合规预设(gentle 等)
- `ScanOrchestrator` 编排层 + 全局并发
- `multi` 命令接线 + 聚合报告视图
- CI 覆盖率门禁 / Docker git 支持

---

## 五、验证

- **约 211 测试全绿**:远程 v2.0 回归(OA 版本/fp_guard/s2_resume)+ 本地 Phase 0-4 全量
- **CI lint 全绿**:ruff E/F/W/I 子集
- **Release Notes**:完整发布说明(亮点/清单/安装/致谢)

---

## 六、后续建议

1. `release/v2.1.0` 分支已推送,建议合并回 master(或直接在 master 上再发后续版本)
2. Docker 镜像名/仓库信息确认与 v2.1.0 一致
3. 发布首篇社区周报(基于本次 Release Notes)
4. 持续跟进 Release 的 Star/Issue 反馈,启动社区增长飞轮
