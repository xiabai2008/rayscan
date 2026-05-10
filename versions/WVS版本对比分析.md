# WVS 全版本对比分析

> 生成时间：2026-05-08  
> 分析范围：11个版本目录，545+ Python 文件

---

## 一、版本总览

| 版本 | 扫描器类名 | 文件数 | 关键特征 | 定位 |
|------|-----------|--------|---------|------|
| v15.0 | VulnerabilityScanner / FullScanner | 231 | 含Web界面、完整报告系统、DVWA实战记录 | 主线稳定版 |
| v15.0-commercial | WVSScanner | 179 | 端口扫描+爬虫+漏洞检测一体化，含marketplace/ai/integrations | 商业分支 |
| v16 | 模块化（带版本后缀） | 29 | 文件名带_v16后缀，架构过渡 | 重构试验 |
| v16_arch | 设计文档 | 5 | 仅含架构设计文件 | 规划文档 |
| v17 | 模块化（带版本后缀） | 21 | 新增XXE/SSRF/PathTraversal/CMDI/分布式/AI引擎 | 功能扩展 |
| v17_transition | 同v17内容 | 22 | 与v17完全一致（过渡备份） | 备份快照 |
| v18 | VulnerabilityScanner / FullScanner | 309 | 含Web界面、大量开发文档、实战记录 | 大版本迭代 |
| v18.4 | VulnerabilityScanner / FullScanner | 226 | v18精简版，修复+优化 | 补丁版本 |
| v19 | WAVScanner | 438 | 完全重构架构，模块化引擎，含cache/lab_profiles | 架构重写 |
| v19.2 | WAVScanner | 325 | v19增强版，lab_profiles自动化，并发优化 | 当前主线最新 |
| v1_v15_complete | 测试文件 | 16 | 仅含测试脚本 | 测试套件 |

---

## 二、架构演进

### 主线分支：v15.0 → v18.4 → v19 → v19.2

```
v15.0 (VulnerabilityScanner)
  │
  ├─→ v16 (模块化重构尝试，文件加_v16后缀)
  │     │
  │     └─→ v17 (新增漏洞类型，加入AI引擎/分布式)
  │           │
  │           ├─→ v17_transition (备份)
  │           │
  │           └─→ v18 (合并回主线，大规模功能集成)
  │                 │
  │                 └─→ v18.4 (精简优化)
  │
  └─→ v15.0-commercial (独立商业分支，WVSScanner)

v19 (完全重写，WAVScanner架构)
  │
  └─→ v19.2 (增强优化版)
```

### 架构分水岭

**v18及之前**（VulnerabilityScanner / FullScanner）：
- 单体扫描器，所有漏洞检测逻辑集中在一个大文件
- 漏洞类型以方法内联：test_sqli、test_xss、test_cmdi、test_lfi
- 爬虫、报告与扫描器耦合

**v19起**（WAVScanner）：
- 模块化引擎，每个漏洞类型独立模块（modules/目录）
- 扫描器仅做调度编排，不包含具体检测逻辑
- 引入 scan pipeline：discover → authenticate → scan_one per endpoint
- 新增 cache、lab_profiles、reporting 等子系统

**v15.0-commercial**（WVSScanner）：
- 独立演进，与主线完全不同
- 流水线式：port_scan → crawl → vulnerability_scan → report
- 含主线没有的模块：ai/、context/、performance/、oob/、integrations/、marketplace/
- 内部版本号标记混乱（CLI=v4.0、AI=v14.0、Integrations=v11.0）

---

## 三、各版本详细对比

### 3.1 v15.0 — 主线稳定版

**代码规模**：231 Python 文件  
**扫描器**：VulnerabilityScanner + FullScanner（1032行 scanner_v18.py）

**优点**：
- ✅ 完整的 Web 管理界面（wvs_web/）
- ✅ 成熟的报告系统（HTML/JSON/Markdown）
- ✅ 丰富的实战测试记录（DVWA/BWAPP等靶场）
- ✅ 含速率限制、缓存集成、登录SQL注入等专业文档
- ✅ 代码结构清晰，模块划分合理

**缺点**：
- ❌ 扫描器文件过大（scanner_v18.py 1032行）
- ❌ 漏洞检测逻辑与扫描调度耦合
- ❌ 缺少并发扫描支持
- ❌ 没有模块化插件系统

---

### 3.2 v15.0-commercial — 商业分支

**代码规模**：179 Python 文件  
**扫描器**：WVSScanner（336行，简洁）

**优点**：
- ✅ 架构简洁清晰（scan → port_scan → crawl → vuln_scan → report）
- ✅ 包含去重器（VulnDeduplicator + VulnFilter）
- ✅ 端口扫描+服务识别集成
- ✅ 独有模块：AI引擎、上下文分析、性能优化、OOB检测、marketplace
- ✅ 含 Docker 部署支持

**缺点**：
- ❌ 与主线不兼容，无法合并
- ❌ 内部版本号混乱，难以追溯
- ❌ 缺少实战测试记录
- ❌ 独立演进，缺少社区/文档支持

---

### 3.3 v16 — 架构过渡版

**代码规模**：29 Python 文件  
**特征**：所有文件名带 _v16 后缀

**优点**：
- ✅ 开始模块化拆分（core/vuln/web/ 分离）
- ✅ Web界面内置（web/__init__.py 669行，单文件完整UI）
- ✅ 新增SSLI检测模块
- ✅ CLI独立（cli_v16.py 266行）

**缺点**：
- ❌ 文件太多带版本后缀，不利于维护
- ❌ 漏洞类型仅覆盖 SQLi、XSS（缺少CMDI/SSRF/XXE等）
- ❌ 没有完整扫描流程（缺少统一调度器）

---

### 3.4 v16_arch — 架构设计文档

**代码规模**：5个文件  
**内容**：CHANGELOG.md + README.md（纯文档）

**说明**：仅为v16的架构设计规划文档，不包含可执行代码。

---

### 3.5 v17 — 功能扩展版

**代码规模**：21 Python 文件  
**新增漏洞类型**：CMDI、SSRF、XXE、PathTraversal

**优点**：
- ✅ 漏洞类型大幅扩展（v16仅2种 → v17增至6种）
- ✅ 新增AI引擎（core/ai_engine.py 427行）
- ✅ 新增分布式扫描支持（core/distributed.py 598行）
- ✅ 新增集成管理器（integrations/manager.py 405行）
- ✅ 模块化程度进一步提升

**缺点**：
- ❌ 仍为过渡版本，没有合并回主线
- ❌ 漏洞检测模块仍为大单文件（sqli_v17.py 324行等）
- ❌ 缺少统一的测试框架

---

### 3.6 v17_transition — 过渡备份

**代码规模**：22个文件  
**内容**：与v17完全一致

**说明**：v17到v18之间的过渡备份快照，无实质差异。

---

### 3.7 v18 — 大版本迭代

**代码规模**：309 Python 文件（最大版本之一）  
**扫描器**：VulnerabilityScanner + FullScanner（1032行）

**优点**：
- ✅ 合并了v16/v17的所有改进
- ✅ 完整的Web管理界面 + API
- ✅ 丰富的开发文档（AUTO_DEV_ROBOT.md、PROGRESS.md等）
- ✅ 含大量实战测试脚本和记录
- ✅ 功能最全面

**缺点**：
- ❌ 文件数量过多，存在冗余
- ❌ 扫描器仍然是大单体（1032行）
- ❌ 缺少现代异步并发支持
- ❌ 部分文档与代码不同步

---

### 3.8 v18.4 — 精简优化版

**代码规模**：226 Python 文件  
**扫描器**：VulnerabilityScanner + FullScanner（同v18）

**优点**：
- ✅ 在v18基础上精简，去掉冗余文件
- ✅ 修复已知bug
- ✅ 保留核心功能

**缺点**：
- ❌ 与v18差异不大，更像热修复
- ❌ 架构问题未解决（单体扫描器）

---

### 3.9 v19 — 架构重写版 ⭐

**代码规模**：438 Python 文件（最大版本）  
**扫描器**：WAVScanner（全新架构）

**优点**：
- ✅ 完全重写的模块化架构
- ✅ 每个漏洞类型独立模块（modules/目录）
- ✅ 扫描器仅做调度，职责清晰
- ✅ 异步并发扫描支持
- ✅ 新增 cache 缓存系统
- ✅ 新增 lab_profiles 靶场自动识别
- ✅ 完整的重构规范文档（REFACTOR_SPEC.md）
- ✅ 现代化代码结构

**缺点**：
- ❌ 架构断裂性变更，与v18不兼容
- ❌ 部分模块仍需完善
- ❌ 文件数量过大（438文件）

---

### 3.10 v19.2 — 当前主线最新 ⭐⭐

**代码规模**：325 Python 文件  
**扫描器**：WAVScanner（增强版）

**优点**：
- ✅ v19架构基础上全面优化
- ✅ lab_profiles 自动化（自动识别DVWA/Pikachu等靶场并配置）
- ✅ 并发扫描优化（_run_module_concurrent）
- ✅ 全局基线缓存（_global_baseline_cache）
- ✅ 修复SQLi误报（sqli-fp-fix-20260507.md）
- ✅ 修复CMDI检测（v19.2-bugfix-20260507.md）
- ✅ XSS/CMDI检测完善
- ✅ JsPathFinder集成
- ✅ 性能测试通过（perftest文档）
- ✅ 丰富的开发文档（11个task-summary文件）
- ✅ 大量实战debug脚本（70+个测试/调试脚本）

**缺点**：
- ❌ 仍依赖特定靶场环境做测试
- ❌ 部分debug脚本重复，可清理
- ❌ 缺少完整的API文档

---

## 四、关键文件对比

### 4.1 扫描器对比

| 指标 | v15.0/v18/v18.4 | v15.0-commercial | v19 | v19.2 |
|------|----------------|-----------------|-----|-------|
| 类名 | VulnerabilityScanner | WVSScanner | WAVScanner | WAVScanner |
| 行数 | 1032 | 336 | ~900 | 929 |
| 架构 | 单体（所有检测内联） | 流水线 | 模块化引擎 | 模块化引擎+增强 |
| 异步 | 部分异步 | 完全异步 | 完全异步 | 完全异步+并发 |
| 漏洞检测 | 内联方法 | 独立子类 | 独立模块 | 独立模块+lab适配 |
| 认证 | 简单 | 无 | _do_authenticate | _do_authenticate+_do_lab_auth |
| 缓存 | 无 | 无 | 基础cache | 全局基线缓存 |
| Lab支持 | 无 | 无 | 无 | 自动识别+配置 |

### 4.2 漏洞类型覆盖

| 漏洞类型 | v15.0 | v15.0-c | v16 | v17 | v18/18.4 | v19 | v19.2 |
|---------|-------|---------|-----|-----|---------|-----|-------|
| SQL注入 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| XSS | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 命令注入 | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ |
| 文件包含(LFI) | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ |
| SSRF | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ |
| XXE | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ |
| 目录遍历 | ❌ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ |
| 信息泄露 | ❌ | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ |
| OOB检测 | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Nuclei集成 | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ |

### 4.3 辅助功能对比

| 功能 | v15.0 | v15.0-c | v16 | v17 | v18/18.4 | v19 | v19.2 |
|------|-------|---------|-----|-----|---------|-----|-------|
| Web界面 | ✅ | ❌ | ✅ | ❌ | ✅ | ❌ | ❌ |
| HTML报告 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 端口扫描 | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| AI引擎 | ❌ | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ |
| 分布式 | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Docker支持 | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Marketplace | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Lab自动化 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| 并发扫描 | ❌ | ❌ | ❌ | ❌ | ❌ | 部分 | ✅ |

---

## 五、版本推荐

### 当前最佳版本：v19.2 ⭐⭐

**理由**：
1. 最新的模块化架构（WAVScanner），代码质量最高
2. 漏洞类型覆盖最全（9种）
3. 唯一支持 Lab 自动化识别的版本
4. 并发扫描性能最优
5. 活跃开发中（2026-05-07仍有bugfix）
6. 丰富的开发文档和测试记录

### 有价值的独特功能

- **v15.0-commercial** 的 marketplace/OOB/AI引擎 → 可考虑合并到v19.x
- **v15.0** 的 Web 管理界面 → 可考虑为v19.x开发
- **v17** 的分布式扫描 → 可考虑为v19.x开发

### 建议清理

- v16_arch：纯文档，可归档
- v17_transition：与v17完全重复，可删除
- v1_v15_complete：仅测试文件，可归档
- v18：被v18.4覆盖，保留v18.4即可

---

## 六、演进路线图

```
v1~v14 (已丢失/未收录)
  │
  └─→ v15.0 (231文件, VulnerabilityScanner, Web界面)
        │
        ├─→ v15.0-commercial (179文件, WVSScanner, 独立商业分支)
        │
        ├─→ v16 (29文件, 模块化尝试, _v16后缀)
        │     └─→ v17 (21文件, +CMDI/SSRF/XXE/AI/分布式)
        │           └─→ v18 (309文件, 合并主线, +Web界面)
        │                 └─→ v18.4 (226文件, 精简优化)
        │
        └─→ v19 (438文件, WAVScanner完全重写)
              └─→ v19.2 (325文件, +lab_profiles/并发/bugfix) ← 当前最新
```

---

*文档结束。如需深入分析某个版本的特定模块，请指定版本和文件名。*
