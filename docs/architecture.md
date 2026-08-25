# RayScan 架构概览

> 本文档与 `docs/modules.md`（模块清单）、`CONTEXT.md`（领域词汇）配套。定位决策见 [ADR-0001](../adr/0001-oa-focused-repositioning.md)。

## 项目结构

```
RayScan/
├── wvs/                       # 核心扫描库
│   ├── cli.py                 # CLI 入口（scan/batch/list-modules/rules/demo…）
│   ├── config.py              # 配置管理（YAML/JSON/环境变量，分层覆盖）
│   ├── models.py              # 数据模型（Vulnerability / ScanTarget / ScanResult）
│   ├── constants.py           # 全局常量
│   ├── exceptions.py          # 异常体系
│   ├── core/                  # 扫描引擎
│   │   ├── scanner.py         # 主扫描器 WAVScanner（阶段编排 + 流式检测 + checkpoint）
│   │   ├── orchestrator.py    # ScanOrchestrator（Stage 编排器）
│   │   ├── stages.py          # Stage 实现（WAF / LabAuth / OADetection / Dedup）
│   │   ├── crawler.py         # 爬虫引擎（+ crawler_parsers.py）
│   │   ├── session.py         # HTTPPool 会话池（主链路）
│   │   ├── session_manager.py # 会话生命周期管理（未接入主链路，待处置）
│   │   ├── scheduler.py       # 任务调度器（未接入主链路，待处置）
│   │   ├── cache.py           # 缓存系统
│   │   ├── rate_limiter.py    # 速率限制（自动调节）
│   │   ├── dedup.py           # 漏洞去重
│   │   ├── encoding_bypass.py # 编码绕过
│   │   ├── lab_profiles.py    # 靶机识别（DVWA/Mutillidae 等自动认证）
│   │   ├── nuclei_template_manager.py  # Nuclei 模板索引/选择
│   │   ├── poc_source_manager.py       # PoC 源管理
│   │   ├── result_merger.py   # 多引擎结果合并
│   │   ├── rule_updater.py    # 规则更新
│   │   ├── oob/               # OOB 检测（dnslog / interactsh / oob_manager）
│   │   └── passive/           # 被动扫描代理（proxy）
│   ├── modules/               # 18 个检测模块（见 docs/modules.md）
│   ├── integrations/          # 第三方集成
│   │   ├── nuclei_integration.py       # Nuclei（已接入主流程）
│   │   ├── sqlmap_integration.py       # sqlmap（独立可用，未接入主流程）
│   │   ├── ffuf_integration.py         # ffuf（同上）
│   │   ├── wappalyzer_integration.py   # Wappalyzer（同上）
│   │   └── awvs/nessus/msf_integration.py  # 商业引擎集成层（Roadmap，未接入）
│   ├── exploit/               # 漏洞利用模块（engine + ssrf/xss/xxe exploit）
│   ├── reporting/             # 报告（console / html / json / csv / markdown）
│   ├── profiles/              # 扫描 Profile（builtin + loader）
│   └── plugins/               # 认证插件（auth）
├── web_ui/                    # Web UI（Flask，本地使用）
├── rules/                     # 检测规则
├── tests/                     # 测试套件
├── docs/                      # 文档（adr/ audit/ agents/）
└── pyproject.toml
```

## 分层架构

```
┌──────────────────────────────────────────────────┐
│              CLI (wvs/cli.py) / Web UI            │  ← 用户接口
├──────────────────────────────────────────────────┤
│         Authentication Layer (plugins/auth)       │  ← 认证插件
├──────────────────────────────────────────────────┤
│  WAVScanner.scan()  ──  ScanOrchestrator          │  ← 编排层
│    ├─ 爬取+流式检测（分批，即爬即测）                │
│    ├─ Stage: WAF / LabAuth / OA指纹 / Dedup       │
│    ├─ Nuclei 阶段（CLI 可用走模板，否则内置回退）     │
│    └─ Checkpoint（30s 落盘，--resume 恢复）         │
├──────────────────────────────────────────────────┤
│         ModuleFactory 注册表（18 模块）             │  ← 检测层
│   core: sqli/xss  ·  lite: oa/cmdi/lfi/…  ×16     │
├──────────────────────────────────────────────────┤
│   Integrations: Nuclei(接入) / sqlmap/ffuf/…       │  ← 外部工具
├──────────────────────────────────────────────────┤
│           Reporting: Console/HTML/JSON/CSV/MD      │  ← 报告输出
└──────────────────────────────────────────────────┘
```

## 核心数据流

```
目标 URL
   │
   ▼
双路径分流（lab_profiles 识别靶机/实战）
   │
   ▼
Crawler ──流式分批──▶ Scanner 调度 ──▶ 检测模块（并发）
   │                                        │
   │                              OOB 验证（dnslog/interactsh）
   ▼                                        ▼
Nuclei 阶段 ──────────────▶ Dedup 去重合并 ──▶ Reporter
```

## 关键设计决策

1. **异步驱动** — 主链路基于 `asyncio` + `httpx`（`aiohttp` 仅用于 OOB dnslog、exploit、wappalyzer 集成）
2. **模块化检测** — 每类漏洞独立模块，`@register_module` 导入时注册到 `ModuleFactory`（唯一事实源），可插拔
3. **配置分层** — 默认值 → 配置文件 → Profile → CLI 参数，逐层覆盖
4. **统一数据模型** — `Vulnerability` / `ScanTarget` / `ScanResult` 贯穿全流程
5. **插件化认证** — `AuthManager` 支持多种认证方式，可扩展
6. **误报治理基线** — 检测判定基于响应证据（baseline 排除 / 内容特征），仅路径可达不视为漏洞
7. **OA 三级检测链路** — 内容指纹 → 版本识别 → 规则级证据验证 + 版本过滤

## 已知架构债（详见 docs/TECH_DEBT.md 与 docs/CODE_AUDIT.md）

- `cli.py` 承载过多业务编排（S6 计划下沉到 Stage）
- `scheduler.py` / `session_manager.py` 未接入主链路
- `modules/base.py` 职责过重（基类 + 注册表 + 检测辅助 + OOB + 统计）
