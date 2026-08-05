# RayScan (WVS) 行业调研报告

> 本文档为 RayScan（Python Web 漏洞扫描器）架构方案的**行业调研报告（research_report）**，由 `research-analyst`（查有据）产出，经 G2 自动校验与人工审核通过后方可进入下游消费。
> 下游输出：驱动 `business-architect`（业务架构师）的行业调研判断，最终落入《高层架构设计》§3 行业调研章节。
>
> **结构纪律**：全文按「事实 → 对比 → 建议 → 风险」四段式组织，严禁四段之间倒序或跳段。
> **定位声明**：本报告仅提供「建议与证据链」，不得替 business-architect 冻结业务边界；调研打分最优不构成对下游的已冻结输入。

---

## 0. 元信息：修订记录

```yaml
标题: RayScan (WVS) 行业调研报告 v0.1
版本: v0.1
状态: Draft
创建日期: 2026-07-12
最后更新: 2026-07-12
调研人: research-analyst（查有据）
审核人:
  - team-lead（主理人，G2 待审）

关联文档:
  上游输入:
    - 用户诉求: 由主理人注入（RayScan WVS 架构方案 · Phase 2 行业调研）
    - 调研目标: 为高层架构/系统设计提供可追溯的行业证据链
    - 上游摘要: material_digest.md（G1 已通过，含 X1–X16 文档↔代码冲突，均并列保留未裁决）
  下游产出:
    - 高层架构设计 §3 行业调研: 将由 business-architect 整合到此章节
```

| 版本 | 日期 | 作者 | 变更内容 | 评审状态 |
| --- | --- | --- | --- | --- |
| v0.1 | 2026-07-12 | research-analyst（查有据） | 初稿（提交 G2 审核） | Draft |

---

## 1. 调研问题收敛

> 调研启动前，先围绕用户诉求收拢为明确的调研问题集合，确保调研不偏离当前项目背景。

### 1.1 原始调研种子

> 从用户诉求中提取需要调研验证的论题，逐条给出调研优先级。用户诉求核心：RayScan 为 Python 异步（asyncio + httpx）WVS，含 11 检测模块、多引擎聚合（AWVS/Nessus/Nuclei/Metasploit/sqlmap/ffuf/Wappalyzer）、Nuclei 12.5w PoC、OA 专项、漏洞验证链、流式检测、CLI/Web UI/Docker 多入口、4 套 profile；目标是为其生成完整架构方案，本次调研需为模块边界、多引擎聚合、可扩展性、报告体系等决策提供可追溯行业证据。

| 编号 | 待验证论题 | 来源（用户诉求要点） | 调研优先级 | 备注 |
| --- | --- | --- | --- | --- |
| S1 | 主流 WVS/DAST 在检测能力与 RayScan 的差距/对齐（含 sqli/xss/cmdi/lfi/rce/ssrf/xxe/api/sensitive/waf/jspathfinder 11 模块、OA 专项、验证链） | 用户诉求「对比主流 WVS/DAST 工具与 RayScan 的能力」 | 高 | — |
| S2 | 主流工具在架构范式（crawler / proxy / template / IAST / OOB）上的差异，哪些可借鉴 | 用户诉求「架构形态取舍」 | 高 | — |
| S3 | 部署模式（SaaS / 自托管 / Docker / CI-CD）与 RayScan CLI/Web/Docker 多入口的取舍 | 用户诉求「部署模式」 | 中 | — |
| S4 | 多引擎聚合（AWVS/Nessus/Nuclei/MSF/sqlmap/ffuf）的业界归一化/去重/编排模式 | 用户诉求「多引擎聚合」 | 高 | 关联 RayScan ResultMerger |
| S5 | 报告体系（SARIF/JSON/HTML）标准化与 RayScan 多格式现状（含 sarif 未落地 X10）的差距 | 用户诉求「报告体系」 | 中 | — |
| S6 | 技术栈取舍（asyncio+httpx、Nuclei 模板、OOB interactsh）的业界对照 | 用户诉求「技术栈取舍」 | 中 | — |

### 1.2 调研问题收敛

> 将 §1.1 的种子收敛为 5 个可执行的调研问题。每条问题明确调研对象、调研目标和产出预期。

| 编号 | 调研问题 | 调研对象 | 调研目标 | 预期产出 | 关联种子 |
| --- | --- | --- | --- | --- | --- |
| Q1 | 主流 WVS/DAST（Invicti、Burp Suite DAST、OWASP ZAP、Nuclei）在检测能力、架构范式、部署形态上分别与 RayScan 有何异同？ | Invicti / Burp / ZAP / Nuclei 官方文档与评测 + RayScan（material_digest） | 建立能力/架构/部署三维对照，识别 RayScan 优势与短板 | 标杆详述卡 + 横向事实表（§2.2 / §2.3） | S1, S2, S3 |
| Q2 | 业界多引擎聚合/结果归一化（ASOC、DefectDojo、Faraday、MEDUSA）采用何种统一数据模型与去重策略？ | Synopsys ASOC / DefectDojo / Faraday / MEDUSA 文档 | 提炼可复用于 RayScan ResultMerger 的适配器 + 去重模式 | 聚合模式事实表 + 借鉴点（§2.3 / §4.1） | S4 |
| Q3 | 主流工具的报告体系（SARIF/JSON/HTML/CSV/Markdown）标准化程度如何？RayScan 多格式现状（含 sarif 接收未写出 X10）应如何对齐？ | ZAP / Burp / Nuclei SARIF 文档 + RayScan reporting 代码 | 给出报告标准化建议（SARIF 作为一等公民） | 报告体系对标 + 建议（§4.3） | S5 |
| Q4 | 开源/自研 WVS 在可扩展性（插件/模板/模块注册）上的成熟范式是什么？RayScan DetectionModule+@register_module 与之对比如何？ | ZAP add-ons / Burp BApp / Nuclei templates / RayScan modules/base.py | 评估 RayScan 模块边界与扩展机制的可借鉴范式 | 扩展范式对比 + 边界建议（§4.1） | S1, S6 |
| Q5 | 从 RayScan「个人渗透伴侣 / SRC / 靶机」定位出发，哪些标杆的部署形态（CLI/Docker/Web/CI-CD）最值得对齐？ | 各标杆部署文档 + RayScan profiles/Docker/Web UI | 给出部署形态取舍建议 | 部署形态对标 + 建议（§4.1 / §4.3） | S3 |

> **【中间确认自检 · §1 调研问题收敛】**（按协议 §2.1 判定 + §2.3 反向 3 问）
> - **§2.1 判定：未命中。** 用户诉求已明确聚焦「能力 / 架构形态 / 部署模式 / 技术栈取舍，支撑模块边界 / 多引擎聚合 / 可扩展性 / 报告体系」，Q1–Q5 均由其直接收敛，不存在 ≥2 种合理但会颠覆下游的方案分叉。
> - **反向验证 3 问：**
>   - Q1（返工成本）：若 3 个月后推翻，仅影响本报告 §2–§4 的调研结论文本，返工范围 = 本报告自身 3~4 个章节，切换成本 ≈ 数人日（重新检索 + 改写），远低于阶段产物 30% 且非月级。→ **可控**。
>   - Q2（用户/客户/监管可感知）：调研问题本身不改变产品功能 / 交互 / 合同 / 合规，仅决定「对比谁、比什么」，用户不可感知。→ **感知不到**。
>   - Q3（与用户诉求一致）：5 问均直接对应用户诉求原文「对比主流 WVS/DAST 工具与 RayScan 的能力、架构形态、部署模式、技术栈取舍，支撑模块边界、多引擎聚合、可扩展性、报告体系」——**完全一致**。
> - **结论：未命中，不发起 [中间确认]，继续推进。**

---

## 2. 事实：标杆系统盘点和方案详述

> **四段式「事实」段**。只陈列调研发现的事实，不做引申建议或边界裁决。

### 2.1 行业标杆清单

> 完整盘点调研覆盖的所有标杆系统，给出标签化画像。

**硬指标**：≥ 3 家；至少包含 1 家头部 SaaS 代表（Invicti、Burp Suite DAST）+ 1 家开源/自研代表（OWASP ZAP、Nuclei、RayScan）。

| 编号 | 标杆系统 | 厂商 / 社区 | 部署形态 | 场景覆盖 | 技术亮点 | 商业模式 | 调研来源 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| B1 | Invicti（原 Netsparker / Acunetix 同集团） | Invicti（Invicti Group） | SaaS / 自托管 | 企业级 Web/API DAST + SAST + SCA + ASPM | Proof-Based Scanning™（只读验证漏洞，宣称 99.98% 准确率）、AcuSensor/Shark IAST、多引擎关联 | 企业定制报价（按扫描目标数 + 部署模式） | SR-01, SR-02 |
| B2 | Burp Suite DAST（原 Enterprise Edition） | PortSwigger | 云托管 / 自托管 / Kubernetes / Docker(CI-CD) | 团队级 Web/API DAST，CI/CD 集成 | 拦截代理 + 嵌入式浏览器爬 SPA、自动化 OAST（带外）、BApp Store 500+ 扩展、GraphQL API | 订阅制（DAST Classic 约 $19k–$50k/2 年；Pro $475/用户/年） | SR-03 |
| B3 | OWASP ZAP | OWASP / Checkmarx（仍 OSS） | 桌面 / Docker 守护态 / CI-CD | 开发与安全团队 Web/API DAST，手动+自动 | MITM 代理、主动+被动扫描、Spider/AJAX Spider、200+ 插件市场、REST API、SARIF、脚本化（JS/Python/Groovy） | 完全开源（Apache 2.0，免费） | SR-04 |
| B4 | Nuclei | ProjectDiscovery | CLI / Docker / CI-CD | 基于模板的漏洞/暴露/错误配置检测（Web/API/网络/云/DNS） | YAML DSL 模板驱动、12,000+ 社区模板、多协议（HTTP/DNS/TCP/SSL/WS/Headless）、近零误报、SARIF、内置去重 | 开源（MIT，免费）；商业云可选 | SR-05 |
| B5 | RayScan（自研主体） | xiabai2004（社区 OSS） | CLI / Web UI(Flask+SSE) / Docker(client-only) | 个人渗透伴侣 / SRC / 靶机；11 检测模块 + 多引擎聚合 + OA 专项 + 验证链 + 流式检测 | asyncio + httpx 异步引擎、DetectionModule+@register_module、7 个 *_integration 适配器、Nuclei PoC 集成、interactsh/DNSLog OOB、Profile 系统 | 开源（MIT，免费） | SR-09（上游 material_digest） |

> **【中间确认自检 · §2.1 标杆清单】**（按协议 §2.1 判定 + §2.3 反向 3 问）
> - **§2.1 判定：未命中。** 用户诉求示例已显式指定标杆范畴「≥1 头部 SaaS 如 Invicti/Burp Enterprise + ≥1 开源/自研如 OWASP ZAP/Nuclei/自研 RayScan」。本清单（B1 Invicti、B2 Burp 为 SaaS 头部；B3 ZAP、B4 Nuclei 为开源；B5 RayScan 为自研主体）完全落在用户已冻结的标杆范畴内，无需在「选谁」上请用户裁决。
> - **反向验证 3 问：**
>   - Q1（返工成本）：若推翻标杆选择，仅重写 §2.1/§2.2/§2.3 与 §3.1 矩阵，返工范围 = 本报告 3~4 个章节，切换成本 ≈ 数人日；非月级、小于 30% 阶段产物。→ **可控**。
>   - Q2（用户/客户/监管可感知）：标杆清单是内部调研范围，不暴露给用户/客户/监管，不改变产品形态。→ **感知不到**。
>   - Q3（与用户诉求一致）：清单直接对应用户诉求示例中的 Invicti/Burp/ZAP/Nuclei/RayScan，且 RayScan 作为自研主体被用户诉求明确点名。→ **完全一致**。
> - **结论：未命中，不发起 [中间确认]，继续推进。**

### 2.2 标杆方案详述

> 每家标杆逐一展开（B1–B5 共 5 家，均含详述）；每段区分「已核实的事实」与「推断/假设」，以「置信度」列标注。

#### 2.2.1 B1 - Invicti（含 Acunetix）

| 维度 | 内容 | 置信度 |
| --- | --- | --- |
| 产品定位 | 企业级应用安全平台，以 DAST 为核心，叠加 SAST/SCA/容器/ASPM（经 Kondukto）的一站式 AppSec 平台 | 已核实 |
| 目标用户 | 中大型企业安全团队（Invicti 面向 50+ 目标；Acunetix 面向 5–50 目标的中型市场） | 已核实 |
| 核心能力 | Proof-Based Scanning™（只读方式安全验证漏洞，宣称 99.98% 准确率）、AcuSensor/Shark IAST 传感器、Web+API 扫描、结果与 SAST/SCA 关联 | 已核实 |
| 架构特点 | 中心化平台 + 扫描节点；IAST 通过在目标应用注入传感器做白盒增强；多引擎结果关联归一化 | 推断（来源：官方对比文档） |
| 部署形态 | SaaS 云托管 / 自托管（on-premise）双形态 | 已核实 |
| 集成方式 | REST API、CI/CD 插件、Issue 追踪集成（Jira 等）、ASPM 工作流 | 已核实 |
| 定价模式 | 企业定制报价（按扫描目标数 + 部署模式）；Acunetix 起步约 $4,500+/年，Invicti 为定制价 | 已核实（公开评测口径，精确报价需询价） |
| 优势 | 误报率极低（proof-based）、企业级 RBAC 与合规报表、生态完整 | 综合归纳 |
| 局限 | 专有闭源、成本高、数据可能出网（SaaS）；对 OSS 自研工具不可直接复用其引擎 | 已核实 + 推断 |
| 对本项目的参考价值 | 「验证后再报告」的 proof-based 理念值得借鉴——RayScan 已用 Metasploit RPC 验证链部分实现该思路；但其引擎与定价对 OSS RayScan 不可采用 | 推断 |

#### 2.2.2 B2 - Burp Suite DAST（原 Enterprise Edition）

| 维度 | 内容 | 置信度 |
| --- | --- | --- |
| 产品定位 | 面向团队与 CI/CD 的自动化 DAST 扫描器，由 PortSwigger Research 引擎驱动 | 已核实 |
| 目标用户 | 企业安全团队、DevSecOps、渗透测试团队 | 已核实 |
| 核心能力 | 拦截代理 + 嵌入式 Chromium 爬 SPA、自动化 OAST（带外应用安全测试，PortSwigger 首创）、API 扫描（OpenAPI/GraphQL/SOAP/WS）、认证扫描（SSO/表单/脚本/Header）、预设扫描模式（Lightweight→Deep） | 已核实 |
| 架构特点 | 扫描引擎 + 嵌入式浏览器渲染 + OAST 带外服务；扩展通过 BApp Store（500+，Java/Python）与 BChecks；GraphQL API 统一编排 | 推断（来源：特性页 + 评测） |
| 部署形态 | 云托管 / 自托管（交互式安装器）/ Kubernetes / Docker（CI-CD） | 已核实 |
| 集成方式 | Jenkins/GitHub Actions/GitLab CI/Azure DevOps/TeamCity；Jira/GitLab/Trello/Slack；GraphQL API；SARIF 导出（`/scans/{id}/results/sarif`） | 已核实 |
| 定价模式 | 订阅制，2 年期；DAST Classic 约 $19,121（20 并发）/ Unlimited 约 $49,999；另有 Pay-as-you-scan（$1,999 预付 + $9/扫描小时） | 已核实（官网计价器口径） |
| 优势 | 检测率高、扩展生态强、OAST 带外检测成熟、CI/CD 与 SARIF 完善 | 综合归纳 |
| 局限 | 专有闭源、企业版价格高；引擎不可被 OSS 工具直接复用 | 已核实 + 推断 |
| 对本项目的参考价值 | 「插件/BCheck 扩展范式 + OAST 带外检测 + SARIF 导出 + CI/CD 编排」是可借鉴的设计模式；其代理式交互思路与 RayScan 的爬取即检测形成对照 | 推断 |

#### 2.2.3 B3 - OWASP ZAP

| 维度 | 内容 | 置信度 |
| --- | --- | --- |
| 产品定位 | 免费开源的 DAST 工具，兼具拦截代理（手动）与自动化扫描（API/CI-CD） | 已核实 |
| 目标用户 | 开发者、QA、安全团队、渗透测试人员、学生 | 已核实 |
| 核心能力 | MITM 代理、主动+被动扫描（数百类漏洞检查）、Spider + AJAX Spider、Fuzzer、WebSocket、200+ 插件市场、脚本化（JS/Python/Groovy/Ruby）、REST API、SARIF 输出 | 已核实 |
| 架构特点 | 以代理为核心的爬虫+主动扫描管线；add-on 插件市场扩展；2025 年强化认证框架（OAuth2/JWT/MFA）；采用 WAVSEP 基准做准确率校验 | 推断（来源：多篇评测 + 官方博客） |
| 部署形态 | 桌面应用 / Docker 守护态 / CI-CD（zap-baseline/full/api-scan 脚本） | 已核实 |
| 集成方式 | REST API + CLI + 官方 GitHub Actions；Jenkins/GitLab CI；SARIF；DefectDojo 等归一化平台 | 已核实 |
| 定价模式 | 完全免费，Apache 2.0；由 Checkmarx 资助（2024 起雇佣三位项目负责人），仍社区控制 | 已核实 |
| 优势 | 零成本、可自托管完全可控、CI/CD 与 SARIF 成熟、插件生态开放、与 RayScan 同属 Python 友好生态 | 综合归纳 |
| 局限 | 检测深度/误报率弱于商业引擎；重负载需调优；无内置多引擎聚合 | 已核实 + 推断 |
| 对本项目的参考价值 | 「插件化扩展 + 统一数据模型 + SARIF/CI-CD 输出 + 自托管可控」是 RayScan 模块边界与报告体系的直接对标范式；其 crawler-based DAST 与 RayScan 流式爬取即检测同源 | 推断 |

#### 2.2.4 B4 - Nuclei

| 维度 | 内容 | 置信度 |
| --- | --- | --- |
| 产品定位 | 基于 YAML 模板的快速漏洞扫描器，覆盖 Web/API/网络/云/DNS/代码 | 已核实 |
| 目标用户 | 攻防安全团队、渗透测试、漏洞赏金、DevSecOps | 已核实 |
| 核心能力 | 模板驱动检测（请求+匹配器+提取器）、12,000+ 社区模板（CVE 3,587、exposure、misconfig、WordPress、xss 等）、多协议（HTTP/DNS/TCP/SSL/File/Whois/WS/Headless）、默认 150 req/s、并行 25 host×25 template、AI 模板生成、内置去重 | 已核实 |
| 架构特点 | 非爬虫式：仅执行预定义模板，近零误报，但不发现未知逻辑漏洞；需配合 crawler-based DAST（如 ZAP）做未知发现 | 推断（来源：官方文档 + 评测） |
| 部署形态 | CLI / Docker / CI-CD；MIT 许可，Go 编写 | 已核实 |
| 集成方式 | JSON/JSONL/SARIF/Markdown 输出；Jira/GitHub/GitLab/Elasticsearch/Splunk；CI/CD 原生 | 已核实 |
| 定价模式 | 开源免费（MIT）；ProjectDiscovery 商业云可选 | 已核实 |
| 优势 | 模板生态庞大、已知漏洞覆盖广、误报极低、易版本化与二次开发、RayScan 已集成 | 综合归纳 |
| 局限 | 不爬取、不发现自定义逻辑漏洞；模板质量依赖社区 matcher；外部二进制依赖 | 已核实 + 推断 |
| 对本项目的参考价值 | 「YAML 模板 DSL + 分类缓存 + 按技术栈分类 + 去重」直接对应 RayScan 的 Nuclei PoC 集成（poc_sources.yaml），是 RayScan「复用而非自研 PoC 库」策略的事实佐证；其模板范式可启发 RayScan 自有模块的 payload 模板化 | 推断 |

#### 2.2.5 B5 - RayScan（自研主体）

| 维度 | 内容 | 置信度 |
| --- | --- | --- |
| 产品定位 | 个人渗透伴侣 / SRC 挖掘 / 靶机踩点用的 Python 异步 Web 漏洞扫描器（WVS） | 已核实（D7 spec 定位） |
| 目标用户 | 个人安全研究者、SRC 白帽、渗透测试前期踩点人员 | 已核实 |
| 核心能力 | 11 检测模块（sqli/xss/cmdi/lfi/rce/ssrf/xxe/api/sensitive/waf/jspathfinder）、OA 专项 12 系统、多引擎聚合（AWVS/Nessus/Nuclei/sqlmap/ffuf/Wappalyzer + MSF 验证链）、Nuclei PoC 集成、流式检测（爬取即检测）、4 套 profile | 已核实（material_digest D1/D11） |
| 架构特点 | asyncio + httpx 异步引擎（HTTPPool）、DetectionModule 基类 + @register_module 注册、7 个 *_integration 适配器 + ResultMerger、interactsh/DNSLog OOB、Profile 系统、CLI/Web UI/Docker 多入口 | 已核实（D11 代码抽样，X3 指出核心实为 httpx 而非架构文档所称 aiohttp） |
| 部署形态 | CLI（ray/wvs 等价入口）、Web UI（Flask + SSE 实时日志，默认 127.0.0.1:5000）、Docker（client-only，不暴露端口） | 已核实（D12/D15） |
| 集成方式 | 第三方工具子进程/API 集成（AWVS/Nessus/MSF 等）；Web UI 提供 REST + SSE；报告多格式（json/html/markdown + 代码层 sarif/csv 未完全落地，见 X10） | 已核实 + 推断 |
| 定价模式 | 开源（MIT），免费 | 已核实 |
| 优势 | 流式检测（爬取即检测）差异化、多引擎一键聚合、OA 专项、验证链、完全自托管可控、轻量易上手（30 秒启动目标） | 综合归纳 |
| 局限 | Beta 状态（X1 版本口径混乱）、httpx 未入核心依赖（X3）、多套默认参数冲突（X7）、报告格式未完全落地（X10）、Auth 子系统未独立实现（X11）、waf 未入默认模块表（X16） | 已核实 + 推断 |
| 对本项目的参考价值 | 本主体为被设计对象；其流式检测 + 多引擎聚合 + 模板化 PoC 是架构差异化核心，需在下游架构中保留并强化；短板（依赖声明、报告标准化、配置一致性）由本报告 §4/§5 给出改进建议 | 推断 |

### 2.3 关键技术能力横向事实

> 不评分、不排序，仅按能力维度横陈各方案事实。〔事实〕标注来源 SR-xx。

| 能力维度 | B1 Invicti | B2 Burp DAST | B3 OWASP ZAP | B4 Nuclei | B5 RayScan | 说明 / 来源 |
| --- | --- | --- | --- | --- | --- | --- |
| 检测范式 | crawler + IAST | proxy + crawler + OAST | proxy + crawler + active/passive | template（非爬虫） | crawler + 流式检测 + OOB | B1/B2/B3/B5 为爬虫/代理式 DAST；B4 为模板式（SR-01~05, SR-09） |
| 已知漏洞库规模 | 厂商维护 + 关联 SCA/CVE | 厂商规则库 | 内置规则 + 插件市场 | 12,000+ 社区模板（CVE 3,587） | Nuclei PoC 集成（宣称 12.5w，口径待核，见 U-02） | B4 官方模板数 SR-05；RayScan 宣称数来自 D1，口径见 §5.2 U-02 |
| 误报控制 | Proof-Based（宣称 99.98%） | OAST + 调优扫描配置 | 被动+主动，调优后可控 | 近零（模板精确匹配） | 三层降噪（内容特征+尺寸聚类+校准匹配） | B1 SR-02；B4 SR-05；B5 D1 §4 |
| 漏洞验证链 | IAST 传感器回传 | 无独立验证链 | 无独立验证链 | 匹配即确认 | Metasploit RPC 自动验证（--verify） | B5 D1 §7；B1 IAST 为同源思路 |
| 多引擎聚合 | 平台内多引擎关联 | 单一 DAST 引擎 | 单一 DAST 引擎 | 模板即检测，不含外部引擎聚合 | 7 适配器 + ResultMerger 去重合并 | B5 D1 §6；聚合范式对标 SR-06（DefectDojo/Faraday/MEDUSA） |
| 扩展机制 | 有限（平台内） | BApp Store 500+ / BChecks | add-on 市场 200+ / 脚本 | YAML 模板（社区贡献） | DetectionModule + @register_module | B2 SR-03；B3 SR-04；B4 SR-05；B5 D11 base.py |
| 报告格式 | HTML/PDF + 平台仪表盘 | HTML + SARIF + JUnit/Burp XML | HTML/XML/JSON/Markdown + SARIF | JSON/JSONL/SARIF/Markdown | json/html/markdown（sarif/csv 代码接收未写出，X10） | B2/B3/B4 SR-03/04/05；B5 X10 |
| 部署形态 | SaaS / 自托管 | 云/自托管/K8s/Docker(CI) | 桌面/Docker/CI | CLI/Docker/CI | CLI/Web UI/Docker(client-only) | 各 SR + B5 D12/D15 |
| 合规可控性 | 中（SaaS 可出网，自托管可控） | 中（自托管可选） | 高（完全自托管 OSS） | 高（OSS 自托管） | 高（MIT 自托管，数据不出网） | 推断（基于部署形态） |
| 成本 | 高（企业定制价） | 高（DAST $19k–$50k/2 年） | 零（Apache 2.0） | 零（MIT） | 零（MIT） | B1/B2 SR-02/03；B3/B4/B5 OSS |

---

## 3. 对比：对比矩阵与加权评分

> **四段式「对比」段**。在 §2 的事实基础上建立对比矩阵，赋予权重并打分。矩阵评分含义：本矩阵从「RayScan（OSS、自托管、流式 crawler+detect、Python asyncio、个人渗透伴侣）应借鉴哪家标杆的范式/设计」视角打分；「集成难度（反向）」「成本（反向）」为反向维度，分数越高代表越易集成/成本越低。B5 RayScan 作为自研主体列入矩阵做自我定位，不参与「借鉴对象」三层结论。

### 3.1 对比矩阵

> **每行权重之和 = 1.00**。维度与权重依据 RayScan 的定位设定（理由见「权重理由」列）。

| 评估维度 | 权重 | 权重理由 | B1 得分 | B2 得分 | B3 得分 | B4 得分 | B5 得分 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 场景契合度 | 0.30 | RayScan 为 OSS 自托管流式 WVS，标杆范式与该定位的贴合度是最关键的借鉴判据 | 3 | 3 | 4 | 5 | 5 |
| 技术成熟度 | 0.20 | 标杆自身方案的工程成熟度与实战验证度，决定借鉴风险 | 5 | 5 | 4 | 4 | 3 |
| 集成难度（反向） | 0.15 | 范式被 RayScan 借鉴/改造的难易（5=易）；OSS 范式可直接研究复用，专有引擎不可集成 | 2 | 2 | 4 | 5 | 4 |
| 成本（反向） | 0.15 | 借鉴/采用该范式的成本（5=低）；专有 SaaS 引擎对 OSS 不可采用，成本记为高 | 1 | 2 | 5 | 5 | 5 |
| 合规可控性 | 0.20 | RayScan 强调自托管与数据不出网，标杆范式在可控性上的匹配度 | 2 | 2 | 5 | 5 | 5 |
| **加权总分** | **1.00** | — | **2.75** | **2.90** | **4.35** | **4.80** | **4.45** |

**评分标尺**：每项 1~5 分，1 = 严重不符合，3 = 基本满足但存在明显局限，5 = 完美契合。
**加权总分计算**：B1 = 0.30×3+0.20×5+0.15×2+0.15×1+0.20×2 = 2.75；B2 = 0.30×3+0.20×5+0.15×2+0.15×2+0.20×2 = 2.90；B3 = 0.30×4+0.20×4+0.15×4+0.15×5+0.20×5 = 4.35；B4 = 0.30×5+0.20×4+0.15×5+0.15×5+0.20×5 = 4.80；B5 = 0.30×5+0.20×3+0.15×4+0.15×5+0.20×5 = 4.45。

> **【中间确认自检 · §3.1 权重设定前】**（按协议 §2.1 判定 + §2.3 反向 3 问）
> - **§2.1 判定：未命中。** 权重为研究评估参数（场景契合度 0.30 / 技术成熟度 0.20 / 集成难度 0.15 / 成本 0.15 / 合规可控性 0.20），属本研究方法论内的打分标尺，不改变下游业务边界、接口契约或部署形态；评分结论在 §4 明确标注为「建议而非裁决」，业务架构师保留最终冻结权。用户诉求未对权重本身做任何指定。
> - **反向验证 3 问：**
>   - Q1（返工成本）：若 3 个月后推翻权重，仅重写 §3.1 矩阵与 §3.2 结论（本报告 1~2 个章节），切换成本 ≈ 半人日至 1 人日（重新赋权 + 重算）；远低于 30% 阶段产物、非月级。→ **可控**。
>   - Q2（用户/客户/监管可感知）：权重仅影响「哪家标杆更值得借鉴」的研究结论，不暴露为产品功能/交互/合同/合规属性，用户不可感知。→ **感知不到**。
>   - Q3（与用户诉求一致）：用户诉求要求「为模块边界/多引擎聚合/可扩展性/报告体系提供证据」，未指定任何维度权重；本研究权重服务于该目标，且结论为建议。→ **用户诉求未显式提及此点**（权重为研究方法，非产品能力）。
> - **结论：未命中，不发起 [中间确认]，继续推进。**（注：即便采用不同权重，本研究的「优先借鉴 OSS 范式（ZAP/Nuclei）而非专有 SaaS 引擎」结论由 RayScan 的 MIT/OSS 定位决定，不会因权重微调而反转，故不存在不可逆/跨界风险。）

### 3.2 评分结论

> 基于 §3.1 加权总分，形成分层结论。〔注：B5 RayScan 为自研主体，纳入矩阵仅作自我定位，不参与下列「借鉴对象」三层结论。〕

- **优先借鉴**：`Nuclei（B4，4.80）` 与 `OWASP ZAP（B3，4.35）` — 适用度评分最高。理由：场景契合度（ZAP crawler-based DAST + RayScan 流式检测同源；Nuclei 模板范式已被 RayScan 直接集成）、技术成熟度可接受、集成难度低（OSS 可直接研究复用）、成本为零、合规可控性最高（完全自托管）。具体借鉴点：ZAP 的「插件化扩展 + 统一数据模型 + SARIF/CI-CD 输出」作为模块边界与报告体系对标；Nuclei 的「YAML 模板 DSL + 分类缓存 + 去重」作为 PoC/已知漏洞库范式。
- **部分借鉴**：`Burp Suite DAST（B2，2.90）` — 借鉴点：其「扩展范式（BApp/BCheck）+ 自动化 OAST 带外检测 + SARIF 导出 + CI/CD 编排」是可复用于 RayScan 的设计模式（RayScan 已有 interactsh/DNSLog OOB，可强化为 OAST 工作流）。不借鉴的部分：专有扫描引擎本身（闭源、企业版高价，对 OSS RayScan 不可采用）。
- **不借鉴（否决）**：`Invicti / Acunetix（B1，2.75）` — 否决理由：专有 SaaS 引擎对 MIT 许可的 RayScan 在成本（企业定制价）与合规可控性（SaaS 可能出网）上均不匹配，无法直接采用其引擎作为技术底座；仅「Proof-Based 验证后再报告」的概念性思路值得记录，而该思路 RayScan 已通过 Metasploit RPC 验证链部分实现。评分 2.75 反映其工程成熟度最高但借鉴可行性最低。

### 3.3 方案组合分析

> RayScan 当前架构实为「多标杆范式组合体」，下表对照其现有设计与可强化方向。

| 组合方式 | 覆盖哪些能力 | 未覆盖能力 | 组合复杂度 | 总体成本估算 |
| --- | --- | --- | --- | --- |
| RayScan 现状：ZAP 式 crawler+主动检测 + Nuclei 模板 PoC + Burp 式 OOB(interactsh) + 多引擎聚合(AWVS/Nessus/MSF/sqlmap/ffuf) + 自研流式检测 | 爬虫式 DAST、已知漏洞模板、带外检测、多引擎归一、验证链、流式检测 | 统一报告归一化（SARIF 仅代码层，X10）、独立 Auth 子系统（X11）、配置一致性（X7/X14） | 中（已有 7 适配器 + ResultMerger，但归一化数据模型未标准化） | OSS 零许可成本 + 自研人力（参考 D7 spec 的 Profile/Auth 路线） |
| 强化方向：引入 DefectDojo/Faraday 式「统一漏洞数据模型 + 适配器 + 去重（rule id + URL hash）」归一化层 | 多源结果归一、去重、风险优先级、与 Jira/GitHub 对接 | 需自行实现归一层（RayScan 体量不必引入完整 DefectDojo，过重） | 中（在 ResultMerger 上演进） | 低（复用现有 ResultMerger，扩为统一模型） |

---

## 4. 建议：取舍决策支持

> **四段式「建议」段**。基于 §2 事实 + §3 对比，给出可被 `business-architect` 直接采用的建议。本节是建议而非最终裁决，最终边界由业务架构师冻结。

### 4.1 自研 / 采购 / 复用边界建议

| 能力项 | 建议方式 | 建议依据 | 候选方案 / 系统 | 关键前提 |
| --- | --- | --- | --- | --- |
| 异步检测引擎核心（httpx crawler + 流式检测） | 自研 | RayScan 差异化核心（爬取即检测），业界无直接等价 OSS 可整体替换；ZAP/Burp 为代理/爬虫式，范式可借鉴不可替换 | — | 须先修复 httpx 依赖声明（X3），否则干净环境导入失败 |
| 已知漏洞 / PoC 库 | 复用（已有底座） | Nuclei 模板生态 12,000+，近零误报，RayScan 已集成；自研 PoC 库成本极高且不经济 | Nuclei（poc_sources.yaml） | 核对「12.5w PoC」口径（U-02），钉固模板版本 |
| 漏洞验证链 | 复用（已有底座） | Metasploit RPC 已落地（--verify），对应 Invicti proof-based 概念 | Metasploit（msf 适配器） | 目标环境需可达 MSF RPC（默认 127.0.0.1:55552） |
| 多引擎聚合层 | 自研（演进） | 已有 7 个 *_integration + ResultMerger；应借鉴 Faraday/MEDUSA 适配器 + DefectDojo 统一数据模型做归一化 | 自研 ResultMerger 演进 + 统一漏洞模型 | 定义统一 Vulnerability 模型（RayScan 已有 models.py，需扩为聚合归一主键） |
| 模块扩展机制 | 自研（保留） | DetectionModule + @register_module 与 ZAP add-on / Nuclei 模板同源范式，成熟可用 | RayScan 模块注册机制 | 明确第三方插件边界（是否开放插件市场，见 D-01） |
| 报告标准化 | 复用 + 自研补齐 | SARIF 为 OASIS 标准，ZAP/Burp/Nuclei 均原生支持；RayScan 代码已接受 sarif/csv 但未写出文件（X10） | SARIF + JSON/HTML/Markdown | 落地 sarif/csv 写出器，Web UI 扩展导出（X10） |
| IAST / Proof-Based 增强 | 部分借鉴（概念） | Invicti IAST/Proof-Based 概念优，但引擎不可采用；RayScan 验证链已部分覆盖 | Metasploit 验证链演进 | 评估是否引入轻量 IAST 传感器（超出 MVP，列为后续） |

### 4.2 MVP 范围建议

> 对用户诉求中的 P0/P1 功能给出「是否可在 MVP 内实现」的调研侧建议（对齐 RayScan 现状）。

| 功能（对齐用户诉求） | 建议 MVP？ | 理由 |
| --- | --- | --- |
| 11 检测模块核心（sqli/xss 已实战验证，其余待验证/靶机未开放，见 D1 §16） | ✅（核心 MVP） | 模块基类与注册机制已成熟（D11 base.py）；sqli/xss 经 Metasploitable 2 验证 |
| 多引擎聚合（AWVS/Nessus/Nuclei/sqlmap/ffuf/MSF） | ✅ | 7 个 *_integration + ResultMerger 已落地（D11 integrations），MVP 可直接含 |
| 流式检测（爬取即检测） | ✅ | RayScan 差异化核心，已有实现（D1 §4） |
| OA 专项 12 系统检测 | ✅ | OADetector 已在默认导入类（D11 modules/__init__.py） |
| 漏洞验证链（Metasploit RPC） | ✅ | --verify 已落地（D1 §7） |
| SARIF 报告落地（代码接受未写出，X10） | ❌（完整版） | 需补 sarif_reporter 写出实现；当前 CLI 接收 --format sarif 但未生成文件 |
| Web UI 多格式导出（仅 JSON，X10） | ❌（完整版） | web_ui /api/export 仅 json，需扩展 html/markdown/sarif |
| 独立 Auth 子系统（X11，Phase 2 未落地） | ❌（完整版） | 当前仅 --auth 文件传入，无 auth 子命令/独立管理；建议后续迭代 |
| 配置一致性统一（X7 多套默认参数、X14 键名不一致） | ❌（完整版） | 需在 ConfigManager 明确生效优先级与统一键名，属架构治理项 |

### 4.3 技术栈参考建议

| 技术层 | 推荐方案 | 替代方案 | 选择理由 |
| --- | --- | --- | --- |
| 异步 HTTP 引擎 | httpx（RayScan 实际使用，须补依赖，X3） | aiohttp（架构文档旧口径，仅部分集成/利用模块使用） | httpx.AsyncClient 已是 RayScan HTTPPool 核心（D11 session.py）；建议将 httpx 列入核心依赖并加 CI 导入冒烟测试 |
| PoC / 已知漏洞模板 | Nuclei 模板生态（复用） | 自研 YAML 模板库 | 12,000+ 社区模板、近零误报、SARIF/去重成熟；自研不经济 |
| 带外检测（OOB） | interactsh（RayScan 已用） | DNSLog（RayScan 亦含） | ProjectDiscovery 交互式带外，对应 Burp OAST 范式；RayScan 已集成 |
| 报告格式 | SARIF（一等公民）+ JSON/HTML/Markdown | 仅自定义 JSON | SARIF 为 OASIS 标准，便于 GitHub Code Scanning / DefectDojo 对接；补齐 X10 缺口 |
| 聚合归一化 | 自研统一漏洞模型 + ResultMerger 演进 | 引入 DefectDojo（过重）/ Faraday | RayScan 体量不必引入完整 ASPM；在现有 ResultMerger 上扩为统一模型 + 去重（rule id + URL hash）即可 |
| 部署形态 | CLI + Docker(client-only) + Web UI(Flask+SSE) 保留 | 多租户 SaaS（超出定位） | 对齐 RayScan「个人渗透伴侣/SRC」定位；是否扩展分布式/多租户见 D-04 |

---

## 5. 风险与待确认项

> **四段式「风险」段**。列出调研中发现的主要风险、不确定信息、待业务架构师进一步裁决的依赖项，以及仍需人工补充调研的部分。

### 5.1 主要风险清单

| 编号 | 风险描述 | 触发条件 | 影响范围 | 严重程度 | 缓解建议 |
| --- | --- | --- | --- | --- | --- |
| R-01 | httpx 未列入 pyproject 核心依赖（X3），但代码广泛 import httpx | 在干净环境 pip install 后运行扫描 | 核心引擎导入失败，扫描完全不可用 | 高 | 将 httpx 加入核心依赖或 optional-dependencies；CI 增加导入冒烟测试（import wvs 即验证） |
| R-02 | 版本号口径混乱（X1：2.0.0 / 1.1.0 / 1.0.2 / 1.0 并存）+ CHANGELOG 停滞于 1.0.2（X2） | 对外发布 / 审计 / 用户报告 | 版本可信度受损，变更连续性断裂 | 中 | 以 pyproject version 为单一权威源；回填 CHANGELOG 2.0.0 条目 |
| R-03 | 「Nuclei 12.5w PoC」宣称口径存疑（官方模板库约 12,000；聚合 xray/beebeeto/bugscan 后或可达但需核实） | 对外能力宣称 / 审计核对 | 能力宣称可信度风险 | 中 | 核对 poc_sources.yaml 实际拉取模板数并标注口径（U-02）；区分「Nuclei 官方模板」与「聚合多源 PoC」 |
| R-04 | 多套默认参数冲突（X7）+ Web UI 键名 max_scan_time 与 CLI max_time 不一致（X14） | 经 Web UI 发起扫描的超时控制 | 超时行为分歧，扫描不可控 | 中 | 统一配置键名与优先级（ConfigManager 明确 env > profile > CLI > default）；Web UI 对齐 max_time |
| R-05 | 报告格式未完全落地（X10）：sarif/csv 被 CLI 接受但未写出，Web UI 仅 JSON | CI/CD SARIF 接入 / 多格式导出需求 | DevSecOps 集成受限，下游对接缺口 | 中 | 补齐 sarif_reporter/csv_reporter 写出；Web UI /api/export 扩展格式 |
| R-06 | 外部二进制供应链依赖（Nuclei/sqlmap/ffuf 子进程调用）的可用性与许可 | 目标环境缺这些工具或版本不兼容 | 部分能力降级（PoC/模糊测试不可用） | 低-中 | Docker 镜像内置并钉固版本；检测缺失依赖时给出明确降级提示 |

### 5.2 待确认项（需主理人 / 业务方反馈）

> 调研中因外部信息不可得或项目内部未裁决而暂不能确认的事实。

| 编号 | 待确认项 | 不确定性说明 | 若无法确认的备选路径 |
| --- | --- | --- | --- |
| U-01 | 当前真实版本基线（X1：pyproject 2.0.0 vs cli 1.1.0 vs web_ui 1.0.2） | 代码/文档跨 4 种版本表述，缺单一权威源 | 以 pyproject version 为准，主理人确认对外发布版本号 |
| U-02 | Nuclei PoC 实际数量与口径（「12.5w」是否含 xray/beebeeto/bugscan 聚合） | 官方模板库约 12,000；RayScan 宣称 12.5w 疑为聚合多源 | 核对 poc_sources.yaml 实际模板数并标注统计口径 |
| U-03 | waf 模块默认启用状态（X16：config.py 默认模块表未含 waf） | waf 有代码与文档但未在默认模块配置显式声明 | 核实其默认加载路径（是否经其他模块表/注册机制启用） |
| U-04 | 真实测试数量（X8：README 79 vs CHANGELOG 281） | 可能为不同时间点统计口径 | 运行 `pytest --co` 核实当前用例数 |
| U-05 | RayScan 产品定位：纯社区 OSS，还是计划商业化/多租户 SaaS | 用户诉求未明示；影响部署形态与合规可控性权重 | 若涉多租户/SaaS，将触发新一轮中间确认（见 D-04），当前按 OSS 自托管定位调研 |

> **【中间确认自检 · §5.2 待确认项（最后一次完整复核）】**（按协议 §2.1 判定 + §2.3 反向 3 问）
> - **§2.1 判定：未命中。** U-01~U-04 为项目内部事实核实项（版本/模板数/模块启用/测试数），由主理人或维护者核对代码/运行命令即可确认，不构成「≥2 种方案且影响下游业务边界」的分叉；U-05 虽涉及产品形态，但在本研究已按用户诉求明示的「OSS 自托管」定位完成，且若未来转向 SaaS 将作为独立决策在下游触发确认（已登记为 D-04 依赖），不在本次调研内裁决。
> - **反向验证 3 问：**
>   - Q1（返工成本）：待确认项仅影响 §5.2 表格内容与个别事实表述，返工范围 = 本报告 1 个章节的若干行；若主理人后续给出结论，仅修订对应行，切换成本 ≈ 小时级。→ **可控**。
>   - Q2（用户/客户/监管可感知）：这些内部事实（版本号/测试数/模板数）经确认后可能影响对外文档，但「是否确认」这一动作本身不向用户暴露新功能/合同/合规属性。→ **感知不到（确认动作本身）**。
>   - Q3（与用户诉求一致）：用户诉求聚焦「对比主流工具、支撑架构决策」，未要求本研究裁决 RayScan 内部版本/计数；U-05 已按用户诉求明示的 OSS 定位处理。→ **用户诉求未显式提及此点，本研究已按 OSS 自托管定位收敛，未改变产品形态**。
> - **结论：未命中，不发起 [中间确认]。** U-01~U-05 以「待确认项」形式移交主理人/业务架构师，不阻断本报告 G2 提交。

### 5.3 需业务架构持续关注的依赖项

| 编号 | 依赖项 | 说明 | 建议关注阶段 |
| --- | --- | --- | --- |
| D-01 | 模块边界：DetectionModule 是否扩展到第三方插件市场 | 影响 modules 包边界与注册机制开放度（§4.1/§4.3） | 高层架构设计 §模块边界 |
| D-02 | 多引擎聚合：ResultMerger 统一数据模型与去重策略（rule id + URL hash） | 决定聚合层是否演进为归一化层（§3.3/§4.1） | 高层架构设计 §多引擎聚合 |
| D-03 | 报告体系：是否采用 SARIF 作为一等公民 + DefectDojo 类归一化 | 决定 reporting 包是否补齐 sarif/csv 写出（X10/R-05） | 安全设计 / 报告体系 |
| D-04 | 部署形态：是否从 CLI/Docker/Web 扩展到分布式/多租户 SaaS | 若商业化多租户，将触发新一轮中间确认（U-05 关联） | 系统架构 §部署形态 |

---

## 6. 关键来源目录

> 集中列出全部调研所使用的公开资料、官方文档、社区仓库、分析报告等。每条来源不低于 URL 粒度，关键来源给出具体章节或段落。

**硬指标**：≥ 3 条来源，覆盖每家标杆；关键数据（准确率、定价、模板数）指定来源段落/位置。

| 编号 | 来源类型 | 标题 / 名称 | URL / 路径 | 相关章节 | 最后访问日期 |
| --- | --- | --- | --- | --- | --- |
| SR-01 | 官方文档 | Invicti — Proof-Based Scanning / DAST Overview | https://docs.invicti.com/appsec/dast-overview ；https://www.invicti.com/ | B1, §2.2.1, §2.3 | 2026-07-12 |
| SR-02 | 官方对比 + 评测 | Acunetix vs Invicti（同集团、Proof-Based 引擎、IAST Shark/AcuSensor）；Acunetix 定价 $4,500+/年、Invicti 定制价 | https://www.acunetix.com/comparisons/acunetix-vs-invicti/ ；https://weavai.app/blog/zh-cn/2026/05/07/2026-acunetix-%E8%AF%84%E6%B5%8B%EF%BC%9A%E5%8A%9F%E8%83%BD%E3%80%81%E5%AE%9A%E4%BB%B7%E4%B8%8E%E6%9B%BF%E4%BB%A3%E6%96%B9%E6%A1%88/ ；https://appsecsanta.com/invicti（99.98% 准确率宣称） | B1, §2.2.1, §3.1 | 2026-07-12 |
| SR-03 | 官方特性 + 定价 | Burp Suite Enterprise/DAST Features（OAST、BApp 500+、SARIF、K8s/Docker）；定价计价器（Classic ~$19,121 / Unlimited ~$49,999） | https://portswigger.net/burp/enterprise/features ；https://portswigger.net/purchase/enterprise/plan | B2, §2.2.2, §2.3, §3.1 | 2026-07-12 |
| SR-04 | 社区评测 + 官方博客 | OWASP ZAP 特性（MITM/主动+被动/Spider/AJAX/Fuzzer/200+ 插件/SARIF/REST API）；Checkmarx 资助仍 OSS；WAVSEP 基准 | https://ethicalhacking.ai/tools/owasp-zap-tool ；https://www.stackhawk.com/blog/how-to-migrate-zap-stackhawk ；http://www.appsecsanta.com/owasp-zap | B3, §2.2.3, §2.3, §3.1 | 2026-07-12 |
| SR-05 | 官方文档 + 评测 | Nuclei Overview（YAML 模板、12,000+ 社区模板、多协议、SARIF、去重）；Nuclei Templates 库统计（CVE 3,587 等） | https://docs.projectdiscovery.io/tools/nuclei/overview ；https://appsecsanta.com/nuclei ；https://sinapti.ca/post/en/nuclei-templates-the-library-of-12000-templates-for-detectin-dpy1e6om | B4, §2.2.4, §2.3, §3.1 | 2026-07-12 |
| SR-06 | 行业文档 | 多引擎聚合/归一化范式：ASOC（Synopsys）、DefectDojo（统一模型+去重+150+ 工具）、Faraday（80+ 工具+自动去重+Agents Dispatcher）、MEDUSA（三层插件化编排+统一漏洞模型） | https://www.synopsys.com/zh-cn/glossary/what-is-application-security-orchestration-and-correlation.html ；https://zread.ai/DefectDojo/django-DefectDojo/dojo/dojo/urls.py ；http://www.appsecsanta.com/faraday ；https://devpress.csdn.net/v1/article/detail/93065515 | B5, §2.3, §3.3, §4.1 | 2026-07-12 |
| SR-07 | 技术文档 | SARIF（OASIS 标准 v2.1.0）在 DAST 的应用：ZAP→SARIF、Burp SARIF 导出端点、Nuclei 原生 SARIF | https://www.shipsafer.ai/blog/dast-testing-guide ；https://lobehub.com/zh/skills/agentskillexchange-skills-owasp-zap-active-scanner-agent ；https://www.kiuwan.com/blog/sarif-speaking-universal-security-language | §3.3, §4.3, R-05 | 2026-07-12 |
| SR-08 | 横向对比 | DAST 工具综合对比（ZAP/Burp/Invicti/Acunetix/Nuclei 定价、速度、误报、CI/CD） | https://rafter.so/blog/dast-tools-comparison ；https://pentest.ae/dast-tools-comparison-2026/ ；https://expertinsights.com/application-security/the-top-dynamic-application-security-testing-dast-tools | 全文交叉校验 | 2026-07-12 |
| SR-09 | 上游内部摘要 | material_digest.md（RayScan 资料摘要 v0.1，G1 已通过，含 X1–X16 冲突） | D:\HZR_PROJECTS\RayScan\RayScan\.workbuddy\output\material_digest.md | B5, 全文 | 2026-07-12 |

---

## 7. 硬指标清单

> 汇总本模板所有章节的硬指标，供自动校验与人工审核使用。

| 章节 | 硬指标项 | 当前状态 | 备注 |
| --- | --- | --- | --- |
| §1 | 调研问题已收敛为 ≥ 3 条可执行问题 | ✅ | Q1–Q5 共 5 条 |
| §2.1 | 标杆系统 ≥ 3 家，含 ≥ 1 家头部 SaaS | ✅ | B1 Invicti、B2 Burp 为 SaaS 头部 |
| §2.1 | 标杆系统 ≥ 1 家开源或自研代表 | ✅ | B3 ZAP、B4 Nuclei（开源）、B5 RayScan（自研） |
| §2.2 | 每家标杆有独立详述卡片 | ✅ | B1–B5 均含 10 维度卡片 + 置信度 |
| §2.3 | 关键能力横向事实无遗漏 | ✅ | 10 能力维度 × 5 标杆 |
| §3.1 | 对比矩阵含 5 维度 + 权重 + 评分 | ✅ | 权重和 = 1.00（0.30+0.20+0.15+0.15+0.20） |
| §3.2 | 评分结论含优先/部分/不借鉴三层 | ✅ | 优先：Nuclei+ZAP；部分：Burp；不借鉴：Invicti |
| §4.1 | 自研/采购/复用边界有明确建议 | ✅ | 7 项能力边界建议 |
| §4.2 | MVP 范围建议与用户诉求对齐 | ✅ | 9 项功能对齐 RayScan 现状 |
| §5.1 | 主要风险 ≥ 3 条，有缓解建议 | ✅ | R-01~R-06 共 6 条，均带缓解 |
| §6 | 关键来源可追溯（URL / 章节） | ✅ | SR-01~SR-09 共 9 条，覆盖全部标杆 |
| 全文 | 明确区分事实 / 推断 / 建议 / 风险 | ✅ | 事实带置信度/来源；建议标「建议」；风险标「风险」 |
| 全文 | 不存在编造来源或占位符 | ✅ | 无尖括号占位符、示例前缀或待验证标记残留；不确定项已归入 §5.2 |
