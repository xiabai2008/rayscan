## Agent skills

### Issue tracker

GitHub Issues via the `gh` CLI (repo: `xiabai2008/rayscan`). See `docs/agents/issue-tracker.md`.

### Triage labels

Default five-role vocabulary (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context — one `CONTEXT.md` + `docs/adr/` at the repo root. See `docs/agents/domain.md`.

### Code change log

All code changes must be logged in this file. Each entry should include:
- Date (YYYY-MM-DD)
- Summary of changes
- Affected files/modules

## Change Log

### 2026-08-25 (S5 OA 真实样本闭环 — 通达 OA V13.5 本地部署复核)
- 通达 OA V13.5 官方安装包（659MB，NSIS 静默解压至 D:\MYOA）本地部署成功：Nginx（8895）+ php-cgi（8360-8369）+ MySQL（3336）+ Redis（6399），首页 200「通达网络智能办公系统（试用版）」
- 新增 `debug_tongda_real.py` 端到端复核：指纹识别命中（html tongda，favicon /static/images/tongda.ico）✅、漏洞检出 0（login_code_scan.php 返回 {"status":"0"}，V13.5 已修复任意用户登录，正确不报）✅——**安全模式真实样本闭环**；漏洞模式（status:1 → 检出）仍由合成靶场闭环
- 部署踩坑（均已解决并登记 OA_RULES.md）：
  - Hyper-V 保留端口区间（8201-8300）导致 php-cgi 无法绑定 8260-8269（"Bad file descriptor"），FPM 端口改 8360-8369（Service.ini + nginx.conf 同步）
  - nginx 队列端口 8750 落在保留区间 8746-8845，改 8896
  - Redis 旧进程密码与配置不符（AUTH failed），需用当前 redis.windows.conf 重启
  - `Set-Content -Encoding UTF8` 给 nginx.conf 加 BOM 导致 nginx 报 "unknown directive"（改无 BOM UTF8 重写）
  - Office_Daemon 看门狗反复触发 Office_Web 服务，OfficeWeb.exe 启动时杀 nginx 进程（手动部署需停用 Daemon）
- `docs/OA_RULES.md` 验证表登记通达真实样本闭环记录（安全模式 0 误报），待实测备注更新为「其余 6 种 OA 待真实/靶场样本复核」
- 遗留：通达漏洞模式（任意用户登录）需旧版（< 11.5.200417）样本才能真实触发，当前 V13.5 已修复

### 2026-08-25 (S5 OA 二次复核 — 网络恢复后拉取镜像实测)
- Docker 网络恢复后拉取 5 个候选镜像验证：
  - `iisimpler/landray-oa:1.0`（616MB）——真实蓝凌 EKP 应用（Tomcat /ekp 含 login.jsp/km 模块），但启动失败（kmssconfig 加密 + 数据库未就绪 + JVM 内存 1675M<2048M），listener 报错返回 404，无法使用
  - `pskzc/seeyon:1.0`（317MB）——gRPC 扫描工具服务（python + protobuf），非真实 OA
  - `wellxterm/kingdee:v1.0`（1.16GB）——arm64 空基础镜像，无金蝶应用
  - `lao5/oracle12c-r2-yonyou-nc:latest`（470MB）——仅 Oracle 12c R2 数据库，无用友 NC 应用
  - `easysoft/zentao:16.5`（官方禅道）——拉取成功但为未安装状态（重定向 install.php），与 Windows 安装包版重复，无新增验证价值
- 结论：4 个候选镜像均不能提供可运行的真实 OA 靶场；vulhub / Vulfocus 均无 7 种国产 OA 镜像
- `docs/OA_RULES.md` 验证表更新二次复核记录；7 种 OA 维持合成靶场闭环结论（漏洞模式 18 检出 + 安全模式 0 误报）

### 2026-08-24 (S5 OA 复核 — 真实靶场复核 + Docker 网络阻塞诊断)
- 启动本地 Docker（29.6.2）对真实靶场复核：Nacos（vulhub 1.4.0，CRITICAL 未授权 1 项）、Confluence（vulhub 7.4.10，安装向导模式全端点 302，0 检出为正确非误报）、禅道（16.5，HIGH SQL 注入 1 项）——`debug_real_recheck.py` 端到端复核全部通过
- Docker 网络阻塞根因诊断：Docker Desktop 手动代理（settings-store.json `OverrideProxyHTTP=127.0.0.1:7897` = Clash Verge）导致大层下载持续 `unexpected EOF`；镜像源（1ms/DaoCloud/NJU）直连返回 403/IncompleteRead；vulhub 仓库核实无泛微/通达/金蝶/蓝凌/致远/用友/万户目录；Docker Hub 非官方 0 星镜像（landray-oa/seeyon/kingdee 等）均无法完整拉取
- 新增 `tools/pull_via_mirror.py`（从 DaoCloud 镜像源手动下载镜像 + docker load，绕过 Clash 代理）——因网络阻塞未成功，保留备用
- 恢复 Docker 配置（daemon.json / settings-store.json 已还原）；`docs/OA_RULES.md` 验证表登记 2026-08-24 复核记录与网络阻塞现状
- 遗留：7 种 OA（泛微/通达/金蝶/蓝凌/致远/用友/万户）真实样本复核仍受 Docker 网络阻塞，维持合成靶场闭环结论

### 2026-08-24 (S5 OA 闭环 — 剩余 8 种 OA 合成靶场闭环)
- 8 种 OA（泛微/通达/金蝶/蓝凌/致远/用友/禅道/万户）合成靶场端到端闭环：新增 `mock_oa_remaining.py`（127.0.0.1:8901-8908，忠实模拟各 OA 首页指纹 + 漏洞端点响应签名），`debug_oa_remaining.py` 两轮验证——漏洞模式 8/8 全部检出（18 项漏洞）、安全模式 8/8 零误报，指纹识别全部命中
- 修复致远 ajax.do 检测缺陷：session 对 5xx 重试后抛 RequestError、正文丢失，导致 500 成功特征（CNVD-2021-01627 上传成功返回 500 + code 08441）永远看不到；`_run_check` 对显式声明非 2xx 状态码的检查项改用独立 httpx 请求 `_fetch_with_status`（trust_env=False）容忍该状态码拿正文
- 修复 sqli 通用验证误报：`"success"` 子串匹配过宽（`{"success":false}` 也命中），改为正则要求 `"success":true`；新增回归测试 `test_sqli_success_false_not_vuln`
- `_scan_impl` 检测成功后回写 `self._detected_oa`（scanner 注入与内部检测统一出口，保持实例状态一致）
- 测试：新增 1 项误报回归测试，全量测试 290 通过；`docs/OA_RULES.md` 验证表 8 种 OA 登记合成靶场闭环记录（漏洞模式 18 检出 + 安全模式 0 误报）
- 遗留：合成靶场闭环检测逻辑，待真实/靶场样本复核（Docker 网络阻塞未解）

### 2026-08-24 (S5 OA 闭环 — 剩余 8 种 OA 规则完善)
- 8 种 OA 检测规则全部补齐规则级 evidence（响应特征），基于公开漏洞研究（CVE/CNVD/PoC），每条规则"仅证据命中才报"，误报 0：
  - 泛微：FileDownloadForOutDoc LFI 加 evidence `root:`（/etc/passwd 回显）
  - 通达：remotelogin.php 替换为 login_code_scan.php 任意用户登录（uid=1 即 admin，evidence `"status":1`）
  - 金蝶：新增 CommonFileServer 任意文件读取（`/CommonFileServer/c:/windows/win.ini`，evidence `[fonts]`，6.x/7.x/8.x 均受影响）
  - 蓝凌：新增 custom.jsp 任意文件读取 CNVD-2021-28277（POST var=file:///etc/passwd，evidence `root:`）
  - 致远：新增 ajax.do 任意文件上传 CNVD-2021-01627（evidence `"code":"08441`，上传成功返回 500）
  - 用友：新增 portal/file 任意文件读取（路径遍历读 web.xml，evidence `<web-app`）
  - 禅道：新增 user-login.html 前台 SQL 注入 CNVD-2022-42853（updatexml 报错注入，evidence `xpath syntax error`）
  - 万户：uploadFile.jsp（GET 探测永不报）替换为 evoInterfaceServlet 未授权访问（evidence `"userList"`，账号+MD5 密码泄露）
- `_run_check` 支持 `status_codes` 参数（默认 `[200]`；致远 ajax.do 上传成功返回 500 需放宽），保持 S1 误报治理基线
- 测试：新增 22 项 `TestRemainingOARules`（8 种 OA 规则配置 + evidence 命中/不命中）；`docs/OA_RULES.md` 检测矩阵/字段表/验证表更新（8 种 OA 标注"规则就绪，待真实/靶场样本闭环"）
- 验证：全量测试 289 通过（含新增 22 项），改动无回归

### 2026-08-24 (S5 OA 闭环 — Confluence 第 4 种 + httpx 代理修复)
- 闭环 4/12 OA：新增 Confluence（vulhub CVE-2021-26084 靶场 7.4.10，127.0.0.1:8890）——指纹识别（title/atlassian 内容指纹）✅、版本识别（ajs-version-number meta → 7.4.10）✅ 真实靶场闭环；漏洞检测（CVE-2021-26084 OGNL 注入 RCE）用合成靶场 mock_confluence.py（127.0.0.1:8897）闭环，误报 0
- 修复 httpx 502 根因：httpx 默认 `trust_env=True`，在 Windows 上读取系统代理（Clash `enable_system_proxy`），导致对本地靶场 127.0.0.1 的请求被转发到 Clash 返回 502（curl/http.client 直连正常）；`session.py::_ensure_client` 与 `OADetector._fetch_homepage_for_fingerprint` 加 `trust_env=False`，仅用显式 proxy_pool
- Confluence 检测规则新增：`OA_RULES["Confluence"]["checks"]` 加 CVE-2021-26084 检查项（POST body `queryString` OGNL payload，evidence `54289`=233*233 回显）；`_run_check` 支持 `param_type`（body/query）；`_detect_oa_version` 加 Confluence 分支（ajs-version-number meta + version= 兜底）
- 测试：新增 8 项 Confluence 测试（指纹/版本/规则集成/证据命中与不命中）；适配 test_fp_guard 的 fake_send 签名（`_send_request` 增 param_type 参数）
- 遗留：真实 Confluence 安装需 Atlassian 试用 license，2026-03-30 起官方停止发放（Data Center 产品），漏洞检测暂以合成靶场闭环；`docs/OA_RULES.md` 验证表登记 Confluence 记录
- 验证：全量测试 267 通过（含新增 Confluence 8 项），改动无回归

### 2026-08-24 (S5 OA 闭环 — 执行)
- 闭环 3/12 OA：Nacos（vulhub 1.4.0，CVE-2021-29441 未授权）、Jenkins（2.578 WAR 关闭安全认证，脚本控制台未授权 RCE）、Spring（合成靶场 mock_spring.py，actuator env/heapdump 泄露）；全链路（指纹→版本→漏洞验证）端到端完整扫描验证通过，误报 0
- 修复 Spring 检测缺陷：session 对 4xx 抛 RequestError 导致 Whitelabel Error Page（404 正文）丢失，OA 指纹永远看不到；新增 `OADetector._fetch_homepage_for_fingerprint` 用独立 httpx 请求容忍 4xx 抓首页指纹
- Jenkins 靶场搭建：Docker 镜像拉取因网络持续 EOF 失败（含多镜像源/代理排查），改下载 Jenkins WAR（腾讯镜像 2.578，54MB）+ 本机 Java 21 运行；发现 Windows Hyper-V 端口保留区间（8001-8100 等）导致 8080/8081 绑定失败，改用 8899
- `docs/OA_RULES.md` 验证表登记 3 条闭环证据（靶场版本+识别结果+漏洞检出+误报）
- 遗留：其余 9 种 OA（泛微/通达/金蝶/蓝凌/致远/用友/禅道/万户/Confluence）受 Docker 网络阻塞未闭环，验证表标注"待实测"
- 验证：全量测试 259 通过（含 test_oa_deep + test_fp_guard 46 项），改动无回归

### 2026-08-24 (S4 信任重建 — 执行)
- T3 僵尸资产出仓：删除 `full_scan.py`（含泄漏个人路径）、`quick_scan.py`（硬编码靶场+旧 API）、`wvs_gui.py`（停止维护）；删除前确认 Dockerfile/CI/tests 无引用；嵌套 `RayScan/` 目录（独立 git 仓库副本，578 文件）归档至仓库外 `C:\Users\HZR\Desktop\HZR_PROJECTS\RayScan-archive-2026-08-24\`——内含 `delivery/` 设计文档（UserStory/系统设计/安全设计/部署设计等 8 份）与 JS 渲染/SPA 爬取/外部基准的独立 git 历史，**疑似独有成果，未删除仅归档，建议评估是否合并回主仓库**
- T2 文档重写：`docs/modules.md`（11→18 模块 + core/optional/lite 分层 + 注册机制）、`docs/architecture.md`（runner→integration 路径修正、httpx 主链路、ScanOrchestrator、删 gui/）、新建 `CONTEXT.md`（16 条领域术语 + 命名规则）
- T1 README 修正：测试徽章 190 passing→259 collected（实测口径）、定位语改 ADR-0001 口径、实战验证→靶机验证、版本表排序修正、结构图删僵尸入口、quick/full_scan 章节改 CLI/Profile 参数说明
- T4 CHANGELOG：顶部加数字单一事实源规则（CI collect-only 实测，不手写）
- T5 CI 加固（`.github/workflows/ci.yml`）：新增 audit job（pip-audit 扫锁文件）、hygiene job（git ls-files 卫生检查）、覆盖率门禁 `--cov-fail-under=30`（基线 32%）、mypy 预算门禁（wvs/core ≤250 错误防增长，基线 245），types job 移除 continue-on-error
- 附带修复：`tests/test_smoke_cli.py::test_version_consistency` 弃用 tomllib（3.11+ 专属）改正则解析，兼容 requires-python>=3.8 全版本；此前该测试在 Py3.9/3.10 必挂
- 验证：全量测试 exit 0（tomllib 修复后），覆盖率 32%

### 2026-08-24 (S4 启动 — 定位决策与信任重建清单)
- 新增 `docs/adr/0001-oa-focused-repositioning.md`：定位收缩至「中文 OA / 国产中间件专项检测器」的正式 ADR（固化演进规划 §11 战略修正，含适应度函数 FF1–FF6 与可逆性触发条件）
- 新增 `docs/audit/rayscan-s4-trust-rebuild-2026-08-24.md`：S4 信任重建执行清单（T1 README 数字修正 / T2 陈旧文档重写 / T3 僵尸资产出仓 / T4 CHANGELOG 数字单一事实源 / T5 CI 门禁加固 / T6 发布冻结至 v2.1.1）
- 依据：2026-08-24 三路项目审查（架构 / 质量门禁与宣称一致性 / 定位与文档）

### 2026-08-05 (S3 OA 专项深化 — 三级检测链路)
- 三级检测链路：指纹识别（内容优先）→ 版本识别 → 漏洞验证（规则级证据优先）+ 版本过滤
- 新增 `OA_CONTENT_FINGERPRINTS`（12 种 OA 内容指纹：title/正文/响应头/Set-Cookie 四类匹配）
- `_detect_oa_type` 升级双通道：内容指纹优先，URL 路径/关键词回退；`_scan_impl` 优先使用 scanner 注入的 `_detected_oa`（修复断链），否则抓首页识别
- 新增 `_detect_oa_version`（Jenkins X-Jenkins 头、Nacos 页面版本变量、Spring/泛微/禅道版本字样，未识别不阻塞）与 `_version_in_range`（[min,max) 语义、无版本放行、解析失败放行）
- `_verify_evidence` 支持检查项规则级 `evidence`（优先于通用类型验证）；`_run_check` 接入版本过滤
- 首个真实版本过滤用例：Nacos 用户列表未授权（CVE-2021-29441）`evidence: pageItems` + `max_version: 1.4.1`
- 新增 `tests/test_oa_deep.py`（23 个测试：指纹/版本/过滤/规则证据/Nacos 集成）
- 新增 `docs/OA_RULES.md`（规则文档 + 检测矩阵 + 实战验证记录表，待实测样本闭环）

### 2026-08-05 (S2 链条接通 — nuclei 接入 + checkpoint 复活)
- Nuclei 接入主流程：`WAVScanner.scan()` Phase 3.5 新增 Nuclei 阶段（config `nuclei.enabled` 默认开，CLI `--no-nuclei` 关闭）；新增 `_run_nuclei`（懒实例化，CLI 可用走模板扫描，不可用走 S1 修复后的内置回退）；结果经 `_deduplicate` 合并
- 模板选择修复：`_cli_scan_async` 不再把模板折叠成父目录 `-t`（原实现=递归扫描整个目录），直接传模板文件逗号列表（上限 200 防命令行超限）
- Checkpoint 复活：`__init__` 初始化 `_modules_done`/`_last_checkpoint_time`/`_checkpoint_interval`/`_resume_checkpoint`（原 `_save_checkpoint` 引用未初始化字段必 AttributeError）；批次循环更新模块完成状态 + `_try_save_checkpoint` 间隔限流落盘；扫描完成落盘最终 checkpoint；`--resume` 注入 checkpoint → scan() 合并已发现漏洞 + 跳过已完成模块
- cli.py：`--no-nuclei` 参数 + `--resume` 注入 `scanner._resume_checkpoint`
- 新增 `tests/test_s2_resume.py`（8 个测试：checkpoint 往返/间隔限流/Vulnerability 序列化/nuclei 懒加载与复用/config 开关）
- 端到端实测：本地 HTTP 服务器扫描 → checkpoint 落盘（modules_done=['sqli','xss']）→ `--resume` 恢复提示与模块跳过均验证通过

### 2026-08-05 (S1 误报治理 — 发版前修复)
- Nuclei 内置回退：移除"可达即报"（`pattern is None` → 不报）；/graphql、/security.txt 补内容特征；/dev 检查项移除（无可靠特征）；body 截断 200→2000；特征匹配改大小写不敏感；`.git/config` 特征 `remote origin` → `[remote`（真实格式）
- OA 检测：`_run_check` 移除 401/403/500/302"状态码即漏洞"判定，仅 HTTP 200 + `_verify_evidence` 响应证据验证（unauth=JSON 数据、info_disclosure=actuator/heapdump 特征、sqli=SQL 报错/JSON success、rce=octet-stream/二进制/Groovy、file_read=JSP 源码特征）；file_upload/info 类 GET 探测不报
- OA 通用路径：移除 /admin/、/login/、/system/、/api/、/webservice/、/backup/ 泛路径检查；保留 4 个可内容验证的泄露路径（web.xml/MANIFEST.MF/.git/HEAD/.env 键值对启发式）
- XXE：`_check_xxe_success` 增加 baseline 排除；三个调用点（参数注入/XML body/SVG 上传）均先取良性 baseline
- SSRF：`_check_ssrf_success` 增加 baseline 排除（含连接错误关键词分支）；`test_cloud_metadata` 补 baseline
- DOM XSS：移除 `_test_dom`（URL fragment 反射伪检测，非真实 DOM 检测；待 headless 验证接入）
- 新增 `tests/test_fp_guard.py`（23 个误报防护回归测试：XXE/SSRF baseline、OA 证据验证、Nuclei 回退特征匹配）
- README：撤下未兑现卖点（多引擎聚合/MSF 验证链标注为 Roadmap），测试数 79→136，项目结构图修正
- 规划文档 `docs/audit/rayscan-evolution-plan-2026-07-12.md` 更新至 v1.2（§11 战略修正：OA 专项 + 工作流闭环，替代自研内核优先）

### 2026-06-27
- Added Code change log section to AGENTS.md

### 2026-06-27 (Profile System)
- Added Profile system: `wvs/profiles/` module with ProfileManager
- Added CLI subcommands: `rayscan profile list|create|delete|export|import`
- Added `rayscan use <profile> -u <url>` command for profile-based scanning
- Added built-in profiles: default, src-quick, pentest-full, sqli-only
- Added 17 tests in `tests/test_profiles/`
