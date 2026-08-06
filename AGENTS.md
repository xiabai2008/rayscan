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
