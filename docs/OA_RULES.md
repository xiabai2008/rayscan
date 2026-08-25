# RayScan OA 专项检测规则文档

> 版本：v1.0 ｜ 2026-08-05（S3 三级链路深化后）
> 代码位置：`wvs/modules/oa/detector.py`（OA_RULES / OA_CONTENT_FINGERPRINTS）
> 误报治理基线：S1（2026-08-05）起，所有检查项仅 **HTTP 200 + 响应证据验证** 通过才报漏洞。

---

## 1. 三级检测链路（S3 深化）

```
第 1 级  指纹识别    内容指纹（title/正文/响应头/Set-Cookie）优先，URL 路径/关键词回退
   │                （scanner 首页指纹注入 → OADetector 首页抓取 → URL 兜底）
   ↓
第 2 级  版本识别    从响应/头提取版本（Jenkins X-Jenkins、Nacos 页面版本变量、
   │                Spring/泛微/禅道页面版本字样），未识别不阻塞
   ↓
第 3 级  漏洞验证    检查项规则级 evidence（响应特征）优先；无则通用类型验证
   │                （unauth=JSON 数据 / sqli=SQL 报错 / rce=二进制或 Groovy…）
   ↓
        版本过滤    min_version/max_version 约束（[min, max) 语义，无版本放行）
```

## 2. 检查项字段

| 字段 | 必填 | 说明 |
|------|:----:|------|
| `path` | ✅ | 检测路径 |
| `type` | ✅ | 漏洞类型（sqli/rce/lfi/file_read/file_upload/auth_bypass/unauth/info_disclosure/info） |
| `severity` | ✅ | critical/high/medium/low/info |
| `method` | | 默认 GET |
| `params` | | 请求参数（payload 类检查项） |
| `evidence` | | **S3 新增**：规则级响应特征（大小写不敏感子串），命中才算漏洞 |
| `min_version` / `max_version` | | **S3 新增**：版本过滤（[min, max) 语义，无版本信息放行） |
| `status_codes` | | **S5 续**：允许的响应状态码（默认 `[200]`；个别漏洞如致远 ajax.do 上传成功返回 500） |

## 3. 12 种 OA 检测矩阵

| OA | 指纹（内容通道） | 检查项数 | 规则级 evidence | 版本识别 |
|----|-----------------|:-------:|:--------------:|---------|
| 泛微-Ecology | ecology/e-cology/weaver/eoffice | 3 | ✅ root:（/etc/passwd 回显）| 页面版本变量 |
| 通达OA | title 通达oa/tongda/ispirit/td_ | 3 | ✅ "status":1（任意用户登录）| — |
| 金蝶-Kingdee | title 金蝶/kingdee/k3cloud | 2 | ✅ [fonts]（win.ini 回显）| — |
| 蓝凌-Landray | landray/ekp/lms | 2 | ✅ root:（/etc/passwd 回显）| — |
| 致远-Seeyon | title 致远/seeyon/yyoa | 3 | ✅ "code":"08441（ajax.do 上传）| — |
| 用友-Yonyou | title 用友/yonyou/ufida/nc cloud | 2 | ✅ <web-app（web.xml 回显）| — |
| 禅道-Zentao | title 禅道/zentao/zentaopms/cookie zentaosid | 2 | ✅ xpath syntax error（报错注入）| 页面版本变量 |
| 万户-Whir | title 万户/whir | 1 | ✅ "userList"（账号密码泄露）| — |
| Nacos | title nacos/nacos/console.nacos | 2 | ✅ pageItems（用户列表）| 页面 nacos_version |
| Spring | Whitelabel Error Page/spring boot | 2 | — | spring-boot 版本字样 |
| Jenkins | **X-Jenkins 响应头**/title jenkins | 2 | — | **X-Jenkins 头** |
| Confluence | title confluence/atlassian | 2 | ✅ 54289（OGNL 233*233 回显）| ajs-version-number meta |

## 4. 版本过滤用例

| 检查项 | CVE | 版本约束 | 说明 |
|--------|-----|---------|------|
| Nacos `/v1/auth/users` 用户列表未授权 | CVE-2021-29441 | `max_version: 1.4.1` | 1.4.1 修复；2.x 目标自动跳过该项 |

> ⚠️ 版本范围来自 CVE 描述，实测中若发现误判（如新版仍可访问），调整约束并在此登记。

## 5. 实战验证记录

| OA | 验证目标 | 指纹识别 | 版本识别 | 漏洞检出 | 误报 | 日期 | 备注 |
|----|---------|:-------:|:-------:|:-------:|:----:|:----:|------|
| Nacos | vulhub CVE-2021-29441（nacos:1.4.0，127.0.0.1:8848） | ✅ 子路径探测 /nacos/ | ✅ 1.4.0（server/state 接口） | ✅ 1（/nacos/v1/auth/users 用户列表未授权，CRITICAL） | 0 | 2026-08-24 | 版本 1.4.0 < 1.4.1 放行版本过滤；configs 接口 500（invalid dataId）正确不报 |
| Jenkins | Jenkins 2.578 WAR（127.0.0.1:8899，关闭安全认证） | ✅ X-Jenkins 响应头 | ✅ 2.578（X-Jenkins 头） | ✅ 1（/computer/(built-in)/script 脚本控制台未授权 RCE，CRITICAL） | 0 | 2026-08-24 | 完整扫描端到端闭环；/script 200 + "Script Console" 证据命中；锁定版（安全开启）/script 302 正确不报 |
| Spring | 合成靶场 mock_spring.py（127.0.0.1:8898，模拟 Whitelabel Error Page + actuator 暴露） | ✅ Whitelabel Error Page（404 正文指纹） | —（无版本字样） | ✅ 2（/actuator/env 配置泄露 HIGH + /actuator/heapdump 堆转储泄露 CRITICAL） | 0 | 2026-08-24 | S5 修复：session 对 4xx 抛异常导致 404 正文丢失，新增 `_fetch_homepage_for_fingerprint` 容忍 4xx；合成靶场如实标注，待真实 Spring Boot 样本复核 |
| Confluence | vulhub CVE-2021-26084（confluence:7.4.10，127.0.0.1:8890）+ 合成靶场 mock_confluence.py（127.0.0.1:8897） | ✅ 内容指纹（title/atlassian） | ✅ 7.4.10（ajs-version-number meta） | ✅ 1（/pages/doenterpagevariables.action OGNL 注入 RCE，CRITICAL，mock 靶场） | 0 | 2026-08-24 | 真实靶场指纹+版本闭环；漏洞检测用合成靶场（真实安装需 Atlassian 试用 license，2026-03-30 起官方停止发放）；httpx 系统代理 502 根因修复（trust_env=False） |
| 泛微-Ecology | 合成靶场 mock_oa_remaining.py（127.0.0.1:8901） | ✅ 内容指纹（e-cology） | — | ✅ 3（FileDownloadForOutDoc LFI evidence root: / weaver.do RCE / WorkflowCenterTreeData SQLi） | 0 | 2026-08-24 | 合成靶场闭环：漏洞模式 3 检出 + 安全模式 0 误报；待真实样本复核 |
| 通达OA | 合成靶场 mock_oa_remaining.py（127.0.0.1:8902）+ **真实样本通达 OA V13.5 官方安装包（D:\MYOA，127.0.0.1:8895，Nginx+PHP+MySQL 3336+Redis 6399）** | ✅ 内容指纹（title 通达OA / html tongda） | — | 合成靶场 ✅ 3（login_code_scan.php 任意用户登录 evidence "status":1 / gateway.php SQLi / document SQLi）；真实样本 0（V13.5 已修复，login_code_scan.php 返回 {"status":"0"} 正确不报） | 0 | 2026-08-25 | **真实样本闭环（安全模式）**：指纹命中 + 0 误报；漏洞模式已由合成靶场闭环（status:1 → 检出）；部署要点——Hyper-V 保留端口区间（8201-8300）导致 php-cgi 无法绑定 8260-8269，FPM 端口改 8360-8369（Service.ini + nginx.conf 同步）、nginx 队列端口 8750→8896、Redis 需用当前配置重启（旧进程密码不符）；Office_Daemon 看门狗会反复触发 Office_Web 杀 nginx，手动部署时需停用 Daemon |
| 金蝶-Kingdee | 合成靶场 mock_oa_remaining.py（127.0.0.1:8903） | ✅ 内容指纹（title 金蝶） | — | ✅ 2（HttpFlowService RCE / CommonFileServer 任意文件读取 evidence [fonts]） | 0 | 2026-08-24 | 合成靶场闭环：漏洞模式 2 检出 + 安全模式 0 误报；待真实样本复核 |
| 蓝凌-Landray | 合成靶场 mock_oa_remaining.py（127.0.0.1:8904） | ✅ 内容指纹（landray） | — | ✅ 2（custom.jsp 任意文件读取 CNVD-2021-28277 evidence root: / custom_pf.jsp 源码泄露） | 0 | 2026-08-24 | 合成靶场闭环：漏洞模式 2 检出 + 安全模式 0 误报；待真实样本复核 |
| 致远-Seeyon | 合成靶场 mock_oa_remaining.py（127.0.0.1:8905） | ✅ 内容指纹（title 致远） | — | ✅ 3（htmlofficeservlet RCE / thirdpartyController RCE / ajax.do 任意文件上传 CNVD-2021-01627 evidence "code":"08441，status_codes=[500]） | 0 | 2026-08-24 | 合成靶场闭环：漏洞模式 3 检出 + 安全模式 0 误报；S5 续修复 session 对 5xx 重试抛错导致 500 成功特征丢失，`_run_check` 对非 2xx 状态码改用独立 httpx 请求；待真实样本复核 |
| 用友-Yonyou | 合成靶场 mock_oa_remaining.py（127.0.0.1:8906） | ✅ 内容指纹（title 用友） | — | ✅ 2（uploadServlet RCE / portal/file 任意文件读取 evidence <web-app） | 0 | 2026-08-24 | 合成靶场闭环：漏洞模式 2 检出 + 安全模式 0 误报；待真实样本复核 |
| 禅道-Zentao | 真实靶场 ZenTaoPMS 16.5 Windows 安装包（127.0.0.1:8893，Apache+MariaDB 10.4.14）+ 合成靶场 mock_oa_remaining.py（127.0.0.1:8907） | ✅ 内容指纹（title 禅道） | ✅ 16.5（登录页资源 URL ?v=16.5） | ✅ 1（user-login.html 前台 SQL 注入 CNVD-2022-42853 evidence xpath syntax error，HIGH） | 0 | 2026-08-24 | **真实靶场闭环**：注入点 = router `setVision()` 的 `owner='$account'` 拼接（非登录查询）；参数走 query string 可绕过 filterCSRF（只清 $_POST 不清 $_GET）；修复 payload `(user)`→`user()`（`(user)` 报 Unknown column 不命中）；api-getModel-api-sql.json 需认证未检出（保守不报）；MariaDB 表损坏修复后登录页空正文问题解决 |
| 万户-Whir | 合成靶场 mock_oa_remaining.py（127.0.0.1:8908） | ✅ 内容指纹（title 万户） | — | ✅ 1（evoInterfaceServlet 未授权访问 evidence "userList"） | 0 | 2026-08-24 | 合成靶场闭环：漏洞模式 1 检出 + 安全模式 0 误报；待真实样本复核 |
| （待实测） | | | | | | | 禅道已真实靶场闭环、通达已真实样本闭环（安全模式）；其余 6 种 OA（泛微/金蝶/蓝凌/致远/用友/万户）已用合成靶场闭环检测逻辑（漏洞模式 18 项检出 + 安全模式 0 误报），待真实/靶场样本复核 |

> **2026-08-24 复核记录**：启动本地 Docker（29.6.2）复核真实靶场——Nacos（1.4.0，CRITICAL 未授权 1 项）、Confluence（7.4.10，安装向导模式全端点 302，0 检出为正确非误报）、禅道（16.5，HIGH SQL 注入 1 项）全部复核通过。
> **2026-08-25 二次复核（网络恢复后）**：Docker 网络恢复后成功拉取 4 个候选镜像——`iisimpler/landray-oa:1.0`（616MB，真实蓝凌 EKP 应用，Tomcat 部署 `/ekp` 含 login.jsp/km 模块，但启动失败：kmssconfig 配置加密 + 数据库未就绪 + JVM 内存不足，listener 启动失败返回 404，无法使用）、`pskzc/seeyon:1.0`（317MB，gRPC 扫描工具服务，非真实 OA）、`wellxterm/kingdee:v1.0`（1.16GB，arm64 空基础镜像，无应用）、`lao5/oracle12c-r2-yonyou-nc:latest`（470MB，仅 Oracle 12c 数据库，无 NC 应用）；禅道官方 `easysoft/zentao:16.5` 拉取成功但为未安装状态（重定向 install.php，与 Windows 安装包版重复，未新增验证价值）。**结论：4 个候选镜像均不能提供可运行的真实 OA 靶场**，7 种 OA 真实样本复核仍受阻，维持合成靶场闭环结论。
> **2026-08-25 通达真实部署复核**：下载通达 OA V13.5 官方安装包（659MB，NSIS 静默解压至 D:\MYOA），配置 Nginx（8895）+ PHP（php-cgi 8360-8369）+ MySQL（3336）+ Redis（6399）后首页 200「通达网络智能办公系统（试用版）」。`debug_tongda_real.py` 端到端复核：指纹识别命中（html tongda，favicon /static/images/tongda.ico）✅、漏洞检出 0（login_code_scan.php 返回 {"status":"0"}，V13.5 已修复任意用户登录，正确不报）✅。**安全模式真实样本闭环**；漏洞模式（status:1 → 检出）仍由合成靶场闭环。
> **2026-08-25 通达部署踩坑**：① Hyper-V 保留端口区间（8201-8300 等）导致 php-cgi 无法绑定 8260-8269（"Bad file descriptor"），FPM 端口改 8360-8369（Service.ini + nginx.conf 同步）；② nginx 队列端口 8750 落在保留区间 8746-8845，改 8896；③ Redis 旧进程密码与配置不符（AUTH failed），需用当前 redis.windows.conf 重启；④ `Set-Content -Encoding UTF8` 会给 nginx.conf 加 BOM 导致 nginx 报 "unknown directive"（用无 BOM UTF8 重写）；⑤ Office_Daemon 看门狗反复触发 Office_Web 服务，OfficeWeb.exe 启动时杀 nginx 进程（手动部署需停用 Daemon 或改用非冲突方式）。
> **可用镜像清单**（已实测排除）：vulhub 仓库无 7 种国产 OA 目录；Vulfocus 无 OA 镜像；Docker Hub 非官方镜像 0 星且不可用。

> 验证流程建议：对每种 OA 至少 1 个授权目标运行 `python -m wvs scan <url> --all-modules`，
> 记录识别结果/漏洞/误报，回填本表。S3 验收标准 = 每种 OA ≥1 真实/靶场样本验证记录。

## 6. 已知边界（S3 承认的短板）

- **file_upload 类**（万户 uploadFile.jsp 等）：GET 探测无法验证上传漏洞，当前永不报（S1 决策），需 POST 上传利用流程才能补全——列为 S3 后深化项。
- **auth_bypass**（通达 remotelogin.php）：当前按"响应为 JSON 数据"验证，未验证 session 文件真实生成——属弱验证，待样本校准。
- **版本识别覆盖**：仅 5 种 OA 有版本提取器，其余 7 种无版本 → 版本过滤不生效（保守放行，不误伤）。
