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

## 3. 12 种 OA 检测矩阵

| OA | 指纹（内容通道） | 检查项数 | 规则级 evidence | 版本识别 |
|----|-----------------|:-------:|:--------------:|---------|
| 泛微-Ecology | ecology/e-cology/weaver/eoffice | 3 | — | 页面版本变量 |
| 通达OA | title 通达oa/tongda/ispirit/td_ | 3 | — | — |
| 金蝶-Kingdee | title 金蝶/kingdee/k3cloud | 1 | — | — |
| 蓝凌-Landray | landray/ekp/lms | 1 | — | — |
| 致远-Seeyon | title 致远/seeyon/yyoa | 2 | — | — |
| 用友-Yonyou | title 用友/yonyou/ufida/nc cloud | 1 | — | — |
| 禅道-Zentao | title 禅道/zentao/zentaopms/cookie zentaosid | 1 | — | 页面版本变量 |
| 万户-Whir | title 万户/whir | 1 | — | — |
| Nacos | title nacos/nacos/console.nacos | 2 | ✅ pageItems（用户列表）| 页面 nacos_version |
| Spring | Whitelabel Error Page/spring boot | 2 | — | spring-boot 版本字样 |
| Jenkins | **X-Jenkins 响应头**/title jenkins | 2 | — | **X-Jenkins 头** |
| Confluence | title confluence/atlassian | 1 | — | — |

## 4. 版本过滤用例

| 检查项 | CVE | 版本约束 | 说明 |
|--------|-----|---------|------|
| Nacos `/v1/auth/users` 用户列表未授权 | CVE-2021-29441 | `max_version: 1.4.1` | 1.4.1 修复；2.x 目标自动跳过该项 |

> ⚠️ 版本范围来自 CVE 描述，实测中若发现误判（如新版仍可访问），调整约束并在此登记。

## 5. 实战验证记录

| OA | 验证目标 | 指纹识别 | 版本识别 | 漏洞检出 | 误报 | 日期 | 备注 |
|----|---------|:-------:|:-------:|:-------:|:----:|:----:|------|
| 泛微-Ecology | 本地 mock 靶场（weaver 指纹 + weaver.do POST RCE） | ✅ 泛微-Ecology | ✅ | ✅ RCE/critical（octet-stream 证据） | 0 | 2026-08-08 | 见 T0 实测（下方说明） |
| Nacos | 本地 mock 靶场 1.3.2（nacos_version 变量 + users 列表 pageItems） | ✅ Nacos | ✅ 1.3.2 | ✅ unauth/critical（CVE-2021-29441，版本过滤放行） | 0 | 2026-08-08 | 正样本 |
| Nacos | 本地 mock 靶场 1.5.0（同响应，版本已修复） | ✅ Nacos | ✅ 1.5.0 | ⬜ 不检出（版本过滤 [min,1.4.1) 正确跳过） | 0 | 2026-08-08 | 负样本，验证版本过滤 |
| Jenkins | 本地 mock 靶场（X-Jenkins 2.249.1 头 + /script Script Console） | ✅ Jenkins | ✅ 2.249.1 | ✅ RCE/critical（Script Console 证据） | 0 | 2026-08-08 | — |

> **T0 实测说明（2026-08-08）**：本地 mock OA 靶场（`http://127.0.0.1:<port>/`，社区可复现，见 AGENTS.md 变更日志）。
> 实测中发现并修复 3 个真实缺陷：①crawler 无端点时流式检测整体跳过（scanner 兜底端点前置）；
> ②httpx「URL 自带 query + params={}」丢弃 query 导致检查项请求缺参（base.py 空 params 不传）；
> ③scanner 注入短名与 OA_RULES key 断链（"泛微"→"泛微-Ecology" 别名映射）+ OA `_create_vuln` 枚举误传导致报告序列化失败。
> 验证流程：`python -m wvs scan http://127.0.0.1:<port>/ --modules oa --no-nuclei`。
> 待办：真实/授权样本继续回填本表（每种 OA ≥1 真实样本后完全闭环）。

> 验证流程建议：对每种 OA 至少 1 个授权目标运行 `python -m wvs scan <url> --all-modules`，
> 记录识别结果/漏洞/误报，回填本表。S3 验收标准 = 每种 OA ≥1 真实/靶场样本验证记录。

## 7. 真实样本收集流程（2026-08-08 建立）

**样本来源（按优先级）**
1. 本地靶场：Docker 镜像/安装包自建（推荐，完全可控）—— 泛微/致远/用友 均有公开安装包（需授权环境）
2. 授权测试目标：客户/学校/CTF 中明确授权的 OA 系统
3. 公开靶场：漏洞平台（如 vulhub 部分 OA 镜像、DVWA 类课程靶机）

**每条样本记录模板**（回填 §5 表格 + 附件）
```markdown
| OA | 验证目标（域名/IP+版本） | 指纹识别(命中指纹) | 版本识别(提取值) | 漏洞检出(类型/严重度/证据) | 误报(说明) | 日期 |
```
附件：扫描报告 JSON（`scan_reports/`）+ 复现命令（含 --allow-loopback 如为本机）。

**闭环标准**：§5 表中该 OA 行含"✅"检出或"⬜ 负样本（版本过滤/修复版）"，且误报列注明根因。

**当前状态**：泛微/Nacos/Jenkins 已有 mock 靶场记录（§5）；真实样本待收集清单：
- [ ] 泛微-Ecology（真实安装包）
- [ ] 致远-Seeyon
- [ ] 用友-Yonyou
- [ ] 通达OA、金蝶、蓝凌、禅道、万户、Spring、Confluence（mock 或真实均可）

## 6. 已知边界（S3 承认的短板）

- **file_upload 类**（万户 uploadFile.jsp 等）：GET 探测无法验证上传漏洞，当前永不报（S1 决策），需 POST 上传利用流程才能补全——列为 S3 后深化项。
- **auth_bypass**（通达 remotelogin.php）：当前按"响应为 JSON 数据"验证，未验证 session 文件真实生成——属弱验证，待样本校准。
- **版本识别覆盖**：仅 5 种 OA 有版本提取器，其余 7 种无版本 → 版本过滤不生效（保守放行，不误伤）。
