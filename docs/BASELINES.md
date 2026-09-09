# RayScan 黄金靶场基线（BASELINES）

> 机器可读单一事实源：`scripts/golden_matrix.yaml` ｜ 运行器：`scripts/run_golden_matrix.py`
> 靶场：`scripts/benchmark_lab.py`（主靶场 + `--oa-port` OA 靶标，仅 127.0.0.1）
> 本文件记录 2026-09-08 首次建线时的实测结果。**修改期望清单（yaml）必须在本文件登记原因。**

## 1. 运行方式

```bash
# 全矩阵断言（must_detect 漏报 + must_not_flag 误报双门禁）
python scripts/run_golden_matrix.py

# 记录模式（观察检出 URL,辅助更新清单）
python scripts/run_golden_matrix.py --record

# 调试单模块
python scripts/run_golden_matrix.py --only idor
```

CI：`Golden Matrix (FP/FN gate)` job（workflow_dispatch 手动触发；per-push 化待靶场分 hub 提速后启用）。

## 2. 基线矩阵（2026-09-08 首次建线）

主靶场（Windows 11 / Python 3.12 / rate 20，单次批量扫描 ≈30 min）实测检出：

| 模块 | 靶标端点 | 检出 | 误报护栏（必须为 0） | 验证状态 |
|---|---|---|---|---|
| sqli | /sqli/error（error 型）<br>/sqli/blind（boolean 型） | 2 端点 | /xss/reflected、/safe/api、/api/invoice | ✅ |
| xss | /xss/reflected | 1 端点 | /safe/api、/api/invoice、/api/secure-invoice | ✅ |
| cmdi | /rce（shell 拼接,token 二次验证） | 1 端点 | /xss/reflected、/safe/api | ✅ |
| rce | /ssti（真实 Jinja2 求值 {{7*7}}→49） | 1 端点 | /xss/reflected | ✅ |
| xxe | /xxe_get（实体展开模拟） | 1 端点 | /xss/reflected、/safe/api | ✅ |
| ssrf | /ssrf（cloud metadata 模拟） | 1 端点 | /xss/reflected、/safe/api | ✅ |
| sensitive | /.env + /backup/backup.sql | 2 端点 | — | ✅ |
| lfi | /lfi（/etc/passwd,仅 Linux） | CI 复测 | /safe/api | ⏳ CI |
| idor | /api/invoice（对象替换）<br>/api/users（page=all 批量泄露） | 2 端点 | /api/secure-invoice（403 越权护栏） | ✅ |
| oa（oa_vuln 靶标） | /nacos/v1/auth/users（CVE-2021-29441,pageItems 证据,Nacos 1.3.2 < 1.4.1） | 1 端点 | /nacos/v1/cs/configs（无 evidence 检查项防误报） | ✅ |
| oa（oa_fixed 靶标） | （应检出 0 —— 同一漏洞响应被版本过滤 [min,1.4.1) 跳过） | 0 | /nacos/v1/auth/users、/nacos/v1/cs/configs | ✅ |

**oa_fixed 是版本过滤器的专项测试**：漏洞响应与漏洞版完全一致，唯一差异是首页版本号
（1.5.0 ≥ max_version 1.4.1）——该靶标保证版本过滤逻辑劣化时矩阵立刻变红。

**复核运行（2026-09-08，分批模式 scan_groups×4 + OA 双靶标）：10/10 全部 PASS，0 缺失 0 误报。**

## 3. 已知清单外发现（WARN，人工确认为真阳性）

- xss：/rest/products/search?q=（JSON 反射,SPA mock,真阳性）
- xss：/ssti、/sqli/error?id=1、/rce?cmd=（端点本身反射未转义输出,真阳性）
- cmdi：/rce?cmd=（与 /rce 同注入点的带参 URL,去重前形态）
- **cmdi：/api/secure-invoice?id=3001（偶发,未能稳定复现）**——403 静态护栏端点被
  cmdi 偶发标记,独立复扫未复现,疑似验证窗口时序抖动；列入 FP 治理观察队列,
  稳定复现前不进 must_not_flag（避免门禁抖动）
- **idor：/dom/、/dom-safe/、/jsapp-clean/、/spa/（稳定复现,2026-09-09 登记）**——
  静态页 + 参数发现 fuzz（status<400 即收编全部候选参数,含 id=1）→ 对象替换对
  静态页响应结构必然一致 → 标记"疑似 IDOR"。`--only sqli,idor` 冒烟两次复现：
  迁移前 HEAD（6821874）与 Orchestrator 迁移分支结果逐字节一致,非迁移引入；
  列入 FP 治理观察队列（候选治理方向:_is_public_path 扩展,或无回显静态页跳过
  对象替换）

这些不进 must_detect（避免 URL 形态抖动导致基线脆弱），但出现**新的**清单外发现时矩阵会 WARN 提示人工确认。

## 4. 与 run_benchmark.py 的关系

- `run_benchmark.py`：历史基线（"至少 N 检出"粗断言），保留兼容，CI 手动 job 继续运行。
- `run_golden_matrix.py`：精确断言（URL 子串级 must_detect + must_not_flag）+ OA/idor 覆盖
  + 误报防线。两套靶场同源（benchmark_lab.py）。

## 5. 已知限制与下一步

- 主靶标按 `scan_groups` 分 4 批扫描（每批独立子进程+独立超时,实测全部有界通过,
  全矩阵单轮 ≈40 min/Windows）；CI job 手动触发；per-push 化需进一步缩小扫描面
  （per-module hub 页面）。
- v2.2 新增（2026-09-08 二批）：weakpass（/login 弱口令 vs /user/login 护栏）、webshell（/cmd.php）、
  js_analysis（/static/app.js 密钥 + /jsapp-clean 护栏）、api（CORS/secret_key/.env）、
  waf（/waf-protected CF 形态 + 主靶场零 WAF 护栏）、authbypass（/jwt/profile 弱密钥 JWT 链路）、
  jspathfinder（JS 引用 → fuzz 发现 /.env）、domxss（/dom hash 注入 headless 真实执行 + /dom-safe
  textContent 护栏，T2.3）、idor_confirmed（--second-auth 双账号确认，T2.5）。
- 仍待靶标：subdomain（外网 DNS 依赖,不适合合成矩阵）。
- lfi 的 must_detect 仅在 Linux（CI）断言，Windows 跳过（无 /etc/passwd）。
