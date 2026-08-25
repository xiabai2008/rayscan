# RayScan 检测基准（Benchmark）

> 版本：v1.0 ｜ 2026-08-08（基准体系建立）
> 靶场：`scripts/benchmark_lab.py`（Python/Flask，仅 127.0.0.1，禁止公网部署）
> 用法：`python scripts/benchmark_lab.py --port 18099`，另开终端 `python -m wvs scan http://127.0.0.1:18099/ --modules <m> --no-nuclei --allow-loopback`

## 1. 检测矩阵基线（2026-08-08 首次运行）

| 模块 | 样本端点 | 检出 | 结果 | 备注 |
|------|---------|:----:|------|------|
| sqli | /sqli/error?（error/union/blind/time 四型） | 4 | ✅ 真阳性 | error 多变体 + stacked；union/blind/time 由 error 端点覆盖 |
| sqli | /sqli/blind?（boolean 条件响应差异） | 1 | ✅ 真阳性 | 靶场通用等值判断（\d+=\d+）；**反射误报已修复**（payload 回显排除） |
| sqli | /xss/reflected?q=（反射参数） | 0 | ✅ 已修复 | **boolean 命中排除 payload 原样回显**（盲注语义）——反射误报清除 |
| xss | /xss/reflected?q= | 4 变体 | ✅ 真阳性 | img onerror / polyglot / svg 均检出 |
| xss | {{config}}（SSTI 探测） | 0 | ✅ 已修复 | **SSTI 弱信号路径删除**（只信 7*7=49 运算求值） |
| cmdi | /rce?cmd=（shell 拼接） | 2 | ✅ 真阳性 | `; echo <token>` 二次验证命中 |
| lfi | /lfi?file= | 0 | ⚠️ 漏报 | **Windows 环境限制**：无 /etc/passwd，payload 返回 file not found；需 Linux 复测 |
| rce | /rce?cmd= | 1 | ✅ 真阳性 | RCE token 回显 |
| rce | 反射端点（xss/cmdi/sqli/error） | 0 | ✅ 已修复 | **Python 注入收敛为运算求值**（删除 token echo/__subclasses__/__builtins__ 回显判定） |
| rce | /cmdi?host=（time-based 盲测） | 1 | ✅ 真阳性 | `;` 分隔符真实触发（Windows time 命令挂起 11s）→ 延迟型命令注入检出 |
| xxe | /xxe_get?xml=（实体展开模拟） | 1 | ✅ 真阳性 | 靶场模拟支持实体展开的解析器（Python ET 默认拒绝）；file:///etc/passwd → root:x:0:0: 命中 |
| ssrf | /ssrf?url=（metadata 回显模拟） | 1 | ✅ 真阳性 | 靶场模拟云 metadata（169.254.169.254 → ami-id/instance-id）；**反射误报已修复** |
| sensitive | /.env + /backup/backup.sql | 2 | ✅ 真阳性 | **基准驱动修复**（见 §2） |

**误报治理进展（第二轮+，2026-08-08）**：反射回显误报 11 → **0**（全类型清除）。
修复策略：**回显类探测收敛为"求值语义"验证**——SSTI/EL 只信模板引擎运算求值（{{7*7}}→49），
删除"特征词/token 回显"类独立判定（__subclasses__/__builtins__/applicationScope 等，
响应出现这些词只证明输入被回显——含截断回显与引号翻倍变形回显，不证明执行）；
**sqli boolean 命中排除 payload 原样回显**（盲注语义，反射端点天然免疫）。

## 2. 基准驱动修复记录（2026-08-08）

| # | 缺陷 | 修复 |
|---|------|------|
| 1 | sensitive `.env` 无引号格式（KEY=VALUE）不匹配任何 pattern | 新增 `env_var_secret` pattern（(?m) 逐行） |
| 2 | sensitive 探测路径缺 `/backup/backup.sql` 等常见备份路径 | 补充路径 |
| 3 | sensitive 内容阈值 `len<50` 误杀短小 .env（43 字符） | 50 → 10 |
| 4 | `scan` 命令无 `--allow-loopback` 参数，无法扫描本地靶场（远端 SSRF 防护缺口） | CLI 注册参数（默认仍拦截内网） |
| 5 | xss SSTI"模板语法反射 + config 关键词"弱信号路径 → 反射端点误报 | 删除弱信号路径，只信 7*7=49 |
| 6 | rce Python 注入 `__subclasses__` 等 expected 特征（payload 子串）→ 反射端点误报 | expected 命中排除 payload 原样回显 |
| 7 | rce ssti_leak_indicators 循环（indicator in payload 即命中）→ 截断/变形回显误报 | **删除独立 leak 判定，SSTI 收敛为运算求值** |
| 8 | rce token echo 路径（变形回显绕过 _is_input_reflection） | 收敛版删除（运算求值已覆盖模板引擎场景） |
| 9 | rce Java EL leak ≥2 indicators 判定同样受变形回显影响 | 加 payload 回显排除 |
| 10 | ssrf metadata pattern 命中未排除 payload 回显（反射端点天然含 URL 字样） | payload 在响应中 → 直接排除 |
| 11 | **sqli boolean 反射误报**（`' AND 'a'='a` 对在反射端点产生响应差异） | **boolean 命中排除 payload 原样回显**（盲注语义）——误报清零 |
| 12 | 靶场 /sqli/blind 条件检查写死 "1=1"（verify 用 2>1 无差异） | 通用数值等值判断（\d+=\d+）+ '1'='1 兼容 |
| 13 | rce 在 Linux 0 检出（收敛后只信模板求值，靶场无模板引擎） | 靶场新增真实 Jinja2 SSTI 端点 /ssti（跨平台真阳性） |

## 4. 外部基准（Juice Shop）

**现状（2026-08-08 第六轮）**：`scripts/run_external_benchmark.py` 启用 **--js-render**（Playwright 渲染 + XHR/fetch 捕获）→ **硬断言（sqli/xss ≥1）**。

**SPA 能力闭环**（本机基准 + 外部基准）：
- `crawler.crawl_js` 新增 **network 请求捕获**（XHR/fetch 监听 → API 端点，含 query/JSON body 参数还原）
- `param_type="json"` 支持（base._send_request / ScanTarget.param_types 传递链）
- **4xx 响应不再抛异常**（HTTPPool）——401/403 对检测有信息价值（登录类 boolean 差异强信号）
- boolean 判定：**状态码差异豁免 payload 回显排除**（回显型注入如 login email 不被误拦）
- scanner 尾斜杠修复对 is_api 端点豁免（/rest/user/login 不加 /）
- 自建 SPA mock（/spa + /rest/*）纳入基准矩阵：**spa_sqli 1/1 ✅、spa_xss 3/1 ✅**

**待验证**：Juice Shop 真实 SPA（Angular）经 CI benchmark-external 硬断言验证（本轮 CI 运行确认）。

**WAVSEP**：无官方 release 资产（api.github.com 404），暂缓；后续可自建 WAVSEP 容器镜像接入。

## 5. 复测流程

```bash
python scripts/benchmark_lab.py --port 18099 &
python -m wvs scan http://127.0.0.1:18099/ --modules sqli xss cmdi rce --no-nuclei --allow-loopback -o bench.json
# 对照 §1 矩阵核对检出/误报/漏报
```

**一键回归**（自动起靶场 + 全模块断言，CI 手动触发同款）：
```bash
python scripts/run_benchmark.py
# CI: gh workflow run ci.yml（Benchmark job，发版前/怀疑回归时触发）
```

## 4. 待办

- [x] xxe/ssrf 真实样本补测（2026-08-08：靶场补 GET 参数型 XXE 提交点 + metadata 模拟，均检出）
- [x] lfi 在 Linux 环境复测（2026-08-08：CI Benchmark 验证 1/1 检出，/etc/passwd）
- [x] 反射回显误报治理（2026-08-08：11 → 0 全类型清零，含 sqli boolean）
- [x] 接入外部基准（Juice Shop 记录模式 + CI benchmark-external job；WAVSEP 无 release 暂缓）
- [x] 基准回归自动化（scripts/run_benchmark.py + CI workflow_dispatch）
- [x] SPA/JSON API 覆盖（2026-08-08 第六轮：--js-render 网络捕获 + json 参数链 + 4xx 可读；自建 SPA mock 纳入基准；Juice Shop 改硬断言待 CI 确认）
