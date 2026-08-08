# RayScan 检测基准（Benchmark）

> 版本：v1.0 ｜ 2026-08-08（基准体系建立）
> 靶场：`scripts/benchmark_lab.py`（Python/Flask，仅 127.0.0.1，禁止公网部署）
> 用法：`python scripts/benchmark_lab.py --port 18099`，另开终端 `python -m wvs scan http://127.0.0.1:18099/ --modules <m> --no-nuclei --allow-loopback`

## 1. 检测矩阵基线（2026-08-08 首次运行）

| 模块 | 样本端点 | 检出 | 结果 | 备注 |
|------|---------|:----:|------|------|
| sqli | /sqli/error?（error/union/blind/time 四型） | 4 | ✅ 真阳性 | error 多变体 + stacked；union/blind/time 由 error 端点覆盖 |
| sqli | /xss/reflected?q=（反射参数） | 1 | ⚠️ 误报 | boolean 差异误判（输入回显 + 响应随 payload 变化）——**已知误报类型** |
| xss | /xss/reflected?q= | 4 变体 | ✅ 真阳性 | img onerror / polyglot / svg 均检出 |
| xss | {{config}}（SSTI 探测） | 0 | ✅ 已修复 | **SSTI 弱信号路径删除**（只信 7*7=49 运算求值） |
| cmdi | /rce?cmd=（shell 拼接） | 2 | ✅ 真阳性 | `; echo <token>` 二次验证命中 |
| lfi | /lfi?file= | 0 | ⚠️ 漏报 | **Windows 环境限制**：无 /etc/passwd，payload 返回 file not found；需 Linux 复测 |
| rce | /rce?cmd= | 1 | ✅ 真阳性 | RCE token 回显 |
| rce | 反射端点（xss/cmdi/sqli/error） | 0 | ✅ 已修复 | **Python 注入收敛为运算求值**（删除 token echo/__subclasses__/__builtins__ 回显判定） |
| rce | /cmdi?host=（time-based 盲测） | 1 | ✅ 真阳性 | `;` 分隔符真实触发（Windows time 命令挂起 11s）→ 延迟型命令注入检出 |
| xxe | /xxe（POST XML 解析） | 0 | ⚠️ 待查 | POST 提交点发现机制受限，靶场 GET 链接不足以驱动；列入待办 |
| ssrf | /ssrf?url=（任意 URL fetch） | 0 | ⚠️ 漏报待查 | **反射回显误报已修复**（payload 回显排除）；真实 SSRF 样本未检出，列入待办 |
| sensitive | /.env + /backup/backup.sql | 2 | ✅ 真阳性 | **基准驱动修复**（见 §2） |

**误报治理进展（第二轮，2026-08-08）**：反射回显误报从 11 个降至 1 个（sqli boolean 反射，已知类型）。
修复策略：**回显类探测收敛为"求值语义"验证**——SSTI/EL 只信模板引擎运算求值（{{7*7}}→49），
删除"特征词/token 回显"类独立判定（__subclasses__/__builtins__/applicationScope 等，
响应出现这些词只证明输入被回显——含截断回显与引号翻倍变形回显，不证明执行）。

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

## 3. 复测流程

```bash
python scripts/benchmark_lab.py --port 18099 &
python -m wvs scan http://127.0.0.1:18099/ --modules sqli xss cmdi rce --no-nuclei --allow-loopback -o bench.json
# 对照 §1 矩阵核对检出/误报/漏报
```

## 4. 待办

- [ ] xxe/ssrf 真实样本补测（POST 提交点发现 / metadata 回调验证）
- [ ] lfi 在 Linux 环境复测（/etc/passwd）
- [ ] 反射回显误报治理（回显类探测加"执行语义"验证，如 SSTI 需模板引擎特征）
- [ ] 接入外部基准（WAVSEP / OWASP Juice Shop）扩充矩阵
- [ ] 每次发版前跑一轮基准，防回归（可挂 CI 手动触发 job）
