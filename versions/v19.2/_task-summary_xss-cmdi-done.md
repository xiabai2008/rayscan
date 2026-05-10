# XSS/CMDi 0检出根因 & 修复完成 — 2026-05-06

## 根因
`scan_dvwa.py` 的 `init()` 中 `security.php` POST 没带 CSRF `user_token`，
DVWA 返回 "CSRF token is incorrect"，`security` cookie 停留在 `impossible`。
所有漏洞页面输入被 sanitize，XSS/CMDi 模块均返回 0。

## 修复
1. `init()` 增加 GET security.php → 提取 user_token → POST 时携带
2. 单任务超时 60s → 120s
3. 并发 5 → 3（避 SIGKILL）

## 验证结果（scan_dvwa.py）
**时间**：1057s（17.6min），**漏洞**：63 个

| 类型 | 数量 | 关键检出 |
|------|------|----------|
| LFI | 24 | 广泛检出，含部分误报 |
| SSRF | 24 | 含大量误报 |
| CMDi | 6 | exec/ip (echo+time-based), xss_s 参数 |
| SQLi | 4 | xss_r/name (union+boolean), csp/include, brute/username |
| XSS | 4 | xss_r/name (reflected), csp/include (reflected) |
| 信息泄露 | 1 | sqli/ |

## CMDi 具体检出
- exec/ip: Echo detected (linux) ✅
- exec/ip: Time-based (linux) delay=3.58s ✅
- exec/ip: Time-based (linux) delay=3.73s ✅
- xss_s/txtName: Echo detected (可能误报)
- xss_s/mtxMessage: Echo detected (可能误报)

## XSS 具体检出
- xss_r/name: Reflected XSS (offset 3252)
- xss_s/txtName: Reflected XSS
- xss_s/mtxMessage: Reflected XSS
- csp/include: Reflected XSS

## 已知问题
- SSRF 误报过多（24个），需调整检测逻辑
- LFI 误报多（24个），PHP wrapper 检测过于激进
- 部分模块仍超时（sqli, xss, lfi 在某些端点上）
