# XSS/CMDi 0 检出根因修复 — 2026-05-06

## 根因
`scan_dvwa.py` 的 `init()` 函数 POST `security.php` 时没带 CSRF `user_token`，
导致 "CSRF token is incorrect"，安全级别始终停留在 `impossible`。
所有漏洞页面（SQLi/XSS/CMDi/exec）的输入在 impossible 级别被完全 sanitize，
因此 XSS 和 CMDi 模块均返回 0 个漏洞。

## 修复
在 `init()` 中增加 GET security.php → 提取 user_token → POST with token。

## 验证
- `[init] security=low` 确认生效
- CMDi Echo detected on exec/ip ✅
- XSS Reflected on xss_r/name, xss_s, csp/include ✅
- XSS DOM-based on xss_s ✅

## 次要修复
- 单任务超时 60s → 120s
- 并发 5 → 3（减少 SIGKILL 风险）
