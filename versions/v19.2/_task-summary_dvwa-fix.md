# DVWA 远端扫描 — 完整诊断与修复

## 日期
2026-05-06 16:00 - 17:33

## 最终结果
**26 漏洞检出，202 秒 (3.4 分钟)**

| 类型 | 数量 | 
|------|------|
| Information Disclosure | 15 |
| Local File Inclusion | 5 |
| SSRF | 3 |
| SQL Injection | 3 |

## LFI ⭐ 已验证
`/vulnerabilities/fi/?page=/etc/passwd` → 直接读出 `root:x:0:0:root:/root:/bin/bash`

## SQLi 检出
`/vulnerabilities/brute/` 的 `username` 参数: Error-based + Boolean-blind + Stacked query

## 发现的关键 Bug（按严重性排序）

### 1. HTTPPool cookie domain 带端口 ⚠️ 核心
`session.set_cookie(url)` → urlparse netloc 返回 `"47.95.192.41:8081"`，httpx 不匹配
→ 修复: `domain="47.95.192.41"`

### 2. 爬虫 _seed_common_paths 破坏 session
`_seed_common_paths` 探测 /login.php 等路径，Server 返回的 cookie 覆盖已登录 cookie
→ 方案: 彻底跳过爬虫，用 ScanTarget 直接构造端点

### 3. DVWA 数据库连接
`db_server = '127.0.0.1'` → PHP MySQL 模块连不上 TCP → 改 `localhost` (socket)

### 4. DVWA CSRF token
v1.10 登录/建库需要从页面提取 `user_token`

### 5. Docker 重启后 Apache 残留 PID
`docker restart` 后 Apache 因旧 PID 文件启动失败
→ 修复: `rm /var/run/apache2/apache2.pid && service apache2 start`

### 6. 爬虫稳定性阈值过早终止
种子路径过多 → 各页侧边栏链接重复 → 稳定性触发 → 提前停
→ 方案: 跳过爬虫直接用已知端点

## 缺失项
- XSS: 0 检出（检测模块需要适配 DVWA 的反射模式）
- CMDi: 0 检出（exec 页面可能需 POST body 而非 query params）

## 有效扫描方案
`scan_dvwa.py` — 直接构造 13 个 ScanTarget + cookies，9 模块并发检测
位置: `C:\Users\HZR\Desktop\wvs-v19\scan_dvwa.py`
