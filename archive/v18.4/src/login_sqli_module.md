# WVS v18.1 - Login Form SQLi 模块开发记录

## 时间: 2026-04-19 10:31-10:50

## 任务: 新增 login_sqli 模块

### 背景
原有 `full_scanner` 对登录表单的 SQLi 检测盲区：
- `_test_form_sqli` 只检测 SQL 错误 + 时间延迟
- Login bypass（无错 SQLi）不在此列

### 问题定位
1. **aiohttp cookie jar bug**: POST 后 `Set-Cookie` 头存在，但 `session.cookie_jar.filter_cookies()` 返回空
2. **Token 提取错误**: 正则匹配到了 `<input name="token"...>` 的 name 而非 value，导致 POST 参数变成 `token=token`
3. **aiohttp 无法验证 session**: 即使 PHPSESSID 被设置，也无法从 cookie jar 读出来验证

### 解决方案
改用 `requests` 库替代 `aiohttp`：
- `requests.post()` → `Response.cookies` 直接获取 `PHPSESSID`
- `requests.get()` + `cookies={'PHPSESSID': ...}` → 验证 session 有效性

### 核心检测逻辑
```
1. GET login 页 → 提取 CSRF token
2. POST {username: SQLi_payload, password: WRONG, token: REAL_TOKEN}
3. 检测信号：
   - PHPSESSID 出现在 Response.cookies → 强信号
   - 用该 PHPSESSID 访问 /profile/ → 成功 = bypass confirmed (95%)
4. 返回 LoginSqliResult，confidence 95%，evidence = session validated
```

### 文件变更
| 文件 | 操作 |
|------|------|
| `wvs/modules/auth/login_sqli_scanner.py` | 新增 (280 行) |
| `wvs/vuln/full_scanner.py` | 修改 (import + init + scan() 调用 + _scan_login_sqli 方法) |

### driftingblues9 验证结果
```
[*] Login SQLi scan: Testing 7 login URL(s)
    [!] Login SQLi found: http://192.168.18.133/index.php?page=login
        payload: admin'--  confidence: 95%
        evidence: Session 'PHPSESSID' set + session validated on member page
    ... (共 11 个 payload，全部命中)
    Login SQLi found: 11 vulnerabilities
```

### 最终扫描结果
```
Sources: ['login_sqli', 'basic', 'nuclei', 'cmdi', 'lfi']
Total: 16 vulns
  Critical: 13 (login_sqli 11 + Nuclei CVE-2012-1823 2)
  High: 2 (Nuclei Admin Panel × 2)
  Info: 1 (Nuclei Apache Tomcat)
```

### 爬虫覆盖率增强

**问题：** 爬虫只跟踪 `<a href>` 链接，CMS 用 `?page=X` 路由时首页无导航 → 只摸到 3 URL

**修复：** `EnhancedCrawler.crawl()` BFS 循环前预置：

```python
queue: List[tuple] = []
# 1. 预置常见静态路由（CMS / 靶机通用）
common_routes = [
    "index.php?page=login", "index.php?page=home", "admin/",
    "index.php?page=article", "index.php?page=register", ...
]
# 2. 参数模糊探测（page/id/cat/q 常见值）
param_buckets = {
    "page": ["login","home","about","register","profile","search",...],
    "id":   ["1","2","3","0","99","100"],
}
```

**效果：** 3 URL → **5 URL**（+ `/admin/`, `/admin/index.php`, `?page=login` 已入爬虫）

### 技术要点
1. **aiohttp cookie jar bug**: `session.cookie_jar.filter_cookies(url)` 需要 URL 匹配才返回 cookie；requests 库无此问题
2. **requests vs aiohttp**: 同步 requests 更可靠，asyncio 包装只在 `await asyncio.sleep(delay)` 处用到
3. **CSRF token**: 多种正则匹配模式（type=hidden+name+value, value+name, name+value 顺序）
4. **去重策略**: payload 命中后立即停止，避免同一漏洞重复报告

### 已知限制
- Admin Panel 检测是 Nuclei 误报（/admin/ 重定向到首页，非真实 admin 面板）
- CVE-2012-1823 在 driftingblues9 上 Nuclei 检出但实际利用需要绕过 ApPHP 处理逻辑
- Basic/CMDi/LFI 均为 0（爬虫只摸到 3 URL，需要提升爬虫覆盖率）
