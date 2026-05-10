# DVWA 扫描修复 — 最终方案

## 已修复的两个 Bug

### 1. CMDi 0 检出
- **根因**：`ScanTarget(url=..., methods=..., params=params, cookies=cookies)` 没传 `data` 字段
- POST 端点（exec、xss_s）的表单数据丢失，CMDi 模块的 `_scan_impl` 里 `target_params` 和 `target_data` 都为空，直接跳到了 `_extract_endpoints` 返回 0 端点
- **修复**：`ScanTarget(url=..., methods=..., params=params, data=data, cookies=cookies)`

### 2. XSS 0 检出
- **根因**：同上，xss_s 页面是 POST，`data` 没传
- xss_r (GET) 理论上应该能检出，但在并发扫描中可能被其他任务影响（服务器过载导致请求超时）
- 独立测试脚本 `_test_xss_cmdi.py` 已验证 XSS 模块能正确返回 1 vuln（xss_r/name）
- 第一次修复后 dawn-slug 扫描已看到 `[XSS] Reflected` + `[CMDi] Echo detected` 输出

### 3. 报告 JSON 写入失败（exit code 1）
- **根因**：相对路径 `scan_reports/` 在当前工作目录不存在时写失败 + 没有 try/except
- **修复**：绝对路径 + try/except + 逐 vuln 安全序列化

### 4. 扫描挂死（服务器打崩）
- **根因**：117 个并发任务 (9 modules × 13 targets) 同时发 HTTP 请求，DVWA Docker 容器被打挂
- **修复**：Semaphore 10→5 + `asyncio.wait_for(timeout=60)` 兜底

## 当前状态
- 远端服务器 47.95.192.41 完全无响应（HTTP ReadTimeout + SSH 超时）
- 监控脚本 `_monitor_dvwa.py` 在后台轮询，恢复后自动重启容器 + 扫描
