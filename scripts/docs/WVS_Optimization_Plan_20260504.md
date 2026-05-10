# WVS v19 全面代码优化方案

## 概述

基于 Metasploitable2 扫描结果（11209s / 67997 请求 / 118 漏洞 / SIGKILL 终止），逐模块分析根因并提出具体代码优化方案。

---

## 一、SQL 注入检测优化 (提高检出率)

### 问题 1.1：数字型注入完全未覆盖

**根因**：`sqli/payloads.py` 所有 payload 都带引号前缀（`' AND 1=1--`），但 Metasploitable2 的 mutillidae 存在大量数字型注入点（如 `?id=1 AND 1=1`）。

**修复**：`sqli/payloads.py` 增加数字型 payloads：

```python
NUMERIC_PAYLOADS: Dict[str, List[str]] = {
    "error": [
        "1 AND 1=1", "1 AND 1=2",
        "1 AND extractvalue(1,concat(0x7e,(SELECT @@version)))",
        "1' AND '1'='1",
    ],
    "boolean": [
        "1 AND 1=1", "1 AND 1=2",
        "1 AND 2>1", "1 AND 2<1",
    ],
    "time": [
        "1 AND SLEEP(3)", "1 AND SLEEP(5)",
    ],
}
```

### 问题 1.2：Boolean-blind 长度差异阈值过严

**根因**：`sqli/detector.py:126-128` 阈值 `len_diff > 100 and len_diff/max(len(true_text), 1) > 0.05`，5% 阈值过于严格。很多真实 SQL 注入只改变少数行数据，响应差异 < 5%。

```python
# 修复：降低阈值到 1%，或增加内容哈希差异作为独立判断
if len_diff > 50 and len_diff / max(len(true_text), 1) > 0.01:
    return True
```

### 问题 1.3：Error-based 第二轮每种 DB 只测前 8 条

**根因**：`sqli/detector.py:336` 限制了 `ERROR_BASED_PAYLOADS[db_type][:8]`。部分 payload 排在后面的更有效（如 `extractvalue` / `updatexml` 双查询注入）。

**修复**：改为按优先级排列 payload，最有效的排前 8：

```python
# sqli/payloads.py 重新排序 ERROR_BASED_PAYLOADS，高成功率 payload 放前面
"mysql": [
    # P0: 双查询（最可靠）
    "' AND extractvalue(1,concat(0x7e,(SELECT @@version)))--",
    "' AND updatexml(1,concat(0x7e,(SELECT @@version)),1)--",
    # P1: 基础引号测试
    "'", "\"", "1'", "1\"",
    # P2: OR/AND 条件
    "' OR '1'='1", "' OR 1=1--", "' AND 1=1--",
    # ...
]
```

### 问题 1.4：缺少二次确认的响应内容验证

**根因**：`sqli/detector.py:826-872` `_verify_with_different_payload` 中，`"boolean"` 类型验证用了 `_is_response_different` 阈值 0.15，但 boolean injection 的差异可能更小。

**修复**：降低 boolean 验证阈值：

```python
elif vuln_type == "boolean":
    if baseline and self._is_response_different(resp, baseline, threshold=0.02):  # 0.15 → 0.02
        return True
```

---

## 二、XSS 检测优化 (提高检出率 + 减少误报)

### 问题 2.1：DOM-based XSS 仅检测 URL fragment

**根因**：`xss/detector.py:354-358` 只在 URL 末尾拼接 `#<script>...`，未检测 JavaScript sink：

- `document.write(location.hash)`
- `eval(location.search)`
- `innerHTML = location.href`

**修复**：增加 JS sink 检测阶段，解析 HTML 中的 `<script>` 块：

```python
async def _test_dom_sinks(self, url, baseline_text):
    """检测 JS 中潜在的 DOM XSS sink"""
    sink_patterns = [
        (r'document\.write\s*\(\s*location\.(?:hash|search|href)', 'document.write(source)'),
        (r'eval\s*\(\s*location\.(?:hash|search)', 'eval(source)'),
        (r'\.innerHTML\s*=\s*location\.(?:hash|search)', 'innerHTML = source'),
        (r'\.outerHTML\s*=\s*location', 'outerHTML = source'),
        (r'\$\(location\.hash', 'jQuery(location.hash)'),
    ]
    for pattern, desc in sink_patterns:
        if re.search(pattern, baseline_text, re.IGNORECASE):
            # 发现潜在 sink，报告为 info 级别
            ...
```

### 问题 2.2：_check_reflection 的 script-tag 检测过于宽松

**根因**：`xss/detector.py:417-440` 第 3 步中，如果响应中 `<script>` 标签数量多于 baseline，且包含 `alert`，就判为 XSS。但 `<script>alert('password reset successful')</script>` 这些页面本身的内容也会触发误报。

**修复**：必须同时满足"payload 被注入"和"新的 event handler 出现"两个条件：

```python
# 简化：只保留 verbatim 匹配和 structural injection 两种模式
# 去掉单独的 "<script> + alert" 检查
if script_injected or event_injected:
    return True, evidence
```

### 问题 2.3：存储型 XSS 回查路径硬编码

**根因**：`xss/detector.py:163-175` 的回查 URL 列表是硬编码的常见 PHP 文件名，在 mutillidae 等框架下不适用。

**修复**：从爬虫发现的端点中动态提取回查 URL：

```python
# 优先使用 crawler 已发现的页面作为回查目标
async def _test_stored_xss(self, url, params, param_name, method, param_type):
    # marker = generate_stored_xss_marker()
    # 注入 marker
    # 回查：遍历已发现的端点，检查 marker 是否出现
    # 而不是硬编码路径
```

---

## 三、SSRF 检测优化 (减少误报)

### 问题 3.1：云元数据 URL 对本地靶机无意义

**根因**：`ssrf/detector.py:113` 将所有 payloads（BASIC + CLOUD_METADATA + INTERNAL_SERVICES）无差别发送。Metasploitable2 是本地 VM，不存在 AWS 元数据服务。

**修复**：增加环境感知，先探测目标是否为云环境：

```python
# 在扫描前检测目标 IP 是否为云环境
# 169.254.169.254 只有 AWS/云 VM 才能访问
# 如果是本地 IP（192.168.x.x / 10.x.x.x / 172.16-31.x.x），跳过云元数据 payloads
def _is_cloud_target(self, url: str) -> bool:
    import ipaddress
    try:
        host = urlparse(url).hostname
        ip = ipaddress.ip_address(host)
        return not ip.is_private
    except:
        return False  # 域名 → 不确定，仍然测试
```

### 问题 3.2：_check_ssrf_success 误报率极高

**根因**：`ssrf/detector.py:357-361` 检查 `<title>`、`<h1>`、`<html`、`<!doctype` 作为成功标志。这些标记在几乎每个 HTTP 响应中都存在。

**修复**：只有以下条件才判定为 SSRF 成功：

1. 响应中包含云元数据内容（现有逻辑保留）
2. 响应中包含来自内网服务协议的 banner 信息（`ssh-`、`220 `、`redis` 等）
3. 移除通用的 HTML 标记检查（`<title>`、`<h1>`、`<html`、`<!doctype`）

```python
# 删除这段误报代码：
# for marker in ["<title>", "<h1>", "<html", "<!doctype",
#               "ssh-", "220 ", "redis", "mysql",
#               "elasticsearch", "mongodb"]:

# 保留协议 banner 检测（更准确）：
service_banners = {
    "ssh-": "SSH service detected",
    "redis_version": "Redis detected",
    "220 ": "FTP/SMTP service detected",
}
```

### 问题 3.3：硬编码 SSRF 路径浪费请求

**根因**：`ssrf/detector.py:300-317` 追加了不存在的路径 `/fetch`、`/proxy`、`/thumbnail` 等。

**修复**：移除硬编码路径，只对爬虫实际发现的端点做 SSRF 检测。

---

## 四、爬虫覆盖优化

### 问题 4.1：max_depth=3 不足以覆盖深层页面

**根因**：`scanner.py:56-58` 默认 `crawl_depth=3`，Metasploitable2 的 mutillidae 页面嵌套深度超过 3 层（首页 → 分类 → 子功能 → 表单页面）。

**修复**：

```python
# config.py 中增加 depth 到 5
# 同时对已知 lab 目标自动提升深度
if self._lab_profile:
    self.crawler.max_depth = max(self.crawler.max_depth, 5)
```

### 问题 4.2：参数发现策略过于保守

**根因**：`crawler.py:400-421` `discover_params` 通过检查参数名是否在响应中出现来判断参数是否有效。但许多有效参数不会在 HTML 中作为文本出现。

**修复**：改为响应差异对比法：

```python
# 发两个请求：带参数 vs 不带参数
# 如果响应有差异，说明参数影响了页面行为
base_resp = await session.get(base_url, timeout=8)
for param_name in batch:
    test_url = f"{base_url}?{param_name}={test_value}"
    test_resp = await session.get(test_url, timeout=8)
    if len(test_resp.text) != len(base_resp.text):
        found_params[param_name] = test_value
```

### 问题 4.3：爬虫未利用已认证 session 重新爬取

**根因**：虽然 `_do_lab_auth` 设置了 cookie，但爬虫在认证前已经爬过一次，认证后的深层页面可能未被发现。

**修复**：认证后重新触发爬虫对关键路径的爬取：

```python
if await self._do_lab_auth():
    # 对 lab profile 中列出的关键路径重新爬取
    for path in lp.crawl_paths:
        await self.crawler.crawl_static(base + path, self.session, depth=1)
```

---

## 五、RCE/CMDi 检测优化 (减少误报)

### 问题 5.1：RCE _detect_java_expression 匹配过于宽松

**根因**：`rce/detector.py:264` 用 `"49" in resp.text` 判断 `{{7*7}}` 执行。任何包含数字 49 的页面都会误报。

**修复**：使用随机数而非固定值：

```python
import random
a, b = random.randint(100, 999), random.randint(100, 999)
expected = str(a * b)
payload = f"{{{{{a}*{b}}}}}"
# 检测 expected 是否出现在响应中
```

### 问题 5.2：RCE _detect_time_based 阈值 2.8s 过低

**根因**：`rce/detector.py:317` `elapsed >= 2.8` 作为 RCE 判断。网络延迟完全可能达到 2.8s。

**修复**：必须搭配 baseline 对比，且至少测 3 次确认：

```python
# 1. 测 baseline 延迟
baseline_times = [time_request() for _ in range(3)]
baseline_avg = mean(baseline_times)
# 2. 测 payload 延迟
payload_times = [time_request(payload) for _ in range(3)]
payload_avg = mean(payload_times)
# 3. payload 延迟必须 > baseline + 2.0s 且 > expected * 0.7
if payload_avg > baseline_avg + 2.0 and payload_avg >= expected * 0.7:
    ...
```

### 问题 5.3：CMDi echo 检测未检查 payload 是否部分反射

**根因**：`cmdi/detector.py:192-208` 虽然有 `_is_input_reflection` 检查，但只检查完整 payload。`; echo abc123` 可能被 PHP 拆分为 `; echo` + `abc123` 分别反射。

**修复**：已实现 `_is_input_reflection`，逻辑正确，保持不变。但需增加 `_is_echo_server` 的覆盖面。

---

## 六、性能优化 (减少请求量)

### 问题 6.1：SSRF 模块对每个参数发送 44 个 payload

**根因**：`ssrf/detector.py:113` 合并了 BASIC(7) + CLOUD_METADATA(12) + INTERNAL_SERVICES(16) + ENCODING_BYPASS(7) ≈ 44 个 payload。

**修复**：分阶段测试，早期退出：

```python
# 阶段 1：只测 BASIC_PAYLOADS（7个）
# 阶段 2：如果有回显特征，扩展到 CLOUD + INTERNAL
# 阶段 3：如果阶段 1+2 都无发现，跳过 SSRF
```

### 问题 6.2：sensitive 模块探测 115+ 个路径

**根因**：`sensitive/detector.py:115` `SENSITIVE_PATHS` 定义了 115+ 个路径，但匹配到 5 个就停止。

**修复**：已有停止机制，但可以优化为优先探测最可能存在的路径。排序逻辑已实现（HIGH_PRIORITY_PATHS先测）。

### 问题 6.3：缺少模块间协调机制

**根因**：每个模块独立发送请求。同一个 endpoint 的 baseline 请求被多个模块重复发送。

**修复**：`scanner.py` 已实现 `_global_baseline_cache`（`scanner.py:432-435`），逻辑正确。确保所有模块都通过 `_get_cached_baseline` 使用该缓存。

### 问题 6.4：SIGKILL 根因分析

**根因**：67997 个请求 + 内存中保留所有响应文本 + httpx AsyncClient 连接池膨胀 → OOM → SIGKILL。

**修复**：
1. 每个模块定期释放临时数据（已通过 `scanner.py:525` `gc.collect()` 部分解决）
2. 限制每个 host 的并发连接数（已通过 `scanner.py:451` `global_sem` 解决）
3. 增加响应文本截断（大多数模块已有[:5000]或[:20000]截断）
4. **新增**：定期输出进度后清理 httpx 内部缓存：

```python
# 在 session.py HTTPPool 中增加
async def gc(self):
    """清理连接池中的空闲连接"""
    if self._sc:
        await self._sc.aclose()
        self._sc = None  # 下次请求时重新创建
```

---

## 七、其他优化

### 7.1：LFI 缺少 Windows 路径的反斜杠变体

**根因**：`lfi/payloads.py` 路径遍历使用 `../`（Unix），缺少 `..\`（Windows）。

```python
# 增加 Windows 变体
WINDOWS_TRAVERSAL = [
    "..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\..\\..\\..\\boot.ini",
]
```

### 7.2：XXE 未检测 JSON 端点

**根因**：`xxe/detector.py:317-328` 只在 XML 路径上追加测试端点，未考虑 JSON API 端点也可能接受 XML（通过 `Content-Type: application/xml`）。

**修复**：对所有 POST 端点发送带 `Content-Type: application/xml` 的 XXE payload。

### 7.3：API 检测模块未添加 contentType 探测

**根因**：API 模块（`api/detector.py`）未在本次文件中。如存在，应在探测 API 时先 HEAD 请求判断 Content-Type，而非盲目 GET 大文件。

---

## 八、优化优先级与预期效果

| 优先级 | 模块 | 问题 | 预期效果 |
|--------|------|------|---------|
| **P0** | SQLi | 增加数字型 payload、降低 boolean 阈值 | 检出率 +300%（4→12+） |
| **P0** | SSRF | 移除 HTML 标记误报、环境感知 | 误报率 -80%（~30→6） |
| **P0** | Crawler | 增加深度至5、认证后重爬 | 端点覆盖 +50%（105→160） |
| **P1** | XSS | DOM sink 检测、回查路径动态化 | DOM XSS 检出 0→N |
| **P1** | RCE | 随机数替代固定值、时间盲测加 baseline | 误报率 -60% |
| **P1** | 性能 | SSRF 分阶段测试、全局基线缓存 | 请求量 -40%（68K→40K） |
| **P2** | XXE | JSON 端点兼容、增加 SVG payload | 可能发现新漏洞 |
| **P2** | LFI | Windows 路径变体 | 覆盖率 +20% |
| **P2** | 内存 | 定期清理 httpx 连接池 | 降低 OOM 风险 |
