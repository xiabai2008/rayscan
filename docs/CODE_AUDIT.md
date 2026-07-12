# 核心代码审计报告（Code Audit）

- **范围**：`wvs/core`（scanner / session / crawler / cache / rate_limiter / scheduler / oob）、关键检测模块（api / cmdi / rce / xss / oa / waf / js_analysis / jspathfinder）、CLI 入口 `wvs/cli.py`。
- **方法**：人工静态走读 + `ruff 0.15` 全量扫描（基线 969 项违规）。
- **配套**：本审计发现已登记至 `docs/TECH_DEBT.md`（TD-003 / TD-006 / TD-008 / TD-009 / TD-011）。

---

## 一、已修复（本次发现并修复）

| 级别 | 位置 | 问题 | 修复 |
|------|------|------|------|
| 🔴 HIGH | `wvs/modules/api/detector.py` | 鉴权绕过检测引用**未定义变量** `auth_text` / `noauth_text`（应为 `resp_auth.text` / `resp_noauth.text`）→ 运行时 `NameError`，整个 API 鉴权绕过模块会崩溃 | 已改为 `resp_auth.text` / `resp_noauth.text` |
| 🔴 HIGH | `wvs/cli.py` | exploit 确认分支使用**未定义** `logger` → `NameError` | 新增模块级 `logger = logging.getLogger(__name__)` |
| 🟡 MED | `wvs/cli.py` `exploit_enabled` | 死变量（赋值从未读取） | 移除 |
| 🟡 MED | `wvs/core/crawler.py` `sizes` | 死变量 | 移除 |
| 🟡 MED | `wvs/core/scanner.py` `seen` | 死变量（去重实际用 `unique` 字典） | 移除 |
| 🟡 MED | `wvs/modules/oa/detector.py` `vuln_type` | 死变量；`_create_vuln` 误传原始字符串 `vuln_type_str` | 改为传枚举 `vuln_type`（与 `severity` 一致，修正类型） |
| 🟡 MED | `wvs/modules/waf/detector.py` `parsed` / `round_body` | 死变量；`urlparse` 导入随之失效 | 移除死变量与 `from urllib.parse import urlparse` |
| 🟡 MED | `wvs/modules/xss/context_analyzer.py` `payloads` / `tag` / `quotes` | 死变量 | 移除 |
| 🟡 MED | `wvs/reporting/console.py` `warn_icon` | 死变量 | 移除 |
| 🟢 LOW | `wvs/modules/js_analysis/__init__.py`、`waf/__init__.py` | 重导出未列入 `__all__`（F401） | 补 `__all__` |

> 以上 24 处 `F821/F401/F841` 已由 `ruff` 复核清零（「All checks passed」）。

---

## 二、高危（待处理）

1. **`exploit_enabled` 逻辑空转（TD-011）** — `wvs/cli.py` 中用户确认授权后仅打日志，**从未真正启用利用模块**（无对应配置键接线）。属「已确认但功能未实现」的缺陷。建议：接线到 scanner/config 的 exploit 开关，或显式标注该确认为纯审计日志。
2. **盲目异常捕获（BLE001，151 处）** — scanner / crawler / 各检测模块大量 `except Exception` / `except:` 吞掉错误。对安全扫描器，吞异常会**掩盖真实错误、导致漏报/误报且无日志**。建议：收窄为具体异常类型 + 必须记录日志。`wvs/exceptions.py`、`wvs/modules/base.py` 已设 per-file 豁免（那里的宽泛捕获是有意的）。

---

## 三、中危

- **可变类级默认值（RUF012，38 处）** — 实例间共享可变状态，易引发跨请求串扰。示例：
  - `wvs/modules/base.py:945` `_modules: Dict[str, type] = {}`（注册表，若按实例修改则共享）
  - `wvs/modules/js_analysis/analyzer.py:47` `findings: List[dict] = []`
  - `wvs/modules/xss/context_analyzer.py:50` `contexts: Dict[int, ReflectionContext] = {}`
  - `wvs/modules/jspathfinder/detector.py:154` `_target_cache: Dict[str, bool] = {}`
  - 建议：改为 `__init__` 内初始化或 `field(default_factory=...)`。
- **未使用参数（ARG001/ARG002，39 处）** — 方法/函数签名含未使用参数，常为未完成重构或签名错误，应清理或补实现。
- **`api/detector.py` 重复请求** — `resp_auth` 在 120 行与 143 行各发一次同一 URL，浪费一次网络往返（可删除其一）。
- **隐式可选（RUF013，19 处）** — `x: str = None` 反模式，应改为 `Optional[str] = None`。
- **E402 模块导入不在顶部（23 处）** — 部分为 `sys.path` 处理（可忽略），部分应上移。

---

## 四、低危 / 技术债（渐进收紧，TD-009）

~200+ 项风格/现代化类违规，按类别：

| 类别 | 约数 | 说明 |
|------|------|------|
| SIM（简化） | ~50 | 可折叠 if、needless bool、if-exp 替代等 |
| PTH（os.path→pathlib） | ~30 | 建议迁移到 `pathlib.Path` |
| B007 / B904 | ~23 | 未用循环变量 / `raise` 缺 `from` |
| C4（推导式） | ~10 | 用推导式替代 `list`/`set` 构造 |
| TRY300/TRY003/TRY400 | ~50 | 异常处理风格（else 分支 / 原生异常 / 日志消息） |
| RUF 系列 | ~30 | 多余分配、key 检查、链式括号等 |

策略：登记为技术债，随 sprint 逐步清零，季度复盘；CI 接入 lint 门禁后由「本地可见」升级为「PR 必过」（见下方路线图）。

---

## 五、架构优势（保留）

- **全链路 async + 显式超时**：网络请求统一走 `aiohttp` / `httpx` 并带 `timeout`；外部工具（nuclei / sqlmap / ffuf / msf）均经 `asyncio.create_subprocess_exec` + `asyncio.wait_for(proc.communicate(), timeout=)`，无挂起风险。
- **流程基础已具备**：PR 流程 + 分支保护 + CI 测试矩阵（3.9–3.12）+ pre-commit（ruff / mypy）已就位，门禁骨架可用。

---

## 六、优先级路线图

1. **立即**：合并本次修复（已就绪）；补 TD-011（exploit 接线或显式标注审计日志）。
2. **本 sprint**：收窄 BLE001（优先 `scanner` / `crawler` 核心路径并补日志）；修复 RUF012 可变类级默认值。
3. **持续**：
   - TD-009 技术债按严重度逐 sprint 清零；
   - CI 接入 `lint` / `format` / `coverage` 门禁（改动已就绪于 `.github/workflows/ci.yml`，待 `gh` 的 `workflow` 作用域授权后推送并纳入分支保护必过项）；
   - 提升 `wvs/core` 单元测试覆盖（TD-008）。
