# RayScan 内置规则目录

本目录随仓库分发。T3.3 起，**OA 检测矩阵的单一事实源在本目录的 `oa/` 子目录**
（每文件一种 OA），由 `wvs/modules/oa/rules_loader.py` 在导入时加载；
`wvs/modules/oa/detector.py` 内保留的硬编码矩阵仅作规则包缺失/无效时的回退。

## OA 规则包（rules/oa/*.yaml）

每文件一种 OA，顶层键：

| 键 | 必填 | 说明 |
|----|:----:|------|
| `name` | ✅ | OA 标识（与 `docs/OA_RULES.md` 检测矩阵 / 扫描器注入名一致） |
| `paths` / `keywords` | | URL 识别通道（子路径探测 + URL 关键词回退） |
| `fingerprints` | | 内容指纹通道：`match: html/title/header/cookie` + `value`（header 型 `value: null` 表示头存在即命中） |
| `checks` | | 检测项列表 |

`checks` 每条字段（详见 `docs/OA_RULES.md` §2）：

| 字段 | 说明 |
|------|------|
| `path` | ✅ 检测路径（`/` 开头） |
| `type` | ✅ sqli/rce/lfi/file_read/file_upload/auth_bypass/unauth/info_disclosure/info |
| `severity` | ✅ critical/high/medium/low/info |
| `method` / `params` / `param_type` | 请求方法（默认 GET）/ 参数 / 参数位置（query/body/json） |
| `evidence` | 规则级响应证据（大小写不敏感子串，命中才报） |
| `min_version` / `max_version` | 版本过滤（[min, max) 语义，无版本信息放行） |
| `status_codes` | 允许的响应状态码（默认 `[200]`） |

**编写注意**：`evidence`/`max_version` 等字符串值必须加引号（`evidence: '54289'`），
否则 YAML 会解析成数字；未知字段/非法取值会被加载器丢弃（宁漏报不误报），并在日志告警。

**新增一种 OA 只需加一个 YAML 文件，无需改代码。**

## 目录优先级

1. 运行时用户覆盖包：`~/.rayscan/rules/oa/`（同名 OA **整体覆盖**内置条目；
   可 init 后放独立 git 仓库，由 `rayscan rules update` 增量同步）
2. 内置规则包：本目录 `oa/`（随版本发布）
3. 内置硬编码回退：`wvs/modules/oa/detector.py` 的 `BUILTIN_OA_RULES`（规则包缺失时生效）

## 其他规则

- 非 OA 的自定义检测规则（指纹、敏感路径、默认口令字典）也可放 `~/.rayscan/rules/`，
  由 `rayscan rules update` 管理；规则采用 YAML 格式。
