# 检测模块说明

RayScan 当前注册 **20 个检测模块**，分三个层级：`core`（默认加载）、`optional`（按需启用）、`lite`（`--all-modules` 启用）。

> 分层由代码决定：`ModuleInfo.category`（`wvs/modules/base.py`），未显式标注的模块默认 `lite`。本文与 `wvs/modules/__init__.py` 的注册表保持同步，模块增删请同步更新。

## 模块层级总览

| 层级 | 模块 | 启用方式 |
|------|------|---------|
| 🟢 core | `sqli` `xss` | 默认加载 |
| 🔵 optional | `jspathfinder` | 配置/参数启用 |
| 🟡 lite | `cmdi` `lfi` `rce` `ssrf` `xxe` `api` `sensitive` `waf` `js_analysis` `oa` `subdomain` `weakpass` `webshell` `idor` `authbypass` `graphql` `mcp` | `--all-modules` |

## 模块清单

| 模块 | category | 检测能力 | 覆盖 |
|------|:--------:|----------|------|
| `sqli` | core | SQL 注入 8 种：error / union / boolean-blind / time-based / stacked / 二阶 / 宽字节 / OOB | A03:2021 |
| `xss` | core | 反射型 / 存储型 / Polyglot / mXSS / SSTI（DOM XSS 待 headless，见 Roadmap） | A03:2021 |
| `jspathfinder` | optional | JavaScript 端点发现 | — |
| `oa` | lite | 12 种 OA/中间件专项：泛微/通达/金蝶/蓝凌/致远/用友/禅道/万户/Nacos/Spring/Jenkins/Confluence，三级检测链路 | 多类 |
| `cmdi` | lite | 命令注入（多分隔符 + time-based 并发） | A03:2021 |
| `graphql` | lite | GraphQL 端点识别 / introspection 开启 / 批量查询检测（证据验证） | API Top 10 |
| `lfi` | lite | 本地文件包含（目录遍历 / PHP 伪协议 / 编码绕过） | A01:2021 |
| `mcp` | lite | MCP Server 暴露检测（端点发现 / 工具列表泄露 / 敏感工具未授权调用） | — |
| `rce` | lite | 远程代码执行 | A03:2021 |
| `ssrf` | lite | 服务端请求伪造（内网探测 / 云元数据 / OOB blind） | A10:2021 |
| `xxe` | lite | XML 外部实体（内联 / 外部 / blind OOB，file/http/ftp/php://） | A05:2021 |
| `api` | lite | API 安全（REST / GraphQL，权限绕过 / 方法篡改 / 批量赋值） | API Top 10 |
| `sensitive` | lite | 敏感信息泄露（Key/Token/密码/云凭证，响应体/注释/JS/robots.txt） | A04:2021 |
| `waf` | lite | WAF 指纹识别与绕过（编码混淆 / 大小写 / 注释插入 / 参数污染） | — |
| `js_analysis` | lite | JavaScript 敏感信息分析 | — |
| `subdomain` | lite | 子域名枚举（DNS 爆破 + crt.sh 证书透明度） | — |
| `weakpass` | lite | 弱口令（表单登录 / phpMyAdmin / Tomcat Manager） | A07:2021 |
| `webshell` | lite | WebShell（路径扫描 + 内容特征 + 启发式） | — |
| `idor` | lite | IDOR / 越权访问（基础实现，深化方向已被 ADR-0001 冻结） | A01:2021 |
| `authbypass` | lite | 认证绕过（基础实现，同上） | A07:2021 |

## 模块注册机制（T2.1 设计）

每个 `detector.py` 在导入时通过 `@register_module` / `register_module()` 自动注册到 `ModuleFactory`，注册表是模块加载的**唯一事实源**：

- `wvs.modules.register_all_modules()` — 遍历导入全部 detector，保证注册表完整
- `wvs.modules.lite.register_lite_modules()` — 单独注册传统 Lite 十件套（cmdi/lfi/rce/ssrf/xxe/sensitive/api/waf/jspathfinder/js_analysis）
- CLI 通过 `ModuleFactory.list_modules()` 展示模块（`python -m wvs list-modules`）

## 目录结构

```
modules/
├── base.py                  # DetectionModule 基类 + ModuleFactory 注册表（category 默认 lite）
├── __init__.py              # 全量导入 + register_all_modules()
├── lite/__init__.py         # Lite 子集注册入口
├── sqli/                    # detector / payloads / analyzer / techniques_mixins
├── xss/                     # detector / payloads / context_analyzer
├── oa/                      # detector（含 12 种内容指纹与规则级证据验证）
├── cmdi/ lfi/ rce/          # detector / payloads
├── ssrf/ xxe/               # detector / payloads
├── api/ sensitive/ waf/     # detector
├── graphql/ mcp/            # detector（GraphQL introspection / MCP 暴露检测）
├── jspathfinder/ js_analysis/
├── subdomain/ weakpass/ webshell/
└── idor/ authbypass/
```

## 与 ROADMAP 的关系

- `idor` / `authbypass` 为基础实现；深化方向（多角色对比等）已被 [ADR-0001](../adr/0001-oa-focused-repositioning.md) 冻结，维持现状不扩。
- DOM XSS（headless 验证）、多引擎聚合、MSF 验证链：见 README Roadmap，均不在当前模块清单内。
