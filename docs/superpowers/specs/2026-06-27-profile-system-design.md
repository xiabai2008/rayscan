# RayScan Profile 系统设计

## 背景

RayScan 定位为个人渗透伴侣，用于 SRC 挖掘和渗透测试前期踩点。用户核心诉求：
- 快速开工，30秒内启动扫描
- 快速切换模块和性能参数
- 工具协同，减少手动复制粘贴
- 高灵敏度，宁可多报不漏真漏洞

## 核心概念

Profile = 扫描参数的预设集合，包含模块开关和性能参数。
Auth = 目标认证信息，独立管理。

## 设计方案

### Profile (YAML)

存储位置：`profiles/` 目录

```yaml
name: src-quick
description: SRC快瞄 — 高灵敏度，快速出结果
modules:
  enabled: [sqli, xss, cmdi, lfi]
  disabled: []
params:
  rate: 20
  threads: 10
  timeout: 15
  crawl_depth: 2
  crawl_max_urls: 50
  verify_ssl: false
```

### Auth File (JSON)

认证信息独立存储，运行时通过 `--auth` 指定：

```json
{
  "cookie": "PHPSESSID=xxx; security=low",
  "headers": {
    "User-Agent": "Mozilla/5.0..."
  }
}
```

支持多种认证类型：
- `cookie`: 会话 Cookie
- `bearer`: Bearer Token / API Key
- `basic`: Basic Auth (username/password)
- `headers`: 自定义请求头

### CLI 接口

```bash
# 使用 Profile + Auth 扫描
rayscan use src-quick --auth my-target.json -u https://target.com

# Profile 管理
rayscan profile list                          # 列出所有
rayscan profile create sqli-only --modules sqli --rate 30
rayscan profile export src-quick -o ./my-profiles/
rayscan profile import ./my-profiles/
rayscan profile delete src-quick

# Auth 独立管理
rayscan auth new my-target --cookie "xxx" --bearer "yyy"
rayscan auth list
rayscan auth delete my-target
```

### 内置 Profile

| 名称 | 用途 |
|------|------|
| `default` | 均衡模式，全模块 |
| `src-quick` | SRC快瞄，高灵敏度，浅爬快速出结果 |
| `pentest-full` | 渗透测试，深度爬，全模块 |
| `sqli-only` | 只扫SQL注入 |

## 文件布局

```
RayScan/
├── profiles/              # Profile 存储
│   ├── default.yaml
│   ├── src-quick.yaml
│   ├── pentest-full.yaml
│   └── sqli-only.yaml
├── auths/                 # Auth 存储 (可选)
│   └── my-target.json
└── rayscan = wvs.cli:main
```

## 实现计划

### Phase 1: Profile 系统
1. 创建 `profiles/` 目录和内置 Profile YAML
2. CLI 添加 `profile` 子命令 (list/create/delete/export/import)
3. CLI 添加 `use <profile>` 加载 Profile
4. 扫描时 Profile 参数覆盖默认配置

### Phase 2: Auth 系统
1. 创建 `auths/` 目录
2. CLI 添加 `auth` 子命令 (new/list/delete)
3. `--auth` 参数支持 JSON 文件和已命名的 Auth
4. Auth 与 Profile 组合使用

## 优先级

Profile 系统优先实现，Auth 系统可在 Profile 稳定后添加。
