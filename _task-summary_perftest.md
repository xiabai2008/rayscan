# v19.2 — 性能测试

## 测试环境
- 靶机: **Raven Security CTF** @ 172.17.43.131 (VMWare VM)
  - Apache/2.4.10 (Debian) + WordPress
  - 目录列举开启 (/vendor/, /js/, /css/, /img/)
  - 联系表单 + 用户管理
- 扫描器: WVS v19.2 全模块

## 测试结果

| 指标 | 数值 |
|------|------|
| 总耗时 | 281.8s (4分42秒) |
| HTTP 请求 | 106 |
| 爬取页面 | 13 |
| 发现端点 | 14 |
| 发现表单 | 8 |
| 漏洞总数 | 5 |

### Phase 明细
| Phase | 描述 | 状态 | 产出 |
|-------|------|------|------|
| 1 | 爬虫 | ✅ | 13页, 14端点, 8表单 |
| 1.5 | JSPathfinder | ✅ | 5 发现 (3 HIGH + 2 INFO) |
| 2 | 检测器 (9模块) | ⚠️ 超时 | 0 (只剩18s预算) |
| 2b | 外部集成 | ✅ | Wappalyzer: Apache/2.4.10 |
| 3 | 去重 | ✅ | 5 漏洞 (去重后) |
| 4 | 报告 | ✅ | - |

### 发现的漏洞
| 级别 | 类型 | 描述 |
|------|------|------|
| HIGH | information_disclosure | JS 硬编码 URL ×3 (JSPathfinder) |
| INFO | other | JS 线索: XSS 19处 (JSPathfinder) |
| INFO | insecure_configuration | 敏感路径暴露: /.DS_Store (JSPathfinder) |

### 工具可用性
| 工具 | 状态 |
|------|------|
| JSPathfinder | ✅ 5 finds |
| Wappalyzer | ✅ Apache/2.4.10 |
| Nuclei | ❌ CLI 未安装 |
| sqlmap | ❌ CLI 未安装 |
| ffuf | ❌ CLI 未安装 |

## 发现并修复的问题

### 1. 爬虫 Playwright 卡死
- **原因**: `crawl_js()` 每页都调 Playwright，`TargetClosedError` (BaseException) 不被 `except Exception` 捕获
- **修复**: JS 渲染默认关闭 (`_js_render=False`)，需显式启用

### 2. Dedup hash 拼接错误
- **原因**: `"info_ev:" + hash(ev) % 10000` → str + int
- **修复**: 改为 `str(hash(ev) % 10000)`

### 3. 超时预算不足
- `max_time=300s` 下 Phase 1+1.5 占 264s，检测器只剩 18s
- **建议**: 实测目标至少 600s，或降低 crawl_depth

## 改动文件
| 文件 | 改动 |
|------|------|
| `wvs/core/crawler.py` | JS 渲染默认禁用 + 异常兜底 |
| `wvs/core/scanner.py` | Phase 1.5 + _run_jspathfinder + hash fix |
| `wvs/modules/jspathfinder/*` | 新增模块 |
| `wvs/modules/__init__.py` | 注册 jspathfinder |
| `wvs/config.py` | jspathfinder + integrations 配置 |
| `README.md` | 重写 v19.2 |
