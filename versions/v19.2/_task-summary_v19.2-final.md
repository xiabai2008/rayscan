# WVS v19.2 — 完整集成接入总结

## 日期
2026-05-07

## 已完成

### 1. 版本号
- `wvs/__init__.py`: 19.0.0 → 19.2.0
- `pyproject.toml`: 19.0.0 → 19.2.0

### 2. 新增集成模块（`wvs/integrations/`）
| 文件 | 大小 | 功能 |
|------|------|------|
| `__init__.py` | 640B | 统一导出 |
| `sqlmap_integration.py` | 11.7KB | subprocess 调用 sqlmap，解析注入点输出 |
| `ffuf_integration.py` | 10.9KB | subprocess 调用 ffuf，JSON 输出解析，智能路径分类 |
| `wappalyzer_integration.py` | 14.3KB | python-Wappalyzer + 内置 25 条指纹 fallback，生成扫描建议 |

### 3. Scanner 核心接入（`wvs/core/scanner.py`）
- 新增 `_run_integrations()` 编排方法 — 并发调度 4 个外部工具
- 新增 `_run_wappalyzer_fingerprint()` — 指纹识别 + WAF 检测
- 新增 `_run_ffuf_discovery()` — 目录爆破
- 新增 `_run_sqlmap_scan()` — 智能触发（仅当 SQLi 模块有发现或 aggressive 模式）
- 扫描流程改为 5 阶段：Crawl → Detectors → **Integrations** → Dedup → Report

### 4. 配置（`wvs/config.py`）
新增 `integrations` 顶级配置节点：
```json
{
  "integrations": {
    "enabled": true,
    "nuclei": {"enabled": true, "timeout": 300, "rate_limit": 20},
    "sqlmap": {"enabled": true, "timeout": 600, "level": 2, "risk": 1, "aggressive": false},
    "ffuf": {"enabled": true, "timeout": 120, "rate": 30},
    "wappalyzer": {"enabled": true, "timeout": 30}
  }
}
```

### 5. pyproject.toml 可选依赖
新增 `integrations` 可选组：`python-Wappalyzer>=1.2.0`, `aiohttp>=3.8.0`

## 验证
- 所有模块导入成功
- Scanner 在工具未安装时优雅降级（`is_available → False → 跳过`）
- 配置默认值全部可读
- AST 语法检查通过
