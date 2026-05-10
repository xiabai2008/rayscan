# WVS v19.2 — 开源工具集成

## 日期
2026-05-07

## 操作
1. 复制 wvs-v19 → wvs-v19.2（187 文件，排除 .git/__pycache__/reports/.claude 等）
2. 版本号更新：19.0.0 → 19.2.0（`pyproject.toml` + `wvs/__init__.py`）
3. 新增 3 个集成模块 + __init__.py

## 新增文件
| 文件 | 大小 | 功能 |
|------|------|------|
| `wvs/integrations/__init__.py` | 640B | 统一导出 4 个集成类 |
| `wvs/integrations/sqlmap_integration.py` | 11.7KB | sqlmap 子进程调用，解析注入点输出 → Vulnerability |
| `wvs/integrations/ffuf_integration.py` | 10.9KB | ffuf 目录/文件爆破，JSON 输出解析，智能路径分类 |
| `wvs/integrations/wappalyzer_integration.py` | 14.3KB | 技术栈指纹识别（python-Wappalyzer + 内置 25 条规则 fallback），生成扫描策略建议 |

## 架构设计
- 所有集成模块遵循 `NucleiIntegration` 一致的接口模式：
  - `is_available` 属性检测工具是否安装
  - 主方法（`scan`/`discover`/`fingerprint`）返回 `List[Vulnerability]`
  - `get_stats()` 返回统计信息
  - 工具不可用时自动降级/跳过，不会报错中断
- Wappalyzer 额外提供 `TechFingerprint` 数据类和 `get_scan_recommendations()` 方法
- pyproject.toml 新增 `integrations` 可选依赖组

## 验证
- 全部 4 个模块导入成功（`from wvs.integrations import SqlmapIntegration, ...`）
- sqlmap/ffuf/nuclei 显示 `is_available: False`（系统未安装对应 CLI，预期行为）
- Wappalyzer 显示 `is_available: True`（内置指纹库始终可用）
