# v19.2 — JSPathfinder 集成 + Scanner 接入 + README

## 完成内容

### 1. JSPathfinder 模块化
- `wvs/modules/jspathfinder/detector.py` (~520行) — DetectionModule 子类
- `wvs/modules/jspathfinder/__init__.py` — 模块导出
- `wvs/modules/__init__.py` — 注册 JSPathfinderDetector
- `wvs/config.py` — 添加 jspathfinder 配置（modules 下）

### 2. Scanner 主流程接入
- `wvs/core/scanner.py`：
  - 新增 `_run_jspathfinder()` 方法
  - Phase 1.5 插入点（爬虫后、检测器前）
  - 结果合并入 `all_vulns`（dedup 之前）
  - 修复预存 bug：`_vuln_signature()` 中 `hash() % 10000` 需 `str()` 转换

### 3. README.md 重写
- 版本号 v19.2
- 新增集成工具表、扫描流程图
- 新增 JSPathfinder 规则覆盖表
- 项目结构更新（integrations/、jspathfinder/）
- v19 vs v19.2 对比表
- 编码：UTF-8 BOM + CRLF (Windows)

### 4. 测试验证
- 模块导入 + 配置加载 ✅
- 独立扫描测试 (8/8) ✅
- Scanner 全流程集成测试 ✅
  - Phase 1.5 正确执行
  - JSPathfinder 结果流入最终报告
  - Phase 2/2b 无影响

## 扫描流程 (v19.2)
```
Phase 1   → Crawler
Phase 1.5 → JSPathfinder (JS secrets + endpoints + fuzz)
Phase 2   → Detectors (sqli/xss/cmdi/lfi/rce/ssrf/xxe/api/sensitive/waf)
Phase 2b  → External integrations (Wappalyzer + ffuf + sqlmap + Nuclei)
Phase 3   → Dedup
Phase 4   → Report
```

## 改动文件清单
| 操作 | 文件 |
|------|------|
| 新增 | `wvs/modules/jspathfinder/detector.py` |
| 新增 | `wvs/modules/jspathfinder/__init__.py` |
| 修改 | `wvs/modules/__init__.py` |
| 修改 | `wvs/config.py` |
| 修改 | `wvs/core/scanner.py` (+20行, bugfix 1行) |
| 重写 | `README.md` |
