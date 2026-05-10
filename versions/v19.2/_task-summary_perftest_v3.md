# v19.2 — 调参测试结果

## 测试参数 (v3 最终版)
| 参数 | 值 | 说明 |
|------|-----|------|
| crawl_depth | 1 | 浅爬优先 |
| crawl_max_urls | 20 | 限制爬取量 |
| concurrent_endpoints | 5 | 中等并发 |
| max_time | 300s | 5分钟预算 |
| 模块 | sqli, xss, cmdi, sensitive | 4 核心 |
| 集成 | Wappalyzer only | 其余 CLI 未安装 |

## 测试结果

| 指标 | 首次 (v1, broken) | 调参后 (v3) |
|------|-------------------|-------------|
| 总耗时 | 282s (超时截断) | **296s (完整)** |
| HTTP 请求 | 106 | **2004** |
| 检测器进度 | 0/90 (0%) | **40/40 (100%)** |
| 漏洞 | 5 | 5 |
| 状态 | ❌ 检测器全跳 | ✅ 全跑完 |

### Phase 耗时分解
```
Phase 1   Crawl        ~30s  (10%)
Phase 1.5 JSPathfinder ~30s  (10%)
Phase 2   Detectors    ~230s (78%)  ← 真正的检测时间
Phase 2b  Wappalyzer   ~3s   (1%)
Phase 3-4 Dedup+Report ~3s   (1%)
```

### 检测器产出
| 模块 | 负载量 | 发现 |
|------|--------|------|
| cmdi | ~500 req | 0 |
| xss | ~600 req | 0 |
| sqli | ~550 req | 0 |
| sensitive | ~350 req | 0 |
| JSPathfinder | - | 5 |

### 结论
- **检测器引擎工作正常**：2004 请求在 300s 内跑完 4 模块 × 10 端点
- **Raven Security 首页没有明显注入点**：检测器扫了但确实不存在 SQLi/XSS/CMDi
- **建议下一个靶子**：扫 `/wordpress/` 子路径或 `172.17.43.129` 的 DVWA
