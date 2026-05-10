# WVS v18.4 智能限速系统

## 概述

智能限速系统为WVS v18.4漏洞扫描工具提供完整的速率控制和WAF规避功能，防止触发Web应用防火墙（WAF）和目标服务器过载。系统包含以下核心组件：

1. **RateLimiter类**：滑动窗口请求限制（最大RPS控制）
2. **AdaptiveRateLimiter类**：基于响应时间、状态码动态调整速率
3. **WAFEvasion策略类**：随机请求间隔、User-Agent轮换、请求模式变化
4. **IntelligentRateLimiter类**：集成以上所有功能的智能限速器

## 功能特性

### 1. 精确的速率控制
- **滑动窗口算法**：精确控制每秒请求数（RPS）
- **两种模式**：
  - **突发模式（burst）**：允许突发请求，只要在时间窗口内不超过限制
  - **均匀模式（uniform）**：请求均匀分布，间隔固定
- **可配置窗口大小**：默认1秒，可调整

### 2. 自适应调整
- **响应时间监控**：响应时间增加时自动降低速率
- **错误状态码处理**：429/503状态码触发指数退避
- **成功率跟踪**：成功率下降时降低速率
- **自动恢复**：一段时间无错误后逐步恢复速率
- **健康状态**：正常（healthy）、警告（warning）、限制（throttled）

### 3. WAF规避策略
- **随机请求间隔**：在基础延迟上添加随机抖动
- **User-Agent轮换**：从预定义列表中选择User-Agent
- **请求头变化**：随机化Accept、Accept-Language等头部
- **请求模式变化**：随机化请求顺序、添加冗余参数

### 4. 完整集成
- **向后兼容**：现有`delay`参数继续有效
- **无缝集成**：与现有`VulnerabilityScanner`、`EnhancedCrawler`、`ConcurrentScanner`无缝集成
- **配置驱动**：通过JSON配置文件轻松调整参数

## 快速开始

### 1. 独立使用智能限速器

```python
from intelligent_rate_limiter import IntelligentRateLimiter

# 创建配置
config = {
    "max_rps": 5,                # 最大5个请求/秒
    "mode": "burst",             # 突发模式
    "enable_adaptive": True,     # 启用自适应调整
    "enable_waf_evasion": True,  # 启用WAF规避
    "enable_jitter": True,       # 启用随机抖动
    "jitter_range": 0.2,         # 抖动范围0.2秒
}

# 创建限速器
rate_limiter = IntelligentRateLimiter(config)

# 使用示例
async def send_request():
    # 等待直到可以发送请求
    wait_time = await rate_limiter.acquire()
    
    # 获取WAF规避头部
    headers = rate_limiter.get_evasion_headers()
    
    # 发送请求...
    # response = await session.get(url, headers=headers)
    
    # 更新指标
    rate_limiter.update_metrics(response.status, response_time)
```

### 2. 与漏洞扫描器集成

```python
from wvs.vuln.scanner_v18 import VulnerabilityScanner

# 配置扫描器，启用智能限速
scanner_config = {
    "timeout": 30,
    "delay": 0.1,  # 原始delay，将被速率限制器覆盖
    
    "rate_limiter": {
        "enabled": True,
        "max_rps": 8,
        "mode": "burst",
        "enable_adaptive": True,
        "enable_waf_evasion": True,
    }
}

scanner = VulnerabilityScanner(scanner_config)
# 现在扫描器会自动应用速率限制和WAF规避
```

### 3. 与并发扫描器集成

```python
from concurrent_scanner import ConcurrentScanner

config = {
    "max_workers": 3,
    "timeout_per_target": 120,
    "scanner_timeout": 30,
    
    "rate_limiter": {
        "enabled": True,
        "max_rps": 15,  # 每个扫描器实例的RPS限制
        "mode": "burst",
        "enable_adaptive": True,
        "enable_waf_evasion": True,
    }
}

scanner = ConcurrentScanner(config)
# 并发扫描器会将限速配置传递给每个扫描器实例
```

## 配置选项

### 基础配置
| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | bool | `true` | 是否启用限速器 |
| `max_rps` | int | `10` | 最大每秒请求数 |
| `mode` | string | `"burst"` | 限速模式：`"burst"`或`"uniform"` |
| `window_size` | float | `1.0` | 时间窗口大小（秒） |

### 自适应调整配置
| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enable_adaptive` | bool | `true` | 是否启用自适应调整 |
| `min_rps` | int | `1` | 最小RPS（自适应调整下限） |
| `recovery_rate` | float | `0.1` | 恢复速率（每次调整增加的比例） |
| `backoff_factor` | float | `2.0` | 退避因子（遇到错误时RPS减少的倍数） |

### WAF规避配置
| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enable_waf_evasion` | bool | `true` | 是否启用WAF规避 |
| `enable_jitter` | bool | `true` | 是否启用随机抖动 |
| `jitter_range` | float | `0.3` | 抖动范围（秒） |
| `enable_rotation` | bool | `true` | 是否启用User-Agent轮换 |

## 配置示例

### 1. 生产环境推荐配置
```json
{
  "rate_limiter": {
    "enabled": true,
    "max_rps": 5,
    "mode": "uniform",
    "enable_adaptive": true,
    "min_rps": 1,
    "recovery_rate": 0.05,
    "backoff_factor": 3.0,
    "enable_waf_evasion": true,
    "enable_jitter": true,
    "jitter_range": 0.2,
    "enable_rotation": true
  }
}
```

### 2. 激进扫描配置（内部测试）
```json
{
  "rate_limiter": {
    "enabled": true,
    "max_rps": 20,
    "mode": "burst",
    "enable_adaptive": false,
    "enable_waf_evasion": false
  }
}
```

### 3. 高隐蔽性配置（高防护目标）
```json
{
  "rate_limiter": {
    "enabled": true,
    "max_rps": 2,
    "mode": "uniform",
    "enable_adaptive": true,
    "min_rps": 1,
    "recovery_rate": 0.02,
    "backoff_factor": 5.0,
    "enable_waf_evasion": true,
    "enable_jitter": true,
    "jitter_range": 0.5,
    "enable_rotation": true
  }
}
```

## 监控和统计

智能限速器提供详细的统计信息：

```python
# 获取统计信息
stats = rate_limiter.get_stats()

# 包含的信息：
# - total_requests: 总请求数
# - total_wait_time: 总等待时间
# - avg_wait_time_per_request: 平均等待时间
# - rate_limiter: 速率限制器指标（RPS、成功率、错误率等）
# - adaptive_status: 自适应状态（健康状态、退避状态等）
```

## 自适应调整逻辑

### 健康状态转换
1. **正常状态（healthy）**：
   - 错误率 < 10%
   - 平均响应时间 < 2秒
   - 逐步提高RPS（按recovery_rate）

2. **警告状态（warning）**：
   - 错误率 10%-30%
   - 平均响应时间 2-5秒
   - 降低RPS至80%

3. **限制状态（throttled）**：
   - 错误率 > 30%
   - 收到429/503状态码
   - 触发指数退避，大幅降低RPS

### 退避机制
- **触发条件**：收到429或503状态码
- **退避时间**：指数增长（5秒 × backoff_factor^n），最大60秒
- **恢复条件**：退避时间结束后，逐步恢复

## 测试和验证

系统包含完整的测试套件：

```bash
# 运行单元测试
python test_rate_limiter.py

# 运行使用示例
python rate_limit_usage_example.py
```

## 文件说明

| 文件 | 说明 |
|------|------|
| `intelligent_rate_limiter.py` | 智能限速系统核心模块 |
| `test_rate_limiter.py` | 单元测试和集成测试 |
| `rate_limit_config_example.json` | 配置示例文件 |
| `rate_limit_usage_example.py` | 使用示例代码 |
| `validation_optimized_config.json` | 更新的验证优化配置 |
| `wvs_optimized_config.json` | 更新的WVS优化配置 |

## 向后兼容性

1. **现有`delay`参数**：继续有效，如果未配置`max_rps`，会根据`delay`自动计算
2. **禁用限速器**：设置`enabled: false`或移除`rate_limiter`配置
3. **逐步启用**：建议先在测试环境中启用，观察效果后再用于生产

## 最佳实践

1. **开始扫描前**：
   - 根据目标防护等级选择合适的配置
   - 从保守配置开始（低RPS），逐步调整
   - 启用自适应调整以应对未知情况

2. **扫描过程中**：
   - 监控速率限制器统计信息
   - 关注429/503状态码出现频率
   - 根据实际情况调整配置

3. **遇到WAF防护时**：
   - 降低`max_rps`，启用`uniform`模式
   - 启用所有WAF规避功能
   - 增加`jitter_range`以增加随机性

## 故障排除

### 常见问题

1. **扫描速度过慢**：
   - 增加`max_rps`值
   - 使用`burst`模式
   - 禁用`enable_adaptive`或降低`backoff_factor`

2. **仍然触发WAF**：
   - 降低`max_rps`值
   - 使用`uniform`模式
   - 增加`jitter_range`
   - 确保`enable_waf_evasion`为`true`

3. **自适应调整过于敏感**：
   - 增加`recovery_rate`
   - 降低`backoff_factor`
   - 调整`min_rps`保证最低性能

## 性能影响

智能限速系统设计为高效异步实现：
- **内存占用**：每个限速器约1-2KB
- **CPU开销**：每次请求约0.01ms
- **网络延迟**：添加的抖动在配置范围内

## 更新日志

### v1.0.0 (2026-04-19)
- 初始版本发布
- 完整的速率限制、自适应调整、WAF规避功能
- 与现有扫描器无缝集成
- 完整测试套件和使用示例

## 技术支持

如遇到问题，请检查：
1. 配置是否正确（参考`rate_limit_config_example.json`）
2. 是否安装了所有依赖
3. 测试文件是否能够正常运行

智能限速系统为WVS v18.4提供了企业级的速率控制和WAF规避能力，帮助安全测试人员在保证扫描效果的同时，最大限度地避免触发防护系统。