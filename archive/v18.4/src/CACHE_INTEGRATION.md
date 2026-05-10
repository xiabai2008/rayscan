# WVS v18.4 扫描结果缓存系统集成指南

## 概述

扫描结果缓存系统旨在减少重复扫描，提升WVS v18.4漏洞扫描工具的性能。系统提供内存缓存、目标指纹生成、缓存管理和持久化存储功能。

## 核心组件

### 1. ScanCache 类
- **功能**: 内存缓存，支持TTL过期和LRU淘汰
- **特性**:
  - 线程安全，支持并发访问
  - 可配置的最大大小和默认TTL
  - 自动清理过期条目
  - 详细的统计信息
- **使用示例**:
  ```python
  cache = ScanCache(max_size=1000, default_ttl=3600)
  cache.set("target_fingerprint", scan_result, ttl=1800)
  result = cache.get("target_fingerprint")
  ```

### 2. TargetFingerprinter 类
- **功能**: 生成目标唯一指纹，用于缓存键
- **指纹级别**:
  - `strict`: 完整URL（包括协议、主机、路径、查询参数、片段）
  - `normal`: 忽略片段，规范化查询参数顺序（默认）
  - `relaxed`: 忽略查询参数和片段
  - `domain`: 只保留域名
- **使用示例**:
  ```python
  fingerprinter = TargetFingerprinter(level="normal")
  fingerprint = fingerprinter.fingerprint("http://example.com/path?q=test#section")
  ```

### 3. CacheManager 类
- **功能**: 管理多个缓存实例，提供统一接口
- **特性**:
  - 支持多个命名缓存
  - 自动持久化到JSON文件
  - 上下文管理器支持
  - 全局单例模式
- **使用示例**:
  ```python
  manager = CacheManager(persist_path="./cache.json")
  cache = manager.get_cache("vuln_scan", max_size=500, ttl=1800)
  manager.cache_scan_result(target_url, scan_result)
  ```

### 4. ScanResultSerializer 类
- **功能**: 序列化/反序列化 ScanResult 对象
- **支持格式**: Python字典、JSON字符串
- **使用示例**:
  ```python
  serializer = ScanResultSerializer()
  json_str = serializer.to_json(scan_result, indent=2)
  restored = serializer.from_json(json_str)
  ```

## 与并发扫描器集成

### 启用缓存
在 `ConcurrentScanner` 配置中添加以下参数：

```python
config = {
    'max_workers': 3,
    'timeout_per_target': 120,
    'enable_validation': True,
    'enable_cache': True,           # 启用缓存（默认True）
    'cache_ttl': 3600,              # 缓存生存时间（秒，默认1小时）
    'cache_persist_path': './scan_cache.json'  # 持久化文件路径
}

scanner = ConcurrentScanner(config)
```

### 工作原理
1. **扫描前检查**: 每个目标扫描前，生成指纹并检查缓存
2. **缓存命中**: 如果找到未过期的缓存结果，直接返回，跳过扫描
3. **缓存未命中**: 执行扫描，完成后将结果存入缓存
4. **自动保存**: 扫描结束后自动保存缓存到文件（如果启用了持久化）

### 性能优势
- **减少重复扫描**: 同一目标短时间内不会被重复扫描
- **提升响应速度**: 缓存命中时扫描时间几乎为零
- **降低负载**: 减少对目标系统的请求压力

## 高级用法

### 自定义指纹策略
```python
# 创建自定义指纹生成器
fingerprinter = TargetFingerprinter(
    level="strict",      # 指纹级别
    include_method=True  # 包含HTTP方法
)

# 生成包含方法的指纹
fingerprint = fingerprinter.fingerprint(url, method="POST")
```

### 多级缓存策略
```python
# 创建不同级别的缓存
manager = CacheManager()

# 快速缓存：小容量，短TTL，用于临时存储
fast_cache = manager.get_cache("fast", max_size=100, ttl=60)

# 持久缓存：大容量，长TTL，用于长期存储
persistent_cache = manager.get_cache("persistent", max_size=5000, ttl=86400)
```

### 缓存统计与监控
```python
# 获取缓存统计
stats = cache.stats()
print(f"命中率: {stats['hit_rate']:.2%}")
print(f"缓存大小: {stats['size']}/{stats['max_size']}")

# 获取所有缓存统计
all_stats = manager.stats_all()
for name, stat in all_stats.items():
    print(f"{name}: {stat['size']}条目, 命中率{stat['hit_rate']:.2%}")
```

### 持久化与恢复
```python
# 创建带持久化的管理器
manager = CacheManager(persist_path="./scan_cache.json")

# 手动保存
manager.save_to_disk()

# 自动保存（使用上下文管理器）
with CacheManager(persist_path="./temp_cache.json") as mgr:
    # 执行扫描操作
    mgr.cache_scan_result(target, result)
    # 退出上下文时自动保存
```

## 集成到现有扫描器

### 与 FullScanner 集成
```python
class CachedFullScanner(FullScanner):
    def __init__(self, config=None):
        super().__init__(config)
        self.cache_manager = get_global_cache_manager()
        self.cache_ttl = config.get('cache_ttl', 3600) if config else 3600

    async def scan(self, url: str, modules: List[str] = None) -> ScanResult:
        # 检查缓存
        cached = self.cache_manager.get_cached_result(url)
        if cached:
            print(f"[缓存命中] {url}")
            return cached

        # 执行扫描
        result = await super().scan(url, modules)

        # 缓存结果
        self.cache_manager.cache_scan_result(url, result, ttl=self.cache_ttl)
        
        return result
```

### 与 nuclei_manager 集成
```python
# 在 nuclei_manager.py 中添加缓存支持
class CachedNucleiManager(NucleiManager):
    def __init__(self, config=None):
        super().__init__(config)
        self.enable_cache = config.get('enable_cache', True) if config else True
        self.cache_manager = None
        
        if self.enable_cache:
            try:
                from cache_system import get_global_cache_manager
                self.cache_manager = get_global_cache_manager()
            except ImportError:
                self.enable_cache = False

    async def scan_target(self, target: str, templates: List[str] = None):
        if self.enable_cache and self.cache_manager:
            cached = self.cache_manager.get_cached_result(target)
            if cached:
                return cached

        result = await super().scan_target(target, templates)
        
        if self.enable_cache and self.cache_manager:
            self.cache_manager.cache_scan_result(target, result)
            
        return result
```

## 配置选项

### ScanCache 配置
| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `max_size` | int | 1000 | 最大缓存条目数 |
| `default_ttl` | float | 3600 | 默认生存时间（秒） |

### TargetFingerprinter 配置
| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `level` | str | "normal" | 指纹级别：strict/normal/relaxed/domain |
| `include_method` | bool | False | 是否包含HTTP方法 |

### CacheManager 配置
| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `persist_path` | str | None | 持久化文件路径 |
| `default_max_size` | int | 1000 | 默认缓存最大大小 |
| `default_ttl` | float | 3600 | 默认TTL（秒） |

### ConcurrentScanner 缓存配置
| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enable_cache` | bool | True | 是否启用缓存 |
| `cache_ttl` | float | 3600 | 缓存生存时间（秒） |
| `cache_persist_path` | str | "./scan_cache.json" | 持久化文件路径 |

## 性能调优建议

### 1. 缓存大小调优
- **小型项目**: `max_size=100-500`
- **中型项目**: `max_size=500-2000`
- **大型项目**: `max_size=2000-10000`

### 2. TTL设置策略
- **频繁变化的目标**: TTL=300-1800秒（5-30分钟）
- **稳定目标**: TTL=3600-86400秒（1-24小时）
- **关键资产**: TTL=604800秒（7天）

### 3. 指纹级别选择
- **精确匹配**: 使用 `strict` 级别
- **平衡性能**: 使用 `normal` 级别（推荐）
- **最大化去重**: 使用 `relaxed` 或 `domain` 级别

### 4. 内存优化
```python
# 限制单个缓存条目大小
class OptimizedScanCache(ScanCache):
    def set(self, key: str, result: ScanResult, ttl: Optional[float] = None) -> bool:
        # 估算结果大小
        estimated_size = self._estimate_size(result)
        if estimated_size > MAX_ENTRY_SIZE:
            return False  # 跳过过大的条目
        return super().set(key, result, ttl)
```

## 故障排除

### 常见问题

1. **缓存未生效**
   - 检查 `enable_cache` 配置是否为 True
   - 确认 `cache_system.py` 可正常导入
   - 查看控制台是否有缓存相关的错误信息

2. **内存使用过高**
   - 减少 `max_size` 参数
   - 缩短 `default_ttl` 值
   - 定期调用 `cache.cleanup()`

3. **持久化失败**
   - 检查文件路径是否有写入权限
   - 确认磁盘空间充足
   - 查看是否有文件锁冲突

4. **指纹冲突**
   - 调整 `TargetFingerprinter` 级别
   - 考虑添加额外维度（如扫描时间、扫描深度）

### 调试模式
```python
import logging

# 启用缓存系统调试日志
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('cache_system')
```

## 最佳实践

1. **渐进式启用**: 先在测试环境中启用缓存，验证无问题后再应用到生产
2. **监控统计**: 定期检查缓存命中率，调整缓存策略
3. **定期清理**: 设置定时任务清理过期缓存
4. **备份重要缓存**: 对重要扫描结果进行定期备份
5. **版本管理**: 当扫描逻辑变化时，清除或迁移旧缓存

## 扩展开发

### 添加新的缓存后端
```python
class RedisScanCache(ScanCache):
    """基于Redis的缓存实现"""
    def __init__(self, redis_client, max_size=1000, default_ttl=3600):
        super().__init__(max_size, default_ttl)
        self.redis = redis_client
        
    def set(self, key: str, result: ScanResult, ttl: Optional[float] = None) -> bool:
        # 序列化结果
        serialized = ScanResultSerializer().to_json(result)
        # 存储到Redis
        self.redis.setex(key, ttl or self.default_ttl, serialized)
        return True
```

### 自定义指纹算法
```python
class CustomFingerprinter(TargetFingerprinter):
    """自定义指纹算法，包含扫描深度"""
    def fingerprint(self, target: str, method: str = "GET", depth: int = 0) -> str:
        base_fingerprint = super().fingerprint(target, method)
        return f"{base_fingerprint}:{depth}"
```

## 总结

缓存系统通过减少重复扫描显著提升WVS v18.4的性能。建议根据实际使用场景调整缓存参数，平衡内存使用和性能提升效果。

集成缓存后，预期性能提升：
- 重复目标扫描时间减少 90%+
- 总体扫描时间减少 30-60%（取决于目标重复率）
- 目标系统负载降低 50%+

如需进一步定制或问题反馈，请参考示例代码和API文档。