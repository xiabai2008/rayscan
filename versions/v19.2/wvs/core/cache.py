"""
WVS v19 扫描结果缓存系统
=================================

提供高效的内存缓存和持久化存储，减少重复扫描，提升扫描性能。

主要组件：
1. ScanCache: 内存缓存，支持TTL过期和LRU淘汰
2. TargetFingerprinter: 生成目标指纹用于去重
3. CacheManager: 管理多个缓存实例，支持持久化
4. ScanResultSerializer: 序列化/反序列化扫描结果

设计原则：
- 线程安全（支持并发访问）
- 可配置的缓存策略（TTL、LRU、大小限制）
- 无缝集成现有扫描器
- 可选持久化（文件/JSON）
"""

import time
import json
import hashlib
import threading
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, parse_qs, urlunparse
from collections import OrderedDict
import logging

from wvs.models import Vulnerability, ScanResult, ScanTarget

logger = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    """缓存条目"""
    result: ScanResult
    timestamp: float = field(default_factory=time.time)
    access_count: int = 0
    last_access: float = field(default_factory=time.time)
    ttl: Optional[float] = None

    def is_expired(self) -> bool:
        """检查是否过期"""
        if self.ttl is None:
            return False
        return (time.time() - self.timestamp) > self.ttl

    def touch(self):
        """更新访问时间"""
        self.last_access = time.time()
        self.access_count += 1


class ScanCache:
    """
    内存缓存，支持TTL过期和LRU淘汰

    特性：
    - 基于内存的键值存储
    - 支持TTL（生存时间）过期
    - 支持LRU（最近最少使用）淘汰
    - 线程安全
    - 可配置的最大大小
    """

    def __init__(self, max_size: int = 1000, default_ttl: Optional[float] = 3600):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._cache: Dict[str, CacheEntry] = {}
        self._lru_order = OrderedDict()
        self._lock = threading.RLock()
        self._hits = 0
        self._misses = 0
        self._evictions = 0

    def set(self, key: str, result: ScanResult, ttl: Optional[float] = None) -> bool:
        """设置缓存条目"""
        with self._lock:
            if len(self._cache) >= self.max_size and key not in self._cache:
                self._evict_one()

            entry_ttl = ttl if ttl is not None else self.default_ttl
            entry = CacheEntry(result=result, ttl=entry_ttl)

            self._cache[key] = entry
            self._lru_order[key] = None
            self._touch_lru(key)

            logger.debug(f"缓存设置: {key}, TTL: {entry_ttl}")
            return True

    def get(self, key: str) -> Optional[ScanResult]:
        """获取缓存条目"""
        with self._lock:
            if key not in self._cache:
                self._misses += 1
                logger.debug(f"缓存未命中: {key}")
                return None

            entry = self._cache[key]

            if entry.is_expired():
                self._remove(key)
                self._misses += 1
                logger.debug(f"缓存过期: {key}")
                return None

            entry.touch()
            self._touch_lru(key)
            self._hits += 1

            logger.debug(f"缓存命中: {key}")
            return entry.result

    def has(self, key: str) -> bool:
        """检查键是否存在且未过期"""
        with self._lock:
            if key not in self._cache:
                return False

            if self._cache[key].is_expired():
                self._remove(key)
                return False

            return True

    def delete(self, key: str) -> bool:
        """删除缓存条目"""
        with self._lock:
            return self._remove(key)

    def clear(self):
        """清空缓存"""
        with self._lock:
            self._cache.clear()
            self._lru_order.clear()
            self._hits = 0
            self._misses = 0
            self._evictions = 0
            logger.info("缓存已清空")

    def cleanup(self):
        """清理过期条目"""
        with self._lock:
            expired_keys = [k for k, e in self._cache.items() if e.is_expired()]
            for key in expired_keys:
                self._remove(key)

            if expired_keys:
                logger.debug(f"清理了 {len(expired_keys)} 个过期条目")

    def stats(self) -> Dict[str, Any]:
        """获取缓存统计信息"""
        with self._lock:
            hits = self._hits
            misses = self._misses
            hit_rate = hits / (hits + misses) if (hits + misses) > 0 else 0

            return {
                "size": len(self._cache),
                "max_size": self.max_size,
                "hits": hits,
                "misses": misses,
                "hit_rate": hit_rate,
                "evictions": self._evictions,
            }

    def _remove(self, key: str) -> bool:
        """内部移除方法"""
        if key in self._cache:
            del self._cache[key]
            if key in self._lru_order:
                del self._lru_order[key]
            logger.debug(f"缓存移除: {key}")
            return True
        return False

    def _evict_one(self):
        """淘汰一个LRU条目"""
        if not self._lru_order:
            return

        lru_key = next(iter(self._lru_order))
        self._remove(lru_key)
        self._evictions += 1
        logger.debug(f"LRU淘汰: {lru_key}")

    def _touch_lru(self, key: str):
        """在LRU顺序中标记为最近使用"""
        if key in self._lru_order:
            self._lru_order.move_to_end(key)
        else:
            self._lru_order[key] = None

    def __len__(self) -> int:
        return len(self._cache)

    def __contains__(self, key: str) -> bool:
        return self.has(key)


class TargetFingerprinter:
    """
    目标指纹生成器

    指纹级别：
    - strict: 完整URL，包括协议、主机、路径、查询参数、片段
    - normal: 忽略片段和查询参数顺序（默认）
    - relaxed: 忽略查询参数，只保留路径
    - domain: 只保留域名
    """

    LEVELS = ["strict", "normal", "relaxed", "domain"]

    def __init__(self, level: str = "normal", include_method: bool = False):
        if level not in self.LEVELS:
            raise ValueError(f"级别必须是以下之一: {self.LEVELS}")

        self.level = level
        self.include_method = include_method

    def fingerprint(self, target: str, method: str = "GET") -> str:
        """生成目标指纹"""
        normalized = self._normalize_url(target)

        if self.include_method:
            normalized = f"{method}:{normalized}"

        return hashlib.md5(normalized.encode('utf-8')).hexdigest()

    def _normalize_url(self, url: str) -> str:
        """根据级别规范化URL"""
        try:
            parsed = urlparse(url)
        except Exception:
            return url

        if self.level == "domain":
            return urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))

        elif self.level == "relaxed":
            return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))

        elif self.level == "normal":
            query = parsed.query
            if query:
                params = parse_qs(query, keep_blank_values=True)
                sorted_params = sorted([(k, sorted(v) if isinstance(v, list) else v)
                                      for k, v in params.items()])
                query_parts = []
                for key, values in sorted_params:
                    if isinstance(values, list):
                        for val in values:
                            query_parts.append(f"{key}={val}" if val is not None else key)
                    else:
                        query_parts.append(f"{key}={values}" if values is not None else key)
                query = "&".join(query_parts)

            return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, ""))

        elif self.level == "strict":
            fragment = parsed.fragment if parsed.fragment else ""
            return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                             parsed.params, parsed.query, fragment))

        return url

    def batch_fingerprint(self, targets: List[str], method: str = "GET") -> Dict[str, str]:
        """批量生成指纹"""
        return {target: self.fingerprint(target, method) for target in targets}


class ScanResultSerializer:
    """扫描结果序列化器"""

    @staticmethod
    def to_dict(result: ScanResult) -> Dict[str, Any]:
        """ScanResult转换为字典"""
        return result.to_dict()

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> ScanResult:
        """字典转换为ScanResult"""
        # 处理target
        if 'target' in data and isinstance(data['target'], dict):
            data['target'] = ScanTarget(**data['target'])

        # 处理vulnerabilities
        if 'vulnerabilities' in data:
            vulns = []
            for v in data['vulnerabilities']:
                if isinstance(v, dict):
                    vulns.append(Vulnerability.from_dict(v))
                elif isinstance(v, Vulnerability):
                    vulns.append(v)
            data['vulnerabilities'] = vulns

        # 移除计算属性
        for key in ['vulnerability_count', 'severity_count']:
            data.pop(key, None)

        return ScanResult(**data)

    @staticmethod
    def to_json(result: ScanResult, indent: Optional[int] = None) -> str:
        """ScanResult转换为JSON字符串"""
        result_dict = ScanResultSerializer.to_dict(result)
        return json.dumps(result_dict, indent=indent, default=str)

    @staticmethod
    def from_json(json_str: str) -> ScanResult:
        """JSON字符串转换为ScanResult"""
        data = json.loads(json_str)
        return ScanResultSerializer.from_dict(data)


class CacheManager:
    """
    缓存管理器

    管理多个缓存实例，提供统一的接口和持久化功能。
    """

    def __init__(self, persist_path: Optional[str] = None,
                 default_max_size: int = 1000, default_ttl: Optional[float] = 3600):
        self.persist_path = persist_path
        self.default_max_size = default_max_size
        self.default_ttl = default_ttl

        self._caches: Dict[str, ScanCache] = {}
        self._fingerprinter = TargetFingerprinter(level="normal")
        self._serializer = ScanResultSerializer()
        self._lock = threading.RLock()

        if persist_path:
            self._load_from_disk()

    def get_cache(self, name: str, max_size: Optional[int] = None,
                  ttl: Optional[float] = None) -> ScanCache:
        """获取或创建命名缓存"""
        with self._lock:
            if name not in self._caches:
                cache_max_size = max_size if max_size is not None else self.default_max_size
                cache_ttl = ttl if ttl is not None else self.default_ttl

                self._caches[name] = ScanCache(max_size=cache_max_size, default_ttl=cache_ttl)
                logger.info(f"创建缓存: {name}, 大小: {cache_max_size}, TTL: {cache_ttl}")

            return self._caches[name]

    def get_scan_cache(self, name: str = "vuln_scan") -> ScanCache:
        """获取漏洞扫描缓存（快捷方法）"""
        return self.get_cache(name)

    def get_fingerprinter(self) -> TargetFingerprinter:
        """获取指纹生成器"""
        return self._fingerprinter

    def cache_scan_result(self, target: str, result: ScanResult,
                          cache_name: str = "vuln_scan", ttl: Optional[float] = None) -> str:
        """缓存扫描结果"""
        cache = self.get_cache(cache_name)
        fingerprint = self._fingerprinter.fingerprint(target)

        cache.set(fingerprint, result, ttl=ttl)
        logger.debug(f"已缓存扫描结果: {target} -> {fingerprint}")

        return fingerprint

    def get_cached_result(self, target: str, cache_name: str = "vuln_scan") -> Optional[ScanResult]:
        """获取缓存的扫描结果"""
        cache = self.get_cache(cache_name)
        fingerprint = self._fingerprinter.fingerprint(target)

        result = cache.get(fingerprint)
        if result:
            logger.debug(f"缓存命中: {target}")
        else:
            logger.debug(f"缓存未命中: {target}")

        return result

    def has_cached_result(self, target: str, cache_name: str = "vuln_scan") -> bool:
        """检查是否有缓存的扫描结果"""
        cache = self.get_cache(cache_name)
        fingerprint = self._fingerprinter.fingerprint(target)
        return cache.has(fingerprint)

    def clear_cache(self, cache_name: Optional[str] = None):
        """清空缓存"""
        with self._lock:
            if cache_name is None:
                for name, cache in self._caches.items():
                    cache.clear()
                logger.info("已清空所有缓存")
            elif cache_name in self._caches:
                self._caches[cache_name].clear()
                logger.info(f"已清空缓存: {cache_name}")

    def cleanup_all(self):
        """清理所有缓存中的过期条目"""
        with self._lock:
            for name, cache in self._caches.items():
                cache.cleanup()
            logger.debug("已清理所有缓存过期条目")

    def stats_all(self) -> Dict[str, Dict[str, Any]]:
        """获取所有缓存的统计信息"""
        with self._lock:
            return {name: cache.stats() for name, cache in self._caches.items()}

    def save_to_disk(self, path: Optional[str] = None):
        """保存缓存到磁盘"""
        save_path = path or self.persist_path
        if not save_path:
            logger.warning("未指定持久化路径，跳过保存")
            return

        with self._lock:
            try:
                cache_data = {}
                for name, cache in self._caches.items():
                    entries = {}
                    for key, entry in cache._cache.items():
                        if not entry.is_expired():
                            result_dict = self._serializer.to_dict(entry.result)
                            entries[key] = {
                                "result": result_dict,
                                "timestamp": entry.timestamp,
                                "access_count": entry.access_count,
                                "last_access": entry.last_access,
                                "ttl": entry.ttl
                            }

                    cache_data[name] = {
                        "max_size": cache.max_size,
                        "default_ttl": cache.default_ttl,
                        "entries": entries
                    }

                with open(save_path, 'w', encoding='utf-8') as f:
                    json.dump(cache_data, f, indent=2, default=str)

                logger.info(f"缓存已保存到: {save_path}")

            except Exception as e:
                logger.error(f"保存缓存失败: {e}")

    def _load_from_disk(self):
        """从磁盘加载缓存"""
        if not self.persist_path:
            return

        try:
            with open(self.persist_path, 'r', encoding='utf-8') as f:
                cache_data = json.load(f)

            with self._lock:
                for name, data in cache_data.items():
                    max_size = data.get("max_size", self.default_max_size)
                    default_ttl = data.get("default_ttl", self.default_ttl)

                    cache = ScanCache(max_size=max_size, default_ttl=default_ttl)

                    for key, entry_data in data.get("entries", {}).items():
                        try:
                            result = self._serializer.from_dict(entry_data["result"])

                            entry = CacheEntry(
                                result=result,
                                timestamp=entry_data["timestamp"],
                                access_count=entry_data.get("access_count", 0),
                                last_access=entry_data.get("last_access", entry_data["timestamp"]),
                                ttl=entry_data.get("ttl")
                            )

                            cache._cache[key] = entry
                            cache._lru_order[key] = None

                        except Exception as e:
                            logger.warning(f"加载缓存条目失败 {key}: {e}")

                    self._caches[name] = cache

            logger.info(f"从 {self.persist_path} 加载了 {len(self._caches)} 个缓存")

        except FileNotFoundError:
            logger.info(f"持久化文件不存在: {self.persist_path}")
        except json.JSONDecodeError:
            logger.warning(f"持久化文件格式错误: {self.persist_path}")
        except Exception as e:
            logger.error(f"加载缓存失败: {e}")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.persist_path:
            self.save_to_disk()


# 全局缓存管理器实例
_global_cache_manager: Optional[CacheManager] = None


def get_global_cache_manager(persist_path: Optional[str] = None) -> CacheManager:
    """获取全局缓存管理器（单例模式）"""
    global _global_cache_manager

    if _global_cache_manager is None:
        _global_cache_manager = CacheManager(persist_path=persist_path)

    return _global_cache_manager


def cache_scan(target: str, result: ScanResult, ttl: Optional[float] = None) -> str:
    """全局函数：缓存扫描结果"""
    manager = get_global_cache_manager()
    return manager.cache_scan_result(target, result, ttl=ttl)


def get_cached_scan(target: str) -> Optional[ScanResult]:
    """全局函数：获取缓存的扫描结果"""
    manager = get_global_cache_manager()
    return manager.get_cached_result(target)
