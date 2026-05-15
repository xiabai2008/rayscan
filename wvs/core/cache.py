"""
RayScan scan result cache system.

Provides in-memory caching with TTL expiry and LRU eviction, plus
optional persistent storage to reduce duplicate scans.

Components:
- ScanCache: In-memory cache with TTL + LRU eviction
- TargetFingerprinter: Generates target fingerprints for dedup
- CacheManager: Manages cache instances with persistence
- ScanResultSerializer: Serializes/deserializes ScanResult objects
"""

import time
import json
import hashlib
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, parse_qs, urlunparse
from collections import OrderedDict
import logging

from wvs.models import Vulnerability, ScanResult, ScanTarget

logger = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    """Cache entry"""

    result: ScanResult
    timestamp: float = field(default_factory=time.time)
    access_count: int = 0
    last_access: float = field(default_factory=time.time)
    ttl: Optional[float] = None

    def is_expired(self) -> bool:
        """Check if entry is expired"""
        if self.ttl is None:
            return False
        return (time.time() - self.timestamp) > self.ttl

    def touch(self):
        """Update access time"""
        self.last_access = time.time()
        self.access_count += 1


class ScanCache:
    """
    In-memory cache with TTL expiry and LRU eviction

    Features:
    - In-memory key-value storage
    - TTL (time-to-live) expiry support
    - LRU (least recently used) eviction support
    - Thread-safe
    - Configurable maximum size
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
        """Set a cache entry"""
        with self._lock:
            if len(self._cache) >= self.max_size and key not in self._cache:
                self._evict_one()

            entry_ttl = ttl if ttl is not None else self.default_ttl
            entry = CacheEntry(result=result, ttl=entry_ttl)

            self._cache[key] = entry
            self._lru_order[key] = None
            self._touch_lru(key)

            logger.debug(f"Cache set: {key}, TTL: {entry_ttl}")
            return True

    def get(self, key: str) -> Optional[ScanResult]:
        """Get a cache entry"""
        with self._lock:
            if key not in self._cache:
                self._misses += 1
                logger.debug(f"Cache miss: {key}")
                return None

            entry = self._cache[key]

            if entry.is_expired():
                self._remove(key)
                self._misses += 1
                logger.debug(f"Cache expired: {key}")
                return None

            entry.touch()
            self._touch_lru(key)
            self._hits += 1

            logger.debug(f"Cache hit: {key}")
            return entry.result

    def has(self, key: str) -> bool:
        """Check if key exists and is not expired"""
        with self._lock:
            if key not in self._cache:
                return False

            if self._cache[key].is_expired():
                self._remove(key)
                return False

            return True

    def delete(self, key: str) -> bool:
        """Delete a cache entry"""
        with self._lock:
            return self._remove(key)

    def clear(self):
        """Clear the cache"""
        with self._lock:
            self._cache.clear()
            self._lru_order.clear()
            self._hits = 0
            self._misses = 0
            self._evictions = 0
            logger.info("Cache cleared")

    def cleanup(self):
        """Clean up expired entries"""
        with self._lock:
            expired_keys = [k for k, e in self._cache.items() if e.is_expired()]
            for key in expired_keys:
                self._remove(key)

            if expired_keys:
                logger.debug(f"Cleaned up {len(expired_keys)} expired entries")

    def stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
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
        """Internal remove method"""
        if key in self._cache:
            del self._cache[key]
            if key in self._lru_order:
                del self._lru_order[key]
            logger.debug(f"Cache removed: {key}")
            return True
        return False

    def _evict_one(self):
        """Evict one LRU entry"""
        if not self._lru_order:
            return

        lru_key = next(iter(self._lru_order))
        self._remove(lru_key)
        self._evictions += 1
        logger.debug(f"LRU eviction: {lru_key}")

    def _touch_lru(self, key: str):
        """Mark key as recently used in LRU order"""
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
    Target fingerprint generator

    Fingerprint levels:
    - strict: Full URL including protocol, host, path, query parameters, fragment
    - normal: Ignore fragment and query parameter order (default)
    - relaxed: Ignore query parameters, keep path only
    - domain: Keep domain only
    """

    LEVELS = ["strict", "normal", "relaxed", "domain"]

    def __init__(self, level: str = "normal", include_method: bool = False):
        if level not in self.LEVELS:
            raise ValueError(f"Level must be one of: {self.LEVELS}")

        self.level = level
        self.include_method = include_method

    def fingerprint(self, target: str, method: str = "GET") -> str:
        """Generate target fingerprint"""
        normalized = self._normalize_url(target)

        if self.include_method:
            normalized = f"{method}:{normalized}"

        return hashlib.md5(normalized.encode("utf-8")).hexdigest()

    def _normalize_url(self, url: str) -> str:
        """Normalize URL based on level"""
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
                sorted_params = sorted([(k, sorted(v) if isinstance(v, list) else v) for k, v in params.items()])
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
            return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, fragment))

        return url

    def batch_fingerprint(self, targets: List[str], method: str = "GET") -> Dict[str, str]:
        """Generate fingerprints in batch"""
        return {target: self.fingerprint(target, method) for target in targets}


class ScanResultSerializer:
    """Scan result serializer"""

    @staticmethod
    def to_dict(result: ScanResult) -> Dict[str, Any]:
        """Convert ScanResult to dict"""
        return result.to_dict()

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> ScanResult:
        """Convert dict to ScanResult"""
        # Handle target
        if "target" in data and isinstance(data["target"], dict):
            data["target"] = ScanTarget(**data["target"])

        # Handle vulnerabilities
        if "vulnerabilities" in data:
            vulns = []
            for v in data["vulnerabilities"]:
                if isinstance(v, dict):
                    vulns.append(Vulnerability.from_dict(v))
                elif isinstance(v, Vulnerability):
                    vulns.append(v)
            data["vulnerabilities"] = vulns

        # Remove computed properties
        for key in ["vulnerability_count", "severity_count"]:
            data.pop(key, None)

        return ScanResult(**data)

    @staticmethod
    def to_json(result: ScanResult, indent: Optional[int] = None) -> str:
        """Convert ScanResult to JSON string"""
        result_dict = ScanResultSerializer.to_dict(result)
        return json.dumps(result_dict, indent=indent, default=str)

    @staticmethod
    def from_json(json_str: str) -> ScanResult:
        """Convert JSON string to ScanResult"""
        data = json.loads(json_str)
        return ScanResultSerializer.from_dict(data)


class CacheManager:
    """
    Cache manager

    Manages multiple cache instances with a unified interface and persistence support.
    """

    def __init__(self, persist_path: Optional[str] = None, default_max_size: int = 1000, default_ttl: Optional[float] = 3600):
        self.persist_path = persist_path
        self.default_max_size = default_max_size
        self.default_ttl = default_ttl

        self._caches: Dict[str, ScanCache] = {}
        self._fingerprinter = TargetFingerprinter(level="normal")
        self._serializer = ScanResultSerializer()
        self._lock = threading.RLock()

        if persist_path:
            self._load_from_disk()

    def get_cache(self, name: str, max_size: Optional[int] = None, ttl: Optional[float] = None) -> ScanCache:
        """Get or create a named cache"""
        with self._lock:
            if name not in self._caches:
                cache_max_size = max_size if max_size is not None else self.default_max_size
                cache_ttl = ttl if ttl is not None else self.default_ttl

                self._caches[name] = ScanCache(max_size=cache_max_size, default_ttl=cache_ttl)
                logger.info(f"Created cache: {name}, size: {cache_max_size}, TTL: {cache_ttl}")

            return self._caches[name]

    def get_scan_cache(self, name: str = "vuln_scan") -> ScanCache:
        """Get vulnerability scan cache (convenience method)"""
        return self.get_cache(name)

    def get_fingerprinter(self) -> TargetFingerprinter:
        """Get the fingerprint generator"""
        return self._fingerprinter

    def cache_scan_result(self, target: str, result: ScanResult, cache_name: str = "vuln_scan", ttl: Optional[float] = None) -> str:
        """Cache a scan result"""
        cache = self.get_cache(cache_name)
        fingerprint = self._fingerprinter.fingerprint(target)

        cache.set(fingerprint, result, ttl=ttl)
        logger.debug(f"Cached scan result: {target} -> {fingerprint}")

        return fingerprint

    def get_cached_result(self, target: str, cache_name: str = "vuln_scan") -> Optional[ScanResult]:
        """Get a cached scan result"""
        cache = self.get_cache(cache_name)
        fingerprint = self._fingerprinter.fingerprint(target)

        result = cache.get(fingerprint)
        if result:
            logger.debug(f"Cache hit: {target}")
        else:
            logger.debug(f"Cache miss: {target}")

        return result

    def has_cached_result(self, target: str, cache_name: str = "vuln_scan") -> bool:
        """Check if a cached scan result exists"""
        cache = self.get_cache(cache_name)
        fingerprint = self._fingerprinter.fingerprint(target)
        return cache.has(fingerprint)

    def clear_cache(self, cache_name: Optional[str] = None):
        """Clear the cache"""
        with self._lock:
            if cache_name is None:
                for name, cache in self._caches.items():
                    cache.clear()
                logger.info("Cleared all caches")
            elif cache_name in self._caches:
                self._caches[cache_name].clear()
                logger.info(f"Cleared cache: {cache_name}")

    def cleanup_all(self):
        """Clean up expired entries in all caches"""
        with self._lock:
            for name, cache in self._caches.items():
                cache.cleanup()
            logger.debug("Cleaned up expired entries in all caches")

    def stats_all(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics for all caches"""
        with self._lock:
            return {name: cache.stats() for name, cache in self._caches.items()}

    def save_to_disk(self, path: Optional[str] = None):
        """Save cache to disk"""
        save_path = path or self.persist_path
        if not save_path:
            logger.warning("No persist path specified, skipping save")
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
                                "ttl": entry.ttl,
                            }

                    cache_data[name] = {"max_size": cache.max_size, "default_ttl": cache.default_ttl, "entries": entries}

                with open(save_path, "w", encoding="utf-8") as f:
                    json.dump(cache_data, f, indent=2, default=str)

                logger.info(f"Cache saved to: {save_path}")

            except Exception as e:
                logger.error(f"Failed to save cache: {e}")

    def _load_from_disk(self):
        """Load cache from disk"""
        if not self.persist_path:
            return

        try:
            with open(self.persist_path, "r", encoding="utf-8") as f:
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
                                ttl=entry_data.get("ttl"),
                            )

                            cache._cache[key] = entry
                            cache._lru_order[key] = None

                        except Exception as e:
                            logger.warning(f"Failed to load cache entry {key}: {e}")

                    self._caches[name] = cache

            logger.info(f"Loaded {len(self._caches)} caches from {self.persist_path}")

        except FileNotFoundError:
            logger.info(f"Persist file does not exist: {self.persist_path}")
        except json.JSONDecodeError:
            logger.warning(f"Persist file format error: {self.persist_path}")
        except Exception as e:
            logger.error(f"Failed to load cache: {e}")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.persist_path:
            self.save_to_disk()


# Global cache manager instance
_global_cache_manager: Optional[CacheManager] = None


def get_global_cache_manager(persist_path: Optional[str] = None) -> CacheManager:
    """Get the global cache manager (singleton pattern)"""
    global _global_cache_manager

    if _global_cache_manager is None:
        _global_cache_manager = CacheManager(persist_path=persist_path)

    return _global_cache_manager


def cache_scan(target: str, result: ScanResult, ttl: Optional[float] = None) -> str:
    """Global function: cache a scan result"""
    manager = get_global_cache_manager()
    return manager.cache_scan_result(target, result, ttl=ttl)


def get_cached_scan(target: str) -> Optional[ScanResult]:
    """Global function: get a cached scan result"""
    manager = get_global_cache_manager()
    return manager.get_cached_result(target)
