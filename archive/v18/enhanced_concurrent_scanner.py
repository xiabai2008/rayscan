#!/usr/bin/env python3
"""
增强版并发扫描器 - 集成智能缓存系统
"""
import asyncio
import time
import json
import sys
import os
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# 导入增强缓存系统
try:
    from enhanced_cache_system import EnhancedCacheManager, AdaptiveTTLManager, CachePredictor
    ENHANCED_CACHE_AVAILABLE = True
except ImportError:
    ENHANCED_CACHE_AVAILABLE = False
    print("警告: 增强缓存系统不可用，将使用基础功能")

# 导入现有扫描器
from wvs.vuln.scanner_v18 import VulnerabilityScanner, ScanResult

@dataclass
class EnhancedScanConfig:
    """增强扫描配置"""
    # 并发配置
    max_workers: int = 3
    timeout_per_target: int = 120
    enable_validation: bool = True
    
    # 缓存配置
    enable_cache: bool = True
    cache_mode: str = "enhanced"  # "none", "basic", "enhanced"
    
    # 增强缓存特性配置
    enable_adaptive_ttl: bool = True
    enable_cache_prediction: bool = True
    enable_redis_support: bool = False
    redis_url: Optional[str] = None
    
    # 性能监控
    enable_performance_monitoring: bool = True
    monitor_interval_seconds: float = 5.0
    
    # 错误处理
    max_retries: int = 2
    retry_delay_seconds: float = 1.0
    circuit_breaker_enabled: bool = True
    
    def to_dict(self) -> Dict:
        return {
            "max_workers": self.max_workers,
            "timeout_per_target": self.timeout_per_target,
            "enable_validation": self.enable_validation,
            "enable_cache": self.enable_cache,
            "cache_mode": self.cache_mode,
            "enhanced_features": {
                "adaptive_ttl": self.enable_adaptive_ttl,
                "cache_prediction": self.enable_cache_prediction,
                "redis_support": self.enable_redis_support,
                "redis_url": self.redis_url
            },
            "performance_monitoring": self.enable_performance_monitoring,
            "error_handling": {
                "max_retries": self.max_retries,
                "retry_delay": self.retry_delay_seconds,
                "circuit_breaker": self.circuit_breaker_enabled
            }
        }


class EnhancedConcurrentScanner:
    """增强版并发扫描器"""
    
    def __init__(self, config: EnhancedScanConfig = None):
        self.config = config or EnhancedScanConfig()
        
        # 初始化缓存系统
        self.cache_manager = None
        self.cache_predictor = None
        self.adaptive_ttl_manager = None
        
        self._init_cache_system()
        
        # 性能监控
        self.metrics = {
            "total_targets": 0,
            "completed_targets": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "cache_hit_rate": 0.0,
            "total_duration": 0.0,
            "retry_count": 0,
            "circuit_breaker_trips": 0,
            "adaptive_ttl_adjustments": 0
        }
        
        # 扫描器实例池
        self.scanner_pool = {}
        
        # 异步组件
        self.task_queue = None
        self.workers = []
        self.results = []
        
        print(f"增强版并发扫描器初始化完成")
        print(f"配置: {self.config.to_dict()}")
    
    def _init_cache_system(self):
        """初始化缓存系统"""
        if not self.config.enable_cache:
            print("缓存功能已禁用")
            return
        
        if self.config.cache_mode == "enhanced" and ENHANCED_CACHE_AVAILABLE:
            try:
                # 初始化增强缓存管理器
                self.cache_manager = EnhancedCacheManager(
                    enable_adaptive_ttl=self.config.enable_adaptive_ttl,
                    enable_cache_prediction=self.config.enable_cache_prediction,
                    enable_redis_support=self.config.enable_redis_support,
                    redis_url=self.config.redis_url
                )
                
                if self.config.enable_cache_prediction:
                    self.cache_predictor = CachePredictor()
                
                if self.config.enable_adaptive_ttl:
                    self.adaptive_ttl_manager = AdaptiveTTLManager()
                
                print(f"增强缓存系统已启用")
                print(f"  自适应TTL: {'是' if self.config.enable_adaptive_ttl else '否'}")
                print(f"  缓存预测: {'是' if self.config.enable_cache_prediction else '否'}")
                print(f"  Redis支持: {'是' if self.config.enable_redis_support else '否'}")
                
            except Exception as e:
                print(f"增强缓存初始化失败: {e}, 回退到基础缓存")
                self._init_basic_cache()
        else:
            self._init_basic_cache()
    
    def _init_basic_cache(self):
        """初始化基础缓存"""
        try:
            from cache_system import get_global_cache_manager
            self.cache_manager = get_global_cache_manager()
            print("基础缓存系统已启用")
        except ImportError:
            print("基础缓存不可用，缓存功能将禁用")
            self.config.enable_cache = False
    
    def get_scanner_for_target(self, target: str) -> VulnerabilityScanner:
        """获取或创建扫描器实例"""
        if target in self.scanner_pool:
            return self.scanner_pool[target]
        
        scanner_config = {
            'timeout': 30,
            'delay': 0.1,
            'max_urls': 100,
            'max_depth': 3,
        }
        
        # 如果启用验证增强，加载优化配置
        if self.config.enable_validation:
            try:
                config_path = os.path.join(os.path.dirname(__file__), 'validation_optimized_config.json')
                if os.path.exists(config_path):
                    with open(config_path, 'r') as f:
                        validation_config = json.load(f)
                    scanner_config['validation'] = validation_config
            except Exception:
                pass
        
        scanner = VulnerabilityScanner(scanner_config)
        self.scanner_pool[target] = scanner
        return scanner
    
    async def scan_with_cache(self, target: str, worker_id: int = 0):
        """带缓存的扫描流程"""
        start_time = time.time()
        
        # 1. 检查缓存
        cached_result = None
        if self.config.enable_cache and self.cache_manager:
            cached_result = self.cache_manager.get_cached_result(target)
            if cached_result:
                self.metrics["cache_hits"] += 1
                print(f"[Worker {worker_id}] 缓存命中: {target}")
                return {
                    "target": target,
                    "result": cached_result,
                    "cached": True,
                    "duration": time.time() - start_time,
                    "worker_id": worker_id
                }
        
        self.metrics["cache_misses"] += 1
        
        # 2. 执行实际扫描
        scanner = self.get_scanner_for_target(target)
        
        try:
            print(f"[Worker {worker_id}] 开始扫描: {target}")
            
            # 这里应该调用实际的扫描逻辑
            # 暂时模拟扫描
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(target, timeout=10) as response:
                    await response.read()
            
            # 创建模拟结果
            result = ScanResult(
                urls=[],
                forms=[],
                vulnerabilities=[],
                js_files=[],
                sensitive_paths=[],
                duration=time.time() - start_time,
                total_requests=1
            )
            
            # 3. 缓存结果
            if self.config.enable_cache and self.cache_manager:
                # 计算自适应TTL
                ttl = None
                if self.adaptive_ttl_manager:
                    ttl = self.adaptive_ttl_manager.calculate_ttl(target)
                    self.metrics["adaptive_ttl_adjustments"] += 1
                
                # 缓存结果
                self.cache_manager.cache_scan_result(target, result, ttl=ttl)
                print(f"[Worker {worker_id}] 已缓存结果: {target}")
            
            return {
                "target": target,
                "result": result,
                "cached": False,
                "duration": time.time() - start_time,
                "worker_id": worker_id
            }
            
        except Exception as e:
            print(f"[Worker {worker_id}] 扫描失败: {target}, 错误: {e}")
            return {
                "target": target,
                "error": str(e),
                "success": False,
                "duration": time.time() - start_time,
                "worker_id": worker_id
            }
    
    async def worker(self, worker_id: int):
        """增强版工作线程"""
        print(f"[Worker {worker_id}] 启动")
        
        while True:
            try:
                target = await self.task_queue.get()
                
                if target is None:  # 停止信号
                    print(f"[Worker {worker_id}] 收到停止信号")
                    self.task_queue.task_done()
                    break
                
                # 执行扫描
                result = await self.scan_with_cache(target, worker_id)
                self.results.append(result)
                
                # 更新性能指标
                self.metrics["completed_targets"] += 1
                if self.metrics["cache_hits"] + self.metrics["cache_misses"] > 0:
                    self.metrics["cache_hit_rate"] = (
                        self.metrics["cache_hits"] / 
                        (self.metrics["cache_hits"] + self.metrics["cache_misses"])
                    )
                
                self.task_queue.task_done()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[Worker {worker_id}] 异常: {e}")
                self.task_queue.task_done()
        
        print(f"[Worker {worker_id}] 退出")
    
    async def scan_many(self, targets: List[str]) -> List[Dict]:
        """并发扫描多个目标"""
        print(f"开始增强版并发扫描")
        print(f"目标数量: {len(targets)}")
        print(f"工作线程: {self.config.max_workers}")
        
        self.metrics["total_targets"] = len(targets)
        start_time = time.time()
        
        # 初始化队列
        self.task_queue = asyncio.Queue()
        self.results = []
        
        # 添加任务到队列
        for target in targets:
            await self.task_queue.put(target)
        
        # 添加停止信号
        for _ in range(self.config.max_workers):
            await self.task_queue.put(None)
        
        # 启动工作线程
        self.workers = []
        for i in range(self.config.max_workers):
            worker_task = asyncio.create_task(self.worker(i))
            self.workers.append(worker_task)
        
        # 启动性能监控（如果启用）
        monitor_task = None
        if self.config.enable_performance_monitoring:
            monitor_task = asyncio.create_task(self._performance_monitor())
        
        # 等待所有任务完成
        await self.task_queue.join()
        
        # 取消工作线程
        for worker in self.workers:
            worker.cancel()
        
        # 等待所有worker完成
        if self.workers:
            await asyncio.gather(*self.workers, return_exceptions=True)
        
        # 停止性能监控
        if monitor_task:
            monitor_task.cancel()
            try:
                await monitor_task
            except asyncio.CancelledError:
                pass
        
        # 计算最终指标
        self.metrics["total_duration"] = time.time() - start_time
        
        print(f"扫描完成!")
        print(f"总耗时: {self.metrics['total_duration']:.2f}秒")
        print(f"缓存命中率: {self.metrics['cache_hit_rate']:.1%}")
        
        return self.results
    
    async def _performance_monitor(self):
        """性能监控任务"""
        while True:
            try:
                self._display_performance_stats()
                await asyncio.sleep(self.config.monitor_interval_seconds)
            except asyncio.CancelledError:
                break
            except Exception:
                break
    
    def _display_performance_stats(self):
        """显示性能统计"""
        completed = self.metrics["completed_targets"]
        total = self.metrics["total_targets"]
        hit_rate = self.metrics["cache_hit_rate"]
        
        progress = completed / total * 100 if total > 0 else 0
        
        print(f"\r[性能监控] 进度: {progress:.1f}% ({completed}/{total}) | "
              f"缓存命中率: {hit_rate:.1%} | "
              f"TTL调整: {self.metrics['adaptive_ttl_adjustments']}", end="")
    
    def get_performance_report(self) -> Dict:
        """获取性能报告"""
        report = {
            "scan_summary": {
                "total_targets": self.metrics["total_targets"],
                "completed_targets": self.metrics["completed_targets"],
                "success_rate": len([r for r in self.results if 'error' not in r]) / len(self.results) if self.results else 0,
                "total_duration": self.metrics["total_duration"],
                "throughput_targets_per_second": self.metrics["completed_targets"] / self.metrics["total_duration"] if self.metrics["total_duration"] > 0 else 0
            },
            "cache_performance": {
                "hits": self.metrics["cache_hits"],
                "misses": self.metrics["cache_misses"],
                "hit_rate": self.metrics["cache_hit_rate"],
                "adaptive_ttl_adjustments": self.metrics["adaptive_ttl_adjustments"]
            },
            "configuration": self.config.to_dict(),
            "enhanced_features": {
                "adaptive_ttl_enabled": self.config.enable_adaptive_ttl and self.adaptive_ttl_manager is not None,
                "cache_prediction_enabled": self.config.enable_cache_prediction and self.cache_predictor is not None,
                "redis_support_enabled": self.config.enable_redis_support
            }
        }
        
        return report


async def demo_enhanced_scanner():
    """演示增强版扫描器"""
    print("=" * 60)
    print("增强版并发扫描器演示")
    print("=" * 60)
    
    # 测试目标
    targets = [
        "http://192.168.18.131/dvwa/",
        "http://192.168.18.131/mutillidae/",
        "http://192.168.18.131/tikiwiki/",
        "http://192.168.18.131/phpmyadmin/",
        "http://192.168.18.131/dvwa/vulnerabilities/sqli/",
        "http://192.168.18.131/dvwa/vulnerabilities/xss_r/"
    ]
    
    # 创建增强配置
    config = EnhancedScanConfig(
        max_workers=3,
        enable_cache=True,
        cache_mode="enhanced",
        enable_adaptive_ttl=True,
        enable_cache_prediction=True,
        enable_performance_monitoring=True,
        monitor_interval_seconds=2.0
    )
    
    # 创建扫描器
    scanner = EnhancedConcurrentScanner(config)
    
    # 运行扫描
    print(f"\\n开始扫描 {len(targets)} 个目标...")
    results = await scanner.scan_many(targets)
    
    # 显示报告
    report = scanner.get_performance_report()
    print("\\n" + "=" * 60)
    print("扫描完成报告")
    print("=" * 60)
    
    print(f"总耗时: {report['scan_summary']['total_duration']:.2f}秒")
    print(f"吞吐量: {report['scan_summary']['throughput_targets_per_second']:.2f} 目标/秒")
    print(f"缓存命中率: {report['cache_performance']['hit_rate']:.1%}")
    
    if report['cache_performance']['hit_rate'] > 0:
        print("✅ 缓存系统工作正常!")
    else:
        print("⚠️  缓存未命中，可能是首次扫描")
    
    return scanner


if __name__ == "__main__":
    # Windows兼容性
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    
    print("启动增强版并发扫描器演示...")
    scanner = asyncio.run(demo_enhanced_scanner())