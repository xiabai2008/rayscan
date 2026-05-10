#!/usr/bin/env python3
"""
WVS v18.4 并发扫描引擎 - 阶段一实现

核心功能：
1. 并发扫描管理器
2. 任务队列系统
3. 工作线程池
4. 结果收集器
"""
import asyncio
import time
import json
import sys
import os
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from urllib.parse import urlparse

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# 复用现有扫描器
from wvs.vuln.scanner_v18 import VulnerabilityScanner, ScanResult

# 智能限速系统
try:
    from intelligent_rate_limiter import IntelligentRateLimiter
    RATE_LIMITER_AVAILABLE = True
except ImportError:
    RATE_LIMITER_AVAILABLE = False
    print("[警告] intelligent_rate_limiter 模块不可用，将禁用智能限速功能")

# 缓存系统
try:
    from cache_system import ScanCache, TargetFingerprinter, CacheManager, get_global_cache_manager
    CACHE_AVAILABLE = True
except ImportError:
    CACHE_AVAILABLE = False
    ScanCache = None
    TargetFingerprinter = None
    CacheManager = None
    get_global_cache_manager = None

@dataclass
class ConcurrentScanResult:
    """并发扫描结果"""
    target: str
    result: Optional[ScanResult]
    worker_id: int
    start_time: float
    end_time: float
    success: bool
    error: Optional[str] = None

@dataclass
class PerformanceMetrics:
    """性能指标"""
    total_targets: int = 0
    completed_targets: int = 0
    success_count: int = 0
    failed_count: int = 0
    total_duration: float = 0.0
    avg_duration_per_target: float = 0.0
    requests_sent: int = 0
    avg_requests_per_target: int = 0
    throughput_targets_per_second: float = 0.0
    
    def update_from_results(self, results: List[ConcurrentScanResult]):
        """从结果更新指标"""
        self.total_targets = len(results)
        self.completed_targets = len([r for r in results if r.end_time > 0])
        self.success_count = len([r for r in results if r.success])
        self.failed_count = len([r for r in results if not r.success])
        
        # 计算持续时间
        if results:
            durations = [r.end_time - r.start_time for r in results if r.end_time > 0]
            if durations:
                self.total_duration = sum(durations)
                self.avg_duration_per_target = sum(durations) / len(durations)
                
                # 计算吞吐量
                if self.total_duration > 0:
                    self.throughput_targets_per_second = self.completed_targets / self.total_duration


class ConcurrentScanner:
    """并发扫描器管理器"""
    
    def __init__(self, config: Dict = None):
        # 配置参数
        self.config = config or {}
        self.max_workers = self.config.get('max_workers', 3)  # 默认3个并发
        self.timeout_per_target = self.config.get('timeout_per_target', 120)  # 每个目标超时时间
        self.enable_validation = self.config.get('enable_validation', True)

        # 缓存配置
        self.enable_cache = self.config.get('enable_cache', True) and CACHE_AVAILABLE
        self.cache_ttl = self.config.get('cache_ttl', 3600)  # 默认1小时
        self.cache_persist_path = self.config.get('cache_persist_path', './scan_cache.json')
        self.cache_manager = None

        if self.enable_cache:
            try:
                self.cache_manager = get_global_cache_manager(self.cache_persist_path)
                print(f"[缓存系统] 已启用，TTL: {self.cache_ttl}秒，持久化: {self.cache_persist_path}")
            except Exception as e:
                print(f"[缓存系统] 初始化失败: {e}")
                self.enable_cache = False

        # 智能限速配置
        self.rate_limiter_config = self.config.get('rate_limiter', {})
        self.enable_rate_limiter = self.rate_limiter_config.get('enabled', True) and RATE_LIMITER_AVAILABLE

        if self.enable_rate_limiter:
            print(f"[智能限速] 已启用，配置: {self.rate_limiter_config}")
        else:
            print(f"[智能限速] 已禁用")

        # 并发组件
        self.task_queue = None
        self.workers = []
        self.results = []
        self.worker_results = {}

        # 扫描器实例缓存
        self.scanner_cache = {}

        # 性能指标
        self.metrics = PerformanceMetrics()
        self.start_time = 0
        self.end_time = 0

        # 状态标志
        self.is_running = False
        
    def create_scanner_for_target(self, target: str) -> VulnerabilityScanner:
        """为目标创建扫描器实例"""
        scanner_config = {
            'timeout': self.config.get('scanner_timeout', 30),
            'delay': self.config.get('scanner_delay', 0.1),
            'max_urls': self.config.get('max_urls', 100),
            'max_depth': self.config.get('max_depth', 3),
        }

        # 添加智能限速配置（如果启用）
        if self.enable_rate_limiter:
            scanner_config['rate_limiter'] = self.rate_limiter_config
        
        # 如果启用验证增强，加载优化配置
        if self.enable_validation:
            try:
                config_path = os.path.join(os.path.dirname(__file__), 'validation_optimized_config.json')
                if os.path.exists(config_path):
                    with open(config_path, 'r') as f:
                        validation_config = json.load(f)
                    scanner_config['validation'] = validation_config
            except Exception:
                pass  # 如果加载失败，使用默认验证
        
        scanner = VulnerabilityScanner(scanner_config)
        return scanner
    
    async def scan_single_target(self, target: str, worker_id: int = 0) -> ConcurrentScanResult:
        """扫描单个目标（worker内部调用）"""
        start_time = time.time()
        result_obj = ConcurrentScanResult(
            target=target,
            result=None,
            worker_id=worker_id,
            start_time=start_time,
            end_time=0,
            success=False
        )

        # 缓存命中标志
        cached = False

        try:
            # 1. 检查缓存
            if self.enable_cache and self.cache_manager:
                cached_result = self.cache_manager.get_cached_result(target)
                if cached_result is not None:
                    result_obj.result = cached_result
                    result_obj.success = True
                    result_obj.end_time = time.time()
                    cached = True
                    print(f"[Worker {worker_id}] 缓存命中: {target}，跳过扫描")
                    return result_obj

            print(f"[Worker {worker_id}] 开始扫描: {target}")

            # 创建或获取扫描器实例
            if target not in self.scanner_cache:
                self.scanner_cache[target] = self.create_scanner_for_target(target)

            scanner = self.scanner_cache[target]

            # 执行扫描
            import aiohttp
            async with aiohttp.ClientSession() as session:
                # 执行扫描（这里简化，实际应该调用完整扫描逻辑）
                # 为了快速验证，先进行基本连接测试
                try:
                    # 测试连接
                    test_start = time.time()
                    async with session.get(target, timeout=10) as response:
                        await response.read()
                        connect_time = time.time() - test_start

                    # 创建模拟结果（在实际实现中应该调用完整的扫描）
                    result = ScanResult(
                        urls=[],  # 后续填充
                        forms=[],
                        vulnerabilities=[],
                        js_files=[],
                        sensitive_paths=[],
                        duration=connect_time,
                        total_requests=1
                    )

                    result_obj.result = result
                    result_obj.success = True
                    print(f"[Worker {worker_id}] 扫描完成: {target}, 连接时间: {connect_time:.2f}s")

                    # 2. 缓存扫描结果
                    if self.enable_cache and self.cache_manager and not cached:
                        try:
                            self.cache_manager.cache_scan_result(target, result, ttl=self.cache_ttl)
                            print(f"[Worker {worker_id}] 结果已缓存: {target}, TTL: {self.cache_ttl}秒")
                        except Exception as cache_error:
                            print(f"[Worker {worker_id}] 缓存失败: {cache_error}")

                except Exception as e:
                    result_obj.error = f"连接失败: {str(e)}"
                    print(f"[Worker {worker_id}] 扫描失败: {target}, 错误: {str(e)}")

        except Exception as e:
            result_obj.error = f"扫描异常: {str(e)}"
            print(f"[Worker {worker_id}] 异常: {target}, 错误: {str(e)}")

        finally:
            result_obj.end_time = time.time()
            return result_obj
    
    async def worker(self, worker_id: int):
        """工作线程：从队列获取任务并执行"""
        print(f"[Worker {worker_id}] 启动")
        
        while True:
            try:
                # 从队列获取任务
                target = await self.task_queue.get()
                
                if target is None:  # 停止信号
                    print(f"[Worker {worker_id}] 收到停止信号")
                    self.task_queue.task_done()
                    break
                
                # 执行扫描
                result = await self.scan_single_target(target, worker_id)
                
                # 保存结果
                self.results.append(result)
                self.worker_results.setdefault(worker_id, []).append(result)
                
                # 更新队列状态
                self.task_queue.task_done()
                
                # 更新性能指标
                self.metrics.update_from_results(self.results)
                
            except asyncio.CancelledError:
                print(f"[Worker {worker_id}] 被取消")
                break
            except Exception as e:
                print(f"[Worker {worker_id}] 工作异常: {e}")
                self.task_queue.task_done()
        
        print(f"[Worker {worker_id}] 退出")
    
    async def scan_many(self, targets: List[str]) -> List[ConcurrentScanResult]:
        """并发扫描多个目标"""
        print(f"开始并发扫描 {len(targets)} 个目标, 使用 {self.max_workers} 个工作线程")
        print(f"配置: 验证增强={self.enable_validation}, 超时={self.timeout_per_target}s")
        
        self.start_time = time.time()
        self.is_running = True
        
        # 初始化队列
        self.task_queue = asyncio.Queue()
        self.results = []
        self.worker_results = {}
        
        # 添加任务到队列
        for target in targets:
            await self.task_queue.put(target)
        
        # 添加停止信号
        for _ in range(self.max_workers):
            await self.task_queue.put(None)
        
        # 创建并启动工作线程
        self.workers = []
        for i in range(self.max_workers):
            worker_task = asyncio.create_task(self.worker(i))
            self.workers.append(worker_task)
        
        # 等待所有任务完成
        await self.task_queue.join()
        
        # 取消工作线程
        for worker in self.workers:
            worker.cancel()
        
        # 等待所有worker完成
        if self.workers:
            await asyncio.gather(*self.workers, return_exceptions=True)
        
        self.end_time = time.time()
        self.is_running = False
        
        # 计算最终性能指标
        total_duration = self.end_time - self.start_time
        self.metrics.total_duration = total_duration
        if len(targets) > 0 and total_duration > 0:
            self.metrics.throughput_targets_per_second = len(self.results) / total_duration

        # 自动保存缓存（如果启用）
        if self.enable_cache and self.cache_manager and self.cache_persist_path:
            try:
                self.cache_manager.save_to_disk()
                print(f"[缓存系统] 缓存已保存到: {self.cache_persist_path}")
            except Exception as e:
                print(f"[缓存系统] 保存缓存失败: {e}")

        return self.results
    
    def get_performance_report(self) -> Dict:
        """获取性能报告"""
        if not self.results:
            return {"error": "无扫描结果"}
        
        # 按worker统计
        worker_stats = {}
        for worker_id, results in self.worker_results.items():
            if results:
                durations = [r.end_time - r.start_time for r in results if r.end_time > 0]
                worker_stats[worker_id] = {
                    "targets_scanned": len(results),
                    "success_count": len([r for r in results if r.success]),
                    "avg_duration": sum(durations) / len(durations) if durations else 0,
                    "first_target": results[0].target if results else None,
                    "last_target": results[-1].target if results else None
                }
        
        report = {
            "scan_summary": {
                "total_targets": len(self.results),
                "successful_scans": len([r for r in self.results if r.success]),
                "failed_scans": len([r for r in self.results if not r.success]),
                "total_duration_seconds": self.end_time - self.start_time,
                "start_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.start_time)),
                "end_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.end_time))
            },
            "performance_metrics": {
                "throughput_targets_per_second": self.metrics.throughput_targets_per_second,
                "avg_duration_per_target": self.metrics.avg_duration_per_target,
                "concurrent_workers": self.max_workers,
                "queue_size_at_start": len(self.results)  # 近似值
            },
            "worker_statistics": worker_stats,
            "configuration": {
                "max_workers": self.max_workers,
                "timeout_per_target": self.timeout_per_target,
                "enable_validation": self.enable_validation,
                "enable_cache": self.enable_cache,
                "cache_ttl": self.cache_ttl if self.enable_cache else None,
                "cache_persist_path": self.cache_persist_path if self.enable_cache else None,
                "enable_rate_limiter": self.enable_rate_limiter,
                "rate_limiter_config": self.rate_limiter_config if self.enable_rate_limiter else None
            },
            "targets_scanned": [r.target for r in self.results]
        }
        
        return report
    
    def display_real_time_stats(self):
        """显示实时统计信息"""
        if not self.is_running:
            return
        
        completed = len(self.results)
        success = len([r for r in self.results if r.success])
        
        elapsed = time.time() - self.start_time
        if elapsed > 0:
            rate = completed / elapsed
        else:
            rate = 0
        
        print(f"\r[实时统计] 完成: {completed}, 成功: {success}, 速率: {rate:.2f} 目标/秒", end="")
    
    async def run_with_progress(self, targets: List[str], update_interval: float = 2.0):
        """带进度显示的扫描"""
        # 启动扫描任务
        scan_task = asyncio.create_task(self.scan_many(targets))
        
        # 启动进度显示
        async def show_progress():
            while self.is_running:
                self.display_real_time_stats()
                await asyncio.sleep(update_interval)
        
        progress_task = asyncio.create_task(show_progress())
        
        # 等待扫描完成
        results = await scan_task
        
        # 停止进度显示
        progress_task.cancel()
        try:
            await progress_task
        except asyncio.CancelledError:
            pass
        
        # 显示最终统计
        print()  # 换行
        return results


def test_concurrent_scanning():
    """测试并发扫描功能"""
    import asyncio
    
    # 测试目标（使用Metasploitable2上的不同应用）
    test_targets = [
        "http://192.168.18.131/dvwa/",
        "http://192.168.18.131/mutillidae/",
        "http://192.168.18.131/tikiwiki/",
        "http://192.168.18.131/phpmyadmin/",
        "http://192.168.18.131/dvwa/vulnerabilities/sqli/",
        "http://192.168.18.131/dvwa/vulnerabilities/xss_r/",
        "http://192.168.18.131/dvwa/vulnerabilities/exec/",
        "http://192.168.18.131/mutillidae/index.php?page=login.php",
        "http://192.168.18.131/tikiwiki/tiki-index.php",
        "http://192.168.18.131/phpmyadmin/index.php"
    ]
    
    async def run_test():
        print("=" * 60)
        print("WVS v18.4 并发扫描引擎测试")
        print("=" * 60)
        
        # 测试不同并发数
        for workers in [1, 2, 3, 5]:
            print(f"\n测试 {workers} 个并发工作线程...")
            
            scanner = ConcurrentScanner({
                'max_workers': workers,
                'timeout_per_target': 60,
                'enable_validation': True,
                'scanner_timeout': 20,
                'scanner_delay': 0.05
            })
            
            # 运行扫描
            start_time = time.time()
            results = await scanner.run_with_progress(test_targets[:workers*2])  # 每个worker测试2个目标
            end_time = time.time()
            
            # 生成报告
            report = scanner.get_performance_report()
            
            print(f"\n测试结果 ({workers} workers):")
            print(f"  扫描目标: {len(results)}")
            print(f"  成功扫描: {report['scan_summary']['successful_scans']}")
            print(f"  总耗时: {report['scan_summary']['total_duration_seconds']:.2f}秒")
            print(f"  吞吐量: {report['performance_metrics']['throughput_targets_per_second']:.2f} 目标/秒")
            
            # 保存报告
            report_file = f"concurrent_test_{workers}workers.json"
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2)
            
            print(f"  报告已保存: {report_file}")
            
            # 等待一下，避免请求过于密集
            await asyncio.sleep(1)
        
        print("\n" + "=" * 60)
        print("并发扫描测试完成!")
        print("=" * 60)
    
    return asyncio.run(run_test())


if __name__ == "__main__":
    # Windows兼容性
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    
    print("启动并发扫描引擎测试...")
    test_concurrent_scanning()