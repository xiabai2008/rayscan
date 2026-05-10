#!/usr/bin/env python3
"""
WVS v18.4 性能优化测试框架

用于测试和对比：
1. 并发扫描引擎性能
2. 智能限速系统效果
3. 缓存优化系统效果
"""
import asyncio
import time
import json
import statistics
from dataclasses import dataclass
from typing import List, Dict, Any
import sys

@dataclass
class PerformanceTestResult:
    """性能测试结果"""
    test_name: str
    duration_seconds: float
    targets_scanned: int
    requests_sent: int
    throughput_targets_per_second: float
    throughput_requests_per_second: float
    success_rate: float
    avg_response_time_ms: float
    error_count: int
    metrics: Dict[str, Any]
    timestamp: str
    
    def to_dict(self):
        return {
            "test_name": self.test_name,
            "duration_seconds": round(self.duration_seconds, 3),
            "targets_scanned": self.targets_scanned,
            "requests_sent": self.requests_sent,
            "throughput_targets_per_second": round(self.throughput_targets_per_second, 2),
            "throughput_requests_per_second": round(self.throughput_requests_per_second, 2),
            "success_rate": round(self.success_rate, 3),
            "avg_response_time_ms": round(self.avg_response_time_ms, 1),
            "error_count": self.error_count,
            "timestamp": self.timestamp
        }


class PerformanceTestRunner:
    """性能测试运行器"""
    
    def __init__(self):
        self.results = []
        self.test_targets = self._generate_test_targets()
        
    def _generate_test_targets(self):
        """生成测试目标列表"""
        base_url = "http://192.168.18.131"
        return [
            f"{base_url}/dvwa/",
            f"{base_url}/mutillidae/",
            f"{base_url}/tikiwiki/",
            f"{base_url}/phpmyadmin/",
            f"{base_url}/dvwa/vulnerabilities/sqli/",
            f"{base_url}/dvwa/vulnerabilities/xss_r/",
            f"{base_url}/dvwa/vulnerabilities/exec/",
            f"{base_url}/mutillidae/index.php?page=login.php",
            f"{base_url}/tikiwiki/tiki-index.php",
            f"{base_url}/phpmyadmin/index.php"
        ]
    
    async def test_baseline_sequential(self):
        """基线测试：顺序扫描"""
        print("运行基线测试：顺序扫描...")
        
        # 这里使用简单的模拟
        start_time = time.time()
        targets_scanned = 0
        requests_sent = 0
        response_times = []
        errors = 0
        
        import aiohttp
        async with aiohttp.ClientSession() as session:
            for target in self.test_targets[:3]:  # 测试3个目标
                try:
                    req_start = time.time()
                    async with session.get(target, timeout=10) as resp:
                        await resp.read()
                    resp_time = (time.time() - req_start) * 1000  # 转换为毫秒
                    response_times.append(resp_time)
                    targets_scanned += 1
                    requests_sent += 1
                    await asyncio.sleep(0.1)  # 模拟扫描间隔
                except Exception as e:
                    errors += 1
                    print(f"目标 {target} 失败: {e}")
        
        duration = time.time() - start_time
        
        result = PerformanceTestResult(
            test_name="baseline_sequential",
            duration_seconds=duration,
            targets_scanned=targets_scanned,
            requests_sent=requests_sent,
            throughput_targets_per_second=targets_scanned / duration if duration > 0 else 0,
            throughput_requests_per_second=requests_sent / duration if duration > 0 else 0,
            success_rate=targets_scanned / 3 if targets_scanned > 0 else 0,
            avg_response_time_ms=statistics.mean(response_times) if response_times else 0,
            error_count=errors,
            metrics={
                "concurrent_workers": 1,
                "rate_limiting": "无",
                "caching": "无",
                "test_targets_count": 3
            },
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
        )
        
        self.results.append(result)
        return result
    
    async def test_concurrent_scanner(self, max_workers=3):
        """测试并发扫描器"""
        print(f"测试并发扫描器 ({max_workers} workers)...")
        
        # 这里会集成concurrent_scanner的实际测试
        # 目前先模拟
        
        start_time = time.time()
        
        # 模拟并发扫描
        async def scan_target(target):
            try:
                import aiohttp
                async with aiohttp.ClientSession() as session:
                    req_start = time.time()
                    async with session.get(target, timeout=10) as resp:
                        await resp.read()
                    return (time.time() - req_start) * 1000, True
            except Exception:
                return 0, False
        
        # 创建并发任务
        tasks = []
        for target in self.test_targets[:5]:  # 测试5个目标
            tasks.append(scan_target(target))
        
        # 并发执行
        scan_results = await asyncio.gather(*tasks)
        
        duration = time.time() - start_time
        
        # 分析结果
        response_times = [r[0] for r in scan_results if r[1]]
        targets_scanned = sum(1 for r in scan_results if r[1])
        requests_sent = len(scan_results)
        errors = sum(1 for r in scan_results if not r[1])
        
        result = PerformanceTestResult(
            test_name=f"concurrent_{max_workers}workers",
            duration_seconds=duration,
            targets_scanned=targets_scanned,
            requests_sent=requests_sent,
            throughput_targets_per_second=targets_scanned / duration if duration > 0 else 0,
            throughput_requests_per_second=requests_sent / duration if duration > 0 else 0,
            success_rate=targets_scanned / len(scan_results) if scan_results else 0,
            avg_response_time_ms=statistics.mean(response_times) if response_times else 0,
            error_count=errors,
            metrics={
                "concurrent_workers": max_workers,
                "rate_limiting": "无",
                "caching": "无",
                "test_targets_count": 5
            },
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
        )
        
        self.results.append(result)
        return result
    
    async def test_with_rate_limiting(self, max_rps=5):
        """测试带限速的扫描"""
        print(f"测试带限速扫描 (最大 {max_rps} RPS)...")
        
        # 这里会集成智能限速器的测试
        # 目前先模拟
        
        start_time = time.time()
        
        # 简单的限速模拟
        from datetime import datetime, timedelta
        request_times = []
        
        async def rate_limited_request(target):
            now = datetime.now()
            
            # 清理1秒内的请求
            request_times[:] = [t for t in request_times 
                              if now - t < timedelta(seconds=1)]
            
            # 检查限制
            if len(request_times) >= max_rps:
                # 需要等待
                oldest = request_times[0]
                wait_seconds = 1.0 - (now - oldest).total_seconds()
                if wait_seconds > 0:
                    await asyncio.sleep(wait_seconds)
            
            # 记录请求时间
            request_times.append(datetime.now())
            
            # 发送请求
            try:
                import aiohttp
                async with aiohttp.ClientSession() as session:
                    req_start = time.time()
                    async with session.get(target, timeout=10) as resp:
                        await resp.read()
                    return (time.time() - req_start) * 1000, True
            except Exception:
                return 0, False
        
        # 执行测试
        tasks = []
        for target in self.test_targets[:4]:  # 测试4个目标
            tasks.append(rate_limited_request(target))
        
        results = await asyncio.gather(*tasks)
        
        duration = time.time() - start_time
        
        # 分析结果
        response_times = [r[0] for r in results if r[1]]
        targets_scanned = sum(1 for r in results if r[1])
        requests_sent = len(results)
        errors = sum(1 for r in results if not r[1])
        
        result = PerformanceTestResult(
            test_name=f"rate_limited_{max_rps}rps",
            duration_seconds=duration,
            targets_scanned=targets_scanned,
            requests_sent=requests_sent,
            throughput_targets_per_second=targets_scanned / duration if duration > 0 else 0,
            throughput_requests_per_second=requests_sent / duration if duration > 0 else 0,
            success_rate=targets_scanned / len(results) if results else 0,
            avg_response_time_ms=statistics.mean(response_times) if response_times else 0,
            error_count=errors,
            metrics={
                "concurrent_workers": 1,
                "rate_limiting": f"最大{max_rps}RPS",
                "caching": "无",
                "test_targets_count": 4
            },
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
        )
        
        self.results.append(result)
        return result
    
    def generate_comparison_report(self):
        """生成对比报告"""
        if not self.results:
            return {"error": "无测试结果"}
        
        # 计算性能提升
        baseline = next((r for r in self.results if r.test_name == "baseline_sequential"), None)
        if not baseline:
            baseline = self.results[0]  # 使用第一个作为基准
        
        comparison = []
        for result in self.results:
            if result == baseline:
                continue
            
            improvement = {
                "test_name": result.test_name,
                "throughput_improvement": (
                    (result.throughput_targets_per_second - baseline.throughput_targets_per_second) 
                    / baseline.throughput_targets_per_second * 100 
                    if baseline.throughput_targets_per_second > 0 else 0
                ),
                "duration_improvement": (
                    (baseline.duration_seconds - result.duration_seconds) 
                    / baseline.duration_seconds * 100 
                    if baseline.duration_seconds > 0 else 0
                ),
                "success_rate_change": result.success_rate - baseline.success_rate,
                "avg_response_time_change": result.avg_response_time_ms - baseline.avg_response_time_ms
            }
            comparison.append(improvement)
        
        report = {
            "test_summary": {
                "total_tests": len(self.results),
                "baseline_test": baseline.test_name,
                "test_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "test_environment": "Metasploitable2 (192.168.18.131)"
            },
            "detailed_results": [r.to_dict() for r in self.results],
            "performance_comparison": comparison,
            "recommendations": self._generate_recommendations()
        }
        
        return report
    
    def _generate_recommendations(self):
        """基于测试结果生成建议"""
        if not self.results:
            return []
        
        recommendations = []
        
        # 找出最佳配置
        best_throughput = max(self.results, key=lambda r: r.throughput_targets_per_second)
        best_success = max(self.results, key=lambda r: r.success_rate)
        fastest = min(self.results, key=lambda r: r.avg_response_time_ms)
        
        if best_throughput.test_name != "baseline_sequential":
            recommendations.append({
                "type": "吞吐量优化",
                "recommendation": f"使用{best_throughput.test_name}配置，吞吐量提升{best_throughput.throughput_targets_per_second:.1f}目标/秒",
                "impact": "高"
            })
        
        if best_success.success_rate > 0.9:
            recommendations.append({
                "type": "可靠性优化",
                "recommendation": f"使用{best_success.test_name}配置，成功率{best_success.success_rate*100:.1f}%",
                "impact": "中"
            })
        
        if fastest.avg_response_time_ms < 100:
            recommendations.append({
                "type": "响应时间优化",
                "recommendation": f"使用{fastest.test_name}配置，平均响应时间{fastest.avg_response_time_ms:.1f}ms",
                "impact": "中"
            })
        
        # 通用建议
        recommendations.extend([
            {
                "type": "并发配置",
                "recommendation": "根据目标服务器性能调整并发数，避免触发WAF",
                "impact": "高"
            },
            {
                "type": "限速策略",
                "recommendation": "在生产环境启用智能限速，避免目标服务器过载",
                "impact": "高"
            },
            {
                "type": "缓存使用",
                "recommendation": "对重复扫描的目标启用缓存，减少网络开销",
                "impact": "中"
            }
        ])
        
        return recommendations
    
    def save_report(self, filename="performance_test_report.json"):
        """保存测试报告"""
        report = self.generate_comparison_report()
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"测试报告已保存: {filename}")
        return report


async def run_all_tests():
    """运行所有性能测试"""
    print("=" * 60)
    print("WVS v18.4 性能优化测试套件")
    print("=" * 60)
    
    runner = PerformanceTestRunner()
    
    # 运行测试
    print("\n1. 基线测试: 顺序扫描")
    await runner.test_baseline_sequential()
    
    print("\n2. 并发扫描测试")
    await runner.test_concurrent_scanner(max_workers=2)
    await runner.test_concurrent_scanner(max_workers=3)
    
    print("\n3. 限速扫描测试")
    await runner.test_with_rate_limiting(max_rps=3)
    await runner.test_with_rate_limiting(max_rps=5)
    
    # 生成报告
    print("\n" + "=" * 60)
    print("生成性能对比报告...")
    report = runner.save_report()
    
    # 显示摘要
    print("\n📊 测试结果摘要:")
    for result in runner.results:
        print(f"  {result.test_name}:")
        print(f"    耗时: {result.duration_seconds:.2f}s")
        print(f"    吞吐量: {result.throughput_targets_per_second:.2f} 目标/秒")
        print(f"    成功率: {result.success_rate*100:.1f}%")
    
    print("\n" + "=" * 60)
    print("性能测试完成!")
    print("=" * 60)
    
    return report


if __name__ == "__main__":
    # Windows兼容性
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    
    # 运行测试
    report = asyncio.run(run_all_tests())