"""性能优化模块"""
import psutil
import asyncio
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from collections import deque


@dataclass
class ResourceMetrics:
    """资源指标"""
    cpu_percent: float
    memory_percent: float
    memory_available_mb: float
    disk_read_mb: float
    disk_write_mb: float
    timestamp: float


@dataclass
class ScanParameters:
    """扫描参数"""
    concurrency: int
    request_interval: float
    timeout: int
    max_retries: int
    follow_redirects: bool


class PerformanceOptimizer:
    """性能优化器"""
    
    def __init__(self):
        self.resource_history: deque = deque(maxlen=100)
        self.target_performance: Dict[str, Dict] = {}
        self.base_concurrency = 50
        self.base_interval = 0.1
    
    def monitor_resources(self) -> ResourceMetrics:
        """监控资源使用情况"""
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory_info = psutil.virtual_memory()
        disk_io = psutil.disk_io_counters()
        
        metrics = ResourceMetrics(
            cpu_percent=cpu_percent,
            memory_percent=memory_info.percent,
            memory_available_mb=memory_info.available / (1024 * 1024),
            disk_read_mb=disk_io.read_bytes / (1024 * 1024) if disk_io else 0,
            disk_write_mb=disk_io.write_bytes / (1024 * 1024) if disk_io else 0,
            timestamp=time.time(),
        )
        
        self.resource_history.append(metrics)
        return metrics
    
    def calculate_optimal_concurrency(self, target_complexity: str = 'medium') -> int:
        """计算最优并发数"""
        current_resources = self.monitor_resources()
        
        # 基础并发数
        base_concurrency = self.base_concurrency
        
        # 根据CPU调整
        cpu_factor = max(0.5, 2.0 - (current_resources.cpu_percent / 50))
        
        # 根据内存调整
        memory_factor = max(0.3, current_resources.memory_available_mb / 1024)
        
        # 根据目标复杂度调整
        complexity_factor = {
            'simple': 1.5,
            'medium': 1.0,
            'complex': 0.7,
            'very_complex': 0.5,
        }.get(target_complexity, 1.0)
        
        optimal_concurrency = int(
            base_concurrency * cpu_factor * memory_factor * complexity_factor
        )
        
        # 限制范围
        return max(10, min(optimal_concurrency, 200))
    
    def calculate_request_interval(self, target_responsiveness: str = 'medium') -> float:
        """计算请求间隔"""
        base_interval = self.base_interval
        
        # 根据目标响应性调整
        responsiveness_factor = {
            'fast': 0.5,
            'medium': 1.0,
            'slow': 2.0,
            'very_slow': 3.0,
        }.get(target_responsiveness, 1.0)
        
        # 根据历史性能调整
        if self.target_performance:
            avg_response_time = self._get_average_response_time()
            if avg_response_time > 0:
                responsiveness_factor *= (avg_response_time / 0.5)
        
        return base_interval * responsiveness_factor
    
    def calculate_timeout(self, target_responsiveness: str = 'medium') -> int:
        """计算超时时间"""
        base_timeout = {
            'fast': 10,
            'medium': 30,
            'slow': 60,
            'very_slow': 120,
        }.get(target_responsiveness, 30)
        
        # 根据历史性能微调
        if self.target_performance:
            p95_response = self._get_p95_response_time()
            if p95_response > 0:
                base_timeout = max(base_timeout, int(p95_response * 2))
        
        return min(base_timeout, 300)  # 最大300秒
    
    def optimize_scan_parameters(self, target_info: Dict) -> ScanParameters:
        """优化扫描参数"""
        # 评估目标复杂度
        target_complexity = self.assess_target_complexity(target_info)
        
        # 测量目标响应性
        target_responsiveness = self.measure_target_responsiveness(
            target_info.get('url', '')
        )
        
        return ScanParameters(
            concurrency=self.calculate_optimal_concurrency(target_complexity),
            request_interval=self.calculate_request_interval(target_responsiveness),
            timeout=self.calculate_timeout(target_responsiveness),
            max_retries=3,
            follow_redirects=True,
        )
    
    def assess_target_complexity(self, target_info: Dict) -> str:
        """评估目标复杂度"""
        complexity_score = 0
        
        # 页面数量
        page_count = len(target_info.get('urls', []))
        if page_count > 1000:
            complexity_score += 3
        elif page_count > 100:
            complexity_score += 2
        elif page_count > 10:
            complexity_score += 1
        
        # 表单数量
        form_count = len(target_info.get('forms', []))
        if form_count > 50:
            complexity_score += 2
        elif form_count > 10:
            complexity_score += 1
        
        # API端点数量
        api_count = len(target_info.get('api_endpoints', []))
        if api_count > 100:
            complexity_score += 3
        elif api_count > 20:
            complexity_score += 2
        
        # 参数数量
        param_count = len(target_info.get('parameters', []))
        if param_count > 200:
            complexity_score += 2
        elif param_count > 50:
            complexity_score += 1
        
        # 确定复杂度
        if complexity_score >= 6:
            return 'very_complex'
        elif complexity_score >= 4:
            return 'complex'
        elif complexity_score >= 2:
            return 'medium'
        else:
            return 'simple'
    
    def measure_target_responsiveness(self, target_url: str) -> str:
        """测量目标响应性"""
        # 这里应该实际测量响应时间
        # 简化实现，返回默认值
        
        if target_url in self.target_performance:
            avg_time = self.target_performance[target_url].get('avg_response_time', 0.5)
            
            if avg_time < 0.2:
                return 'fast'
            elif avg_time < 0.5:
                return 'medium'
            elif avg_time < 1.0:
                return 'slow'
            else:
                return 'very_slow'
        
        return 'medium'
    
    def update_target_performance(self, target_url: str, response_time: float):
        """更新目标性能数据"""
        if target_url not in self.target_performance:
            self.target_performance[target_url] = {
                'response_times': deque(maxlen=100),
                'avg_response_time': 0,
                'p95_response_time': 0,
            }
        
        perf = self.target_performance[target_url]
        perf['response_times'].append(response_time)
        
        # 计算平均值
        times = list(perf['response_times'])
        perf['avg_response_time'] = sum(times) / len(times)
        
        # 计算P95
        if times:
            sorted_times = sorted(times)
            p95_index = int(len(sorted_times) * 0.95)
            perf['p95_response_time'] = sorted_times[min(p95_index, len(sorted_times) - 1)]
    
    def _get_average_response_time(self) -> float:
        """获取平均响应时间"""
        if not self.target_performance:
            return 0.5
        
        total = 0
        count = 0
        for perf in self.target_performance.values():
            total += perf.get('avg_response_time', 0)
            count += 1
        
        return total / count if count > 0 else 0.5
    
    def _get_p95_response_time(self) -> float:
        """获取P95响应时间"""
        if not self.target_performance:
            return 1.0
        
        all_times = []
        for perf in self.target_performance.values():
            all_times.extend(list(perf.get('response_times', [])))
        
        if not all_times:
            return 1.0
        
        sorted_times = sorted(all_times)
        p95_index = int(len(sorted_times) * 0.95)
        return sorted_times[min(p95_index, len(sorted_times) - 1)]
    
    def get_resource_trend(self) -> Dict[str, List[float]]:
        """获取资源使用趋势"""
        if not self.resource_history:
            return {'cpu': [], 'memory': []}
        
        return {
            'cpu': [m.cpu_percent for m in self.resource_history],
            'memory': [m.memory_percent for m in self.resource_history],
        }
    
    def should_throttle(self) -> bool:
        """判断是否需要节流"""
        if not self.resource_history:
            return False
        
        current = self.resource_history[-1]
        
        # CPU或内存使用率过高
        if current.cpu_percent > 90 or current.memory_percent > 85:
            return True
        
        return False
    
    def get_optimization_report(self) -> Dict[str, Any]:
        """获取优化报告"""
        if not self.resource_history:
            return {'status': 'no_data'}
        
        recent = list(self.resource_history)[-10:]
        
        avg_cpu = sum(m.cpu_percent for m in recent) / len(recent)
        avg_memory = sum(m.memory_percent for m in recent) / len(recent)
        
        return {
            'status': 'healthy' if avg_cpu < 70 and avg_memory < 80 else 'stressed',
            'average_cpu': round(avg_cpu, 2),
            'average_memory': round(avg_memory, 2),
            'recommendations': self._generate_recommendations(avg_cpu, avg_memory),
        }
    
    def _generate_recommendations(self, avg_cpu: float, avg_memory: float) -> List[str]:
        """生成优化建议"""
        recommendations = []
        
        if avg_cpu > 80:
            recommendations.append("CPU使用率较高，建议降低并发数")
        
        if avg_memory > 80:
            recommendations.append("内存使用率较高，建议优化内存使用或增加内存")
        
        if not recommendations:
            recommendations.append("系统运行正常，当前配置合理")
        
        return recommendations


class ResourceMonitor:
    """资源监控器"""
    
    def __init__(self, interval: int = 5):
        self.interval = interval
        self.running = False
        self.metrics_history: deque = deque(maxlen=1000)
        self._monitor_task = None
    
    async def start(self):
        """开始监控"""
        self.running = True
        self._monitor_task = asyncio.create_task(self._monitor_loop())
    
    async def stop(self):
        """停止监控"""
        self.running = False
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
    
    async def _monitor_loop(self):
        """监控循环"""
        while self.running:
            try:
                metrics = self._collect_metrics()
                self.metrics_history.append(metrics)
                await asyncio.sleep(self.interval)
            except Exception as e:
                print(f"Monitor error: {e}")
                await asyncio.sleep(self.interval)
    
    def _collect_metrics(self) -> Dict[str, Any]:
        """收集指标"""
        return {
            'timestamp': time.time(),
            'cpu': psutil.cpu_percent(interval=0.1),
            'memory': psutil.virtual_memory()._asdict(),
            'disk': psutil.disk_usage('/')._asdict(),
            'network': psutil.net_io_counters()._asdict() if psutil.net_io_counters() else {},
        }
    
    def get_current_metrics(self) -> Dict[str, Any]:
        """获取当前指标"""
        return self._collect_metrics()
    
    def get_metrics_history(self, limit: int = 100) -> List[Dict]:
        """获取历史指标"""
        return list(self.metrics_history)[-limit:]
    
    def check_alerts(self) -> List[Dict]:
        """检查告警"""
        alerts = []
        
        if not self.metrics_history:
            return alerts
        
        current = self.metrics_history[-1]
        
        # CPU告警
        if current.get('cpu', 0) > 90:
            alerts.append({
                'level': 'critical',
                'type': 'cpu',
                'message': f"CPU使用率过高: {current['cpu']:.1f}%",
            })
        elif current.get('cpu', 0) > 75:
            alerts.append({
                'level': 'warning',
                'type': 'cpu',
                'message': f"CPU使用率较高: {current['cpu']:.1f}%",
            })
        
        # 内存告警
        memory_percent = current.get('memory', {}).get('percent', 0)
        if memory_percent > 90:
            alerts.append({
                'level': 'critical',
                'type': 'memory',
                'message': f"内存使用率过高: {memory_percent:.1f}%",
            })
        elif memory_percent > 80:
            alerts.append({
                'level': 'warning',
                'type': 'memory',
                'message': f"内存使用率较高: {memory_percent:.1f}%",
            })
        
        return alerts
