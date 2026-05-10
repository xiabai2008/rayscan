"""批量扫描和结果对比模块"""
import json
from typing import List, Dict, Optional
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict


@dataclass
class ScanResult:
    """扫描结果数据类"""
    scan_id: str
    target: str
    timestamp: str
    duration: float
    vulnerability_count: int
    vulnerabilities: List[Dict]
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict) -> "ScanResult":
        return cls(**data)
    
    def save(self, output_dir: Path):
        """保存结果到文件"""
        output_path = output_dir / f"result_{self.scan_id}.json"
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
        return output_path


class BatchScanner:
    """批量扫描器"""
    
    def __init__(self, base_config):
        self.base_config = base_config
        self.results: List[ScanResult] = []
    
    async def scan_multiple(self, targets: List[str]) -> List[ScanResult]:
        """批量扫描多个目标"""
        from .scanner import WVSScanner
        
        self.results = []
        for i, target in enumerate(targets, 1):
            print(f"\n[{i}/{len(targets)}] 扫描目标: {target}")
            
            config = self.base_config
            config.target = target
            
            scanner = WVSScanner(config)
            result = await scanner.scan()
            
            scan_result = ScanResult(
                scan_id=result["scan_id"],
                target=target,
                timestamp=datetime.now().isoformat(),
                duration=result["duration"],
                vulnerability_count=result["vulnerabilities"],
                vulnerabilities=result["details"],
            )
            self.results.append(scan_result)
        
        return self.results
    
    def generate_summary_report(self) -> Dict:
        """生成批量扫描汇总报告"""
        total_targets = len(self.results)
        total_vulns = sum(r.vulnerability_count for r in self.results)
        avg_duration = sum(r.duration for r in self.results) / total_targets if total_targets > 0 else 0
        
        # 统计各目标漏洞数
        target_stats = []
        for r in self.results:
            target_stats.append({
                "target": r.target,
                "vulnerabilities": r.vulnerability_count,
                "duration": r.duration,
            })
        
        # 按漏洞数排序
        target_stats.sort(key=lambda x: x["vulnerabilities"], reverse=True)
        
        return {
            "summary": {
                "total_targets": total_targets,
                "total_vulnerabilities": total_vulns,
                "average_duration": avg_duration,
                "scan_time": datetime.now().isoformat(),
            },
            "target_ranking": target_stats,
            "details": [r.to_dict() for r in self.results],
        }


class ResultComparator:
    """扫描结果对比器"""
    
    def __init__(self):
        self.previous_results: Dict[str, ScanResult] = {}
    
    def load_previous_result(self, result_path: str) -> ScanResult:
        """加载历史扫描结果"""
        with open(result_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return ScanResult.from_dict(data)
    
    def compare(self, current: ScanResult, previous: ScanResult) -> Dict:
        """对比两次扫描结果"""
        # 提取漏洞指纹集合
        current_vulns = {self._vuln_fingerprint(v) for v in current.vulnerabilities}
        previous_vulns = {self._vuln_fingerprint(v) for v in previous.vulnerabilities}
        
        # 计算差异
        new_vulns = current_vulns - previous_vulns
        fixed_vulns = previous_vulns - current_vulns
        unchanged_vulns = current_vulns & previous_vulns
        
        return {
            "target": current.target,
            "current_scan": current.scan_id,
            "previous_scan": previous.scan_id,
            "summary": {
                "current_total": len(current_vulns),
                "previous_total": len(previous_vulns),
                "new": len(new_vulns),
                "fixed": len(fixed_vulns),
                "unchanged": len(unchanged_vulns),
            },
            "new_vulnerabilities": list(new_vulns),
            "fixed_vulnerabilities": list(fixed_vulns),
            "unchanged_vulnerabilities": list(unchanged_vulns),
        }
    
    def _vuln_fingerprint(self, vuln: Dict) -> str:
        """生成漏洞指纹"""
        return f"{vuln.get('name', '')}:{vuln.get('url', '')}:{vuln.get('payload', '')[:50]}"
    
    def generate_trend_report(self, results: List[ScanResult]) -> Dict:
        """生成漏洞趋势报告"""
        if not results:
            return {}
        
        # 按时间排序
        sorted_results = sorted(results, key=lambda r: r.timestamp)
        
        trend = []
        for r in sorted_results:
            trend.append({
                "timestamp": r.timestamp,
                "scan_id": r.scan_id,
                "vulnerability_count": r.vulnerability_count,
            })
        
        # 计算趋势
        if len(trend) >= 2:
            first_count = trend[0]["vulnerability_count"]
            last_count = trend[-1]["vulnerability_count"]
            change = last_count - first_count
            change_percent = (change / first_count * 100) if first_count > 0 else 0
        else:
            change = 0
            change_percent = 0
        
        return {
            "trend": trend,
            "change": change,
            "change_percent": change_percent,
            "direction": "improving" if change < 0 else "worsening" if change > 0 else "stable",
        }
