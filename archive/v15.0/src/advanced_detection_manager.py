#!/usr/bin/env python3
"""
高级漏洞检测管理器 - 统一管理四个高级检测模块
"""
import asyncio
import time
import json
import sys
import os
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

class DetectionModule(Enum):
    """检测模块枚举"""
    ZERO_DAY = "zero_day"          # 零日漏洞检测
    LOGIC = "logic"               # 逻辑漏洞检测  
    API_SECURITY = "api_security" # API安全扫描
    AUTH_BYPASS = "auth_bypass"   # 身份验证绕过


@dataclass
class AdvancedDetectionConfig:
    """高级检测配置"""
    
    # 模块启用配置
    enable_zero_day: bool = True
    enable_logic: bool = True
    enable_api_security: bool = True
    enable_auth_bypass: bool = True
    
    # 扫描深度配置
    scan_depth: str = "medium"  # low, medium, high, paranoid
    
    # 性能配置
    max_concurrent_detections: int = 3
    timeout_per_module: int = 300  # 5分钟
    
    # 报告配置
    generate_detailed_report: bool = True
    include_evidence: bool = True
    include_remediation: bool = True
    
    # 目标特定配置
    skip_targets: List[str] = field(default_factory=list)
    focus_targets: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "modules": {
                "zero_day": self.enable_zero_day,
                "logic": self.enable_logic,
                "api_security": self.enable_api_security,
                "auth_bypass": self.enable_auth_bypass
            },
            "scan_depth": self.scan_depth,
            "performance": {
                "max_concurrent_detections": self.max_concurrent_detections,
                "timeout_per_module": self.timeout_per_module
            },
            "report": {
                "detailed": self.generate_detailed_report,
                "include_evidence": self.include_evidence,
                "include_remediation": self.include_remediation
            },
            "targets": {
                "skip": self.skip_targets,
                "focus": self.focus_targets
            }
        }


@dataclass
class AdvancedVulnerability:
    """高级漏洞统一格式"""
    module: str                    # 检测模块
    category: str                  # 漏洞类别
    title: str                     # 漏洞标题
    description: str               # 漏洞描述
    severity: str                  # 严重程度 (critical, high, medium, low, info)
    confidence: float              # 置信度 (0.0-1.0)
    evidence: Dict[str, Any]       # 漏洞证据
    location: str                  # 漏洞位置
    remediation: str               # 修复建议
    references: List[str]          # 参考链接
    cvss_score: Optional[float] = None  # CVSS评分
    timestamp: str = ""            # 检测时间
    
    def to_dict(self) -> Dict:
        return {
            "module": self.module,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "confidence": round(self.confidence, 2),
            "evidence": self.evidence,
            "location": self.location,
            "remediation": self.remediation,
            "references": self.references,
            "cvss_score": self.cvss_score,
            "timestamp": self.timestamp or time.strftime("%Y-%m-%d %H:%M:%S")
        }


class AdvancedDetectionManager:
    """高级漏洞检测管理器"""
    
    def __init__(self, config: AdvancedDetectionConfig = None):
        self.config = config or AdvancedDetectionConfig()
        
        # 模块实例
        self.modules = {}
        
        # 性能指标
        self.metrics = {
            "total_targets": 0,
            "completed_detections": 0,
            "detected_vulnerabilities": 0,
            "module_stats": {},
            "total_duration": 0,
            "start_time": None
        }
        
        # 检测结果
        self.results = []
        
        print(f"高级漏洞检测管理器初始化完成")
        print(f"配置: {json.dumps(self.config.to_dict(), indent=2)}")
    
    async def initialize(self):
        """初始化所有检测模块"""
        print("初始化高级检测模块...")
        
        # 零日漏洞检测模块
        if self.config.enable_zero_day:
            try:
                from zero_day_detector import ZeroDayDetector
                self.modules[DetectionModule.ZERO_DAY] = ZeroDayDetector()
                print(f"  零日漏洞检测模块: 加载成功")
                
                # 更新模板
                print(f"  更新Nuclei模板...")
                try:
                    self.modules[DetectionModule.ZERO_DAY].update_templates()
                    print(f"  模板更新完成")
                except Exception as e:
                    print(f"  模板更新失败: {e}")
                    
            except ImportError as e:
                print(f"  零日漏洞检测模块: 加载失败 - {e}")
        
        # 逻辑漏洞检测模块
        if self.config.enable_logic:
            try:
                from logic_vulnerability_detector import LogicVulnerabilityDetector
                self.modules[DetectionModule.LOGIC] = LogicVulnerabilityDetector()
                print(f"  逻辑漏洞检测模块: 加载成功")
            except ImportError as e:
                print(f"  逻辑漏洞检测模块: 加载失败 - {e}")
        
        # API安全扫描模块
        if self.config.enable_api_security:
            try:
                from api_security_scanner import APISecurityScanner
                self.modules[DetectionModule.API_SECURITY] = APISecurityScanner()
                print(f"  API安全扫描模块: 加载成功")
            except ImportError as e:
                print(f"  API安全扫描模块: 加载失败 - {e}")
        
        # 身份验证绕过模块
        if self.config.enable_auth_bypass:
            try:
                from auth_bypass_detector import AuthBypassDetector
                self.modules[DetectionModule.AUTH_BYPASS] = AuthBypassDetector()
                print(f"  身份验证绕过模块: 加载成功")
            except ImportError as e:
                print(f"  身份验证绕过模块: 加载失败 - {e}")
        
        print(f"模块初始化完成: {len(self.modules)}/{4} 个模块可用")
    
    async def detect_target(self, target: str) -> List[AdvancedVulnerability]:
        """检测单个目标"""
        vulnerabilities = []
        
        # 跳过特定目标
        if target in self.config.skip_targets:
            print(f"跳过目标: {target}")
            return vulnerabilities
        
        print(f"开始检测目标: {target}")
        
        # 并发执行所有启用的模块
        tasks = []
        for module_name, module in self.modules.items():
            task = asyncio.create_task(self._run_detection_module(module_name, module, target))
            tasks.append(task)
        
        # 等待所有检测完成
        module_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 收集结果
        for i, (module_name, result) in enumerate(zip(self.modules.keys(), module_results)):
            if isinstance(result, Exception):
                print(f"  {module_name.value} 模块检测失败: {result}")
                continue
            
            if result:
                vulnerabilities.extend(result)
                self.metrics["detected_vulnerabilities"] += len(result)
                print(f"  {module_name.value} 模块: 发现 {len(result)} 个漏洞")
        
        return vulnerabilities
    
    async def _run_detection_module(self, module_name: DetectionModule, module, target: str):
        """运行单个检测模块"""
        try:
            # 根据模块类型调用不同的方法
            if module_name == DetectionModule.ZERO_DAY:
                result = await module.scan_target_async(target)
            elif module_name == DetectionModule.LOGIC:
                result = await module.detect_logic_vulnerabilities(target)
            elif module_name == DetectionModule.API_SECURITY:
                result = await module.scan_api(target)
            elif module_name == DetectionModule.AUTH_BYPASS:
                result = await module.test_auth_mechanisms(target)
            else:
                result = []
            
            # 转换为统一格式
            return self._convert_to_advanced_vulnerabilities(module_name, result)
            
        except Exception as e:
            print(f"  模块 {module_name.value} 执行异常: {e}")
            return []
    
    def _convert_to_advanced_vulnerabilities(self, module_name: DetectionModule, raw_results):
        """将原始结果转换为高级漏洞格式"""
        vulnerabilities = []
        
        # 这里应该根据每个模块的实际结果格式进行转换
        # 目前先返回空列表，等模块具体实现后再完善
        
        return vulnerabilities
    
    async def detect_many(self, targets: List[str]) -> Dict[str, List[AdvancedVulnerability]]:
        """检测多个目标"""
        print(f"开始高级漏洞检测，目标数量: {len(targets)}")
        
        await self.initialize()
        
        self.metrics["total_targets"] = len(targets)
        self.metrics["start_time"] = time.time()
        
        results = {}
        
        # 按顺序检测每个目标（未来可以改为并发）
        for target in targets:
            print(f"\n检测目标 {len(results) + 1}/{len(targets)}: {target}")
            
            vulnerabilities = await self.detect_target(target)
            results[target] = vulnerabilities
            
            self.metrics["completed_detections"] += 1
            
            # 显示进度
            progress = self.metrics["completed_detections"] / self.metrics["total_targets"] * 100
            print(f"进度: {progress:.1f}% - 发现 {len(vulnerabilities)} 个漏洞")
        
        # 计算总耗时
        self.metrics["total_duration"] = time.time() - self.metrics["start_time"]
        
        print(f"\n高级漏洞检测完成!")
        print(f"总耗时: {self.metrics['total_duration']:.2f}秒")
        print(f"检测目标: {self.metrics['completed_detections']}/{self.metrics['total_targets']}")
        print(f"发现漏洞: {self.metrics['detected_vulnerabilities']}个")
        
        return results
    
    def generate_report(self, results: Dict[str, List[AdvancedVulnerability]]) -> Dict:
        """生成详细报告"""
        report = {
            "summary": {
                "total_targets": self.metrics["total_targets"],
                "completed_targets": self.metrics["completed_detections"],
                "total_vulnerabilities": self.metrics["detected_vulnerabilities"],
                "total_duration": round(self.metrics["total_duration"], 2),
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "configuration": self.config.to_dict()
            },
            "vulnerabilities_by_target": {},
            "vulnerabilities_by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            },
            "vulnerabilities_by_module": {
                "zero_day": 0,
                "logic": 0,
                "api_security": 0,
                "auth_bypass": 0
            }
        }
        
        # 统计漏洞
        for target, vulns in results.items():
            report["vulnerabilities_by_target"][target] = []
            
            for vuln in vulns:
                # 添加到目标列表
                report["vulnerabilities_by_target"][target].append(vuln.to_dict())
                
                # 按严重程度统计
                severity = vuln.severity.lower()
                if severity in report["vulnerabilities_by_severity"]:
                    report["vulnerabilities_by_severity"][severity] += 1
                
                # 按模块统计
                module = vuln.module
                if module in report["vulnerabilities_by_module"]:
                    report["vulnerabilities_by_module"][module] += 1
        
        # 生成风险评分
        report["risk_score"] = self._calculate_risk_score(report)
        
        return report
    
    def _calculate_risk_score(self, report: Dict) -> float:
        """计算风险评分（0-10）"""
        weights = {
            "critical": 10.0,
            "high": 7.5,
            "medium": 5.0,
            "low": 2.5,
            "info": 0.5
        }
        
        total_score = 0
        for severity, count in report["vulnerabilities_by_severity"].items():
            total_score += weights.get(severity, 0) * count
        
        # 归一化到0-10
        risk_score = min(total_score / (report["total_targets"] + 1) * 2, 10)
        return round(risk_score, 1)
    
    def save_report(self, report: Dict, filename: str = "advanced_detection_report.json"):
        """保存报告到文件"""
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"报告已保存: {filename}")
        return filename


async def demo_advanced_detection():
    """演示高级漏洞检测"""
    print("=" * 60)
    print("高级漏洞检测演示")
    print("=" * 60)
    
    # 测试目标
    targets = [
        "http://192.168.18.131/dvwa/",
        "http://192.168.18.131/mutillidae/"
    ]
    
    # 配置
    config = AdvancedDetectionConfig(
        enable_zero_day=True,
        enable_logic=True,
        enable_api_security=True,
        enable_auth_bypass=True,
        scan_depth="medium"
    )
    
    # 创建管理器
    manager = AdvancedDetectionManager(config)
    
    # 执行检测
    print(f"开始检测 {len(targets)} 个目标...")
    results = await manager.detect_many(targets)
    
    # 生成报告
    print(f"\n生成详细报告...")
    report = manager.generate_report(results)
    
    # 显示摘要
    print("\n" + "=" * 60)
    print("高级漏洞检测结果摘要")
    print("=" * 60)
    
    print(f"目标数量: {report['summary']['total_targets']}")
    print(f"完成检测: {report['summary']['completed_targets']}")
    print(f"总耗时: {report['summary']['total_duration']}秒")
    print(f"发现漏洞: {report['summary']['total_vulnerabilities']}个")
    
    print(f"\n漏洞分布:")
    for severity, count in report["vulnerabilities_by_severity"].items():
        if count > 0:
            print(f"  {severity}: {count}个")
    
    print(f"\n模块检测结果:")
    for module, count in report["vulnerabilities_by_module"].items():
        print(f"  {module}: {count}个")
    
    print(f"\n风险评分: {report['risk_score']}/10")
    
    if report['risk_score'] >= 7:
        print("⚠️  高风险目标，需要立即修复!")
    elif report['risk_score'] >= 4:
        print("⚠️  中风险目标，建议修复")
    else:
        print("✅ 低风险目标，安全性较好")
    
    # 保存报告
    manager.save_report(report)
    
    return manager, report


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    
    print("启动高级漏洞检测演示...")
    manager, report = asyncio.run(demo_advanced_detection())