#!/usr/bin/env python3
"""
零日漏洞检测模块 - 基于Nuclei集成
"""
import asyncio
import json
import os
import subprocess
import time
from dataclasses import dataclass
from typing import List, Dict, Optional, Any
import yaml

@dataclass
class ZeroDayVulnerability:
    """零日漏洞结果"""
    template_id: str
    template_name: str
    severity: str
    description: str
    matched_at: str
    info: Dict[str, Any]
    confidence: float = 1.0
    evidence: Dict[str, Any] = None
    
    def to_dict(self):
        return {
            "template_id": self.template_id,
            "template_name": self.template_name,
            "severity": self.severity,
            "description": self.description,
            "matched_at": self.matched_at,
            "info": self.info,
            "confidence": self.confidence,
            "evidence": self.evidence or {}
        }


class NucleiTemplateManager:
    """Nuclei模板管理器"""
    
    def __init__(self, nuclei_path: str = None, template_dir: str = None):
        self.nuclei_path = nuclei_path or r"C:\Tools\nuclei\nuclei.exe"
        self.template_dir = template_dir or "./nuclei-templates"
        
        if not os.path.exists(self.nuclei_path):
            raise FileNotFoundError(f"Nuclei未找到: {self.nuclei_path}")
    
    def update_templates(self):
        """更新模板"""
        print(f"更新Nuclei模板...")
        
        # 确保模板目录存在
        os.makedirs(self.template_dir, exist_ok=True)
        
        # 运行nuclei更新命令
        cmd = [self.nuclei_path, "-update-templates"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                print("模板更新成功")
                return True
            else:
                print(f"模板更新失败: {result.stderr}")
                return False
        except Exception as e:
            print(f"模板更新异常: {e}")
            return False
    
    def get_template_stats(self) -> Dict:
        """获取模板统计信息"""
        cmd = [self.nuclei_path, "-tl"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                # 解析输出
                stats = {}
                for line in result.stdout.split('\n'):
                    if 'templates' in line.lower():
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            stats['total_templates'] = int(parts[0])
                return stats
            return {"error": "获取模板统计失败"}
        except Exception as e:
            return {"error": str(e)}


class TemplateMatcher:
    """模板匹配器"""
    
    def __init__(self):
        self.template_cache = {}
    
    def match_templates(self, target_info: Dict) -> List[str]:
        """基于目标信息匹配模板"""
        # 简化的匹配逻辑
        # 实际实现应该基于目标的技术栈、端口、服务等
        
        recommended_templates = []
        
        # 根据目标类型推荐模板
        if target_info.get('has_web'):
            recommended_templates.extend([
                "cves", "vulnerabilities", "exposures",
                "misconfiguration", "technologies"
            ])
        
        return recommended_templates


class TemplateExecutor:
    """模板执行器"""
    
    def __init__(self, nuclei_path: str = None):
        self.nuclei_path = nuclei_path or r"C:\Tools\nuclei\nuclei.exe"
        self.max_concurrent = 3
    
    async def execute_template(self, target: str, template: str) -> List[Dict]:
        """执行单个模板"""
        cmd = [
            self.nuclei_path,
            "-u", target,
            "-t", template,
            "-json",
            "-timeout", "30",
            "-rate-limit", "10"
        ]
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                results = []
                for line in stdout.decode().strip().split('\n'):
                    if line:
                        try:
                            result = json.loads(line)
                            results.append(result)
                        except json.JSONDecodeError:
                            continue
                return results
            else:
                print(f"模板执行失败: {stderr.decode()}")
                return []
                
        except Exception as e:
            print(f"执行异常: {e}")
            return []
    
    async def execute_templates(self, target: str, templates: List[str]) -> Dict[str, List[Dict]]:
        """并发执行多个模板"""
        tasks = []
        for template in templates[:10]:  # 限制前10个模板
            task = asyncio.create_task(self.execute_template(target, template))
            tasks.append(task)
        
        # 限制并发数
        results_by_template = {}
        for i in range(0, len(tasks), self.max_concurrent):
            batch = tasks[i:i + self.max_concurrent]
            batch_results = await asyncio.gather(*batch, return_exceptions=True)
            
            for j, result in enumerate(batch_results):
                template_index = i + j
                if template_index < len(templates):
                    template = templates[template_index]
                    if isinstance(result, Exception):
                        print(f"模板 {template} 执行异常: {result}")
                        results_by_template[template] = []
                    else:
                        results_by_template[template] = result
        
        return results_by_template


class TemplateResultAnalyzer:
    """模板结果分析器"""
    
    def __init__(self):
        self.severity_weights = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.5,
            "low": 0.3,
            "info": 0.1
        }
    
    def analyze_results(self, results_by_template: Dict[str, List[Dict]]) -> List[ZeroDayVulnerability]:
        """分析结果并转换为漏洞对象"""
        vulnerabilities = []
        
        for template, results in results_by_template.items():
            for result in results:
                vuln = self._parse_result(result, template)
                if vuln:
                    vulnerabilities.append(vuln)
        
        # 按严重程度排序
        vulnerabilities.sort(key=lambda x: self.severity_weights.get(x.severity.lower(), 0), reverse=True)
        
        return vulnerabilities
    
    def _parse_result(self, result: Dict, template: str) -> Optional[ZeroDayVulnerability]:
        """解析单个结果"""
        try:
            template_info = result.get("template-id", "").split("/")
            template_name = template_info[-1] if template_info else template
            
            severity = result.get("info", {}).get("severity", "medium").lower()
            description = result.get("info", {}).get("description", "")
            matched_at = result.get("matched-at", "")
            
            # 计算置信度
            confidence = self._calculate_confidence(result)
            
            return ZeroDayVulnerability(
                template_id=result.get("template-id", template),
                template_name=template_name,
                severity=severity,
                description=description,
                matched_at=matched_at,
                info=result.get("info", {}),
                confidence=confidence,
                evidence=result
            )
        except Exception as e:
            print(f"解析结果失败: {e}")
            return None
    
    def _calculate_confidence(self, result: Dict) -> float:
        """计算置信度"""
        base_confidence = 0.7
        
        # 根据严重程度调整
        severity = result.get("info", {}).get("severity", "medium").lower()
        if severity == "critical":
            base_confidence += 0.2
        elif severity == "high":
            base_confidence += 0.1
        
        # 根据匹配证据调整
        if result.get("matcher-status", False):
            base_confidence += 0.1
        
        return min(base_confidence, 1.0)


class ZeroDayDetector:
    """零日漏洞检测主类"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        
        # 初始化组件
        self.template_manager = NucleiTemplateManager(
            self.config.get('nuclei_path'),
            self.config.get('template_dir')
        )
        self.template_matcher = TemplateMatcher()
        self.template_executor = TemplateExecutor(self.config.get('nuclei_path'))
        self.result_analyzer = TemplateResultAnalyzer()
        
        print("零日漏洞检测器初始化完成")
    
    def update_templates(self):
        """更新模板"""
        return self.template_manager.update_templates()
    
    async def scan_target(self, target: str) -> List[ZeroDayVulnerability]:
        """扫描单个目标"""
        print(f"开始零日漏洞扫描: {target}")
        
        # 1. 获取目标信息（简化）
        target_info = self._analyze_target(target)
        
        # 2. 匹配模板
        template_categories = self.template_matcher.match_templates(target_info)
        
        # 3. 执行模板
        results_by_template = await self.template_executor.execute_templates(target, template_categories)
        
        # 4. 分析结果
        vulnerabilities = self.result_analyzer.analyze_results(results_by_template)
        
        print(f"扫描完成，发现 {len(vulnerabilities)} 个零日漏洞")
        return vulnerabilities
    
    async def scan_multiple_targets(self, targets: List[str]) -> Dict[str, List[ZeroDayVulnerability]]:
        """扫描多个目标"""
        results = {}
        
        tasks = []
        for target in targets:
            task = asyncio.create_task(self.scan_target(target))
            tasks.append(task)
        
        # 限制并发
        for i in range(0, len(tasks), 3):
            batch = tasks[i:i + 3]
            batch_results = await asyncio.gather(*batch, return_exceptions=True)
            
            for j, result in enumerate(batch_results):
                target_index = i + j
                if target_index < len(targets):
                    target = targets[target_index]
                    if isinstance(result, Exception):
                        print(f"目标 {target} 扫描失败: {result}")
                        results[target] = []
                    else:
                        results[target] = result
        
        return results
    
    def _analyze_target(self, target: str) -> Dict:
        """分析目标（简化版）"""
        # 实际实现应该进行端口扫描、技术栈识别等
        return {
            "url": target,
            "has_web": True,
            "technologies": []  # 应该填充实际检测到的技术
        }
    
    def generate_report(self, vulnerabilities: List[ZeroDayVulnerability]) -> Dict:
        """生成报告"""
        return {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_vulnerabilities": len(vulnerabilities),
            "vulnerabilities_by_severity": self._group_by_severity(vulnerabilities),
            "vulnerabilities": [v.to_dict() for v in vulnerabilities]
        }
    
    def _group_by_severity(self, vulnerabilities: List[ZeroDayVulnerability]) -> Dict:
        """按严重程度分组"""
        groups = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in vulnerabilities:
            severity = v.severity.lower()
            if severity in groups:
                groups[severity] += 1
        return groups


async def demo_zero_day_detector():
    """演示零日漏洞检测器"""
    print("=" * 60)
    print("零日漏洞检测器演示")
    print("=" * 60)
    
    # 创建检测器
    detector = ZeroDayDetector()
    
    # 更新模板
    print("1. 更新Nuclei模板...")
    success = detector.update_templates()
    if not success:
        print("  模板更新失败，使用现有模板继续")
    
    # 扫描目标
    targets = ["http://192.168.18.131/dvwa/"]
    
    print(f"\n2. 扫描目标: {targets[0]}")
    vulnerabilities = await detector.scan_target(targets[0])
    
    # 显示结果
    print(f"\n3. 扫描结果:")
    print(f"   发现漏洞: {len(vulnerabilities)} 个")
    
    if vulnerabilities:
        print(f"\n   漏洞详情:")
        for i, vuln in enumerate(vulnerabilities[:5]):  # 显示前5个
            print(f"   {i+1}. [{vuln.severity.upper()}] {vuln.template_name}")
            print(f"      描述: {vuln.description[:100]}...")
            print(f"      置信度: {vuln.confidence:.1%}")
    
    # 生成报告
    report = detector.generate_report(vulnerabilities)
    
    # 保存报告
    with open("zero_day_detection_report.json", "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"\n报告已保存: zero_day_detection_report.json")
    
    return detector


if __name__ == "__main__":
    print("启动零日漏洞检测器...")
    detector = asyncio.run(demo_zero_day_detector())