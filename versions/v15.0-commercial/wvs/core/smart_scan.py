"""智能扫描模块 - AI驱动的自适应扫描"""
import re
import json
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from collections import defaultdict
import hashlib


@dataclass
class TargetProfile:
    """目标画像"""
    tech_stack: List[str]           # 技术栈
    frameworks: List[str]           # 框架
    languages: List[str]            # 编程语言
    server_software: str = ""       # 服务器软件
    cms: str = ""                   # CMS类型
    waf_detected: bool = False      # 是否检测到WAF
    rate_limit: bool = False        # 是否有限流


class SmartScanner:
    """智能扫描器"""
    
    def __init__(self):
        self.target_profile: Optional[TargetProfile] = None
        self.scan_history: List[Dict] = []
        self.adaptive_delay = 0.1
        self.concurrency = 50
    
    def analyze_target(self, responses: List[Dict]) -> TargetProfile:
        """分析目标技术栈"""
        tech_stack = set()
        frameworks = set()
        languages = set()
        server_software = ""
        cms = ""
        waf_detected = False
        
        for resp in responses:
            headers = resp.get("headers", {})
            body = resp.get("body", "")
            
            # 检测服务器软件
            server = headers.get("Server", "")
            if server:
                server_software = server
                tech_stack.add(server.split("/")[0])
            
            # 检测框架
            if "X-Powered-By" in headers:
                frameworks.add(headers["X-Powered-By"])
            
            # 检测WAF
            waf_signatures = [
                "cloudflare", "akamai", "incapsula", "sucuri",
                "mod_security", "aws", "aliyun"
            ]
            for waf in waf_signatures:
                if waf in str(headers).lower() or waf in body.lower():
                    waf_detected = True
                    tech_stack.add(f"WAF:{waf}")
            
            # 检测CMS
            cms_signatures = {
                "wordpress": ["/wp-content/", "wp-includes"],
                "drupal": ["/sites/default/", "drupal.js"],
                "joomla": ["/components/", "/modules/"],
                "django": ["csrfmiddlewaretoken", "__debug__"],
                "spring": ["Whitelabel Error Page", "spring-boot"],
            }
            for cms_name, sigs in cms_signatures.items():
                if any(sig in body for sig in sigs):
                    cms = cms_name
                    tech_stack.add(cms_name)
            
            # 检测编程语言
            lang_signatures = {
                "php": [".php", "<?php"],
                "jsp": [".jsp", "<%@"],
                "asp": [".asp", "<%@"],
                "python": ["django", "flask", "python"],
                "nodejs": ["express", "node.js", "npm"],
            }
            for lang, sigs in lang_signatures.items():
                if any(sig in body.lower() for sig in sigs):
                    languages.add(lang)
        
        self.target_profile = TargetProfile(
            tech_stack=list(tech_stack),
            frameworks=list(frameworks),
            languages=list(languages),
            server_software=server_software,
            cms=cms,
            waf_detected=waf_detected,
        )
        
        return self.target_profile
    
    def adapt_strategy(self) -> Dict:
        """根据目标画像调整扫描策略"""
        if not self.target_profile:
            return self._default_strategy()
        
        strategy = {
            "concurrency": 50,
            "delay": 0.1,
            "payloads": [],
            "checks": {},
        }
        
        profile = self.target_profile
        
        # WAF检测 - 降低并发，增加延迟
        if profile.waf_detected:
            strategy["concurrency"] = 20
            strategy["delay"] = 0.5
            strategy["evasion"] = True
        
        # 根据技术栈选择payload
        if "wordpress" in profile.tech_stack:
            strategy["payloads"].extend(self._get_wordpress_payloads())
        if "php" in profile.languages:
            strategy["payloads"].extend(self._get_php_payloads())
        if "django" in profile.tech_stack or "python" in profile.languages:
            strategy["payloads"].extend(self._get_python_payloads())
        if "nodejs" in profile.languages:
            strategy["payloads"].extend(self._get_nodejs_payloads())
        
        # 根据框架选择检测项
        if profile.cms:
            strategy["checks"]["cms_vulnerabilities"] = True
        if profile.frameworks:
            strategy["checks"]["framework_vulnerabilities"] = True
        
        self.concurrency = strategy["concurrency"]
        self.adaptive_delay = strategy["delay"]
        
        return strategy
    
    def _default_strategy(self) -> Dict:
        """默认策略"""
        return {
            "concurrency": 50,
            "delay": 0.1,
            "payloads": [],
            "checks": {"all": True},
        }
    
    def _get_wordpress_payloads(self) -> List[str]:
        """WordPress专用payload"""
        return [
            "?author=1",
            "/wp-json/wp/v2/users",
            "/?rest_route=/wp/v2/users",
            "wp-content/plugins/",
        ]
    
    def _get_php_payloads(self) -> List[str]:
        """PHP专用payload"""
        return [
            "<?php echo 'test'; ?>",
            "<?=system($_GET['cmd'])?>",
            "php://filter/read=convert.base64-encode/resource=",
        ]
    
    def _get_python_payloads(self) -> List[str]:
        """Python专用payload"""
        return [
            "{{config}}",
            "{{7*7}}",
            "{% import os %}{{os.system('id')}}",
        ]
    
    def _get_nodejs_payloads(self) -> List[str]:
        """Node.js专用payload"""
        return [
            "require('child_process').exec('id')",
            "process.mainModule.require('child_process').execSync('id')",
        ]


class SemanticDeduplicator:
    """语义去重器"""
    
    def __init__(self):
        self.seen_signatures: set = set()
        self.similarity_threshold = 0.85
    
    def get_signature(self, vuln: Dict) -> str:
        """生成漏洞签名"""
        # 基于漏洞类型、URL路径、参数名生成签名
        vuln_type = vuln.get("type", "unknown")
        url = vuln.get("url", "")
        param = vuln.get("parameter", "")
        
        # 提取URL路径（不含域名和查询参数）
        path = re.sub(r'^https?://[^/]+', '', url).split('?')[0]
        
        # 归一化路径
        path = re.sub(r'/\d+', '/{id}', path)
        path = re.sub(r'[a-f0-9]{32}', '{hash}', path)
        
        signature = f"{vuln_type}:{path}:{param}"
        return hashlib.md5(signature.encode()).hexdigest()
    
    def is_duplicate(self, vuln: Dict) -> bool:
        """检查是否重复"""
        signature = self.get_signature(vuln)
        
        if signature in self.seen_signatures:
            return True
        
        # 检查相似度
        for seen_vuln in self._get_seen_vulns():
            if self._calculate_similarity(vuln, seen_vuln) > self.similarity_threshold:
                return True
        
        self.seen_signatures.add(signature)
        return False
    
    def _get_seen_vulns(self) -> List[Dict]:
        """获取已记录的漏洞"""
        # 这里应该从数据库加载
        return []
    
    def _calculate_similarity(self, vuln1: Dict, vuln2: Dict) -> float:
        """计算漏洞相似度"""
        # 简单实现：比较类型和URL
        if vuln1.get("type") != vuln2.get("type"):
            return 0.0
        
        url1 = vuln1.get("url", "")
        url2 = vuln2.get("url", "")
        
        # 使用编辑距离计算URL相似度
        distance = self._levenshtein_distance(url1, url2)
        max_len = max(len(url1), len(url2))
        
        if max_len == 0:
            return 1.0
        
        return 1.0 - (distance / max_len)
    
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """计算编辑距离"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]


class VulnerabilityPredictor:
    """漏洞预测器"""
    
    def __init__(self):
        self.historical_data: List[Dict] = []
        self.pattern_weights = defaultdict(float)
    
    def train(self, historical_vulns: List[Dict]):
        """训练预测模型"""
        self.historical_data = historical_vulns
        
        # 统计漏洞模式
        for vuln in historical_vulns:
            url_pattern = self._extract_url_pattern(vuln.get("url", ""))
            vuln_type = vuln.get("type", "unknown")
            
            key = f"{vuln_type}:{url_pattern}"
            self.pattern_weights[key] += 1
    
    def predict(self, target_urls: List[str]) -> List[Dict]:
        """预测可能存在漏洞的URL"""
        predictions = []
        
        for url in target_urls:
            url_pattern = self._extract_url_pattern(url)
            
            # 查找匹配的模式
            for key, weight in self.pattern_weights.items():
                vuln_type, pattern = key.split(":", 1)
                
                if pattern in url_pattern or url_pattern in pattern:
                    confidence = min(weight / 10, 1.0)  # 归一化
                    predictions.append({
                        "url": url,
                        "predicted_type": vuln_type,
                        "confidence": confidence,
                        "reason": f"Historical pattern match: {pattern}",
                    })
        
        # 按置信度排序
        predictions.sort(key=lambda x: x["confidence"], reverse=True)
        return predictions[:10]  # 返回前10个
    
    def _extract_url_pattern(self, url: str) -> str:
        """提取URL模式"""
        # 移除域名和协议
        path = re.sub(r'^https?://[^/]+', '', url)
        
        # 归一化
        path = re.sub(r'/\d+', '/{num}', path)
        path = re.sub(r'\?.*$', '', path)  # 移除查询参数
        
        return path


class FalsePositiveFilter:
    """误报过滤器"""
    
    def __init__(self):
        self.fp_patterns = [
            r"captcha", r"验证码", r"robot", r"bot check",
            r"maintenance", r"维护", r"coming soon",
            r"403 forbidden", r"401 unauthorized",
        ]
        self.confirmed_vulns: set = set()
    
    def filter(self, vulns: List[Dict]) -> List[Dict]:
        """过滤误报"""
        filtered = []
        
        for vuln in vulns:
            # 检查是否是误报模式
            if self._is_false_positive(vuln):
                continue
            
            # 检查是否已确认
            if self._is_confirmed(vuln):
                vuln["confirmed"] = True
            
            filtered.append(vuln)
        
        return filtered
    
    def _is_false_positive(self, vuln: Dict) -> bool:
        """检查是否是误报"""
        response = vuln.get("response", "")
        
        for pattern in self.fp_patterns:
            if re.search(pattern, response, re.IGNORECASE):
                return True
        
        return False
    
    def _is_confirmed(self, vuln: Dict) -> bool:
        """检查是否已确认"""
        signature = f"{vuln.get('type')}:{vuln.get('url')}"
        return signature in self.confirmed_vulns
    
    def confirm(self, vuln: Dict):
        """确认漏洞"""
        signature = f"{vuln.get('type')}:{vuln.get('url')}"
        self.confirmed_vulns.add(signature)
