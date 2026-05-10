"""上下文感知扫描模块"""
import re
import asyncio
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum


class RiskLevel(Enum):
    """风险等级"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class TargetContext:
    """目标上下文信息"""
    framework: str
    auth_method: str
    risk_level: str
    recommended_template: str
    tech_stack: List[str]
    server_software: str
    cms: str
    waf_detected: bool


class ContextAwareScanner:
    """上下文感知扫描器"""
    
    FRAMEWORK_SIGNATURES = {
        'wordpress': [
            r'/wp-content/',
            r'/wp-includes/',
            r'WordPress [\d.]+',
            r'wp-json',
        ],
        'spring_boot': [
            r'Spring Boot [\d.]+',
            r'/actuator/health',
            r'/actuator/info',
            r'Whitelabel Error Page',
        ],
        'django': [
            r'powered by Django',
            r'csrfmiddlewaretoken',
            r'/admin/jsi18n/',
            r'__debug__',
        ],
        'react': [
            r'data-reactroot',
            r'react-dom.production.min.js',
            r'__REACT_DEVTOOLS_GLOBAL_HOOK__',
        ],
        'vue': [
            r'vue\.js',
            r'__VUE__',
            r'data-v-',
        ],
        'angular': [
            r'ng-',
            r'angular\.js',
            r'__ngContext',
        ],
        'laravel': [
            r'Laravel',
            r'csrf-token',
        ],
        'rails': [
            r'Rails',
            r'csrf-param',
            r'authenticity_token',
        ],
    }
    
    AUTH_PATTERNS = {
        'jwt': [
            r'Bearer [A-Za-z0-9-_.]+',
            r'Authorization: Bearer',
        ],
        'session': [
            r'Session=[A-Za-z0-9]+',
            r'PHPSESSID=[A-Za-z0-9]+',
            r'JSESSIONID=[A-Za-z0-9]+',
        ],
        'oauth': [
            r'access_token=[A-Za-z0-9]+',
            r'refresh_token=[A-Za-z0-9]+',
        ],
        'api_key': [
            r'X-API-Key',
            r'api-key',
            r'apikey',
        ],
        'basic_auth': [
            r'WWW-Authenticate: Basic',
            r'Authorization: Basic [A-Za-z0-9]+',
        ],
    }
    
    CMS_SIGNATURES = {
        'wordpress': [r'/wp-content/', r'/wp-admin/', r'wp-json'],
        'drupal': [r'/sites/default/', r'drupal.js', r'/node/'],
        'joomla': [r'/components/', r'/modules/', r'com_'],
        'magento': [r'/skin/frontend/', r'Mage.Cookies'],
        'shopify': [r'myshopify.com', r'shopify.com'],
    }
    
    def __init__(self):
        self.session = None
    
    async def analyze(self, target_url: str, session=None) -> TargetContext:
        """分析目标上下文"""
        self.session = session
        
        # 获取页面内容
        html, headers = await self._fetch_page(target_url)
        
        # 检测框架
        framework = self._detect_framework(html, headers)
        
        # 检测认证方式
        auth_method = self._detect_auth_method(html, headers)
        
        # 检测CMS
        cms = self._detect_cms(html, headers)
        
        # 检测技术栈
        tech_stack = self._detect_tech_stack(html, headers)
        
        # 检测服务器软件
        server_software = headers.get('Server', '')
        
        # 检测WAF
        waf_detected = self._detect_waf(headers)
        
        # 计算风险等级
        risk_level = self._calculate_risk_level(
            framework, auth_method, cms, waf_detected
        )
        
        # 推荐扫描模板
        recommended_template = self._select_template(
            framework, auth_method, cms, risk_level
        )
        
        return TargetContext(
            framework=framework,
            auth_method=auth_method,
            risk_level=risk_level,
            recommended_template=recommended_template,
            tech_stack=tech_stack,
            server_software=server_software,
            cms=cms,
            waf_detected=waf_detected,
        )
    
    async def _fetch_page(self, url: str) -> tuple:
        """获取页面内容"""
        # 这里应该使用实际的HTTP请求
        # 简化实现，返回模拟数据
        html = ""
        headers = {}
        
        if self.session:
            try:
                # 实际实现时使用aiohttp
                pass
            except Exception as e:
                print(f"Error fetching {url}: {e}")
        
        return html, headers
    
    def _detect_framework(self, html: str, headers: Dict) -> str:
        """检测Web框架"""
        content = html + str(headers)
        
        for framework, patterns in self.FRAMEWORK_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return framework
        
        # 检测技术栈提示
        powered_by = headers.get('X-Powered-By', '')
        if powered_by:
            return powered_by.lower()
        
        return 'unknown'
    
    def _detect_auth_method(self, html: str, headers: Dict) -> str:
        """检测认证方式"""
        content = html + str(headers)
        
        for auth_type, patterns in self.AUTH_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return auth_type
        
        # 检查认证端点
        auth_indicators = ['login', 'auth', 'signin', 'oauth', 'sso']
        if any(indicator in html.lower() for indicator in auth_indicators):
            return 'form_based'
        
        return 'none'
    
    def _detect_cms(self, html: str, headers: Dict) -> str:
        """检测CMS"""
        content = html + str(headers)
        
        for cms, patterns in self.CMS_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return cms
        
        return ''
    
    def _detect_tech_stack(self, html: str, headers: Dict) -> List[str]:
        """检测技术栈"""
        stack = []
        
        # 从框架检测
        framework = self._detect_framework(html, headers)
        if framework != 'unknown':
            stack.append(framework)
        
        # 检测编程语言
        content = html + str(headers)
        
        lang_signatures = {
            'php': [r'\.php', r'<?php', r'X-Powered-By: PHP'],
            'python': [r'python', r'django', r'flask', r'wsgi'],
            'nodejs': [r'node.js', r'express', r'npm'],
            'java': [r'java', r'spring', r'tomcat', r'jetty'],
            'ruby': [r'ruby', r'rails', r'sinatra'],
            'go': [r'go', r'gin', r'echo'],
        }
        
        for lang, patterns in lang_signatures.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    if lang not in stack:
                        stack.append(lang)
                    break
        
        return stack
    
    def _detect_waf(self, headers: Dict) -> bool:
        """检测WAF"""
        waf_signatures = [
            'cloudflare',
            'akamai',
            'incapsula',
            'sucuri',
            'mod_security',
            'aws',
            'aliyun',
            'baidu',
        ]
        
        header_str = str(headers).lower()
        for waf in waf_signatures:
            if waf in header_str:
                return True
        
        return False
    
    def _calculate_risk_level(self, framework: str, auth_method: str, 
                             cms: str, waf_detected: bool) -> str:
        """计算风险等级"""
        risk_score = 0
        
        # 框架风险评分
        framework_risks = {
            'wordpress': 3,
            'joomla': 2,
            'drupal': 2,
            'spring_boot': 1,
            'django': 1,
            'unknown': 2,
        }
        risk_score += framework_risks.get(framework, 1)
        
        # 认证风险评分
        auth_risks = {
            'none': 3,
            'form_based': 2,
            'session': 1,
            'jwt': 1,
            'oauth': 1,
        }
        risk_score += auth_risks.get(auth_method, 2)
        
        # CMS风险
        if cms in ['wordpress', 'joomla']:
            risk_score += 1
        
        # WAF降低风险
        if waf_detected:
            risk_score -= 1
        
        # 确定等级
        if risk_score >= 5:
            return RiskLevel.CRITICAL.value
        elif risk_score >= 3:
            return RiskLevel.HIGH.value
        elif risk_score >= 2:
            return RiskLevel.MEDIUM.value
        else:
            return RiskLevel.LOW.value
    
    def _select_template(self, framework: str, auth_method: str, 
                        cms: str, risk_level: str) -> str:
        """选择扫描模板"""
        # CMS专用模板
        if cms == 'wordpress':
            return 'wordpress_deep_scan'
        
        # API专用模板
        if auth_method in ['jwt', 'oauth', 'api_key']:
            return 'api_security_scan'
        
        # 框架专用模板
        if framework in ['spring_boot', 'django', 'laravel', 'rails']:
            return 'framework_specific_scan'
        
        # 根据风险等级选择
        if risk_level == RiskLevel.CRITICAL.value:
            return 'comprehensive_security_scan'
        elif risk_level == RiskLevel.HIGH.value:
            return 'deep_security_scan'
        else:
            return 'standard_security_scan'


class FrameworkDetector:
    """框架检测器"""
    
    def __init__(self):
        self.signatures = ContextAwareScanner.FRAMEWORK_SIGNATURES
    
    def detect(self, html: str, headers: Dict) -> Dict[str, float]:
        """检测框架并返回置信度"""
        content = html + str(headers)
        results = {}
        
        for framework, patterns in self.signatures.items():
            match_count = 0
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    match_count += 1
            
            # 计算置信度
            confidence = match_count / len(patterns) if patterns else 0
            if confidence > 0:
                results[framework] = round(confidence, 2)
        
        return results


class AuthAnalyzer:
    """认证分析器"""
    
    def __init__(self):
        self.patterns = ContextAwareScanner.AUTH_PATTERNS
    
    def analyze(self, html: str, headers: Dict) -> Dict[str, Any]:
        """分析认证机制"""
        content = html + str(headers)
        
        detected_methods = []
        for auth_type, patterns in self.patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    detected_methods.append(auth_type)
                    break
        
        # 评估安全性
        security_score = self._calculate_auth_security(detected_methods)
        
        return {
            'detected_methods': detected_methods,
            'security_score': security_score,
            'recommendations': self._generate_recommendations(detected_methods),
        }
    
    def _calculate_auth_security(self, methods: List[str]) -> int:
        """计算认证安全评分"""
        if not methods:
            return 0  # 无认证
        
        scores = {
            'oauth': 90,
            'jwt': 85,
            'api_key': 70,
            'session': 75,
            'basic_auth': 50,
            'form_based': 60,
        }
        
        return max(scores.get(m, 50) for m in methods)
    
    def _generate_recommendations(self, methods: List[str]) -> List[str]:
        """生成安全建议"""
        recommendations = []
        
        if 'none' in methods or not methods:
            recommendations.append("建议添加认证机制保护敏感资源")
        
        if 'basic_auth' in methods:
            recommendations.append("Basic Auth安全性较低，建议升级到JWT或OAuth2")
        
        if 'session' in methods:
            recommendations.append("确保Session使用安全的Cookie属性(HttpOnly, Secure)")
        
        return recommendations
