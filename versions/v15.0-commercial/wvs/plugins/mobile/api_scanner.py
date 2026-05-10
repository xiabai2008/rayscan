"""移动API安全扫描器 - v12.0"""
from typing import Dict, List, Any, Optional
import re
import requests
from dataclasses import dataclass


@dataclass
class MobileAPICheck:
    """移动API检查项"""
    name: str
    description: str
    severity: str
    check_func: callable


class MobileAPISecurityScanner:
    """移动后端API安全扫描器"""
    
    def __init__(self, api_gateway=None):
        self.api_gateway = api_gateway
        self.session = requests.Session()
        self.findings = []
    
    def scan_mobile_api(self, api_endpoints: List[str], auth_tokens: Dict[str, str]) -> Dict[str, Any]:
        """扫描移动后端API"""
        results = {
            'endpoints_scanned': len(api_endpoints),
            'mobile_specific_checks': [],
            'jwt_validation': [],
            'token_rotation': [],
            'device_fingerprinting': [],
            'offline_data_protection': [],
            'summary': {},
        }
        
        for endpoint in api_endpoints:
            # 1. JWT移动验证检查
            jwt_results = self._check_jwt_mobile_validation(endpoint, auth_tokens)
            results['jwt_validation'].extend(jwt_results)
            
            # 2. Token轮换检查
            rotation_results = self._check_token_rotation(endpoint, auth_tokens)
            results['token_rotation'].extend(rotation_results)
            
            # 3. 设备指纹检查
            device_results = self._check_device_fingerprinting(endpoint, auth_tokens)
            results['device_fingerprinting'].extend(device_results)
            
            # 4. 离线数据保护检查
            offline_results = self._check_offline_data_protection(endpoint, auth_tokens)
            results['offline_data_protection'].extend(offline_results)
            
            # 5. 移动特定检查
            mobile_results = self._run_mobile_specific_checks(endpoint, auth_tokens)
            results['mobile_specific_checks'].extend(mobile_results)
        
        results['summary'] = self._generate_summary(results)
        return results
    
    def _check_jwt_mobile_validation(self, endpoint: str, auth_tokens: Dict) -> List[Dict]:
        """检查JWT移动验证"""
        issues = []
        
        # 检查JWT是否包含必要的移动声明
        token = auth_tokens.get('access_token', '')
        if token and '.' in token:
            # 简单的JWT结构检查
            parts = token.split('.')
            if len(parts) == 3:
                import base64
                try:
                    # 解码payload
                    payload = base64.urlsafe_b64decode(parts[1] + '==')
                    claims = __import__('json').loads(payload)
                    
                    # 检查移动相关声明
                    mobile_claims = ['device_id', 'app_version', 'platform']
                    missing_claims = [c for c in mobile_claims if c not in claims]
                    
                    if missing_claims:
                        issues.append({
                            'type': 'jwt_missing_mobile_claims',
                            'severity': 'medium',
                            'endpoint': endpoint,
                            'description': f'JWT缺少移动设备声明: {missing_claims}',
                            'recommendation': '在JWT中包含device_id、app_version、platform等声明',
                        })
                    
                    # 检查过期时间
                    if 'exp' not in claims:
                        issues.append({
                            'type': 'jwt_no_expiration',
                            'severity': 'high',
                            'endpoint': endpoint,
                            'description': 'JWT未设置过期时间',
                            'recommendation': '始终设置exp声明，建议移动应用Token有效期不超过24小时',
                        })
                    
                except Exception:
                    pass
        
        return issues
    
    def _check_token_rotation(self, endpoint: str, auth_tokens: Dict) -> List[Dict]:
        """检查Token轮换机制"""
        issues = []
        
        # 检查是否支持refresh token
        if 'refresh_token' not in auth_tokens:
            issues.append({
                'type': 'no_refresh_token',
                'severity': 'medium',
                'endpoint': endpoint,
                'description': 'API未实现Refresh Token机制',
                'recommendation': '实现Refresh Token机制，定期轮换Access Token',
            })
        
        # 检查Token绑定
        headers = {'Authorization': f'Bearer {auth_tokens.get("access_token", "")}'}
        
        try:
            # 尝试用相同Token从不同User-Agent访问
            response1 = self.session.get(endpoint, headers=headers, timeout=10)
            
            # 修改User-Agent再次请求
            headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
            response2 = self.session.get(endpoint, headers=headers, timeout=10)
            
            if response1.status_code == 200 and response2.status_code == 200:
                # Token未被设备绑定
                issues.append({
                    'type': 'token_not_device_bound',
                    'severity': 'medium',
                    'endpoint': endpoint,
                    'description': 'Token未与设备绑定，可在不同设备上使用',
                    'recommendation': '将Token与设备指纹绑定，检测异常设备登录',
                })
        except:
            pass
        
        return issues
    
    def _check_device_fingerprinting(self, endpoint: str, auth_tokens: Dict) -> List[Dict]:
        """检查设备指纹验证"""
        issues = []
        
        headers = {
            'Authorization': f'Bearer {auth_tokens.get("access_token", "")}',
            'User-Agent': 'TestApp/1.0',
        }
        
        try:
            # 正常请求
            response1 = self.session.get(endpoint, headers=headers, timeout=10)
            
            # 修改设备信息再次请求
            headers['X-Device-ID'] = 'fake-device-id'
            headers['X-Platform'] = 'android'
            response2 = self.session.get(endpoint, headers=headers, timeout=10)
            
            # 如果两次都成功，说明没有设备指纹验证
            if response1.status_code == 200 and response2.status_code == 200:
                issues.append({
                    'type': 'no_device_fingerprinting',
                    'severity': 'low',
                    'endpoint': endpoint,
                    'description': 'API未验证设备指纹',
                    'recommendation': '实现设备指纹验证，检测异常设备',
                })
        except:
            pass
        
        return issues
    
    def _check_offline_data_protection(self, endpoint: str, auth_tokens: Dict) -> List[Dict]:
        """检查离线数据保护"""
        issues = []
        
        # 检查API响应中是否包含敏感数据缓存指令
        try:
            headers = {'Authorization': f'Bearer {auth_tokens.get("access_token", "")}'}
            response = self.session.get(endpoint, headers=headers, timeout=10)
            
            cache_control = response.headers.get('Cache-Control', '')
            
            if 'private' not in cache_control.lower() and 'no-store' not in cache_control.lower():
                issues.append({
                    'type': 'sensitive_data_caching',
                    'severity': 'medium',
                    'endpoint': endpoint,
                    'description': 'API响应可能允许客户端缓存敏感数据',
                    'recommendation': '设置Cache-Control: private, no-store防止敏感数据被缓存',
                })
            
            # 检查是否返回过多敏感信息
            try:
                data = response.json()
                sensitive_fields = ['password', 'ssn', 'credit_card', 'secret_key']
                
                def find_sensitive(data, path=''):
                    found = []
                    if isinstance(data, dict):
                        for key, value in data.items():
                            new_path = f"{path}.{key}" if path else key
                            if any(sf in key.lower() for sf in sensitive_fields):
                                found.append(new_path)
                            if isinstance(value, (dict, list)):
                                found.extend(find_sensitive(value, new_path))
                    elif isinstance(data, list):
                        for i, item in enumerate(data):
                            found.extend(find_sensitive(item, f"{path}[{i}]"))
                    return found
                
                sensitive_paths = find_sensitive(data)
                if sensitive_paths:
                    issues.append({
                        'type': 'sensitive_data_exposure',
                        'severity': 'high',
                        'endpoint': endpoint,
                        'description': f'API响应包含敏感字段: {sensitive_paths[:3]}',
                        'recommendation': '从API响应中移除敏感字段',
                    })
            except:
                pass
                
        except:
            pass
        
        return issues
    
    def _run_mobile_specific_checks(self, endpoint: str, auth_tokens: Dict) -> List[Dict]:
        """运行移动特定检查"""
        issues = []
        
        # 检查Root/越狱检测API
        root_detection_endpoints = ['/api/v1/device/check', '/api/device/verify', '/security/device']
        
        for check_endpoint in root_detection_endpoints:
            full_url = endpoint.rstrip('/') + check_endpoint
            try:
                headers = {'Authorization': f'Bearer {auth_tokens.get("access_token", "")}'}
                response = self.session.get(full_url, headers=headers, timeout=5)
                
                if response.status_code == 200:
                    issues.append({
                        'type': 'root_detection_api_exposed',
                        'severity': 'low',
                        'endpoint': full_url,
                        'description': '发现设备检测API，可能被逆向分析',
                        'recommendation': '将设备检测逻辑移到服务端，客户端只接收结果',
                    })
                    break
            except:
                pass
        
        # 检查API版本控制
        if '/v1/' not in endpoint and '/v2/' not in endpoint:
            issues.append({
                'type': 'no_api_versioning',
                'severity': 'low',
                'endpoint': endpoint,
                'description': 'API未使用版本控制',
                'recommendation': '使用/api/v1/格式进行API版本控制',
            })
        
        return issues
    
    def _generate_summary(self, results: Dict) -> Dict:
        """生成摘要"""
        all_issues = (
            results.get('jwt_validation', []) +
            results.get('token_rotation', []) +
            results.get('device_fingerprinting', []) +
            results.get('offline_data_protection', []) +
            results.get('mobile_specific_checks', [])
        )
        
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for issue in all_issues:
            sev = issue.get('severity', 'low')
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        return {
            'total_issues': len(all_issues),
            'critical': severity_counts['critical'],
            'high': severity_counts['high'],
            'medium': severity_counts['medium'],
            'low': severity_counts['low'],
            'risk_score': severity_counts['critical'] * 10 + severity_counts['high'] * 5 + severity_counts['medium'] * 2,
        }
