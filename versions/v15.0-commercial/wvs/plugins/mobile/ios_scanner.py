"""iOS IPA 安全扫描器 - v12.0"""
import zipfile
import plistlib
import re
import os
import tempfile
from typing import Dict, List, Any, Optional
from pathlib import Path


class IOSBinaryAnalyzer:
    """iOS二进制分析器"""
    
    SECURITY_CHECKS = {
        'pie_enabled': {
            'check': 'PIE',
            'severity': 'medium',
            'description': '未启用PIE (Position Independent Executable)',
            'recommendation': '启用PIE以支持ASLR',
        },
        'arc_enabled': {
            'check': 'ARC',
            'severity': 'medium',
            'description': '未启用ARC (Automatic Reference Counting)',
            'recommendation': '启用ARC防止内存管理错误',
        },
        'stack_canary': {
            'check': 'Stack Canary',
            'severity': 'high',
            'description': '未启用栈溢出保护',
            'recommendation': '启用-fstack-protector-all',
        },
        'fortify_source': {
            'check': 'Fortify Source',
            'severity': 'medium',
            'description': '未启用源码强化',
            'recommendation': '使用-D_FORTIFY_SOURCE=2编译',
        },
    }
    
    def analyze_binary(self, binary_path: str) -> List[Dict]:
        """分析二进制文件安全属性"""
        issues = []
        
        # 使用otool检查安全属性
        import subprocess
        
        try:
            # 检查PIE
            result = subprocess.run(['otool', '-hv', binary_path], 
                                   capture_output=True, text=True, timeout=30)
            if 'PIE' not in result.stdout:
                issues.append({
                    'type': 'pie_disabled',
                    'severity': 'medium',
                    'location': binary_path,
                    'description': '二进制未启用PIE',
                    'recommendation': '在Xcode中设置Build Settings -> Position Independent Executable = YES',
                })
            
            # 检查栈保护
            result = subprocess.run(['otool', '-Iv', binary_path],
                                   capture_output=True, text=True, timeout=30)
            if '___stack_chk_fail' not in result.stdout:
                issues.append({
                    'type': 'stack_protection_disabled',
                    'severity': 'high',
                    'location': binary_path,
                    'description': '未启用栈溢出保护',
                    'recommendation': '在Build Settings中启用-fstack-protector-all',
                })
            
            # 检查ARC
            if '_objc_release' not in result.stdout:
                issues.append({
                    'type': 'arc_disabled',
                    'severity': 'medium',
                    'location': binary_path,
                    'description': '未启用ARC',
                    'recommendation': '在Build Settings中设置Objective-C Automatic Reference Counting = YES',
                })
                
        except FileNotFoundError:
            issues.append({
                'type': 'otool_not_available',
                'severity': 'low',
                'location': binary_path,
                'description': 'otool工具不可用，无法完成二进制分析',
                'recommendation': '在macOS上运行此扫描',
            })
        except Exception as e:
            issues.append({
                'type': 'binary_analysis_error',
                'severity': 'low',
                'location': binary_path,
                'description': f'二进制分析失败: {str(e)}',
            })
        
        return issues


class IOSPlistAnalyzer:
    """iOS plist配置分析器"""
    
    def analyze(self, plist_path: str) -> List[Dict]:
        """分析Info.plist配置"""
        issues = []
        
        try:
            with open(plist_path, 'rb') as f:
                plist = plistlib.load(f)
            
            # 检查ATS (App Transport Security)
            ats = plist.get('NSAppTransportSecurity', {})
            if ats.get('NSAllowsArbitraryLoads', False):
                issues.append({
                    'type': 'ats_disabled',
                    'severity': 'high',
                    'location': 'Info.plist NSAppTransportSecurity',
                    'description': '禁用了App Transport Security，允许明文HTTP连接',
                    'recommendation': '移除NSAllowsArbitraryLoads或设置为false',
                })
            
            # 检查域名例外
            exceptions = ats.get('NSExceptionDomains', {})
            for domain, config in exceptions.items():
                if config.get('NSExceptionAllowsInsecureHTTPLoads', False):
                    issues.append({
                        'type': 'ats_domain_exception',
                        'severity': 'medium',
                        'location': f'Info.plist NSExceptionDomains.{domain}',
                        'description': f'域名 {domain} 允许不安全HTTP加载',
                        'recommendation': '移除NSExceptionAllowsInsecureHTTPLoads',
                    })
            
            # 检查文件共享
            if plist.get('UIFileSharingEnabled', False):
                issues.append({
                    'type': 'file_sharing_enabled',
                    'severity': 'medium',
                    'location': 'Info.plist UIFileSharingEnabled',
                    'description': '启用了文件共享，应用文档可在iTunes中访问',
                    'recommendation': '如非必需，禁用UIFileSharingEnabled',
                })
            
            # 检查后台模式
            bg_modes = plist.get('UIBackgroundModes', [])
            sensitive_modes = ['location', 'bluetooth-central', 'bluetooth-peripheral']
            for mode in bg_modes:
                if mode in sensitive_modes:
                    issues.append({
                        'type': 'sensitive_background_mode',
                        'severity': 'low',
                        'location': f'Info.plist UIBackgroundModes.{mode}',
                        'description': f'应用申请了敏感后台模式: {mode}',
                        'recommendation': '确保后台模式使用符合App Store审核要求',
                    })
            
            # 检查隐私权限描述
            privacy_keys = [
                'NSCameraUsageDescription',
                'NSMicrophoneUsageDescription',
                'NSLocationWhenInUseUsageDescription',
                'NSLocationAlwaysUsageDescription',
                'NSPhotoLibraryUsageDescription',
                'NSContactsUsageDescription',
            ]
            
            for key in privacy_keys:
                if key in plist:
                    desc = plist[key]
                    if len(desc) < 10 or 'used' in desc.lower():
                        issues.append({
                            'type': 'weak_privacy_description',
                            'severity': 'low',
                            'location': f'Info.plist {key}',
                            'description': f'隐私权限描述过于简单: {desc}',
                            'recommendation': '提供清晰、具体的权限使用说明',
                        })
            
        except Exception as e:
            issues.append({
                'type': 'plist_parse_error',
                'severity': 'low',
                'location': plist_path,
                'description': f'无法解析plist: {str(e)}',
            })
        
        return issues


class JailbreakDetector:
    """越狱检测检查器"""
    
    DETECTION_METHODS = [
        '检查常见越狱文件路径',
        '检查是否能写入系统目录',
        '检查是否存在Cydia应用',
        '检查动态库注入',
    ]
    
    def check_jailbreak_protection(self, binary_path: str) -> List[Dict]:
        """检查越狱检测实现"""
        issues = []
        
        # 检查代码中是否有越狱检测逻辑
        jailbreak_keywords = [
            '/Applications/Cydia.app',
            '/Library/MobileSubstrate',
            'SBOOM',
            'cydia',
            'jailbreak',
            'JBDetect',
        ]
        
        try:
            # 使用strings命令检查
            import subprocess
            result = subprocess.run(['strings', binary_path],
                                   capture_output=True, text=True, timeout=30)
            
            found_keywords = []
            for keyword in jailbreak_keywords:
                if keyword.lower() in result.stdout.lower():
                    found_keywords.append(keyword)
            
            if not found_keywords:
                issues.append({
                    'type': 'no_jailbreak_detection',
                    'severity': 'low',
                    'location': binary_path,
                    'description': '未发现越狱检测代码',
                    'recommendation': '建议实现越狱检测，防止在越狱设备上运行敏感功能',
                })
            
        except FileNotFoundError:
            pass  # strings命令不可用
        
        return issues


class KeychainAnalyzer:
    """Keychain使用分析器"""
    
    def analyze(self, binary_path: str) -> List[Dict]:
        """分析Keychain使用安全性"""
        issues = []
        
        keychain_apis = [
            'SecItemAdd',
            'SecItemCopyMatching',
            'SecItemUpdate',
            'SecItemDelete',
        ]
        
        try:
            import subprocess
            result = subprocess.run(['strings', binary_path],
                                   capture_output=True, text=True, timeout=30)
            
            found_apis = [api for api in keychain_apis if api in result.stdout]
            
            if not found_apis:
                issues.append({
                    'type': 'no_keychain_usage',
                    'severity': 'medium',
                    'location': binary_path,
                    'description': '未使用Keychain存储敏感数据',
                    'recommendation': '使用Keychain替代NSUserDefaults存储密码、Token等敏感信息',
                })
            
        except FileNotFoundError:
            pass
        
        return issues


class IOSSecurityScanner:
    """iOS安全扫描器主类"""
    
    def scan_ipa(self, ipa_path: str) -> Dict[str, Any]:
        """扫描iOS IPA文件"""
        results = {
            'platform': 'ios',
            'file': ipa_path,
            'file_size_mb': 0,
            'binary_analysis': [],
            'plist_vulnerabilities': [],
            'jailbreak_detection': [],
            'keychain_security': [],
            'summary': {},
        }
        
        # 获取文件大小
        try:
            results['file_size_mb'] = os.path.getsize(ipa_path) / (1024 * 1024)
        except:
            pass
        
        # 解压IPA
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                with zipfile.ZipFile(ipa_path, 'r') as zf:
                    zf.extractall(tmpdir)
                
                # 查找.app目录
                payload_dir = os.path.join(tmpdir, 'Payload')
                if os.path.exists(payload_dir):
                    app_dirs = [d for d in os.listdir(payload_dir) if d.endswith('.app')]
                    
                    if app_dirs:
                        app_dir = os.path.join(payload_dir, app_dirs[0])
                        
                        # 1. 分析Info.plist
                        plist_path = os.path.join(app_dir, 'Info.plist')
                        if os.path.exists(plist_path):
                            plist_analyzer = IOSPlistAnalyzer()
                            results['plist_vulnerabilities'].extend(plist_analyzer.analyze(plist_path))
                        
                        # 2. 分析二进制
                        binary_name = app_dirs[0].replace('.app', '')
                        binary_path = os.path.join(app_dir, binary_name)
                        
                        if os.path.exists(binary_path):
                            binary_analyzer = IOSBinaryAnalyzer()
                            results['binary_analysis'].extend(binary_analyzer.analyze_binary(binary_path))
                            
                            # 3. 越狱检测检查
                            jb_detector = JailbreakDetector()
                            results['jailbreak_detection'].extend(
                                jb_detector.check_jailbreak_protection(binary_path)
                            )
                            
                            # 4. Keychain分析
                            keychain_analyzer = KeychainAnalyzer()
                            results['keychain_security'].extend(
                                keychain_analyzer.analyze(binary_path)
                            )
                        
                        # 5. 检查资源文件
                        self._check_resources(app_dir, results)
                        
            except zipfile.BadZipFile:
                results['error'] = '无效的IPA文件'
            except Exception as e:
                results['error'] = str(e)
        
        # 生成摘要
        results['summary'] = self._generate_summary(results)
        
        return results
    
    def _check_resources(self, app_dir: str, results: Dict):
        """检查资源文件"""
        # 检查是否有硬编码密钥
        for root, dirs, files in os.walk(app_dir):
            for file in files:
                if file.endswith(('.plist', '.json', '.xml', '.strings')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', errors='ignore') as f:
                            content = f.read()
                        
                        # 检查硬编码密钥
                        if re.search(r'(api[_-]?key|secret|password|token)\s*[:=]\s*["\'][^"\']+["\']', 
                                    content, re.IGNORECASE):
                            results['plist_vulnerabilities'].append({
                                'type': 'hardcoded_secret_in_resources',
                                'severity': 'high',
                                'location': file_path,
                                'description': '资源文件中发现硬编码敏感信息',
                                'recommendation': '使用Keychain或加密存储',
                            })
                        
                        # 检查HTTP URL
                        if 'http://' in content and 'https://' not in content:
                            results['plist_vulnerabilities'].append({
                                'type': 'cleartext_http_in_resources',
                                'severity': 'medium',
                                'location': file_path,
                                'description': '资源文件中包含明文HTTP URL',
                                'recommendation': '使用HTTPS',
                            })
                    except:
                        pass
    
    def _generate_summary(self, results: Dict) -> Dict:
        """生成摘要"""
        all_issues = (
            results.get('binary_analysis', []) +
            results.get('plist_vulnerabilities', []) +
            results.get('jailbreak_detection', []) +
            results.get('keychain_security', [])
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
