"""Android APK 安全扫描器 - v12.0"""
import zipfile
import re
import os
import tempfile
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from pathlib import Path


@dataclass
class AndroidVulnerability:
    """Android漏洞"""
    type: str
    severity: str
    location: str
    description: str
    recommendation: str


class AndroidManifestAnalyzer:
    """AndroidManifest.xml 分析器"""
    
    DANGEROUS_PERMISSIONS = [
        'android.permission.READ_CONTACTS',
        'android.permission.WRITE_CONTACTS',
        'android.permission.READ_SMS',
        'android.permission.SEND_SMS',
        'android.permission.RECEIVE_SMS',
        'android.permission.READ_CALL_LOG',
        'android.permission.WRITE_CALL_LOG',
        'android.permission.READ_PHONE_STATE',
        'android.permission.CALL_PHONE',
        'android.permission.CAMERA',
        'android.permission.RECORD_AUDIO',
        'android.permission.ACCESS_FINE_LOCATION',
        'android.permission.ACCESS_COARSE_LOCATION',
        'android.permission.READ_EXTERNAL_STORAGE',
        'android.permission.WRITE_EXTERNAL_STORAGE',
    ]
    
    COMPONENT_PROTECTION = {
        'activity': 'android:exported',
        'service': 'android:exported',
        'receiver': 'android:exported',
        'provider': 'android:exported',
    }
    
    def __init__(self, manifest_xml: str):
        self.manifest_xml = manifest_xml
        self.root = None
        self.issues = []
        self._parse()
    
    def _parse(self):
        """解析Manifest XML"""
        try:
            self.root = ET.fromstring(self.manifest_xml)
        except ET.ParseError:
            self.issues.append({
                'type': 'manifest_parse_error',
                'severity': 'high',
                'description': '无法解析AndroidManifest.xml',
            })
    
    def check_exported_components(self) -> List[Dict]:
        """检查导出的四大组件"""
        issues = []
        
        if not self.root:
            return issues
        
        ns = {'android': 'http://schemas.android.com/apk/res/android'}
        
        for component_type, attr in self.COMPONENT_PROTECTION.items():
            for elem in self.root.iter(component_type):
                # 检查exported属性
                exported = elem.get(attr, 'false')
                exported_str = str(exported).lower()
                
                if exported_str == 'true':
                    # 检查是否有permission保护
                    permission = elem.get('{http://schemas.android.com/apk/res/android}permission')
                    
                    if not permission:
                        issues.append({
                            'type': f'{component_type}_exported_without_permission',
                            'severity': 'high',
                            'location': f'{component_type}: {elem.get("{http://schemas.android.com/apk/res/android}name", "unknown")}',
                            'description': f'{component_type}组件 exported=true 且无permission保护，可能被其他应用恶意调用',
                            'recommendation': f'添加 android:permission 属性限制访问，或将 exported 设为 false',
                        })
        
        return issues
    
    def check_permission_abuses(self) -> List[Dict]:
        """检查权限滥用"""
        issues = []
        
        if not self.root:
            return issues
        
        uses_perms = self.root.findall('.//uses-permission')
        for perm in uses_perms:
            perm_name = perm.get('{http://schemas.android.com/apk/res/android}name', '')
            if perm_name in self.DANGEROUS_PERMISSIONS:
                severity = 'medium'
                if 'CAMERA' in perm_name or 'RECORD_AUDIO' in perm_name:
                    severity = 'low'  # 很多应用正常需要
                
                issues.append({
                    'type': 'dangerous_permission',
                    'severity': severity,
                    'location': f'uses-permission: {perm_name}',
                    'description': f'应用申请了危险权限: {perm_name}',
                    'recommendation': f'评估权限必要性，如非必需则移除',
                })
        
        return issues
    
    def check_debuggable(self) -> List[Dict]:
        """检查是否可调试"""
        issues = []
        
        if not self.root:
            return issues
        
        application = self.root.find('application')
        if application is not None:
            debuggable = application.get('{http://schemas.android.com/apk/res/android}debuggable', 'false')
            if str(debuggable).lower() == 'true':
                issues.append({
                    'type': 'debuggable_enabled',
                    'severity': 'critical',
                    'location': 'application android:debuggable="true"',
                    'description': '应用已启用可调试模式，允许通过ADB连接和调试',
                    'recommendation': '发布前务必将 android:debuggable 设为 false',
                })
        
        return issues
    
    def check_backup_enabled(self) -> List[Dict]:
        """检查allowBackup"""
        issues = []
        
        if not self.root:
            return issues
        
        application = self.root.find('application')
        if application is not None:
            allow_backup = application.get('{http://schemas.android.com/apk/res/android}allowBackup', 'true')
            if str(allow_backup).lower() == 'true':
                issues.append({
                    'type': 'allowBackup_enabled',
                    'severity': 'medium',
                    'location': 'application android:allowBackup="true"',
                    'description': '应用数据可通过ADB backup命令被提取',
                    'recommendation': '如涉及敏感数据，将 android:allowBackup 设为 false',
                })
        
        return issues
    
    def check_network_security_config(self) -> List[Dict]:
        """检查网络安全配置"""
        issues = []
        
        if not self.root:
            return issues
        
        application = self.root.find('application')
        if application is not None:
            network_config = application.get('{http://schemas.android.com/apk/res/android}networkSecurityConfig')
            if not network_config:
                issues.append({
                    'type': 'no_network_security_config',
                    'severity': 'low',
                    'location': 'application',
                    'description': '未配置NetworkSecurityConfig，可能允许HTTP明文传输',
                    'recommendation': '创建network_security_config.xml并配置usesCleartextTraffic策略',
                })
        
        return issues


class SmaliCodeAnalyzer:
    """Smali代码分析器"""
    
    SENSITIVE_API_PATTERNS = {
        'http_connection': {
            'patterns': [r'Ljavax/net/ssl/.*;', r'Ljava/net/HttpURLConnection'],
            'severity': 'medium',
            'description': '使用HTTP连接，明文传输风险',
        },
        'crypto_usage': {
            'patterns': [r'Ljavax/crypto/', r'Ljava/security/KeyStore'],
            'severity': 'medium',
            'description': '使用加密API，需确保密钥安全存储',
        },
        'webview_js': {
            'patterns': [r'setJavaScriptEnabled\(Z\)', r'addJavascriptInterface'],
            'severity': 'high',
            'description': 'WebView启用JS或注入接口，可能导致XSS',
        },
        'log_leak': {
            'patterns': [r'android/util/Log\.(v|d|i|w|e)', r'Landroid/util/Log;'],
            'severity': 'low',
            'description': '代码中使用了日志输出，可能泄露敏感信息',
        },
        'hardcoded_secret': {
            'patterns': [r'"password"\s*:', r'"secret"\s*:', r'"api_key"\s*:', r'"token"\s*:'],
            'severity': 'critical',
            'description': '代码中硬编码了密钥/Token',
        },
        'sql_injection': {
            'patterns': [r'execSQL\(', r'rawQuery\(.*\+'],
            'severity': 'high',
            'description': '可能存在SQL注入漏洞',
        },
        'file_access': {
            'patterns': [r'openFileOutput\(', r'openFileInput\(', r'getSharedPreferences\('],
            'severity': 'low',
            'description': '文件操作，需确保路径安全',
        },
    }
    
    def analyze(self, smali_files: List[str]) -> List[Dict]:
        """分析Smali文件"""
        issues = []
        
        for smali_file in smali_files:
            file_issues = self._analyze_file(smali_file)
            issues.extend(file_issues)
        
        return issues
    
    def _analyze_file(self, file_path: str) -> List[Dict]:
        """分析单个Smali文件"""
        issues = []
        
        try:
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read()
            
            for category, info in self.SENSITIVE_API_PATTERNS.items():
                for pattern in info['patterns']:
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        issues.append({
                            'type': category,
                            'severity': info['severity'],
                            'location': f'{file_path}:{line_num}',
                            'description': info['description'],
                            'recommendation': self._get_recommendation(category),
                        })
        except Exception as e:
            issues.append({
                'type': 'file_read_error',
                'severity': 'low',
                'location': file_path,
                'description': f'无法读取文件: {str(e)}',
            })
        
        return issues
    
    def _get_recommendation(self, category: str) -> str:
        """获取修复建议"""
        recommendations = {
            'http_connection': '使用HTTPS替代HTTP，配置证书校验',
            'crypto_usage': '确保密钥存储在Android Keystore中，不要硬编码密钥',
            'webview_js': '在WebView中禁用JS或严格限制addJavascriptInterface注入',
            'log_leak': '在发布前移除所有日志输出语句',
            'hardcoded_secret': '使用Android Keystore或后台动态获取，不要硬编码',
            'sql_injection': '使用参数化查询替代字符串拼接',
            'file_access': '确保文件路径经过校验，防止路径穿越',
        }
        return recommendations.get(category, '请审查代码')


class DataStorageChecker:
    """数据存储安全检查器"""
    
    def __init__(self, apk_path: str):
        self.apk_path = apk_path
    
    def check_shared_preferences(self) -> List[Dict]:
        """检查SharedPreferences配置"""
        issues = []
        
        # 检查是否使用MODE_WORLD_READABLE
        issues.append({
            'type': 'shared_preferences_mode',
            'severity': 'medium',
            'location': 'SharedPreferences usage',
            'description': '需检查SharedPreferences是否使用安全模式',
            'recommendation': '使用MODE_PRIVATE，避免MODE_WORLD_READABLE',
        })
        
        return issues
    
    def check_database(self) -> List[Dict]:
        """检查数据库安全"""
        issues = []
        
        issues.append({
            'type': 'database_permissions',
            'severity': 'medium',
            'location': 'SQLite database',
            'description': '检查数据库文件权限，确保不允许其他应用访问',
            'recommendation': '使用SQLCipher加密敏感数据库',
        })
        
        return issues


class MobileSecurityScanner:
    """移动安全扫描器主类"""
    
    def __init__(self):
        self.android_scanner = None
        self.ios_scanner = None
    
    def scan_android_apk(self, apk_path: str) -> Dict[str, Any]:
        """扫描Android APK"""
        results = {
            'platform': 'android',
            'file': apk_path,
            'file_size_mb': 0,
            'manifest_issues': [],
            'code_vulnerabilities': [],
            'data_storage_risks': [],
            'network_security': [],
            'permission_abuses': [],
            'summary': {},
        }
        
        # 获取文件大小
        try:
            results['file_size_mb'] = os.path.getsize(apk_path) / (1024 * 1024)
        except:
            pass
        
        # 解压APK
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                with zipfile.ZipFile(apk_path, 'r') as zf:
                    zf.extractall(tmpdir)
                
                # 1. 分析Manifest
                manifest_path = os.path.join(tmpdir, 'AndroidManifest.xml')
                if os.path.exists(manifest_path):
                    with open(manifest_path, 'r', errors='ignore') as f:
                        manifest_content = f.read()
                    
                    analyzer = AndroidManifestAnalyzer(manifest_content)
                    results['manifest_issues'].extend(analyzer.check_exported_components())
                    results['manifest_issues'].extend(analyzer.check_debuggable())
                    results['manifest_issues'].extend(analyzer.check_backup_enabled())
                    results['manifest_issues'].extend(analyzer.check_network_security_config())
                    results['permission_abuses'].extend(analyzer.check_permission_abuses())
                
                # 2. 分析Smali代码
                smali_dir = os.path.join(tmpdir, 'smali', 'smali_classes')
                if os.path.exists(smali_dir):
                    smali_files = list(Path(smali_dir).rglob('*.smali'))
                    code_analyzer = SmaliCodeAnalyzer()
                    results['code_vulnerabilities'].extend(code_analyzer.analyze([str(f) for f in smali_files]))
                
                # 3. 检查资源文件中的硬编码
                res_dir = os.path.join(tmpdir, 'res')
                if os.path.exists(res_dir):
                    for res_file in Path(res_dir).rglob('*'):
                        if res_file.suffix in ['.xml', '.txt']:
                            try:
                                content = res_file.read_text(errors='ignore')
                                if re.search(r'(api[_-]?key|secret|password|token)\s*=', content, re.IGNORECASE):
                                    results['code_vulnerabilities'].append({
                                        'type': 'hardcoded_in_resources',
                                        'severity': 'high',
                                        'location': str(res_file),
                                        'description': '资源文件中发现硬编码敏感信息',
                                        'recommendation': '使用BuildConfig或加密存储敏感配置',
                                    })
                            except:
                                pass
                
                # 4. 检查网络配置
                assets_dir = os.path.join(tmpdir, 'assets')
                if os.path.exists(assets_dir):
                    for asset_file in Path(assets_dir).rglob('*'):
                        if asset_file.suffix in ['.xml', '.json']:
                            try:
                                content = asset_file.read_text(errors='ignore')
                                if 'http://' in content and 'https://' not in content:
                                    results['network_security'].append({
                                        'type': 'cleartext_http_detected',
                                        'severity': 'medium',
                                        'location': str(asset_file),
                                        'description': '发现明文HTTP配置',
                                        'recommendation': '使用HTTPS替代HTTP',
                                    })
                            except:
                                pass
                
            except zipfile.BadZipFile:
                results['error'] = '无效的APK文件'
            except Exception as e:
                results['error'] = str(e)
        
        # 生成摘要
        results['summary'] = self._generate_summary(results)
        
        return results
    
    def scan_android_source(self, source_dir: str) -> Dict[str, Any]:
        """扫描Android源码目录"""
        results = {
            'platform': 'android_source',
            'directory': source_dir,
            'manifest_issues': [],
            'code_vulnerabilities': [],
            'data_storage_risks': [],
            'summary': {},
        }
        
        # 分析Manifest
        manifest_path = os.path.join(source_dir, 'app', 'src', 'main', 'AndroidManifest.xml')
        if not os.path.exists(manifest_path):
            manifest_path = os.path.join(source_dir, 'AndroidManifest.xml')
        
        if os.path.exists(manifest_path):
            with open(manifest_path, 'r', errors='ignore') as f:
                manifest_content = f.read()
            
            analyzer = AndroidManifestAnalyzer(manifest_content)
            results['manifest_issues'].extend(analyzer.check_exported_components())
            results['manifest_issues'].extend(analyzer.check_debuggable())
            results['manifest_issues'].extend(analyzer.check_backup_enabled())
            results['permission_abuses'] = analyzer.check_permission_abuses()
        
        # 分析Java/Kotlin源码
        java_dir = os.path.join(source_dir, 'app', 'src', 'main', 'java')
        if os.path.exists(java_dir):
            code_analyzer = SmaliCodeAnalyzer()
            java_files = list(Path(java_dir).rglob('*.java'))
            kotlin_files = list(Path(java_dir).rglob('*.kt'))
            results['code_vulnerabilities'].extend(code_analyzer.analyze([str(f) for f in java_files + kotlin_files]))
        
        results['summary'] = self._generate_summary(results)
        return results
    
    def _generate_summary(self, results: Dict) -> Dict:
        """生成摘要"""
        all_issues = (
            results.get('manifest_issues', []) +
            results.get('code_vulnerabilities', []) +
            results.get('data_storage_risks', []) +
            results.get('network_security', []) +
            results.get('permission_abuses', [])
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
