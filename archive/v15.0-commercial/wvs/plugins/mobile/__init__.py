"""移动安全扫描器 - v12.0 统一入口"""
from typing import Dict, List, Any, Optional
import os


class MobileSecurityScanner:
    """移动安全扫描器主类"""
    
    def __init__(self):
        self.android_scanner = None
        self.ios_scanner = None
        self.api_scanner = None
        self._init_scanners()
    
    def _init_scanners(self):
        """初始化子扫描器"""
        try:
            from .android_scanner import MobileSecurityScanner
            self.android_scanner = MobileSecurityScanner()
        except ImportError:
            pass
        
        try:
            from .ios_scanner import IOSSecurityScanner
            self.ios_scanner = IOSSecurityScanner()
        except ImportError:
            pass
        
        try:
            from .api_scanner import MobileAPISecurityScanner
            self.api_scanner = MobileAPISecurityScanner()
        except ImportError:
            pass
    
    def scan(self, target: str, platform: str = 'auto', **kwargs) -> Dict[str, Any]:
        """
        统一扫描入口
        
        Args:
            target: APK/IPA文件路径或API端点
            platform: android/ios/api/auto
            **kwargs: 额外参数
        
        Returns:
            扫描结果字典
        """
        # 自动检测平台
        if platform == 'auto':
            platform = self._detect_platform(target)
        
        # 根据平台调用对应扫描器
        if platform == 'android':
            return self.scan_android(target, **kwargs)
        elif platform == 'ios':
            return self.scan_ios(target, **kwargs)
        elif platform == 'api':
            return self.scan_mobile_api(target, **kwargs)
        else:
            return {
                'error': f'不支持的平台: {platform}',
                'supported_platforms': ['android', 'ios', 'api'],
            }
    
    def _detect_platform(self, target: str) -> str:
        """自动检测目标平台"""
        if target.endswith('.apk'):
            return 'android'
        elif target.endswith('.ipa'):
            return 'ios'
        elif target.startswith('http'):
            return 'api'
        elif os.path.isdir(target):
            # 检查目录内容
            if os.path.exists(os.path.join(target, 'AndroidManifest.xml')):
                return 'android'
            elif any(f.endswith('.xcodeproj') for f in os.listdir(target)):
                return 'ios'
        
        return 'api'  # 默认
    
    def scan_android(self, apk_path: str, **kwargs) -> Dict[str, Any]:
        """扫描Android应用"""
        if not self.android_scanner:
            return {'error': 'Android扫描器未初始化'}
        
        if os.path.isfile(apk_path) and apk_path.endswith('.apk'):
            return self.android_scanner.scan_android_apk(apk_path)
        elif os.path.isdir(apk_path):
            return self.android_scanner.scan_android_source(apk_path)
        else:
            return {'error': '无效的Android目标，请提供APK文件或源码目录'}
    
    def scan_ios(self, ipa_path: str, **kwargs) -> Dict[str, Any]:
        """扫描iOS应用"""
        if not self.ios_scanner:
            return {'error': 'iOS扫描器未初始化'}
        
        if os.path.isfile(ipa_path) and ipa_path.endswith('.ipa'):
            return self.ios_scanner.scan_ipa(ipa_path)
        else:
            return {'error': '无效的iOS目标，请提供IPA文件'}
    
    def scan_mobile_api(self, endpoints: List[str], auth_tokens: Dict[str, str], **kwargs) -> Dict[str, Any]:
        """扫描移动后端API"""
        if not self.api_scanner:
            return {'error': 'API扫描器未初始化'}
        
        if isinstance(endpoints, str):
            endpoints = [endpoints]
        
        return self.api_scanner.scan_mobile_api(endpoints, auth_tokens)
    
    def get_capabilities(self) -> Dict[str, Any]:
        """获取扫描器能力"""
        return {
            'platforms': {
                'android': self.android_scanner is not None,
                'ios': self.ios_scanner is not None,
                'api': self.api_scanner is not None,
            },
            'android_checks': [
                'Manifest配置检查',
                '导出组件检测',
                '权限滥用分析',
                'Smali代码安全分析',
                '数据存储风险',
                '网络安全配置',
                '硬编码密钥检测',
            ],
            'ios_checks': [
                '二进制安全属性分析',
                'Info.plist配置检查',
                'ATS配置验证',
                '越狱检测实现',
                'Keychain使用分析',
                '资源文件安全检查',
            ],
            'api_checks': [
                'JWT移动验证',
                'Token轮换机制',
                '设备指纹验证',
                '离线数据保护',
                '移动特定API检查',
            ],
        }
