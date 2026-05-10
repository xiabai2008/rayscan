"""WVS v18.0 - 移动安全扫描插件

功能：
1. Android APK 安全扫描
2. iOS IPA 安全扫描
3. 移动 API 安全测试
"""
import re
import json
import zipfile
import subprocess
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass
from xml.etree import ElementTree


@dataclass
class MobileVulnerability:
    platform: str  # android / ios
    app_name: str
    package_name: str
    vulnerability: str
    severity: str
    file_path: str
    description: str
    recommendation: str


class AndroidScanner:
    """Android APK 安全扫描"""
    
    # 敏感权限
    DANGEROUS_PERMISSIONS = [
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_PHONE_STATE",
        "android.permission.CALL_PHONE",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
    ]
    
    # 敏感 API
    SENSITIVE_APIS = {
        "Runtime.getRuntime().exec": "命令执行",
        "ProcessBuilder": "进程创建",
        "System.loadLibrary": "Native 库加载",
        "DexClassLoader": "动态代码加载",
        "URLClassLoader": "动态类加载",
        "getSharedPreferences": "共享首选项",
        "SQLiteDatabase": "SQLite 数据库",
        "HttpClient": "HTTP 客户端",
        "WebView.loadUrl": "WebView 加载",
        "addJavascriptInterface": "JavaScript 接口",
        "Cipher.getInstance": "加密操作",
        "MessageDigest": "哈希操作",
        "SecretKey": "密钥操作",
    }
    
    # 硬编码敏感信息模式
    SECRET_PATTERNS = [
        (r'password\s*=\s*["\']([^"\']+)["\']', "密码"),
        (r'api[_-]?key\s*=\s*["\']([^"\']+)["\']', "API Key"),
        (r'secret[_-]?key\s*=\s*["\']([^"\']+)["\']', "Secret Key"),
        (r'token\s*=\s*["\']([^"\']+)["\']', "Token"),
        (r'aws[_-]?access[_-]?key[_-]?id\s*=\s*["\']([^"\']+)["\']', "AWS Access Key"),
        (r'aws[_-]?secret[_-]?access[_-]?key\s*=\s*["\']([^"\']+)["\']', "AWS Secret Key"),
    ]
    
    def __init__(self, apk_path: str = None):
        self.apk_path = apk_path
        self.extract_dir = None
    
    def scan(self, apk_path: str = None) -> List[MobileVulnerability]:
        """扫描 APK"""
        if apk_path:
            self.apk_path = apk_path
        
        if not self.apk_path or not Path(self.apk_path).exists():
            return []
        
        findings = []
        
        # 解压 APK
        self.extract_dir = self._extract_apk()
        if not self.extract_dir:
            return []
        
        # 分析 AndroidManifest.xml
        manifest_findings = self._analyze_manifest()
        findings.extend(manifest_findings)
        
        # 分析 Smali 代码
        smali_findings = self._analyze_smali()
        findings.extend(smali_findings)
        
        # 检测硬编码敏感信息
        secret_findings = self._detect_secrets()
        findings.extend(secret_findings)
        
        return findings
    
    def _extract_apk(self) -> Optional[Path]:
        """解压 APK"""
        try:
            extract_dir = Path(self.apk_path).parent / f"apk_extract_{Path(self.apk_path).stem}"
            extract_dir.mkdir(parents=True, exist_ok=True)
            
            with zipfile.ZipFile(self.apk_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            
            return extract_dir
        except:
            return None
    
    def _analyze_manifest(self) -> List[MobileVulnerability]:
        """分析 AndroidManifest.xml"""
        findings = []
        manifest_path = self.extract_dir / "AndroidManifest.xml"
        
        if not manifest_path.exists():
            # 尝试使用 apktool 解码
            self._decode_apk()
            manifest_path = self.extract_dir / "AndroidManifest.xml"
        
        if not manifest_path.exists():
            return findings
        
        try:
            # 解析 XML（二进制格式需要 apktool）
            tree = ElementTree.parse(manifest_path)
            root = tree.getroot()
            
            # 获取包名
            package_name = root.get("package", "unknown")
            
            # 检查导出组件
            for component in root.findall(".//activity[@android:exported='true']"):
                name = component.get("{http://schemas.android.com/apk/res/android}name")
                findings.append(MobileVulnerability(
                    platform="android",
                    app_name=Path(self.apk_path).stem,
                    package_name=package_name,
                    vulnerability=f"导出 Activity: {name}",
                    severity="medium",
                    file_path="AndroidManifest.xml",
                    description="Activity 可被其他应用调用",
                    recommendation="设置 android:exported='false' 或添加权限保护"
                ))
            
            # 检查危险权限
            for perm in root.findall(".//uses-permission"):
                name = perm.get("{http://schemas.android.com/apk/res/android}name", "")
                if name in self.DANGEROUS_PERMISSIONS:
                    findings.append(MobileVulnerability(
                        platform="android",
                        app_name=Path(self.apk_path).stem,
                        package_name=package_name,
                        vulnerability=f"敏感权限: {name.split('.')[-1]}",
                        severity="medium",
                        file_path="AndroidManifest.xml",
                        description=f"应用请求敏感权限: {name}",
                        recommendation="评估权限必要性，考虑使用替代方案"
                    ))
            
            # 检查调试模式
            if root.get("{http://schemas.android.com/apk/res/android}debuggable") == "true":
                findings.append(MobileVulnerability(
                    platform="android",
                    app_name=Path(self.apk_path).stem,
                    package_name=package_name,
                    vulnerability="调试模式启用",
                    severity="high",
                    file_path="AndroidManifest.xml",
                    description="应用处于可调试状态",
                    recommendation="发布版本禁用调试模式"
                ))
            
            # 检查备份
            if root.get("{http://schemas.android.com/apk/res/android}allowBackup") == "true":
                findings.append(MobileVulnerability(
                    platform="android",
                    app_name=Path(self.apk_path).stem,
                    package_name=package_name,
                    vulnerability="允许备份",
                    severity="medium",
                    file_path="AndroidManifest.xml",
                    description="应用数据可被备份",
                    recommendation="发布版本禁用备份"
                ))
        
        except Exception as e:
            pass
        
        return findings
    
    def _analyze_smali(self) -> List[MobileVulnerability]:
        """分析 Smali 代码"""
        findings = []
        smali_dir = self.extract_dir / "smali"
        
        if not smali_dir.exists():
            # 尝试解码
            self._decode_apk()
        
        if not smali_dir.exists():
            return findings
        
        for smali_file in smali_dir.rglob("*.smali"):
            try:
                content = smali_file.read_text(errors='ignore')
                
                for api, desc in self.SENSITIVE_APIS.items():
                    if api in content:
                        findings.append(MobileVulnerability(
                            platform="android",
                            app_name=Path(self.apk_path).stem,
                            package_name="",
                            vulnerability=f"敏感 API: {desc}",
                            severity="medium",
                            file_path=str(smali_file.relative_to(self.extract_dir)),
                            description=f"使用敏感 API: {api}",
                            recommendation="评估 API 使用安全性"
                        ))
            except:
                pass
        
        return findings
    
    def _detect_secrets(self) -> List[MobileVulnerability]:
        """检测硬编码敏感信息"""
        findings = []
        
        for file_path in self.extract_dir.rglob("*"):
            if file_path.is_file() and file_path.suffix in ['.java', '.smali', '.xml', '.json', '.properties', '.txt']:
                try:
                    content = file_path.read_text(errors='ignore')
                    
                    for pattern, secret_type in self.SECRET_PATTERNS:
                        matches = re.finditer(pattern, content, re.I)
                        for match in matches:
                            value = match.group(1)
                            if len(value) > 5:  # 过滤短字符串
                                findings.append(MobileVulnerability(
                                    platform="android",
                                    app_name=Path(self.apk_path).stem,
                                    package_name="",
                                    vulnerability=f"硬编码{secret_type}",
                                    severity="high",
                                    file_path=str(file_path.relative_to(self.extract_dir)),
                                    description=f"发现硬编码{secret_type}: {value[:20]}...",
                                    recommendation="使用安全的密钥存储方案"
                                ))
                except:
                    pass
        
        return findings
    
    def _decode_apk(self):
        """使用 apktool 解码 APK"""
        try:
            subprocess.run(
                ["apktool", "d", self.apk_path, "-o", str(self.extract_dir), "-f"],
                capture_output=True,
                timeout=120
            )
        except:
            pass


class iOSScanner:
    """iOS IPA 安全扫描"""
    
    def scan(self, ipa_path: str) -> List[MobileVulnerability]:
        """扫描 IPA"""
        findings = []
        
        # 解压 IPA
        try:
            extract_dir = Path(ipa_path).parent / f"ipa_extract_{Path(ipa_path).stem}"
            extract_dir.mkdir(parents=True, exist_ok=True)
            
            with zipfile.ZipFile(ipa_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            
            # 查找 .app 目录
            app_dir = list(extract_dir.rglob("Payload/*.app"))
            if not app_dir:
                return findings
            
            app_dir = app_dir[0]
            
            # 检查 Info.plist
            plist_path = app_dir / "Info.plist"
            if plist_path.exists():
                # 检查 ATS 配置、权限等
                pass
            
            # 检查二进制安全
            # 需要 otool (macOS)
            
        except:
            pass
        
        return findings


class MobileAPIScanner:
    """移动 API 安全扫描"""
    
    def __init__(self):
        self.jwt_vulnerabilities = []
        self.auth_issues = []
    
    async def scan_api_endpoint(self, url: str, token: str = None) -> List[Dict]:
        """扫描 API 端点"""
        findings = []
        
        # JWT 安全检查
        if token and token.startswith("eyJ"):
            jwt_findings = self._check_jwt(token)
            findings.extend(jwt_findings)
        
        return findings
    
    def _check_jwt(self, token: str) -> List[Dict]:
        """检查 JWT 安全"""
        findings = []
        
        try:
            import base64
            
            # 解码 JWT
            parts = token.split(".")
            if len(parts) == 3:
                # 解码 header
                header = base64.urlsafe_b64decode(parts[0] + "==")
                header_data = json.loads(header)
                
                # 检查算法
                alg = header_data.get("alg", "")
                if alg == "none":
                    findings.append({
                        "type": "JWT无算法",
                        "severity": "critical",
                        "description": "JWT使用none算法"
                    })
                
                # 检查弱密钥
                if alg in ["HS256", "HS384", "HS512"]:
                    findings.append({
                        "type": "JWT弱算法",
                        "severity": "medium",
                        "description": f"JWT使用对称加密算法: {alg}"
                    })
        
        except:
            pass
        
        return findings


class MobileScanner:
    """移动安全扫描主类"""
    
    def __init__(self):
        self.android = AndroidScanner()
        self.ios = iOSScanner()
        self.api = MobileAPIScanner()
    
    def scan_apk(self, path: str) -> List[MobileVulnerability]:
        """扫描 Android APK"""
        return self.android.scan(path)
    
    def scan_ipa(self, path: str) -> List[MobileVulnerability]:
        """扫描 iOS IPA"""
        return self.ios.scan(path)
    
    async def scan_api(self, url: str, token: str = None) -> List[Dict]:
        """扫描移动 API"""
        return await self.api.scan_api_endpoint(url, token)
