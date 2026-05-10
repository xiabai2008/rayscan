"""
统一的数据模型定义
解决WVS v18.4中Vulnerability类重复定义、字段不一致的问题
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from uuid import uuid4

from .constants import DEFAULT_VERIFY_SSL


class Severity(Enum):
    """漏洞严重程度"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VulnerabilityType(Enum):
    """漏洞类型枚举"""
    SQL_INJECTION = "sql_injection"
    XSS = "cross_site_scripting"
    COMMAND_INJECTION = "command_injection"
    LFI = "local_file_inclusion"
    RFI = "remote_file_inclusion"
    XXE = "xml_external_entity"
    SSRF = "server_side_request_forgery"
    IDOR = "insecure_direct_object_reference"
    BROKEN_AUTH = "broken_authentication"
    BROKEN_ACCESS = "broken_access_control"
    INSECURE_CONFIG = "insecure_configuration"
    INFO_DISCLOSURE = "information_disclosure"
    API_SECURITY = "api_security"
    LOGIC_VULNERABILITY = "logic_vulnerability"
    REMOTE_CODE_EXECUTION = "remote_code_execution"
    ZERO_DAY = "zero_day"
    OTHER = "other"


class Confidence(Enum):
    """检测置信度"""
    LOW = "low"          # 20-40%
    MEDIUM = "medium"    # 40-70%
    HIGH = "high"        # 70-90%
    CERTAIN = "certain"  # 90-100%


@dataclass
class Vulnerability:
    """
    统一的漏洞数据模型
    解决WVS v18.4中重复定义、字段不一致的问题
    
    注意：不在dataclass上挂载exploit()等方法，保持数据模型的纯净
    """
    # 核心标识信息
    id: str = field(default_factory=lambda: str(uuid4()))
    type: VulnerabilityType = VulnerabilityType.OTHER
    title: str = ""
    
    # 目标信息
    url: str = ""
    method: str = "GET"
    parameter: Optional[str] = None
    parameter_type: Optional[str] = None  # query, body, header, cookie
    
    # 技术细节
    payload: Optional[str] = None
    evidence: Optional[str] = ""
    http_request: Optional[str] = None
    http_response: Optional[str] = None
    
    # 评估信息
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.LOW
    cvss_score: Optional[float] = None
    cwe_id: Optional[int] = None
    
    # 修复建议
    description: str = ""
    impact: str = ""
    recommendation: str = ""
    references: List[str] = field(default_factory=list)
    
    # 元数据
    timestamp: datetime = field(default_factory=datetime.now)
    scanner: str = "wvs"
    module: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    
    # 上下文信息
    context: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式（None 安全）"""
        data = asdict(self)
        
        # 处理特殊类型（None 安全）
        data['type'] = self.type.value if self.type else "unknown"
        data['severity'] = self.severity.value if self.severity else "info"
        data['confidence'] = self.confidence.value if self.confidence else "unknown"
        data['timestamp'] = self.timestamp.isoformat() if self.timestamp else None
        
        # 处理可选字段（None 时删除）
        for key in ['parameter', 'parameter_type', 'payload', 'evidence', 
                   'http_request', 'http_response', 'cvss_score', 'cwe_id',
                   'module', 'description', 'recommendation', 'references',
                   'tags', 'impact', 'scanner', 'context']:
            if data.get(key) is None:
                del data[key]
        
        return data
    
    # P9: Aliases that map to canonical VulnerabilityType values
    _TYPE_ALIASES = {
        "code_injection": VulnerabilityType.REMOTE_CODE_EXECUTION,
        "expression_injection": VulnerabilityType.REMOTE_CODE_EXECUTION,
        "php_code_injection": VulnerabilityType.REMOTE_CODE_EXECUTION,
        "el_injection": VulnerabilityType.REMOTE_CODE_EXECUTION,
        "ssti": VulnerabilityType.REMOTE_CODE_EXECUTION,
        "rce": VulnerabilityType.REMOTE_CODE_EXECUTION,
        "broken_access": VulnerabilityType.BROKEN_ACCESS,
    }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Vulnerability':
        """从字典创建Vulnerability对象"""
        # 处理特殊类型
        data = data.copy()

        if 'type' in data:
            raw = data['type']
            try:
                data['type'] = VulnerabilityType(raw)
            except ValueError:
                # P9: Map known aliases (code_injection, EL, etc.) → canonical type
                mapped = cls._TYPE_ALIASES.get(raw)
                if mapped is not None:
                    data['type'] = mapped
                else:
                    data['type'] = VulnerabilityType.OTHER
        
        if 'severity' in data:
            data['severity'] = Severity(data['severity'])
        
        if 'confidence' in data:
            data['confidence'] = Confidence(data['confidence'])
        
        if 'timestamp' in data and isinstance(data['timestamp'], str):
            data['timestamp'] = datetime.fromisoformat(data['timestamp'])
        
        # Normalize: ensure string optional fields are never None
        for key in ['parameter', 'parameter_type', 'payload', 'evidence',
                    'http_request', 'http_response', 'module']:
            if key in data and data[key] is None:
                data[key] = ""
        # 移除其他None值，让dataclass使用默认值
        for key in list(data.keys()):
            if data[key] is None:
                del data[key]

        return cls(**data)
    
    def __str__(self) -> str:
        """友好的字符串表示"""
        return f"[{self.severity.value.upper()}] {self.type.value}: {self.title}"


@dataclass
class ScanTarget:
    """扫描目标"""
    url: str
    methods: List[str] = field(default_factory=lambda: ["GET", "POST"])
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    auth: Optional[Dict[str, str]] = None
    data: Optional[Dict[str, str]] = None
    params: Optional[Dict[str, str]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass 
class ScanResult:
    """扫描结果"""
    target: ScanTarget
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    scan_time: datetime = field(default_factory=datetime.now)
    duration: float = 0.0  # 扫描耗时（秒）
    requests_made: int = 0
    endpoints_found: int = 0
    modules_run: int = 0
    errors: List[Dict[str, Any]] = field(default_factory=list)
    
    @property
    def vulnerability_count(self) -> Dict[str, int]:
        """按类型统计漏洞数量（None 安全）"""
        counts = {}
        for vuln in self.vulnerabilities:
            vuln_type = vuln.type.value if vuln.type else "unknown"
            counts[vuln_type] = counts.get(vuln_type, 0) + 1
        return counts
    
    @property
    def severity_count(self) -> Dict[str, int]:
        """按严重程度统计漏洞数量（None 安全）"""
        counts = {}
        for vuln in self.vulnerabilities:
            severity = (vuln.severity.value if vuln.severity else "info")
            counts[severity] = counts.get(severity, 0) + 1
        return counts
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        data = asdict(self)
        data['target'] = self.target.to_dict()
        data['vulnerabilities'] = [v.to_dict() for v in self.vulnerabilities]
        data['scan_time'] = self.scan_time.isoformat()
        data['vulnerability_count'] = self.vulnerability_count
        data['severity_count'] = self.severity_count
        return data


@dataclass
class ModuleConfig:
    """模块配置"""
    enabled: bool = True
    timeout: int = 30
    threads: int = 3
    depth: int = 3
    custom_params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScannerConfig:
    """扫描器全局配置"""
    # 基本设置
    timeout: int = 30
    threads: int = 3
    user_agent: str = "WVS/19.0"
    follow_redirects: bool = True
    verify_ssl: bool = DEFAULT_VERIFY_SSL

    # 模块配置
    modules: Dict[str, ModuleConfig] = field(default_factory=dict)

    # 性能设置
    delay: float = 0.1
    max_requests_per_second: int = 10
    retry_count: int = 3
    concurrent_endpoints: int = 6
    concurrent_modules: int = 2

    # 爬虫设置
    crawl_depth: int = 4
    crawl_max_urls: int = 300

    # WAF / OOB / 速率控制
    enable_waf_detection: bool = True
    enable_waf_evasion: bool = True
    enable_oob: bool = False
    oob_provider: str = "interactsh"
    rate_mode: str = "burst"
    enable_adaptive_rate: bool = True

    # 全局超时
    max_time: int = 3600

    # 输出设置
    output_format: str = "json"
    output_file: Optional[str] = None
    verbose: bool = False

    def get_module_config(self, module_name: str) -> ModuleConfig:
        """获取模块配置，如果不存在则创建默认配置"""
        if module_name not in self.modules:
            self.modules[module_name] = ModuleConfig()
        return self.modules[module_name]


# 便捷函数
def create_vulnerability(
    vuln_type: VulnerabilityType,
    url: str,
    severity: Severity = Severity.MEDIUM,
    confidence: Confidence = Confidence.MEDIUM,
    title: str = "",
    description: str = "",
    payload: Optional[str] = None,
    parameter: Optional[str] = None,
    **kwargs
) -> Vulnerability:
    """创建漏洞对象的便捷函数"""
    if not title:
        title = f"{vuln_type.value.replace('_', ' ').title()} vulnerability"
    
    return Vulnerability(
        type=vuln_type,
        url=url,
        severity=severity,
        confidence=confidence,
        title=title,
        description=description,
        payload=payload,
        parameter=parameter,
        **kwargs
    )


if __name__ == "__main__":
    # 测试数据模型
    vuln = create_vulnerability(
        vuln_type=VulnerabilityType.SQL_INJECTION,
        url="http://example.com/login",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        parameter="username",
        payload="admin' OR '1'='1",
        description="SQL注入漏洞，可绕过登录验证",
        recommendation="使用参数化查询或预编译语句"
    )
    
    print("示例漏洞:")
    print(f"  ID: {vuln.id}")
    print(f"  类型: {vuln.type.value}")
    print(f"  严重程度: {vuln.severity.value}")
    print(f"  置信度: {vuln.confidence.value}")
    print(f"  标题: {vuln.title}")
    print(f"  URL: {vuln.url}")
    
    # 测试序列化/反序列化
    vuln_dict = vuln.to_dict()
    print(f"\n序列化为字典: {len(vuln_dict)}个字段")
    
    vuln_restored = Vulnerability.from_dict(vuln_dict)
    print(f"反序列化成功: {vuln_restored.id == vuln.id}")