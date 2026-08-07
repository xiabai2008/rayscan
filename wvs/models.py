"""
RayScan unified data models.

Consolidates Vulnerability, ScanTarget, ScanResult, and configuration models
that were duplicated across v18.x versions.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from .constants import DEFAULT_VERIFY_SSL


class Severity(Enum):
    """Vulnerability severity level"""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VulnerabilityType(Enum):
    """Vulnerability type enumeration"""

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
    """Detection confidence level"""

    LOW = "low"  # 20-40%
    MEDIUM = "medium"  # 40-70%
    HIGH = "high"  # 70-90%
    CERTAIN = "certain"  # 90-100%


@dataclass
class Vulnerability:
    """
    Unified vulnerability data model
    Resolves issues in WVS v18.4 with duplicate definitions and inconsistent fields

    Note: Do not attach exploit() etc. methods to the dataclass — keep the data model pure
    """

    # Core identifiers
    id: str = field(default_factory=lambda: str(uuid4()))
    type: VulnerabilityType = VulnerabilityType.OTHER
    title: str = ""

    # Target info
    url: str = ""
    method: str = "GET"
    parameter: Optional[str] = None
    parameter_type: Optional[str] = None  # query, body, header, cookie

    # Technical details
    payload: Optional[str] = None
    evidence: Optional[str] = ""
    http_request: Optional[str] = None
    http_response: Optional[str] = None

    # Assessment info
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.LOW
    cvss_score: Optional[float] = None
    cwe_id: Optional[int] = None

    # Remediation info
    description: str = ""
    impact: str = ""
    recommendation: str = ""
    references: List[str] = field(default_factory=list)

    # Metadata
    timestamp: datetime = field(default_factory=datetime.now)
    scanner: str = "wvs"
    module: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    # Context info
    context: Dict[str, Any] = field(default_factory=dict)

    # Explain mode: ordered list of detection signals (Phase 1: --explain)
    # Each entry: {"kind": str, "detail": str, "data": dict|None}
    evidence_chain: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format (None-safe)"""
        data = asdict(self)

        # Handle special types (None-safe)
        data["type"] = self.type.value if self.type else "unknown"
        data["severity"] = self.severity.value if self.severity else "info"
        data["confidence"] = self.confidence.value if self.confidence else "unknown"
        data["timestamp"] = self.timestamp.isoformat() if self.timestamp else None

        # Handle optional fields (delete when None)
        for key in [
            "parameter",
            "parameter_type",
            "payload",
            "evidence",
            "http_request",
            "http_response",
            "cvss_score",
            "cwe_id",
            "module",
            "description",
            "recommendation",
            "references",
            "tags",
            "impact",
            "scanner",
            "context",
        ]:
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
    def from_dict(cls, data: Dict[str, Any]) -> "Vulnerability":
        """Create a Vulnerability object from a dictionary"""
        # Handle special types
        data = data.copy()

        if "type" in data:
            raw = data["type"]
            try:
                data["type"] = VulnerabilityType(raw)
            except ValueError:
                # P9: Map known aliases (code_injection, EL, etc.) → canonical type
                mapped = cls._TYPE_ALIASES.get(raw)
                if mapped is not None:
                    data["type"] = mapped
                else:
                    data["type"] = VulnerabilityType.OTHER

        if "severity" in data:
            data["severity"] = Severity(data["severity"])

        if "confidence" in data:
            data["confidence"] = Confidence(data["confidence"])

        if "timestamp" in data and isinstance(data["timestamp"], str):
            data["timestamp"] = datetime.fromisoformat(data["timestamp"])

        # Normalize: ensure string optional fields are never None
        for key in ["parameter", "parameter_type", "payload", "evidence", "http_request", "http_response", "module"]:
            if key in data and data[key] is None:
                data[key] = ""
        # Remove other None values so dataclass uses defaults
        for key in list(data.keys()):
            if data[key] is None:
                del data[key]

        return cls(**data)

    def __str__(self) -> str:
        """User-friendly string representation"""
        return f"[{self.severity.value.upper()}] {self.type.value}: {self.title}"


@dataclass
class ScanTarget:
    """Scan target"""

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
    """Scan result"""

    target: ScanTarget
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    scan_time: datetime = field(default_factory=datetime.now)
    duration: float = 0.0  # Scan duration (seconds)
    requests_made: int = 0
    endpoints_found: int = 0
    modules_run: int = 0
    errors: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def vulnerability_count(self) -> Dict[str, int]:
        """Count vulnerabilities by type (None-safe)"""
        counts = {}
        for vuln in self.vulnerabilities:
            vuln_type = vuln.type.value if vuln.type else "unknown"
            counts[vuln_type] = counts.get(vuln_type, 0) + 1
        return counts

    @property
    def severity_count(self) -> Dict[str, int]:
        """Count vulnerabilities by severity (None-safe)"""
        counts = {}
        for vuln in self.vulnerabilities:
            severity = vuln.severity.value if vuln.severity else "info"
            counts[severity] = counts.get(severity, 0) + 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data["target"] = self.target.to_dict()
        data["vulnerabilities"] = [v.to_dict() for v in self.vulnerabilities]
        data["scan_time"] = self.scan_time.isoformat()
        data["vulnerability_count"] = self.vulnerability_count
        data["severity_count"] = self.severity_count
        return data


@dataclass
class ModuleConfig:
    """Module configuration"""

    enabled: bool = True
    timeout: int = 30
    threads: int = 3
    depth: int = 3
    custom_params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScannerConfig:
    """Scanner global configuration"""

    # Basic settings
    timeout: int = 30
    threads: int = 3
    user_agent: str = "WVS/19.0"
    follow_redirects: bool = True
    verify_ssl: bool = DEFAULT_VERIFY_SSL

    # Module configuration
    modules: Dict[str, ModuleConfig] = field(default_factory=dict)

    # Performance settings
    delay: float = 0.1
    max_requests_per_second: int = 10
    retry_count: int = 3
    concurrent_endpoints: int = 6
    concurrent_modules: int = 2

    # Crawler settings
    crawl_depth: int = 4
    crawl_max_urls: int = 300

    # WAF / OOB / Rate control
    enable_waf_detection: bool = True
    enable_waf_evasion: bool = True
    enable_oob: bool = False
    oob_provider: str = "interactsh"
    rate_mode: str = "burst"
    enable_adaptive_rate: bool = True

    # Global timeout
    max_time: int = 3600

    # Output settings
    output_format: str = "json"
    output_file: Optional[str] = None
    verbose: bool = False

    def get_module_config(self, module_name: str) -> ModuleConfig:
        """Get module configuration, creates a default one if it doesn't exist"""
        if module_name not in self.modules:
            self.modules[module_name] = ModuleConfig()
        return self.modules[module_name]


# Convenience function
def create_vulnerability(
    vuln_type: VulnerabilityType,
    url: str,
    severity: Severity = Severity.MEDIUM,
    confidence: Confidence = Confidence.MEDIUM,
    title: str = "",
    description: str = "",
    payload: Optional[str] = None,
    parameter: Optional[str] = None,
    **kwargs,
) -> Vulnerability:
    """Convenience function to create a Vulnerability object"""
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
        **kwargs,
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
        recommendation="使用参数化查询或预编译语句",
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
