"""YAML 配置解析模块"""
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, field

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

from .config import ScanConfig
from .auth import AuthConfig


@dataclass
class ScanProfile:
    """扫描策略配置"""
    name: str
    description: str
    port_range: tuple = (1, 1000)
    max_depth: int = 3
    max_urls: int = 100
    concurrency: int = 50
    timeout: float = 10.0
    
    # 检测模块开关
    modules: Dict[str, bool] = field(default_factory=lambda: {
        "xss": True,
        "sqli": True,
        "info": True,
        "traversal": True,
    })
    
    # POC 验证
    verify_poc: bool = False
    
    # 过滤配置
    min_confidence: float = 0.5
    deduplicate: bool = True


class ConfigManager:
    """配置管理器"""
    
    # 预定义扫描策略
    PROFILES = {
        "quick": ScanProfile(
            name="quick",
            description="快速扫描 - 仅检测高危漏洞",
            port_range=(80, 443),
            max_depth=2,
            max_urls=50,
            modules={"xss": True, "sqli": True, "info": False, "traversal": False},
            verify_poc=False,
        ),
        "standard": ScanProfile(
            name="standard",
            description="标准扫描 - 全面检测",
            port_range=(1, 1000),
            max_depth=3,
            max_urls=100,
            modules={"xss": True, "sqli": True, "info": True, "traversal": True},
            verify_poc=False,
        ),
        "deep": ScanProfile(
            name="deep",
            description="深度扫描 - 包含 POC 验证",
            port_range=(1, 65535),
            max_depth=5,
            max_urls=500,
            modules={"xss": True, "sqli": True, "info": True, "traversal": True},
            verify_poc=True,
            min_confidence=0.3,
        ),
    }
    
    @classmethod
    def get_profile(cls, name: str) -> Optional[ScanProfile]:
        """获取预定义策略"""
        return cls.PROFILES.get(name)
    
    @classmethod
    def list_profiles(cls) -> Dict[str, str]:
        """列出所有可用策略"""
        return {name: profile.description for name, profile in cls.PROFILES.items()}
    
    @classmethod
    def load_from_yaml(cls, yaml_path: str) -> Dict[str, Any]:
        """从 YAML 文件加载配置"""
        if not YAML_AVAILABLE:
            raise ImportError("需要安装 PyYAML: pip install pyyaml")
        
        path = Path(yaml_path)
        if not path.exists():
            raise FileNotFoundError(f"配置文件不存在: {yaml_path}")
        
        with open(path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
        
        return config
    
    @classmethod
    def save_to_yaml(cls, config: Dict[str, Any], yaml_path: str):
        """保存配置到 YAML 文件"""
        if not YAML_AVAILABLE:
            raise ImportError("需要安装 PyYAML: pip install pyyaml")
        
        with open(yaml_path, "w", encoding="utf-8") as f:
            yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
    
    @classmethod
    def create_scan_config(cls, target: str, profile_name: str = "standard",
                          yaml_config: str = None, **overrides) -> ScanConfig:
        """
        创建扫描配置
        
        Args:
            target: 扫描目标
            profile_name: 策略名称 (quick/standard/deep)
            yaml_config: YAML 配置文件路径
            **overrides: 覆盖配置
        """
        # 加载 YAML 配置
        if yaml_config:
            yaml_cfg = cls.load_from_yaml(yaml_config)
        else:
            yaml_cfg = {}
        
        # 获取策略
        profile = cls.get_profile(profile_name) or cls.PROFILES["standard"]
        
        # 合并配置
        config_dict = {
            "target": target,
            "port_range": yaml_cfg.get("scan", {}).get("port_range", profile.port_range),
            "max_depth": yaml_cfg.get("scan", {}).get("max_depth", profile.max_depth),
            "max_urls": yaml_cfg.get("scan", {}).get("max_urls", profile.max_urls),
            "concurrency": yaml_cfg.get("scan", {}).get("concurrency", profile.concurrency),
            "timeout": yaml_cfg.get("scan", {}).get("timeout", profile.timeout),
            "check_xss": yaml_cfg.get("scan", {}).get("modules", {}).get("xss", profile.modules["xss"]),
            "check_sqli": yaml_cfg.get("scan", {}).get("modules", {}).get("sqli", profile.modules["sqli"]),
            "check_info": yaml_cfg.get("scan", {}).get("modules", {}).get("info", profile.modules["info"]),
            "check_traversal": yaml_cfg.get("scan", {}).get("modules", {}).get("traversal", profile.modules["traversal"]),
            "verify_poc": yaml_cfg.get("scan", {}).get("verify_poc", profile.verify_poc),
            "min_confidence": yaml_cfg.get("scan", {}).get("min_confidence", profile.min_confidence),
            "deduplicate": yaml_cfg.get("scan", {}).get("deduplicate", profile.deduplicate),
        }
        
        # 处理认证配置
        auth_cfg = yaml_cfg.get("auth", {})
        if auth_cfg:
            auth_type = auth_cfg.get("type", "none")
            if auth_type == "cookie":
                config_dict["auth"] = AuthConfig(auth_type="cookie", cookie=auth_cfg.get("value"))
            elif auth_type == "bearer":
                config_dict["auth"] = AuthConfig(auth_type="bearer", token=auth_cfg.get("value"))
            elif auth_type == "basic":
                creds = auth_cfg.get("value", "").split(":", 1)
                if len(creds) == 2:
                    config_dict["auth"] = AuthConfig(auth_type="basic", username=creds[0], password=creds[1])
            else:
                config_dict["auth"] = AuthConfig(auth_type="none")
        else:
            config_dict["auth"] = AuthConfig(auth_type="none")
        
        # 应用覆盖配置
        config_dict.update(overrides)
        
        return ScanConfig(**config_dict)
    
    @classmethod
    def generate_sample_config(cls) -> str:
        """生成示例配置文件内容"""
        return '''# WVS 扫描配置文件示例

# 扫描目标
target: http://example.com

# 扫描策略
scan:
  # 端口范围
  port_range: [1, 1000]
  
  # 爬虫配置
  max_depth: 3
  max_urls: 100
  
  # 并发配置
  concurrency: 50
  timeout: 10.0
  
  # 检测模块
  modules:
    xss: true
    sqli: true
    info: true
    traversal: true
  
  # POC 验证
  verify_poc: false
  
  # 过滤配置
  min_confidence: 0.5
  deduplicate: true

# 认证配置 (可选)
# auth:
#   type: cookie  # cookie, bearer, basic
#   value: sessionid=abc123

# 输出配置
output:
  dir: reports
  formats: [html, json, csv]
'''
