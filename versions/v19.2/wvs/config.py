"""
统一配置管理系统
解决WVS v18.4中配置管理混乱、硬编码和配置混用的问题
"""
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional
import yaml

from .models import ScannerConfig, ModuleConfig
from .constants import DEFAULT_TIMEOUT, DEFAULT_RETRY_COUNT, DEFAULT_MAX_RPS, DEFAULT_DELAY, DEFAULT_VERIFY_SSL


class ConfigError(Exception):
    """配置相关异常"""
    pass


class ConfigManager:
    """
    统一的配置管理器
    
    特性：
    1. 支持多种配置源（文件、环境变量、命令行参数）
    2. 类型安全的配置访问
    3. 配置验证和默认值
    4. 配置合并策略
    """
    
    # 默认配置 (v19 P0-P4 upgrade)
    DEFAULT_CONFIG = {
        "timeout": DEFAULT_TIMEOUT,
        "threads": 5,
        "user_agent": "WVS/19.0",
        "follow_redirects": True,
        "verify_ssl": DEFAULT_VERIFY_SSL,
        "delay": DEFAULT_DELAY,
        "max_requests_per_second": 20,
        "retry_count": DEFAULT_RETRY_COUNT,
        "output_format": "json",
        "verbose": False,
        # New: crawler config (P10: conservative defaults)
        "crawl_depth": 4,             # P11: increased from 3 for deeper coverage
        "crawl_max_urls": 300,        # P11: increased from 200 for multiservice targets
        # New: concurrency
        "concurrent_endpoints": 6,     # P11: reduced from 8 to reduce server overload
        "concurrent_modules": 2,       # P10: reduced from 3 to reduce server load
        # New: WAF detection
        "enable_waf_detection": True,
        "enable_waf_evasion": True,
        # New: OOB
        "enable_oob": False,
        "oob_provider": "interactsh",
        # New: rate limiting mode
        "rate_mode": "burst",
        "enable_adaptive_rate": True,
        # P10: Global scan timeout (seconds) — prevents runaway scans
        "max_time": 3600,  # 1 hour max
        "modules": {
            "sqli": {
                "enabled": True,
                "timeout": 30,
                "threads": 2,        # P10: reduced from 3
                "depth": 3,
                "custom_params": {"test_boolean_blind": True, "test_time_based": True}
            },
            "xss": {
                "enabled": True,
                "timeout": 30,
                "threads": 2,        # P10: reduced from 3
                "depth": 3,
                "custom_params": {"test_dom_xss": True, "confidence_threshold": 0.7}
            },
            "cmdi": {
                "enabled": True,
                "timeout": 30,
                "threads": 2,
                "depth": 2
            },
            "lfi": {
                "enabled": True,
                "timeout": 30,
                "threads": 2,
                "depth": 2
            },
            "api": {
                "enabled": True,
                "timeout": 60,
                "threads": 2,
                "depth": 2
            },
            "sensitive": {
                "enabled": True,
                "timeout": 30,
                "threads": 2,
                "depth": 2
            },
            "xxe": {
                "enabled": True,
                "timeout": 30,
                "threads": 2,
                "depth": 2
            },
            "ssrf": {
                "enabled": True,
                "timeout": 30,
                "threads": 2,
                "depth": 2
            },
            "rce": {
                "enabled": True,
                "timeout": 30,
                "threads": 2,
                "depth": 3,
            },
            # v19.2: JS pathfinder — endpoint discovery & secret scanning
            "jspathfinder": {
                "enabled": True,
                "timeout": 15,
                "threads": 10,
                "depth": 1,
                "custom_params": {
                    "fuzz": True,
                    "use_playwright": False,
                },
            },
        },
        # v19.2: External tool integrations
        "integrations": {
            "enabled": True,
            "nuclei": {
                "enabled": True,
                "timeout": 300,
                "rate_limit": 20,
            },
            "sqlmap": {
                "enabled": True,
                "timeout": 600,
                "level": 2,
                "risk": 1,
                "aggressive": False,
            },
            "ffuf": {
                "enabled": True,
                "timeout": 120,
                "rate": 30,
            },
            "wappalyzer": {
                "enabled": True,
                "timeout": 30,
            },
        },
    }
    
    # 环境变量映射
    ENV_MAPPING = {
        "WVS_TIMEOUT": "timeout",
        "WVS_THREADS": "threads",
        "WVS_USER_AGENT": "user_agent",
        "WVS_VERIFY_SSL": "verify_ssl",
        "WVS_DELAY": "delay",
        "WVS_MAX_RPS": "max_requests_per_second",
        "WVS_RETRY_COUNT": "retry_count",
        "WVS_OUTPUT_FORMAT": "output_format",
        "WVS_VERBOSE": "verbose",
    }
    
    def __init__(self, config_file: Optional[str] = None):
        """
        初始化配置管理器
        
        Args:
            config_file: 配置文件路径（可选）
        """
        self.config_file = config_file
        self._config = self.DEFAULT_CONFIG.copy()
        self._scanner_config: Optional[ScannerConfig] = None
        
        # 加载配置
        self._load_config()
    
    def _load_config(self) -> None:
        """加载配置"""
        # 1. 加载默认配置
        config = self.DEFAULT_CONFIG.copy()
        
        # 2. 加载配置文件
        if self.config_file and os.path.exists(self.config_file):
            file_config = self._load_config_file(self.config_file)
            config = self._merge_configs(config, file_config)
        
        # 3. 加载环境变量
        env_config = self._load_env_vars()
        config = self._merge_configs(config, env_config)
        
        self._config = config
    
    def _load_config_file(self, filepath: str) -> Dict[str, Any]:
        """从文件加载配置"""
        path = Path(filepath)
        
        if not path.exists():
            raise ConfigError(f"配置文件不存在: {filepath}")
        
        try:
            content = path.read_text(encoding='utf-8')
            
            if path.suffix.lower() in ['.yaml', '.yml']:
                return yaml.safe_load(content) or {}
            elif path.suffix.lower() == '.json':
                return json.loads(content)
            else:
                # 尝试自动检测格式
                try:
                    return json.loads(content)
                except json.JSONDecodeError:
                    return yaml.safe_load(content) or {}
                    
        except (yaml.YAMLError, json.JSONDecodeError) as e:
            raise ConfigError(f"配置文件解析失败 {filepath}: {e}")
        except Exception as e:
            raise ConfigError(f"读取配置文件失败 {filepath}: {e}")
    
    def _load_env_vars(self) -> Dict[str, Any]:
        """从环境变量加载配置"""
        config = {}
        
        for env_var, config_key in self.ENV_MAPPING.items():
            value = os.getenv(env_var)
            if value is not None:
                # 类型转换
                if config_key in ['timeout', 'threads', 'max_requests_per_second', 'retry_count']:
                    try:
                        config[config_key] = int(value)
                    except ValueError:
                        pass
                elif config_key in ['delay']:
                    try:
                        config[config_key] = float(value)
                    except ValueError:
                        pass
                elif config_key in ['verify_ssl', 'verbose']:
                    config[config_key] = value.lower() in ['true', '1', 'yes', 'y']
                else:
                    config[config_key] = value
        
        return config
    
    def _merge_configs(self, base: Dict[str, Any], overlay: Dict[str, Any]) -> Dict[str, Any]:
        """递归合并配置字典"""
        result = base.copy()
        
        for key, value in overlay.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        获取配置值
        
        Args:
            key: 配置键，支持点号分隔（如 'modules.sqli.timeout'）
            default: 默认值
        
        Returns:
            配置值
        """
        keys = key.split('.')
        value = self._config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key: str, value: Any) -> None:
        """
        设置配置值
        
        Args:
            key: 配置键，支持点号分隔
            value: 配置值
        """
        keys = key.split('.')
        config = self._config
        
        # 遍历到最后一个键的父级
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
        self._scanner_config = None  # 使缓存的ScannerConfig失效
    
    def get_scanner_config(self) -> ScannerConfig:
        """
        获取ScannerConfig对象
        
        Returns:
            ScannerConfig实例
        """
        if self._scanner_config is None:
            self._scanner_config = self._create_scanner_config()
        return self._scanner_config
    
    def _create_scanner_config(self) -> ScannerConfig:
        """从配置字典创建ScannerConfig对象"""
        # 创建模块配置
        modules_config = {}
        for module_name, module_data in self._config.get('modules', {}).items():
            modules_config[module_name] = ModuleConfig(
                enabled=module_data.get('enabled', True),
                timeout=module_data.get('timeout', 30),
                threads=module_data.get('threads', 3),
                depth=module_data.get('depth', 3),
                custom_params=module_data.get('custom_params', {})
            )
        
        # 创建ScannerConfig
        return ScannerConfig(
            timeout=self.get('timeout', DEFAULT_TIMEOUT),
            threads=self.get('threads', 3),
            user_agent=self.get('user_agent', 'WVS/19.0'),
            follow_redirects=self.get('follow_redirects', True),
            verify_ssl=self.get('verify_ssl', DEFAULT_VERIFY_SSL),
            delay=self.get('delay', DEFAULT_DELAY),
            max_requests_per_second=self.get('max_requests_per_second', DEFAULT_MAX_RPS),
            retry_count=self.get('retry_count', DEFAULT_RETRY_COUNT),
            output_format=self.get('output_format', 'json'),
            output_file=self.get('output_file'),
            verbose=self.get('verbose', False),
            modules=modules_config,
            crawl_depth=self.get('crawl_depth', 4),
            crawl_max_urls=self.get('crawl_max_urls', 300),
            concurrent_endpoints=self.get('concurrent_endpoints', 6),
            concurrent_modules=self.get('concurrent_modules', 2),
            enable_waf_detection=self.get('enable_waf_detection', True),
            enable_waf_evasion=self.get('enable_waf_evasion', True),
            enable_oob=self.get('enable_oob', False),
            oob_provider=self.get('oob_provider', 'interactsh'),
            rate_mode=self.get('rate_mode', 'burst'),
            enable_adaptive_rate=self.get('enable_adaptive_rate', True),
            max_time=self.get('max_time', 3600),
        )
    
    def save(self, filepath: Optional[str] = None) -> None:
        """
        保存配置到文件
        
        Args:
            filepath: 文件路径，如果为None则使用初始化的config_file
        """
        save_path = filepath or self.config_file
        if not save_path:
            raise ConfigError("未指定配置文件路径")
        
        path = Path(save_path)
        
        try:
            # 确保目录存在
            path.parent.mkdir(parents=True, exist_ok=True)
            
            # 保存为YAML格式
            content = yaml.dump(self._config, default_flow_style=False, allow_unicode=True)
            path.write_text(content, encoding='utf-8')
            
        except Exception as e:
            raise ConfigError(f"保存配置失败 {save_path}: {e}")
    
    def validate(self) -> bool:
        """
        验证配置
        
        Returns:
            配置是否有效
        """
        try:
            # 基本类型验证
            if not isinstance(self.get('timeout'), int) or self.get('timeout') <= 0:
                return False
            
            if not isinstance(self.get('threads'), int) or self.get('threads') <= 0:
                return False
            
            if not isinstance(self.get('delay'), (int, float)) or self.get('delay') < 0:
                return False
            
            # 模块配置验证
            modules = self.get('modules', {})
            for module_name, module_config in modules.items():
                if not isinstance(module_config, dict):
                    return False
                
                if 'enabled' in module_config and not isinstance(module_config['enabled'], bool):
                    return False
            
            return True
            
        except Exception:
            return False
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return self._config.copy()
    
    def __str__(self) -> str:
        """友好的字符串表示"""
        config_str = []
        config_str.append("WVS 配置:")
        config_str.append(f"  超时: {self.get('timeout')}秒")
        config_str.append(f"  线程数: {self.get('threads')}")
        config_str.append(f"  用户代理: {self.get('user_agent')}")
        config_str.append(f"  延迟: {self.get('delay')}秒")
        
        # 模块状态
        enabled_modules = []
        modules = self.get('modules', {})
        for module_name, module_config in modules.items():
            if module_config.get('enabled', True):
                enabled_modules.append(module_name)
        
        config_str.append(f"  启用模块: {', '.join(enabled_modules)}")
        
        return "\n".join(config_str)


# 全局配置实例（单例模式）
_global_config: Optional[ConfigManager] = None


def get_global_config(config_file: Optional[str] = None) -> ConfigManager:
    """
    获取全局配置管理器
    
    Args:
        config_file: 配置文件路径（仅在首次调用时生效）
    
    Returns:
        ConfigManager实例
    """
    global _global_config
    
    if _global_config is None:
        _global_config = ConfigManager(config_file)
    
    return _global_config


def reset_global_config(config_file: Optional[str] = None) -> None:
    """
    重置全局配置
    
    Args:
        config_file: 新的配置文件路径
    """
    global _global_config
    _global_config = ConfigManager(config_file)


# 示例配置文件
EXAMPLE_CONFIG = {
    "timeout": 45,
    "threads": 5,
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "follow_redirects": True,
    "verify_ssl": True,
    "delay": 0.2,
    "max_requests_per_second": 5,
    "retry_count": 2,
    "output_format": "html",
    "verbose": True,
    "modules": {
        "sqli": {
            "enabled": True,
            "timeout": 60,
            "threads": 3,
            "depth": 5,
            "custom_params": {
                "test_boolean_blind": True,
                "test_time_based": True
            }
        },
        "xss": {
            "enabled": True,
            "timeout": 45,
            "threads": 4,
            "depth": 4,
            "custom_params": {
                "test_dom_xss": True,
                "confidence_threshold": 0.7
            }
        },
        "api_security": {
            "enabled": True,
            "timeout": 90,
            "threads": 2,
            "depth": 3
        }
    }
}


def create_example_config(filepath: str) -> None:
    """
    创建示例配置文件
    
    Args:
        filepath: 配置文件路径
    """
    path = Path(filepath)
    
    # 确保目录存在
    path.parent.mkdir(parents=True, exist_ok=True)
    
    # 保存为YAML格式
    content = yaml.dump(EXAMPLE_CONFIG, default_flow_style=False, allow_unicode=True)
    path.write_text(content, encoding='utf-8')


if __name__ == "__main__":
    # 测试配置管理器
    print("测试配置管理器...")
    
    # 创建配置管理器
    config = ConfigManager()
    
    print("\n1. 默认配置:")
    print(config)
    
    print("\n2. 获取特定配置:")
    print(f"  超时: {config.get('timeout')}")
    print(f"  SQLI模块超时: {config.get('modules.sqli.timeout')}")
    
    print("\n3. 设置配置:")
    config.set('timeout', 60)
    config.set('modules.sqli.custom_params.test_boolean_blind', True)
    print(f"  新超时: {config.get('timeout')}")
    
    print("\n4. 验证配置:")
    print(f"  配置有效: {config.validate()}")
    
    print("\n5. 转换为ScannerConfig:")
    scanner_config = config.get_scanner_config()
    print(f"  ScannerConfig对象: {scanner_config}")
    
    print("\n测试完成！")