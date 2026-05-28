"""
RayScan unified configuration management.

Supports multiple config sources (YAML files, environment variables, CLI args)
with type-safe access, validation, and merge strategy.
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional
import yaml

from .models import ScannerConfig, ModuleConfig
from .constants import DEFAULT_TIMEOUT, DEFAULT_RETRY_COUNT, DEFAULT_DELAY, DEFAULT_VERIFY_SSL


class ConfigError(Exception):
    """Configuration related exception"""

    pass


class ConfigManager:
    """
    Unified configuration manager

    Features:
    1. Supports multiple configuration sources (file, environment variables, command-line arguments)
    2. Type-safe configuration access
    3. Configuration validation and defaults
    4. Configuration merge strategy
    """

    # Default configuration (v19 P0-P4 upgrade)
    DEFAULT_CONFIG = {
        "timeout": DEFAULT_TIMEOUT,
        "threads": 5,
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "follow_redirects": True,
        "verify_ssl": DEFAULT_VERIFY_SSL,
        "delay": DEFAULT_DELAY,
        "max_requests_per_second": 20,
        "retry_count": DEFAULT_RETRY_COUNT,
        "output_format": "json",
        "verbose": False,
        # New: crawler config (P10: conservative defaults)
        "crawl_depth": 4,  # P11: increased from 3 for deeper coverage
        "crawl_max_urls": 300,  # P11: increased from 200 for multiservice targets
        # New: concurrency
        "concurrent_endpoints": 10,  # increased from 6 for faster scanning
        "concurrent_modules": 2,  # P10: reduced from 3 to reduce server load
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
                "threads": 2,  # P10: reduced from 3
                "depth": 3,
                "custom_params": {"test_boolean_blind": True, "test_time_based": True},
            },
            "xss": {
                "enabled": True,
                "timeout": 30,
                "threads": 2,  # P10: reduced from 3
                "depth": 3,
                "custom_params": {"test_dom_xss": True, "confidence_threshold": 0.7},
            },
            "cmdi": {"enabled": True, "timeout": 30, "threads": 2, "depth": 2},
            "lfi": {"enabled": True, "timeout": 30, "threads": 2, "depth": 2},
            "api": {"enabled": True, "timeout": 60, "threads": 2, "depth": 2},
            "sensitive": {"enabled": True, "timeout": 30, "threads": 2, "depth": 2},
            "xxe": {"enabled": True, "timeout": 30, "threads": 2, "depth": 2},
            "ssrf": {"enabled": True, "timeout": 30, "threads": 2, "depth": 2},
            "rce": {
                "enabled": True,
                "timeout": 30,
                "threads": 2,
                "depth": 3,
            },
            # v19.2: JS pathfinder — disabled by default in v1.1.0 (sqli+xss focus)
            "jspathfinder": {
                "enabled": False,
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

    # Environment variable mapping
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
        Initialize the configuration manager

        Args:
            config_file: Path to configuration file (optional)
        """
        self.config_file = config_file
        self._config = self.DEFAULT_CONFIG.copy()
        self._scanner_config: Optional[ScannerConfig] = None

        # Load configuration
        self._load_config()

    def _load_config(self) -> None:
        """Load configuration"""
        # 1. Load default configuration
        config = self.DEFAULT_CONFIG.copy()

        # 2. Load configuration file
        if self.config_file and os.path.exists(self.config_file):
            file_config = self._load_config_file(self.config_file)
            config = self._merge_configs(config, file_config)

        # 3. Load environment variables
        env_config = self._load_env_vars()
        config = self._merge_configs(config, env_config)

        self._config = config

    def _load_config_file(self, filepath: str) -> Dict[str, Any]:
        """Load configuration from file"""
        path = Path(filepath)

        if not path.exists():
            raise ConfigError(f"Configuration file not found: {filepath}")

        try:
            content = path.read_text(encoding="utf-8")

            if path.suffix.lower() in [".yaml", ".yml"]:
                return yaml.safe_load(content) or {}
            elif path.suffix.lower() == ".json":
                return json.loads(content)
            else:
                # Try to auto-detect format
                try:
                    return json.loads(content)
                except json.JSONDecodeError:
                    return yaml.safe_load(content) or {}

        except (yaml.YAMLError, json.JSONDecodeError) as e:
            raise ConfigError(f"Failed to parse configuration file {filepath}: {e}")
        except Exception as e:
            raise ConfigError(f"Failed to read configuration file {filepath}: {e}")

    def _load_env_vars(self) -> Dict[str, Any]:
        """Load configuration from environment variables"""
        config = {}

        for env_var, config_key in self.ENV_MAPPING.items():
            value = os.getenv(env_var)
            if value is not None:
                # Type conversion
                if config_key in ["timeout", "threads", "max_requests_per_second", "retry_count"]:
                    try:
                        config[config_key] = int(value)
                    except ValueError:
                        pass
                elif config_key in ["delay"]:
                    try:
                        config[config_key] = float(value)
                    except ValueError:
                        pass
                elif config_key in ["verify_ssl", "verbose"]:
                    config[config_key] = value.lower() in ["true", "1", "yes", "y"]
                else:
                    config[config_key] = value

        return config

    def _merge_configs(self, base: Dict[str, Any], overlay: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively merge configuration dictionaries"""
        result = base.copy()

        for key, value in overlay.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value

        return result

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value

        Args:
            key: Configuration key, dot-separated (e.g. 'modules.sqli.timeout')
            default: Default value

        Returns:
            Configuration value
        """
        keys = key.split(".")
        value = self._config

        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default

    def set(self, key: str, value: Any) -> None:
        """
        Set a configuration value

        Args:
            key: Configuration key, dot-separated
            value: Configuration value
        """
        keys = key.split(".")
        config = self._config

        # Traverse to the parent of the last key
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]

        config[keys[-1]] = value
        self._scanner_config = None  # Invalidate cached ScannerConfig

    def get_scanner_config(self) -> ScannerConfig:
        """
        Get the ScannerConfig object

        Returns:
            ScannerConfig instance
        """
        if self._scanner_config is None:
            self._scanner_config = self._create_scanner_config()
        return self._scanner_config

    def _create_scanner_config(self) -> ScannerConfig:
        """Create ScannerConfig from config dictionary (auto-map dataclass fields)"""
        from dataclasses import fields, MISSING

        # Create module configurations
        modules_config = {}
        for module_name, module_data in self._config.get("modules", {}).items():
            modules_config[module_name] = ModuleConfig(
                enabled=module_data.get("enabled", True),
                timeout=module_data.get("timeout", 30),
                threads=module_data.get("threads", 3),
                depth=module_data.get("depth", 3),
                custom_params=module_data.get("custom_params", {}),
            )

        # Auto-map ScannerConfig fields to eliminate manual per-field duplication
        kwargs = {}
        for f in fields(ScannerConfig):
            if f.name == "modules":
                kwargs["modules"] = modules_config
                continue
            default = f.default if f.default is not MISSING else None
            kwargs[f.name] = self.get(f.name, default)

        return ScannerConfig(**kwargs)

    def save(self, filepath: Optional[str] = None) -> None:
        """
        Save configuration to file

        Args:
            filepath: File path, defaults to the config_file from initialization if None
        """
        save_path = filepath or self.config_file
        if not save_path:
            raise ConfigError("No configuration file path specified")

        path = Path(save_path)

        try:
            # Ensure directory exists
            path.parent.mkdir(parents=True, exist_ok=True)

            # Save as YAML format
            content = yaml.dump(self._config, default_flow_style=False, allow_unicode=True)
            path.write_text(content, encoding="utf-8")

        except Exception as e:
            raise ConfigError(f"Failed to save configuration to {save_path}: {e}")

    def validate(self) -> bool:
        """
        Validate configuration

        Returns:
            Whether the configuration is valid
        """
        try:
            # Basic type validation
            if not isinstance(self.get("timeout"), int) or self.get("timeout") <= 0:
                return False

            if not isinstance(self.get("threads"), int) or self.get("threads") <= 0:
                return False

            if not isinstance(self.get("delay"), (int, float)) or self.get("delay") < 0:
                return False

            # Module configuration validation
            modules = self.get("modules", {})
            for module_name, module_config in modules.items():
                if not isinstance(module_config, dict):
                    return False

                if "enabled" in module_config and not isinstance(module_config["enabled"], bool):
                    return False

            return True

        except Exception:
            return False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return self._config.copy()

    def __str__(self) -> str:
        """User-friendly string representation"""
        config_str = []
        config_str.append("WVS Configuration:")
        config_str.append(f"  Timeout: {self.get('timeout')}s")
        config_str.append(f"  Threads: {self.get('threads')}")
        config_str.append(f"  User-Agent: {self.get('user_agent')}")
        config_str.append(f"  Delay: {self.get('delay')}s")

        # Module status
        enabled_modules = []
        modules = self.get("modules", {})
        for module_name, module_config in modules.items():
            if module_config.get("enabled", True):
                enabled_modules.append(module_name)

        config_str.append(f"  Enabled modules: {', '.join(enabled_modules)}")

        return "\n".join(config_str)


# Example configuration
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
        "sqli": {"enabled": True, "timeout": 60, "threads": 3, "depth": 5, "custom_params": {"test_boolean_blind": True, "test_time_based": True}},
        "xss": {"enabled": True, "timeout": 45, "threads": 4, "depth": 4, "custom_params": {"test_dom_xss": True, "confidence_threshold": 0.7}},
        "api_security": {"enabled": True, "timeout": 90, "threads": 2, "depth": 3},
    },
}


def create_example_config(filepath: str) -> None:
    """
    Create an example configuration file

    Args:
        filepath: Configuration file path
    """
    path = Path(filepath)

    # Ensure directory exists
    path.parent.mkdir(parents=True, exist_ok=True)

    # Save as YAML format
    content = yaml.dump(EXAMPLE_CONFIG, default_flow_style=False, allow_unicode=True)
    path.write_text(content, encoding="utf-8")


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
    config.set("timeout", 60)
    config.set("modules.sqli.custom_params.test_boolean_blind", True)
    print(f"  新超时: {config.get('timeout')}")

    print("\n4. 验证配置:")
    print(f"  配置有效: {config.validate()}")

    print("\n5. 转换为ScannerConfig:")
    scanner_config = config.get_scanner_config()
    print(f"  ScannerConfig对象: {scanner_config}")

    print("\n测试完成！")
