"""
RayScan PoC Source Manager — 多来源 PoC 管理

整合以下来源：
- Nuclei YAML 模板 (12.5w+)
- xRay POC 规则
- Beebeeto PoC
- BugScan PoC

配置示例 (config.yaml):
```yaml
poc_sources:
  nuclei:
    enabled: true
    paths: ["~/.rayscan/nuclei-templates"]
    auto_update: true
  xray:
    enabled: true
    paths: ["~/.rayscan/xray-pocs"]
  beebeeto:
    enabled: false
    paths: ["~/.rayscan/beebeeto-pocs"]
  bugscan:
    enabled: false
    paths: ["~/.rayscan/bugscan-pocs"]
```
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .nuclei_template_manager import POC_SOURCES, get_template_manager

logger = logging.getLogger("wvs.poc_source_manager")

# 默认 PoC 来源配置
DEFAULT_POC_CONFIG: Dict[str, dict] = {
    "nuclei": {
        "enabled": True,
        "label": "Nuclei YAML 模板",
        "description": "ProjectDiscovery 模板引擎，12.5w+ CVE/PoC",
        "dir": "nuclei-templates",
        "ext": ".yaml",
        "priority": 1,
    },
    "xray": {
        "enabled": True,
        "label": "xRay POC 规则",
        "description": "长亭科技 xRay 扫描器 POC 规则集",
        "dir": "xray-pocs",
        "ext": ".yaml",
        "priority": 2,
    },
    "beebeeto": {
        "enabled": False,
        "label": "Beebeeto PoC",
        "description": "Beebeeto 开源 PoC 框架",
        "dir": "beebeeto-pocs",
        "ext": ".py",
        "priority": 3,
    },
    "bugscan": {
        "enabled": False,
        "label": "BugScan PoC",
        "description": "BugScan 社区 PoC 库",
        "dir": "bugscan-pocs",
        "ext": ".php",
        "priority": 4,
    },
}


@dataclass
class PoCSourceInfo:
    """PoC 来源信息"""
    name: str
    label: str
    description: str
    enabled: bool
    dir_name: str
    ext: str
    priority: int
    template_count: int = 0
    base_path: Optional[str] = None


class PoCSourceManager:
    """
    PoC 来源管理器

    管理多个来源的 PoC 模板，提供统一的查询接口。
    """

    def __init__(self, rayscan_dir: Optional[str] = None):
        self.rayscan_dir = rayscan_dir or str(Path.home() / ".rayscan")
        self.sources: Dict[str, PoCSourceInfo] = {}
        self._init_sources()

    def _init_sources(self) -> None:
        """初始化 PoC 来源"""
        for name, cfg in DEFAULT_POC_CONFIG.items():
            base_path = str(Path(self.rayscan_dir) / cfg["dir"])
            source = PoCSourceInfo(
                name=name,
                label=cfg["label"],
                description=cfg["description"],
                enabled=cfg["enabled"],
                dir_name=cfg["dir"],
                ext=cfg["ext"],
                priority=cfg["priority"],
                base_path=base_path,
            )
            # 统计已有模板数
            p = Path(base_path)
            if p.exists():
                source.template_count = len(list(p.rglob(f"*{cfg['ext']}")))
            self.sources[name] = source

    def get_enabled_sources(self) -> List[PoCSourceInfo]:
        """获取已启用的 PoC 来源"""
        return [s for s in self.sources.values() if s.enabled]

    def get_source(self, name: str) -> Optional[PoCSourceInfo]:
        """获取指定来源信息"""
        return self.sources.get(name)

    def get_total_count(self) -> int:
        """获取所有来源的模板总数"""
        return sum(s.template_count for s in self.sources.values())

    def is_source_available(self, name: str) -> bool:
        """检查指定来源是否可用（目录存在且有模板）"""
        source = self.sources.get(name)
        if not source or not source.enabled:
            return False
        p = Path(source.base_path) if source.base_path else None
        return p is not None and p.exists() and source.template_count > 0

    def enable_source(self, name: str) -> bool:
        """启用指定来源"""
        if name in self.sources:
            self.sources[name].enabled = True
            return True
        return False

    def disable_source(self, name: str) -> bool:
        """禁用指定来源"""
        if name in self.sources:
            self.sources[name].enabled = False
            return True
        return False

    def scan_for_sources(self) -> Dict[str, int]:
        """
        扫描文件系统，发现可用的 PoC 来源

        Returns:
            {来源名: 模板数}
        """
        results = {}
        for name, cfg in DEFAULT_POC_CONFIG.items():
            p = Path(self.rayscan_dir) / cfg["dir"]
            if p.exists():
                count = len(list(p.rglob(f"*{cfg['ext']}")))
                if name in self.sources:
                    self.sources[name].template_count = count
                    self.sources[name].enabled = count > 0
                results[name] = count
            else:
                results[name] = 0
        return results

    def register_to_template_manager(self) -> int:
        """
        将所有已启用的来源注册到全局模板管理器

        Returns:
            注册的模板目录数
        """
        tm = get_template_manager()
        registered = 0
        for source in self.get_enabled_sources():
            if source.base_path and Path(source.base_path).exists():
                tm.add_template_dir(source.base_path)
                registered += 1
                logger.info(f"[PoCSource] 注册来源: {source.label} ({source.base_path})")
        return registered

    def print_summary(self) -> str:
        """打印 PoC 来源摘要"""
        lines = []
        lines.append("📦 PoC 来源管理")
        lines.append("=" * 50)
        for source in sorted(self.sources.values(), key=lambda s: s.priority):
            status = "✅" if source.enabled else "❌"
            count_str = f" ({source.template_count} 模板)" if source.template_count > 0 else " (空)"
            lines.append(f"  {status} {source.label}{count_str}")
            lines.append(f"     {source.description}")
        lines.append(f"\n  总计: {self.get_total_count()} 个模板")
        return "\n".join(lines)


# 全局实例
_default_source_manager: Optional[PoCSourceManager] = None


def get_poc_source_manager(rayscan_dir: Optional[str] = None) -> PoCSourceManager:
    """获取或创建全局 PoC 来源管理器实例"""
    global _default_source_manager
    if _default_source_manager is None:
        _default_source_manager = PoCSourceManager(rayscan_dir)
    return _default_source_manager
