"""插件系统 - 可扩展的漏洞检测框架"""
import asyncio
import importlib
import inspect
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Dict, Type, Any, Optional

from ..vuln.base import Vulnerability


class VulnPlugin(ABC):
    """漏洞检测插件基类"""
    
    # 插件元数据
    name: str = ""  # 插件名称
    version: str = "1.0.0"
    author: str = ""
    description: str = ""
    severity: str = "HIGH"  # 默认严重等级
    
    # 依赖的其他插件
    dependencies: List[str] = []
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.enabled = True
    
    @abstractmethod
    async def check(self, target: str, context: Dict) -> List[Vulnerability]:
        """
        执行漏洞检测
        
        Args:
            target: 扫描目标 URL
            context: 扫描上下文，包含 session, urls, forms 等
        
        Returns:
            发现的漏洞列表
        """
        pass
    
    @property
    def plugin_id(self) -> str:
        """获取插件唯一标识"""
        return f"{self.name}@{self.version}"
    
    def get_config(self, key: str, default=None):
        """获取插件配置"""
        return self.config.get(key, default)
    
    async def before_scan(self):
        """扫描前钩子"""
        pass
    
    async def after_scan(self):
        """扫描后钩子"""
        pass


class PluginManager:
    """插件管理器"""
    
    def __init__(self):
        self.plugins: Dict[str, VulnPlugin] = {}
        self.plugin_classes: Dict[str, Type[VulnPlugin]] = {}
    
    def register(self, plugin_class: Type[VulnPlugin]):
        """注册插件类"""
        if not issubclass(plugin_class, VulnPlugin):
            raise ValueError(f"插件必须继承 VulnPlugin: {plugin_class}")
        
        instance = plugin_class()
        self.plugin_classes[instance.name] = plugin_class
        self.plugins[instance.name] = instance
        
        return self
    
    def unregister(self, name: str):
        """注销插件"""
        if name in self.plugins:
            del self.plugins[name]
            del self.plugin_classes[name]
    
    def load_from_directory(self, directory: str):
        """从目录加载插件"""
        plugin_dir = Path(directory)
        if not plugin_dir.exists():
            return
        
        for file_path in plugin_dir.glob("*.py"):
            if file_path.name.startswith("_"):
                continue
            
            self._load_plugin_file(file_path)
    
    def _load_plugin_file(self, file_path: Path):
        """加载单个插件文件"""
        try:
            # 动态导入模块
            spec = importlib.util.spec_from_file_location(
                file_path.stem, file_path
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # 查找插件类
            for name, obj in inspect.getmembers(module):
                if (inspect.isclass(obj) and 
                    issubclass(obj, VulnPlugin) and 
                    obj is not VulnPlugin):
                    self.register(obj)
                    
        except Exception as e:
            print(f"加载插件失败 {file_path}: {e}")
    
    def get_plugin(self, name: str) -> Optional[VulnPlugin]:
        """获取插件实例"""
        return self.plugins.get(name)
    
    def list_plugins(self) -> List[Dict[str, Any]]:
        """列出所有插件"""
        return [
            {
                "name": p.name,
                "version": p.version,
                "author": p.author,
                "description": p.description,
                "enabled": p.enabled,
            }
            for p in self.plugins.values()
        ]
    
    def enable_plugin(self, name: str):
        """启用插件"""
        if name in self.plugins:
            self.plugins[name].enabled = True
    
    def disable_plugin(self, name: str):
        """禁用插件"""
        if name in self.plugins:
            self.plugins[name].enabled = False
    
    async def execute_all(self, target: str, context: Dict) -> List[Vulnerability]:
        """执行所有启用的插件"""
        all_vulns = []
        
        # 按依赖顺序排序
        sorted_plugins = self._sort_by_dependencies()
        
        for plugin in sorted_plugins:
            if not plugin.enabled:
                continue
            
            try:
                await plugin.before_scan()
                vulns = await plugin.check(target, context)
                all_vulns.extend(vulns)
                await plugin.after_scan()
            except Exception as e:
                print(f"插件 {plugin.name} 执行失败: {e}")
        
        return all_vulns
    
    def _sort_by_dependencies(self) -> List[VulnPlugin]:
        """按依赖关系排序插件"""
        # 简单实现：没有依赖的在前
        no_deps = [p for p in self.plugins.values() if not p.dependencies]
        has_deps = [p for p in self.plugins.values() if p.dependencies]
        return no_deps + has_deps


# 内置插件示例
class CSRFPlugin(VulnPlugin):
    """CSRF 检测插件示例"""
    
    name = "csrf_detector"
    version = "1.0.0"
    author = "WVS Team"
    description = "检测跨站请求伪造漏洞"
    severity = "MEDIUM"
    
    async def check(self, target: str, context: Dict) -> List[Vulnerability]:
        """检测 CSRF 漏洞"""
        vulns = []
        forms = context.get("forms", [])
        
        for form in forms:
            # 检查表单是否有 CSRF Token
            has_token = False
            inputs = form.inputs if hasattr(form, 'inputs') else form.get("inputs", [])
            
            for inp in inputs:
                name = inp.get("name", "").lower()
                if "csrf" in name or "token" in name:
                    has_token = True
                    break
            
            if not has_token:
                action = form.action if hasattr(form, 'action') else form.get("action", "")
                vulns.append(Vulnerability(
                    name="CSRF 漏洞",
                    severity=Severity.MEDIUM,
                    url=action,
                    payload="Missing CSRF Token",
                    description="表单缺少 CSRF Token 保护",
                    remediation="添加 CSRF Token 验证",
                    confidence=0.7,
                ))
        
        return vulns


class SecurityHeadersPlugin(VulnPlugin):
    """安全响应头检测插件"""
    
    name = "security_headers"
    version = "1.0.0"
    author = "WVS Team"
    description = "检测缺失的安全响应头"
    severity = "LOW"
    
    REQUIRED_HEADERS = [
        "X-Content-Type-Options",
        "X-Frame-Options",
        "X-XSS-Protection",
        "Content-Security-Policy",
        "Strict-Transport-Security",
    ]
    
    async def check(self, target: str, context: Dict) -> List[Vulnerability]:
        """检测安全响应头"""
        vulns = []
        session = context.get("session")
        
        if not session:
            return vulns
        
        try:
            async with session.get(target, timeout=10, ssl=False) as resp:
                headers = resp.headers
                
                for header in self.REQUIRED_HEADERS:
                    if header not in headers:
                        vulns.append(Vulnerability(
                            name=f"缺失安全响应头: {header}",
                            severity=Severity.LOW,
                            url=target,
                            payload=header,
                            description=f"响应头缺少 {header}",
                            remediation=f"添加 {header} 响应头",
                            confidence=0.95,
                        ))
        except Exception:
            pass
        
        return vulns


# 注册内置插件
from ..vuln.base import Severity

plugin_manager = PluginManager()
plugin_manager.register(CSRFPlugin)
plugin_manager.register(SecurityHeadersPlugin)

# 导入额外插件（自动注册）
try:
    from . import extra_plugins
except ImportError:
    pass
