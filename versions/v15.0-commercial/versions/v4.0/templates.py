"""扫描模板系统 - 预设扫描配置"""
import yaml
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict


@dataclass
class ScanTemplate:
    """扫描模板"""
    name: str
    description: str
    profile: str = "standard"
    target_type: str = "web"  # web, api, network
    
    # 检测开关
    checks: Dict[str, bool] = None
    
    # 插件列表
    plugins: List[str] = None
    
    # 扫描选项
    options: Dict = None
    
    # 认证配置
    auth: Dict = None
    
    # 报告配置
    report_formats: List[str] = None
    
    def __post_init__(self):
        if self.checks is None:
            self.checks = {
                "xss": True,
                "sqli": True,
                "csrf": True,
                "info_disclosure": True,
                "dir_traversal": True,
            }
        if self.plugins is None:
            self.plugins = []
        if self.options is None:
            self.options = {
                "concurrency": 50,
                "timeout": 30,
                "verify_poc": False,
            }
        if self.auth is None:
            self.auth = {}
        if self.report_formats is None:
            self.report_formats = ["html", "json"]
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict) -> "ScanTemplate":
        return cls(**data)


# 内置模板
BUILTIN_TEMPLATES = {
    "quick": ScanTemplate(
        name="quick",
        description="快速扫描 - 只检测高危漏洞",
        profile="quick",
        checks={
            "xss": True,
            "sqli": True,
            "csrf": False,
            "info_disclosure": False,
            "dir_traversal": False,
        },
        options={"concurrency": 100, "timeout": 15, "verify_poc": False},
    ),
    
    "standard": ScanTemplate(
        name="standard",
        description="标准扫描 - 全面检测常见漏洞",
        profile="standard",
        checks={
            "xss": True,
            "sqli": True,
            "csrf": True,
            "info_disclosure": True,
            "dir_traversal": True,
        },
        options={"concurrency": 50, "timeout": 30, "verify_poc": False},
    ),
    
    "deep": ScanTemplate(
        name="deep",
        description="深度扫描 - 包含POC验证",
        profile="deep",
        checks={
            "xss": True,
            "sqli": True,
            "csrf": True,
            "info_disclosure": True,
            "dir_traversal": True,
        },
        plugins=["ssrf_detector", "cmd_injection_detector", "xxe_detector"],
        options={"concurrency": 30, "timeout": 60, "verify_poc": True},
    ),
    
    "api": ScanTemplate(
        name="api",
        description="API安全扫描 - 针对REST API",
        profile="standard",
        target_type="api",
        checks={
            "xss": False,
            "sqli": True,
            "csrf": False,
            "info_disclosure": True,
            "dir_traversal": False,
        },
        plugins=["ssrf_detector", "cmd_injection_detector"],
        options={"concurrency": 50, "timeout": 30, "verify_poc": True},
    ),
    
    "compliance": ScanTemplate(
        name="compliance",
        description="合规扫描 - 符合等保2.0/PCI-DSS",
        profile="deep",
        checks={
            "xss": True,
            "sqli": True,
            "csrf": True,
            "info_disclosure": True,
            "dir_traversal": True,
        },
        plugins=[
            "security_headers",
            "ssrf_detector",
            "cmd_injection_detector",
            "xxe_detector",
            "open_redirect_detector",
        ],
        options={"concurrency": 30, "timeout": 60, "verify_poc": True},
        report_formats=["html", "pdf", "json"],
    ),
}


class TemplateManager:
    """模板管理器"""
    
    def __init__(self, templates_dir: str = "templates"):
        self.templates_dir = Path(templates_dir)
        self.templates_dir.mkdir(exist_ok=True)
        self.custom_templates: Dict[str, ScanTemplate] = {}
        self._load_custom_templates()
    
    def _load_custom_templates(self):
        """加载自定义模板"""
        for template_file in self.templates_dir.glob("*.yaml"):
            try:
                with open(template_file, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    template = ScanTemplate.from_dict(data)
                    self.custom_templates[template.name] = template
            except Exception as e:
                print(f"加载模板失败 {template_file}: {e}")
    
    def get_template(self, name: str) -> Optional[ScanTemplate]:
        """获取模板"""
        # 先查内置
        if name in BUILTIN_TEMPLATES:
            return BUILTIN_TEMPLATES[name]
        # 再查自定义
        return self.custom_templates.get(name)
    
    def list_templates(self) -> List[Dict]:
        """列出所有模板"""
        templates = []
        
        # 内置模板
        for name, template in BUILTIN_TEMPLATES.items():
            templates.append({
                "name": name,
                "description": template.description,
                "type": "builtin",
            })
        
        # 自定义模板
        for name, template in self.custom_templates.items():
            templates.append({
                "name": name,
                "description": template.description,
                "type": "custom",
            })
        
        return templates
    
    def save_template(self, template: ScanTemplate):
        """保存自定义模板"""
        template_file = self.templates_dir / f"{template.name}.yaml"
        with open(template_file, "w", encoding="utf-8") as f:
            yaml.dump(template.to_dict(), f, allow_unicode=True, sort_keys=False)
        self.custom_templates[template.name] = template
    
    def delete_template(self, name: str) -> bool:
        """删除自定义模板"""
        if name in self.custom_templates:
            template_file = self.templates_dir / f"{name}.yaml"
            if template_file.exists():
                template_file.unlink()
            del self.custom_templates[name]
            return True
        return False
    
    def apply_template(self, template_name: str, target: str) -> Dict:
        """应用模板生成扫描配置"""
        template = self.get_template(template_name)
        if not template:
            raise ValueError(f"模板不存在: {template_name}")
        
        return {
            "target": target,
            "profile": template.profile,
            "checks": template.checks,
            "plugins": template.plugins,
            "options": template.options,
            "auth": template.auth,
            "report_formats": template.report_formats,
        }


# 全局模板管理器
template_manager = TemplateManager()
