"""插件市场 - v15.0"""
import os
import json
import hashlib
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum


class LicenseType(Enum):
    """许可证类型"""
    FREE = "free"
    PREMIUM = "premium"
    ENTERPRISE = "enterprise"


@dataclass
class PluginMetadata:
    """插件元数据"""
    id: str
    name: str
    version: str
    description: str
    author: str
    license_type: str
    price: float
    category: str
    tags: List[str]
    dependencies: List[str]
    min_wvs_version: str
    download_count: int = 0
    rating: float = 0.0
    reviews_count: int = 0
    last_updated: str = ""
    
    def to_dict(self) -> Dict:
        return asdict(self)


class PluginRegistry:
    """插件注册表"""
    
    def __init__(self, registry_path: str = './data/plugin_registry.json'):
        self.registry_path = registry_path
        self.plugins: Dict[str, PluginMetadata] = {}
        self._load_registry()
    
    def _load_registry(self):
        """加载注册表"""
        if os.path.exists(self.registry_path):
            try:
                with open(self.registry_path, 'r') as f:
                    data = json.load(f)
                    for plugin_id, plugin_data in data.items():
                        self.plugins[plugin_id] = PluginMetadata(**plugin_data)
            except:
                pass
    
    def _save_registry(self):
        """保存注册表"""
        os.makedirs(os.path.dirname(self.registry_path), exist_ok=True)
        data = {k: v.to_dict() for k, v in self.plugins.items()}
        with open(self.registry_path, 'w') as f:
            json.dump(data, f, indent=2)
    
    def register_plugin(self, metadata: PluginMetadata) -> bool:
        """注册插件"""
        self.plugins[metadata.id] = metadata
        self._save_registry()
        return True
    
    def get_plugin(self, plugin_id: str) -> Optional[PluginMetadata]:
        """获取插件"""
        return self.plugins.get(plugin_id)
    
    def get_plugins(self, category: Optional[str] = None,
                   license_type: Optional[str] = None) -> List[PluginMetadata]:
        """获取插件列表"""
        plugins = list(self.plugins.values())
        
        if category:
            plugins = [p for p in plugins if p.category == category]
        
        if license_type:
            plugins = [p for p in plugins if p.license_type == license_type]
        
        return plugins
    
    def search_plugins(self, query: str) -> List[PluginMetadata]:
        """搜索插件"""
        query = query.lower()
        results = []
        
        for plugin in self.plugins.values():
            if (query in plugin.name.lower() or
                query in plugin.description.lower() or
                any(query in tag.lower() for tag in plugin.tags)):
                results.append(plugin)
        
        return results
    
    def update_download_count(self, plugin_id: str):
        """更新下载计数"""
        if plugin_id in self.plugins:
            self.plugins[plugin_id].download_count += 1
            self._save_registry()


class LicenseManager:
    """许可证管理器"""
    
    def __init__(self, licenses_path: str = './data/licenses.json'):
        self.licenses_path = licenses_path
        self.licenses: Dict[str, Dict] = {}
        self._load_licenses()
    
    def _load_licenses(self):
        """加载许可证"""
        if os.path.exists(self.licenses_path):
            try:
                with open(self.licenses_path, 'r') as f:
                    self.licenses = json.load(f)
            except:
                pass
    
    def _save_licenses(self):
        """保存许可证"""
        os.makedirs(os.path.dirname(self.licenses_path), exist_ok=True)
        with open(self.licenses_path, 'w') as f:
            json.dump(self.licenses, f, indent=2)
    
    def generate_license(self, plugin_id: str, user_id: str,
                        license_type: str = 'premium',
                        duration_days: int = 365) -> str:
        """生成许可证"""
        license_key = hashlib.sha256(
            f"{plugin_id}:{user_id}:{datetime.now().isoformat()}".encode()
        ).hexdigest()[:32].upper()
        
        self.licenses[license_key] = {
            'plugin_id': plugin_id,
            'user_id': user_id,
            'license_type': license_type,
            'created_at': datetime.now().isoformat(),
            'expires_at': (datetime.now() + timedelta(days=duration_days)).isoformat(),
            'is_active': True,
        }
        
        self._save_licenses()
        return license_key
    
    def validate_license(self, plugin_id: str, license_key: str) -> Dict:
        """验证许可证"""
        if license_key not in self.licenses:
            return {'valid': False, 'error': 'License not found'}
        
        license_data = self.licenses[license_key]
        
        if license_data['plugin_id'] != plugin_id:
            return {'valid': False, 'error': 'License does not match plugin'}
        
        if not license_data['is_active']:
            return {'valid': False, 'error': 'License is deactivated'}
        
        expires_at = datetime.fromisoformat(license_data['expires_at'])
        if datetime.now() > expires_at:
            return {'valid': False, 'error': 'License expired'}
        
        return {
            'valid': True,
            'license_type': license_data['license_type'],
            'expires_at': license_data['expires_at'],
        }
    
    def revoke_license(self, license_key: str) -> bool:
        """吊销许可证"""
        if license_key in self.licenses:
            self.licenses[license_key]['is_active'] = False
            self._save_licenses()
            return True
        return False


class PaymentGateway:
    """支付网关（模拟）"""
    
    SUBSCRIPTION_PLANS = {
        'community': {
            'price': 0,
            'features': [
                'basic_scanning',
                'community_plugins',
                'standard_support',
            ],
            'limits': {
                'concurrent_scans': 3,
                'api_calls_per_day': 1000,
                'max_plugins': 5,
            },
        },
        'professional': {
            'price': 99,
            'features': [
                'advanced_scanning',
                'premium_plugins',
                'priority_support',
                'compliance_reports',
                'ai_enhanced_analysis',
            ],
            'limits': {
                'concurrent_scans': 10,
                'api_calls_per_day': 10000,
                'max_plugins': 20,
            },
        },
        'enterprise': {
            'price': -1,  # 定制价格
            'features': [
                'all_features',
                'dedicated_support',
                'sla_guarantees',
                'custom_development',
                'on_premise_deployment',
            ],
            'limits': {
                'concurrent_scans': -1,  # 无限
                'api_calls_per_day': -1,
                'max_plugins': -1,
            },
        },
    }
    
    def create_subscription(self, user_id: str, plan: str,
                           payment_method: str = 'stripe') -> Dict:
        """创建订阅"""
        if plan not in self.SUBSCRIPTION_PLANS:
            return {'error': f'Unknown plan: {plan}'}
        
        plan_data = self.SUBSCRIPTION_PLANS[plan]
        
        # 模拟支付处理
        subscription_id = hashlib.sha256(
            f"{user_id}:{plan}:{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        return {
            'success': True,
            'subscription_id': subscription_id,
            'plan': plan,
            'price': plan_data['price'],
            'features': plan_data['features'],
            'limits': plan_data['limits'],
            'status': 'active',
            'next_billing_date': (datetime.now() + timedelta(days=30)).isoformat(),
        }
    
    def cancel_subscription(self, subscription_id: str) -> Dict:
        """取消订阅"""
        return {
            'success': True,
            'subscription_id': subscription_id,
            'status': 'cancelled',
            'effective_date': (datetime.now() + timedelta(days=30)).isoformat(),
        }
    
    def get_plan_details(self, plan: str) -> Dict:
        """获取计划详情"""
        return self.SUBSCRIPTION_PLANS.get(plan, {})


class PluginMarketplace:
    """插件市场主类"""
    
    def __init__(self):
        self.plugin_registry = PluginRegistry()
        self.license_manager = LicenseManager()
        self.payment_gateway = PaymentGateway()
        self.installed_plugins: Dict[str, str] = {}  # plugin_id -> version
        self._load_installed_plugins()
    
    def _load_installed_plugins(self):
        """加载已安装插件"""
        installed_path = './data/installed_plugins.json'
        if os.path.exists(installed_path):
            try:
                with open(installed_path, 'r') as f:
                    self.installed_plugins = json.load(f)
            except:
                pass
    
    def _save_installed_plugins(self):
        """保存已安装插件"""
        os.makedirs('./data', exist_ok=True)
        with open('./data/installed_plugins.json', 'w') as f:
            json.dump(self.installed_plugins, f, indent=2)
    
    def browse_plugins(self, category: Optional[str] = None,
                      pricing: str = 'all') -> List[Dict]:
        """浏览插件市场"""
        plugins = self.plugin_registry.get_plugins(category)
        
        if pricing == 'free':
            plugins = [p for p in plugins if p.license_type == 'free']
        elif pricing == 'premium':
            plugins = [p for p in plugins if p.license_type == 'premium']
        
        return [self._enrich_plugin_metadata(p) for p in plugins]
    
    def _enrich_plugin_metadata(self, plugin: PluginMetadata) -> Dict:
        """丰富插件元数据"""
        data = plugin.to_dict()
        data['is_installed'] = plugin.id in self.installed_plugins
        data['installed_version'] = self.installed_plugins.get(plugin.id)
        data['has_update'] = (
            data['is_installed'] and
            data['installed_version'] != plugin.version
        )
        return data
    
    def install_plugin(self, plugin_id: str, license_key: Optional[str] = None) -> Dict:
        """安装插件"""
        plugin = self.plugin_registry.get_plugin(plugin_id)
        
        if not plugin:
            return {'success': False, 'error': 'Plugin not found'}
        
        # 检查许可证
        if plugin.license_type == 'premium':
            if not license_key:
                return {
                    'success': False,
                    'error': 'Premium plugin requires license key',
                    'purchase_url': f'/marketplace/buy/{plugin_id}',
                }
            
            validation = self.license_manager.validate_license(plugin_id, license_key)
            if not validation['valid']:
                return {'success': False, 'error': validation['error']}
        
        # 模拟下载和安装
        self.installed_plugins[plugin_id] = plugin.version
        self._save_installed_plugins()
        
        self.plugin_registry.update_download_count(plugin_id)
        
        return {
            'success': True,
            'plugin_id': plugin_id,
            'version': plugin.version,
            'message': f'Plugin {plugin.name} installed successfully',
        }
    
    def uninstall_plugin(self, plugin_id: str) -> Dict:
        """卸载插件"""
        if plugin_id in self.installed_plugins:
            del self.installed_plugins[plugin_id]
            self._save_installed_plugins()
            return {'success': True, 'message': f'Plugin {plugin_id} uninstalled'}
        return {'success': False, 'error': 'Plugin not installed'}
    
    def get_subscription_plans(self) -> Dict[str, Any]:
        """获取订阅计划"""
        return self.payment_gateway.SUBSCRIPTION_PLANS
    
    def subscribe(self, user_id: str, plan: str) -> Dict:
        """订阅计划"""
        return self.payment_gateway.create_subscription(user_id, plan)
    
    def search_plugins(self, query: str) -> List[Dict]:
        """搜索插件"""
        plugins = self.plugin_registry.search_plugins(query)
        return [self._enrich_plugin_metadata(p) for p in plugins]
    
    def get_plugin_details(self, plugin_id: str) -> Optional[Dict]:
        """获取插件详情"""
        plugin = self.plugin_registry.get_plugin(plugin_id)
        if plugin:
            return self._enrich_plugin_metadata(plugin)
        return None
    
    def get_installed_plugins(self) -> List[Dict]:
        """获取已安装插件"""
        results = []
        for plugin_id, version in self.installed_plugins.items():
            plugin = self.plugin_registry.get_plugin(plugin_id)
            if plugin:
                data = self._enrich_plugin_metadata(plugin)
                results.append(data)
        return results
