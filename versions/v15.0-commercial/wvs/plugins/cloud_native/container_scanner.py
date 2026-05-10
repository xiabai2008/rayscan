"""容器镜像扫描模块 - v10.0"""
import re
import json
import tempfile
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ContainerVulnerability:
    """容器漏洞"""
    type: str
    severity: str
    description: str
    package: str
    version: str
    fixed_version: str
    cve_id: str


@dataclass
class ContainerMisconfiguration:
    """容器配置错误"""
    type: str
    severity: str
    description: str
    recommendation: str


class ContainerScanner:
    """容器镜像扫描器"""
    
    def __init__(self):
        self.vulnerability_db = self._load_vulnerability_database()
        self.docker_available = self._check_docker()
    
    def _check_docker(self) -> bool:
        """检查Docker是否可用"""
        try:
            import docker
            docker.from_env()
            return True
        except:
            return False
    
    def _load_vulnerability_database(self) -> Dict:
        """加载漏洞数据库"""
        # 模拟CVE数据库
        return {
            'CVE-2023-1234': {
                'package': 'openssl',
                'affected_versions': ['1.1.1-1.1.1t'],
                'fixed_version': '1.1.1u',
                'severity': 'high',
                'description': 'OpenSSL缓冲区溢出漏洞',
            },
            'CVE-2023-5678': {
                'package': 'log4j',
                'affected_versions': ['2.0-2.14.1'],
                'fixed_version': '2.15.0',
                'severity': 'critical',
                'description': 'Log4j远程代码执行漏洞',
            },
        }
    
    def scan_image(self, image_name: str) -> Dict[str, Any]:
        """扫描容器镜像"""
        results = {
            'image_info': {},
            'vulnerabilities': [],
            'misconfigurations': [],
            'secrets': [],
            'compliance': {},
        }
        
        if not self.docker_available:
            results['error'] = 'Docker not available'
            return results
        
        try:
            import docker
            client = docker.from_env()
            
            # 获取镜像信息
            image = client.images.get(image_name)
            results['image_info'] = self._extract_image_info(image)
            
            # 扫描基础镜像漏洞
            base_vulns = self._scan_base_image(image)
            results['vulnerabilities'].extend(base_vulns)
            
            # 扫描依赖包漏洞
            dependency_vulns = self._scan_dependencies(image)
            results['vulnerabilities'].extend(dependency_vulns)
            
            # 检查安全配置
            misconfigs = self._check_security_configs(image)
            results['misconfigurations'].extend(misconfigs)
            
            # 检查敏感信息
            secrets = self._scan_for_secrets(image)
            results['secrets'].extend(secrets)
            
            # CIS合规检查
            results['compliance'] = self._check_cis_compliance(image)
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def _extract_image_info(self, image) -> Dict:
        """提取镜像信息"""
        return {
            'id': image.id,
            'tags': image.tags,
            'size_mb': image.attrs.get('Size', 0) / (1024 * 1024),
            'created': image.attrs.get('Created', ''),
            'architecture': image.attrs.get('Architecture', ''),
            'os': image.attrs.get('Os', ''),
            'config': {
                'user': image.attrs.get('Config', {}).get('User', ''),
                'exposed_ports': list(image.attrs.get('Config', {}).get('ExposedPorts', {}).keys()),
                'env': image.attrs.get('Config', {}).get('Env', []),
                'cmd': image.attrs.get('Config', {}).get('Cmd', []),
                'entrypoint': image.attrs.get('Config', {}).get('Entrypoint', []),
            },
        }
    
    def _scan_base_image(self, image) -> List[Dict]:
        """扫描基础镜像漏洞"""
        vulnerabilities = []
        
        # 获取基础镜像信息
        base_image = self._get_base_image(image)
        
        if base_image:
            # 查询CVE数据库
            for cve_id, cve_info in self.vulnerability_db.items():
                vulnerabilities.append({
                    'type': 'base_image_vulnerability',
                    'cve_id': cve_id,
                    'severity': cve_info['severity'],
                    'description': cve_info['description'],
                    'affected_package': cve_info['package'],
                    'fixed_version': cve_info['fixed_version'],
                })
        
        return vulnerabilities
    
    def _get_base_image(self, image) -> str:
        """获取基础镜像"""
        # 从镜像历史中提取基础镜像
        history = image.history()
        for layer in history:
            if 'FROM' in str(layer.get('CreatedBy', '')):
                return layer.get('CreatedBy', '').replace('FROM ', '')
        return ''
    
    def _scan_dependencies(self, image) -> List[Dict]:
        """扫描依赖包漏洞"""
        vulnerabilities = []
        
        # 提取镜像中的包列表
        packages = self._extract_packages_from_image(image)
        
        # 检查每个包的漏洞
        for package in packages:
            pkg_vulns = self._check_package_vulnerabilities(package)
            vulnerabilities.extend(pkg_vulns)
        
        return vulnerabilities
    
    def _extract_packages_from_image(self, image) -> List[Dict]:
        """从镜像中提取包列表"""
        packages = []
        
        # 模拟包提取
        # 实际实现时需要创建临时容器执行包管理器命令
        
        return packages
    
    def _check_package_vulnerabilities(self, package: Dict) -> List[Dict]:
        """检查包漏洞"""
        vulnerabilities = []
        
        for cve_id, cve_info in self.vulnerability_db.items():
            if package.get('name') == cve_info['package']:
                vulnerabilities.append({
                    'type': 'dependency_vulnerability',
                    'cve_id': cve_id,
                    'severity': cve_info['severity'],
                    'description': cve_info['description'],
                    'affected_package': package['name'],
                    'affected_version': package.get('version', ''),
                    'fixed_version': cve_info['fixed_version'],
                })
        
        return vulnerabilities
    
    def _check_security_configs(self, image) -> List[Dict]:
        """检查安全配置"""
        misconfigurations = []
        
        config = image.attrs.get('Config', {})
        
        # 检查是否以root用户运行
        user = config.get('User', '')
        if not user or user == 'root':
            misconfigurations.append({
                'type': 'root_user',
                'severity': 'high',
                'description': '容器以root用户运行',
                'recommendation': '在Dockerfile中使用USER指令指定非root用户',
            })
        
        # 检查是否禁用root文件系统
        # 这需要运行时检查，这里仅做静态分析
        
        # 检查是否暴露敏感端口
        exposed_ports = config.get('ExposedPorts', {})
        sensitive_ports = ['22', '23', '3389', '3306', '5432', '6379', '27017']
        for port in exposed_ports:
            port_num = port.split('/')[0]
            if port_num in sensitive_ports:
                misconfigurations.append({
                    'type': 'sensitive_port_exposed',
                    'severity': 'medium',
                    'description': f'容器暴露了敏感端口: {port}',
                    'recommendation': '避免在容器中直接暴露数据库等敏感服务端口',
                })
        
        # 检查健康检查
        if not image.attrs.get('Config', {}).get('Healthcheck'):
            misconfigurations.append({
                'type': 'no_healthcheck',
                'severity': 'low',
                'description': '容器未配置健康检查',
                'recommendation': '在Dockerfile中添加HEALTHCHECK指令',
            })
        
        return misconfigurations
    
    def _scan_for_secrets(self, image) -> List[Dict]:
        """扫描敏感信息"""
        secrets = []
        
        config = image.attrs.get('Config', {})
        env_vars = config.get('Env', [])
        
        # 检查环境变量中的敏感信息
        sensitive_patterns = [
            (r'PASSWORD', 'password'),
            (r'SECRET', 'secret'),
            (r'TOKEN', 'token'),
            (r'KEY', 'key'),
            (r'API_KEY', 'api_key'),
            (r'PRIVATE_KEY', 'private_key'),
            (r'AWS_ACCESS_KEY', 'aws_access_key'),
        ]
        
        for env in env_vars:
            for pattern, secret_type in sensitive_patterns:
                if re.search(pattern, env, re.IGNORECASE):
                    secrets.append({
                        'type': 'environment_variable',
                        'key': env.split('=')[0],
                        'secret_type': secret_type,
                        'severity': 'critical',
                        'description': f'环境变量中包含敏感信息: {env.split("=")[0]}',
                        'recommendation': '使用Docker Secrets或环境变量文件管理敏感信息',
                    })
                    break
        
        return secrets
    
    def _check_cis_compliance(self, image) -> Dict:
        """CIS Docker基准检查"""
        checks = {
            'passed': [],
            'failed': [],
            'score': 0,
        }
        
        config = image.attrs.get('Config', {})
        
        # CIS 4.1 - 确保创建了非root用户
        if config.get('User') and config.get('User') != 'root':
            checks['passed'].append('CIS 4.1: 容器使用非root用户')
        else:
            checks['failed'].append('CIS 4.1: 容器使用root用户运行')
        
        # CIS 4.6 - 确保添加了HEALTHCHECK
        if config.get('Healthcheck'):
            checks['passed'].append('CIS 4.6: 容器配置了健康检查')
        else:
            checks['failed'].append('CIS 4.6: 容器未配置健康检查')
        
        # CIS 4.9 - 确保使用COPY而非ADD
        # 这需要检查Dockerfile，静态分析无法确定
        
        # 计算分数
        total = len(checks['passed']) + len(checks['failed'])
        checks['score'] = (len(checks['passed']) / total * 100) if total > 0 else 0
        
        return checks
    
    def generate_report(self, results: Dict, output_format: str = 'json') -> str:
        """生成扫描报告"""
        if output_format == 'json':
            return json.dumps(results, indent=2)
        elif output_format == 'html':
            return self._generate_html_report(results)
        else:
            return self._generate_text_report(results)
    
    def _generate_html_report(self, results: Dict) -> str:
        """生成HTML报告"""
        # 简化实现
        return f"""
        <html>
        <head><title>Container Security Report</title></head>
        <body>
            <h1>容器安全扫描报告</h1>
            <p>镜像: {results.get('image_info', {}).get('tags', ['Unknown'])[0]}</p>
            <p>漏洞数量: {len(results.get('vulnerabilities', []))}</p>
            <p>配置问题: {len(results.get('misconfigurations', []))}</p>
        </body>
        </html>
        """
    
    def _generate_text_report(self, results: Dict) -> str:
        """生成文本报告"""
        lines = [
            "容器安全扫描报告",
            "=" * 60,
            f"镜像: {results.get('image_info', {}).get('tags', ['Unknown'])[0]}",
            f"漏洞: {len(results.get('vulnerabilities', []))}",
            f"配置问题: {len(results.get('misconfigurations', []))}",
            f"敏感信息: {len(results.get('secrets', []))}",
        ]
        return "\n".join(lines)
