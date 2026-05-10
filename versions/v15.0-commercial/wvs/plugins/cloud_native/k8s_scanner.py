"""Kubernetes安全扫描模块 - v10.0"""
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum


class K8sResourceType(Enum):
    """K8s资源类型"""
    POD = "Pod"
    DEPLOYMENT = "Deployment"
    SERVICE = "Service"
    CONFIGMAP = "ConfigMap"
    SECRET = "Secret"
    SERVICE_ACCOUNT = "ServiceAccount"
    ROLE = "Role"
    ROLE_BINDING = "RoleBinding"
    CLUSTER_ROLE = "ClusterRole"
    CLUSTER_ROLE_BINDING = "ClusterRoleBinding"
    NETWORK_POLICY = "NetworkPolicy"


@dataclass
class K8sSecurityIssue:
    """K8s安全问题"""
    type: str
    severity: str
    resource_type: str
    resource_name: str
    namespace: str
    description: str
    recommendation: str


class KubernetesScanner:
    """Kubernetes安全扫描器"""
    
    def __init__(self, kubeconfig_path: str = None):
        self.kubeconfig_path = kubeconfig_path
        self.k8s_available = self._check_kubernetes()
        self.api_client = None
        
        if self.k8s_available:
            self._init_client()
    
    def _check_kubernetes(self) -> bool:
        """检查Kubernetes是否可用"""
        try:
            import kubernetes
            return True
        except ImportError:
            return False
    
    def _init_client(self):
        """初始化K8s客户端"""
        try:
            import kubernetes
            
            if self.kubeconfig_path:
                kubernetes.config.load_kube_config(config_file=self.kubeconfig_path)
            else:
                try:
                    kubernetes.config.load_incluster_config()
                except:
                    kubernetes.config.load_kube_config()
            
            self.api_client = kubernetes.client.ApiClient()
            self.v1 = kubernetes.client.CoreV1Api()
            self.apps_v1 = kubernetes.client.AppsV1Api()
            self.rbac_v1 = kubernetes.client.RbacAuthorizationV1Api()
            self.networking_v1 = kubernetes.client.NetworkingV1Api()
            
        except Exception as e:
            print(f"Failed to initialize K8s client: {e}")
            self.k8s_available = False
    
    def scan_cluster(self) -> Dict[str, Any]:
        """扫描整个集群"""
        results = {
            'cluster_info': {},
            'nodes': [],
            'pods': [],
            'rbac': [],
            'network_policies': [],
            'secrets': [],
            'compliance': {},
        }
        
        if not self.k8s_available:
            results['error'] = 'Kubernetes not available'
            return results
        
        try:
            # 扫描节点
            results['nodes'] = self.scan_nodes()
            
            # 扫描Pod
            results['pods'] = self.scan_pods()
            
            # 扫描RBAC
            results['rbac'] = self.scan_rbac()
            
            # 扫描网络策略
            results['network_policies'] = self.scan_network_policies()
            
            # 扫描Secrets
            results['secrets'] = self.scan_secrets()
            
            # CIS合规检查
            results['compliance'] = self.check_cis_compliance()
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def scan_nodes(self) -> List[Dict]:
        """扫描节点"""
        issues = []
        
        try:
            nodes = self.v1.list_node()
            
            for node in nodes.items:
                node_issues = self._check_node_security(node)
                issues.extend(node_issues)
                
        except Exception as e:
            issues.append({
                'type': 'api_error',
                'severity': 'critical',
                'description': f'Failed to list nodes: {e}',
            })
        
        return issues
    
    def _check_node_security(self, node) -> List[Dict]:
        """检查节点安全"""
        issues = []
        
        # 检查节点是否使用容器运行时
        node_info = node.status.node_info
        if not node_info.container_runtime_version:
            issues.append({
                'type': 'no_container_runtime',
                'severity': 'high',
                'node': node.metadata.name,
                'description': 'Node does not have container runtime configured',
            })
        
        # 检查kubelet配置
        # 这需要访问节点，简化实现
        
        return issues
    
    def scan_pods(self, namespace: str = None) -> List[Dict]:
        """扫描Pod"""
        issues = []
        
        try:
            if namespace:
                pods = self.v1.list_namespaced_pod(namespace)
            else:
                pods = self.v1.list_pod_for_all_namespaces()
            
            for pod in pods.items:
                pod_issues = self._check_pod_security(pod)
                issues.extend(pod_issues)
                
        except Exception as e:
            issues.append({
                'type': 'api_error',
                'severity': 'critical',
                'description': f'Failed to list pods: {e}',
            })
        
        return issues
    
    def _check_pod_security(self, pod) -> List[Dict]:
        """检查Pod安全"""
        issues = []
        
        pod_name = pod.metadata.name
        namespace = pod.metadata.namespace
        
        for container in pod.spec.containers:
            security_context = container.security_context
            
            # 检查是否以root用户运行
            if not security_context or not security_context.run_as_non_root:
                issues.append({
                    'type': 'root_user_pod',
                    'severity': 'high',
                    'namespace': namespace,
                    'pod': pod_name,
                    'container': container.name,
                    'description': 'Pod container is not configured to run as non-root',
                    'recommendation': 'Set securityContext.runAsNonRoot: true',
                })
            
            # 检查是否启用特权模式
            if security_context and security_context.privileged:
                issues.append({
                    'type': 'privileged_pod',
                    'severity': 'critical',
                    'namespace': namespace,
                    'pod': pod_name,
                    'container': container.name,
                    'description': 'Pod container is running in privileged mode',
                    'recommendation': 'Set securityContext.privileged: false',
                })
            
            # 检查是否禁用root文件系统
            if not security_context or not security_context.read_only_root_filesystem:
                issues.append({
                    'type': 'writable_rootfs_pod',
                    'severity': 'medium',
                    'namespace': namespace,
                    'pod': pod_name,
                    'container': container.name,
                    'description': 'Pod container has writable root filesystem',
                    'recommendation': 'Set securityContext.readOnlyRootFilesystem: true',
                })
            
            # 检查是否限制 capabilities
            if not security_context or not security_context.capabilities:
                issues.append({
                    'type': 'excessive_capabilities',
                    'severity': 'medium',
                    'namespace': namespace,
                    'pod': pod_name,
                    'container': container.name,
                    'description': 'Pod container does not drop unnecessary capabilities',
                    'recommendation': 'Set securityContext.capabilities.drop: ["ALL"]',
                })
            
            # 检查敏感环境变量
            if container.env:
                sensitive_envs = self._check_sensitive_env_vars(container.env)
                for env_name in sensitive_envs:
                    issues.append({
                        'type': 'sensitive_env_var',
                        'severity': 'high',
                        'namespace': namespace,
                        'pod': pod_name,
                        'container': container.name,
                        'description': f'Container has sensitive environment variable: {env_name}',
                        'recommendation': 'Use Kubernetes Secrets instead of environment variables',
                    })
        
        # 检查是否使用默认ServiceAccount
        if pod.spec.service_account_name == 'default':
            issues.append({
                'type': 'default_service_account',
                'severity': 'medium',
                'namespace': namespace,
                'pod': pod_name,
                'description': 'Pod is using the default service account',
                'recommendation': 'Create a dedicated service account for this pod',
            })
        
        # 检查是否配置资源限制
        for container in pod.spec.containers:
            if not container.resources or not container.resources.limits:
                issues.append({
                    'type': 'no_resource_limits',
                    'severity': 'low',
                    'namespace': namespace,
                    'pod': pod_name,
                    'container': container.name,
                    'description': 'Container does not have resource limits configured',
                    'recommendation': 'Set resources.limits for CPU and memory',
                })
        
        return issues
    
    def _check_sensitive_env_vars(self, env_vars) -> List[str]:
        """检查敏感环境变量"""
        sensitive_keys = ['password', 'secret', 'token', 'key', 'credential', 'private']
        sensitive_envs = []
        
        for env in env_vars:
            if any(key in env.name.lower() for key in sensitive_keys):
                sensitive_envs.append(env.name)
        
        return sensitive_envs
    
    def scan_rbac(self) -> List[Dict]:
        """扫描RBAC配置"""
        issues = []
        
        try:
            # 检查ClusterRoleBindings
            crbs = self.rbac_v1.list_cluster_role_binding()
            for crb in crbs.items:
                crb_issues = self._check_cluster_role_binding(crb)
                issues.extend(crb_issues)
            
            # 检查RoleBindings
            rbs = self.rbac_v1.list_role_binding_for_all_namespaces()
            for rb in rbs.items:
                rb_issues = self._check_role_binding(rb)
                issues.extend(rb_issues)
            
            # 检查ClusterRoles
            crs = self.rbac_v1.list_cluster_role()
            for cr in crs.items:
                cr_issues = self._check_cluster_role(cr)
                issues.extend(cr_issues)
                
        except Exception as e:
            issues.append({
                'type': 'api_error',
                'severity': 'critical',
                'description': f'Failed to list RBAC resources: {e}',
            })
        
        return issues
    
    def _check_cluster_role_binding(self, crb) -> List[Dict]:
        """检查ClusterRoleBinding"""
        issues = []
        
        # 检查是否绑定到cluster-admin
        if crb.role_ref.name == 'cluster-admin':
            for subject in crb.subjects or []:
                if subject.kind == 'ServiceAccount' and subject.name == 'default':
                    issues.append({
                        'type': 'default_sa_cluster_admin',
                        'severity': 'critical',
                        'name': crb.metadata.name,
                        'description': 'Default service account has cluster-admin access',
                        'recommendation': 'Remove cluster-admin binding from default service account',
                    })
                elif subject.kind == 'Group' and subject.name == 'system:authenticated':
                    issues.append({
                        'type': 'all_users_cluster_admin',
                        'severity': 'critical',
                        'name': crb.metadata.name,
                        'description': 'All authenticated users have cluster-admin access',
                        'recommendation': 'Restrict cluster-admin access to specific users only',
                    })
        
        return issues
    
    def _check_role_binding(self, rb) -> List[Dict]:
        """检查RoleBinding"""
        issues = []
        # 简化实现
        return issues
    
    def _check_cluster_role(self, cr) -> List[Dict]:
        """检查ClusterRole"""
        issues = []
        
        # 检查是否有过度的权限
        dangerous_verbs = ['*', 'create', 'delete', 'update', 'patch']
        dangerous_resources = ['secrets', 'pods', 'pods/exec', 'pods/log']
        
        for rule in cr.rules or []:
            has_dangerous_verbs = any(verb in dangerous_verbs for verb in rule.verbs or [])
            has_dangerous_resources = any(res in dangerous_resources for res in rule.resources or [])
            
            if has_dangerous_verbs and has_dangerous_resources:
                issues.append({
                    'type': 'excessive_permissions',
                    'severity': 'high',
                    'name': cr.metadata.name,
                    'description': f'ClusterRole has dangerous permissions: {rule.verbs} on {rule.resources}',
                    'recommendation': 'Principle of least privilege: grant only necessary permissions',
                })
        
        return issues
    
    def scan_network_policies(self) -> List[Dict]:
        """扫描网络策略"""
        issues = []
        
        try:
            # 检查每个命名空间是否有默认拒绝策略
            namespaces = self.v1.list_namespace()
            
            for ns in namespaces.items:
                namespace = ns.metadata.name
                
                # 跳过系统命名空间
                if namespace in ['kube-system', 'kube-public', 'kube-node-lease']:
                    continue
                
                policies = self._get_network_policies(namespace)
                
                if not policies:
                    issues.append({
                        'type': 'no_network_policy',
                        'severity': 'medium',
                        'namespace': namespace,
                        'description': f'Namespace {namespace} has no network policies',
                        'recommendation': 'Implement default deny network policy',
                    })
                
        except Exception as e:
            issues.append({
                'type': 'api_error',
                'severity': 'critical',
                'description': f'Failed to check network policies: {e}',
            })
        
        return issues
    
    def _get_network_policies(self, namespace: str) -> List:
        """获取网络策略"""
        try:
            policies = self.networking_v1.list_namespaced_network_policy(namespace)
            return policies.items
        except:
            return []
    
    def scan_secrets(self) -> List[Dict]:
        """扫描Secrets"""
        issues = []
        
        try:
            secrets = self.v1.list_secret_for_all_namespaces()
            
            for secret in secrets.items:
                # 检查默认token
                if secret.type == 'kubernetes.io/service-account-token':
                    if secret.metadata.name == 'default-token':
                        issues.append({
                            'type': 'default_token_secret',
                            'severity': 'low',
                            'namespace': secret.metadata.namespace,
                            'secret': secret.metadata.name,
                            'description': 'Default service account token is being used',
                            'recommendation': 'Use dedicated service accounts instead of default',
                        })
                
                # 检查敏感数据
                if secret.data:
                    for key in secret.data.keys():
                        if any(sensitive in key.lower() for sensitive in ['password', 'secret', 'key', 'token']):
                            # 检查是否过期（简化实现）
                            pass
                
        except Exception as e:
            issues.append({
                'type': 'api_error',
                'severity': 'critical',
                'description': f'Failed to list secrets: {e}',
            })
        
        return issues
    
    def check_cis_compliance(self) -> Dict:
        """CIS Kubernetes基准检查"""
        checks = {
            'passed': [],
            'failed': [],
            'score': 0,
        }
        
        # CIS 5.2.1 - 确保使用最小权限的ServiceAccount
        # 这需要扫描所有Pod的ServiceAccount使用情况
        
        # CIS 5.2.2 - 确保最小化Secret访问
        # 这需要检查RBAC规则
        
        # CIS 5.3.2 - 确保使用命名空间网络策略
        network_issues = self.scan_network_policies()
        if not network_issues:
            checks['passed'].append('CIS 5.3.2: Namespaces have network policies')
        else:
            checks['failed'].append('CIS 5.3.2: Some namespaces lack network policies')
        
        # 计算分数
        total = len(checks['passed']) + len(checks['failed'])
        checks['score'] = (len(checks['passed']) / total * 100) if total > 0 else 0
        
        return checks
