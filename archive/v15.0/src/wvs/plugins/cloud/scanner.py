"""WVS v18.0 - 云原生安全扫描插件

功能：
1. Docker 容器镜像扫描
2. Kubernetes 配置审计
3. 云服务安全检查 (AWS/Azure/GCP)
"""
import re
import json
import subprocess
from typing import Dict, List, Any
from dataclasses import dataclass
from enum import Enum


class CloudProvider(Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    ALIBABA = "alibaba"
    TENCENT = "tencent"


@dataclass
class CloudVulnerability:
    provider: CloudProvider
    resource_type: str
    resource_id: str
    vulnerability: str
    severity: str
    recommendation: str
    metadata: Dict = None


class DockerScanner:
    """Docker 镜像安全扫描"""
    
    # 敏感文件路径
    SENSITIVE_PATHS = [
        "/etc/passwd",
        "/etc/shadow",
        "/root/.ssh/id_rsa",
        "/root/.aws/credentials",
        "/app/.env",
        "/app/config/secrets.yml",
    ]
    
    # 危险命令
    DANGEROUS_COMMANDS = [
        "curl | bash",
        "wget | sh",
        "curl | sh",
        "apt-get install -y --no-install-recommends",
    ]
    
    # 已知漏洞镜像
    VULNERABLE_BASE_IMAGES = [
        "ubuntu:14.04",
        "debian:jessie",
        "centos:6",
        "python:3.6",
        "node:8",
        "openjdk:8",
    ]
    
    def scan_dockerfile(self, dockerfile_path: str) -> List[Dict]:
        """扫描 Dockerfile"""
        findings = []
        
        try:
            with open(dockerfile_path, 'r') as f:
                content = f.read()
                lines = content.split('\n')
            
            for i, line in enumerate(lines, 1):
                line = line.strip()
                
                # 检查危险命令
                for cmd in self.DANGEROUS_COMMANDS:
                    if cmd in line.lower():
                        findings.append({
                            "line": i,
                            "content": line,
                            "issue": f"危险命令: {cmd}",
                            "severity": "high",
                            "recommendation": "避免从网络下载并执行脚本"
                        })
                
                # 检查 ADD 命令
                if line.startswith("ADD "):
                    findings.append({
                        "line": i,
                        "content": line,
                        "issue": "使用 ADD 而非 COPY",
                        "severity": "medium",
                        "recommendation": "优先使用 COPY 命令"
                    })
                
                # 检查敏感信息
                if re.search(r'(password|secret|key|token)\s*=', line, re.I):
                    findings.append({
                        "line": i,
                        "content": line,
                        "issue": "可能包含敏感信息",
                        "severity": "high",
                        "recommendation": "使用环境变量或 secrets 管理"
                    })
                
                # 检查基础镜像
                if line.startswith("FROM "):
                    for vuln_img in self.VULNERABLE_BASE_IMAGES:
                        if vuln_img in line:
                            findings.append({
                                "line": i,
                                "content": line,
                                "issue": f"过时的基础镜像: {vuln_img}",
                                "severity": "medium",
                                "recommendation": "升级到最新版本"
                            })
                
                # 检查 root 用户
                if "USER root" in line or (line.startswith("USER ") and "root" in line):
                    findings.append({
                        "line": i,
                        "content": line,
                        "issue": "容器以 root 用户运行",
                        "severity": "medium",
                        "recommendation": "创建非 root 用户运行"
                    })
        
        except Exception as e:
            findings.append({
                "line": 0,
                "content": "",
                "issue": f"扫描失败: {str(e)}",
                "severity": "info",
                "recommendation": ""
            })
        
        return findings
    
    def scan_image(self, image_name: str) -> List[Dict]:
        """扫描容器镜像（使用 trivy 或 grype）"""
        findings = []
        
        # 检查 trivy 是否安装
        try:
            result = subprocess.run(
                ["trivy", "image", "--format", "json", image_name],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                for result in data.get("Results", []):
                    for vuln in result.get("Vulnerabilities", []):
                        findings.append({
                            "type": "容器漏洞",
                            "cve": vuln.get("VulnerabilityID"),
                            "package": vuln.get("PkgName"),
                            "severity": vuln.get("Severity"),
                            "description": vuln.get("Description"),
                            "fixed_version": vuln.get("FixedVersion")
                        })
        except FileNotFoundError:
            findings.append({
                "type": "工具缺失",
                "issue": "trivy 未安装",
                "recommendation": "安装 trivy: https://github.com/aquasecurity/trivy"
            })
        except Exception as e:
            findings.append({
                "type": "扫描错误",
                "issue": str(e)
            })
        
        return findings


class KubernetesScanner:
    """Kubernetes 安全扫描"""
    
    # 危险配置检查项
    SECURITY_CHECKS = {
        "privileged": {
            "check": lambda spec: spec.get("privileged", False),
            "issue": "容器以特权模式运行",
            "severity": "critical"
        },
        "hostNetwork": {
            "check": lambda spec: spec.get("hostNetwork", False),
            "issue": "使用主机网络",
            "severity": "high"
        },
        "hostPID": {
            "check": lambda spec: spec.get("hostPID", False),
            "issue": "使用主机 PID 命名空间",
            "severity": "high"
        },
        "hostIPC": {
            "check": lambda spec: spec.get("hostIPC", False),
            "issue": "使用主机 IPC 命名空间",
            "severity": "high"
        },
        "runAsRoot": {
            "check": lambda spec: spec.get("runAsUser", 0) == 0,
            "issue": "容器以 root 用户运行",
            "severity": "high"
        },
        "readOnlyRootFilesystem": {
            "check": lambda spec: not spec.get("readOnlyRootFilesystem", False),
            "issue": "根文件系统可写",
            "severity": "medium"
        },
        "allowPrivilegeEscalation": {
            "check": lambda spec: spec.get("allowPrivilegeEscalation", True),
            "issue": "允许权限提升",
            "severity": "high"
        },
    }
    
    def scan_pod_spec(self, spec: Dict) -> List[Dict]:
        """扫描 Pod 安全配置"""
        findings = []
        
        # 获取安全上下文
        security_context = spec.get("securityContext", {})
        container_security = spec.get("containers", [{}])[0].get("securityContext", {})
        
        # 合并安全配置
        combined = {**security_context, **container_security}
        
        for check_name, check_info in self.SECURITY_CHECKS.items():
            if check_info["check"](combined):
                findings.append({
                    "check": check_name,
                    "issue": check_info["issue"],
                    "severity": check_info["severity"],
                    "recommendation": f"设置 {check_name} 为安全值"
                })
        
        return findings
    
    def scan_deployment(self, deployment: Dict) -> List[Dict]:
        """扫描 Deployment 配置"""
        findings = []
        
        spec = deployment.get("spec", {}).get("template", {}).get("spec", {})
        findings.extend(self.scan_pod_spec(spec))
        
        # 检查 Service Account
        if spec.get("automountServiceAccountToken", True):
            findings.append({
                "check": "automountServiceAccountToken",
                "issue": "自动挂载 Service Account Token",
                "severity": "medium",
                "recommendation": "如不需要，设置为 false"
            })
        
        return findings
    
    def scan_namespace(self, namespace: str = "default") -> List[Dict]:
        """扫描命名空间中的所有资源"""
        findings = []
        
        try:
            # 使用 kubectl 获取资源
            result = subprocess.run(
                ["kubectl", "get", "deployments,pods", "-n", namespace, "-o", "json"],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                
                for item in data.get("items", []):
                    kind = item.get("kind")
                    name = item.get("metadata", {}).get("name", "unknown")
                    
                    if kind == "Deployment":
                        deployment_findings = self.scan_deployment(item)
                        for f in deployment_findings:
                            f["resource"] = f"{kind}/{name}"
                            findings.append(f)
                    
                    elif kind == "Pod":
                        pod_findings = self.scan_pod_spec(item.get("spec", {}))
                        for f in pod_findings:
                            f["resource"] = f"{kind}/{name}"
                            findings.append(f)
        
        except FileNotFoundError:
            findings.append({
                "check": "kubectl",
                "issue": "kubectl 未安装",
                "severity": "info"
            })
        except Exception as e:
            findings.append({
                "check": "扫描错误",
                "issue": str(e)
            })
        
        return findings


class CloudSecurityScanner:
    """云服务安全扫描"""
    
    # AWS 安全检查
    AWS_CHECKS = {
        "s3_public_access": {
            "service": "s3",
            "check": lambda bucket: bucket.get("PublicAccessBlockConfiguration", {}).get("BlockPublicAcls", True) == False,
            "issue": "S3 存储桶公开访问",
            "severity": "critical"
        },
        "ec2_public_ip": {
            "service": "ec2",
            "check": lambda instance: instance.get("PublicIpAddress") is not None,
            "issue": "EC2 实例有公网 IP",
            "severity": "medium"
        },
        "rds_publicly_accessible": {
            "service": "rds",
            "check": lambda db: db.get("PubliclyAccessible", False),
            "issue": "RDS 实例公开可访问",
            "severity": "critical"
        },
    }
    
    def scan_aws(self, region: str = "us-east-1") -> List[CloudVulnerability]:
        """扫描 AWS 安全配置"""
        findings = []
        
        # 这里需要 AWS SDK (boto3)
        # 实际实现需要配置 AWS 凭证
        
        return findings
    
    def scan_azure(self, subscription_id: str = None) -> List[CloudVulnerability]:
        """扫描 Azure 安全配置"""
        findings = []
        
        # 需要 Azure SDK
        
        return findings
    
    def scan_gcp(self, project_id: str = None) -> List[CloudVulnerability]:
        """扫描 GCP 安全配置"""
        findings = []
        
        # 需要 GCP SDK
        
        return findings


class CloudNativeScanner:
    """云原生安全扫描主类"""
    
    def __init__(self):
        self.docker = DockerScanner()
        self.k8s = KubernetesScanner()
        self.cloud = CloudSecurityScanner()
    
    def scan_dockerfile(self, path: str) -> List[Dict]:
        """扫描 Dockerfile"""
        return self.docker.scan_dockerfile(path)
    
    def scan_image(self, image: str) -> List[Dict]:
        """扫描容器镜像"""
        return self.docker.scan_image(image)
    
    def scan_k8s(self, namespace: str = "default") -> List[Dict]:
        """扫描 K8s 集群"""
        return self.k8s.scan_namespace(namespace)
    
    def scan_cloud(self, provider: CloudProvider, **kwargs) -> List[CloudVulnerability]:
        """扫描云服务"""
        if provider == CloudProvider.AWS:
            return self.cloud.scan_aws(**kwargs)
        elif provider == CloudProvider.AZURE:
            return self.cloud.scan_azure(**kwargs)
        elif provider == CloudProvider.GCP:
            return self.cloud.scan_gcp(**kwargs)
        return []
