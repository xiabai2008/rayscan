"""生态集成模块 - v11.0"""
import json
import requests
from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class IntegrationConfig:
    """集成配置"""
    enabled: bool
    name: str
    config: Dict[str, Any]


class UnifiedAPIGateway:
    """统一API网关"""
    
    def __init__(self, config_path: str = 'config/integrations.yaml'):
        self.config = self._load_config(config_path)
        self.integrations: Dict[str, Any] = {}
        self._init_integrations()
    
    def _load_config(self, config_path: str) -> Dict:
        """加载配置"""
        try:
            import yaml
            with open(config_path, 'r') as f:
                return yaml.safe_load(f) or {}
        except:
            return {}
    
    def _init_integrations(self):
        """初始化集成"""
        # CI/CD集成
        if self.config.get('gitlab_ci', {}).get('enabled'):
            self.integrations['gitlab_ci'] = GitLabCIIntegration(
                self.config['gitlab_ci']
            )
        
        if self.config.get('github_actions', {}).get('enabled'):
            self.integrations['github_actions'] = GitHubActionsIntegration(
                self.config['github_actions']
            )
        
        # 问题跟踪集成
        if self.config.get('jira', {}).get('enabled'):
            self.integrations['jira'] = JiraIntegration(
                self.config['jira']
            )
        
        # 通讯集成
        if self.config.get('slack', {}).get('enabled'):
            self.integrations['slack'] = SlackIntegration(
                self.config['slack']
            )
        
        if self.config.get('dingtalk', {}).get('enabled'):
            self.integrations['dingtalk'] = DingTalkIntegration(
                self.config['dingtalk']
            )
    
    def forward_vulnerability(self, vulnerability: Dict, target_system: str) -> Dict:
        """转发漏洞到目标系统"""
        if target_system not in self.integrations:
            return {'error': f'Integration not found: {target_system}'}
        
        integration = self.integrations[target_system]
        return integration.create_issue(vulnerability)
    
    def send_notification(self, message: str, channels: List[str], severity: str = 'info') -> Dict:
        """发送通知到多个渠道"""
        results = {}
        
        for channel in channels:
            if channel in self.integrations:
                try:
                    result = self.integrations[channel].send_notification(message, severity)
                    results[channel] = result
                except Exception as e:
                    results[channel] = {'error': str(e)}
        
        return results
    
    def list_integrations(self) -> List[str]:
        """列出已启用的集成"""
        return list(self.integrations.keys())


class GitLabCIIntegration:
    """GitLab CI集成"""
    
    def __init__(self, config: Dict):
        self.api_token = config.get('api_token')
        self.project_id = config.get('project_id')
        self.base_url = config.get('url', 'https://gitlab.com')
    
    def create_merge_request_comment(self, mr_iid: int, comment: str) -> Dict:
        """在Merge Request中添加评论"""
        url = f"{self.base_url}/api/v4/projects/{self.project_id}/merge_requests/{mr_iid}/notes"
        
        headers = {'PRIVATE-TOKEN': self.api_token}
        data = {'body': comment}
        
        response = requests.post(url, headers=headers, json=data)
        
        return {
            'success': response.status_code == 201,
            'data': response.json() if response.status_code == 201 else None,
        }
    
    def create_issue(self, vulnerability: Dict) -> Dict:
        """创建GitLab Issue"""
        url = f"{self.base_url}/api/v4/projects/{self.project_id}/issues"
        
        headers = {'PRIVATE-TOKEN': self.api_token}
        data = {
            'title': f"[SECURITY] {vulnerability['type']} - {vulnerability.get('severity', 'Unknown')}",
            'description': self._format_issue_description(vulnerability),
            'labels': 'security,vulnerability',
        }
        
        response = requests.post(url, headers=headers, json=data)
        
        return {
            'success': response.status_code == 201,
            'issue_id': response.json().get('iid') if response.status_code == 201 else None,
        }
    
    def _format_issue_description(self, vuln: Dict) -> str:
        """格式化Issue描述"""
        return f"""
## Security Vulnerability

**Type:** {vuln.get('type', 'Unknown')}
**Severity:** {vuln.get('severity', 'Unknown')}
**Target:** {vuln.get('target', 'Unknown')}

### Description
{vuln.get('description', 'No description available')}

### Recommendation
{vuln.get('recommendation', 'No recommendation available')}

### Evidence
```json
{json.dumps(vuln.get('evidence', {}), indent=2)}
```
        """
    
    def send_notification(self, message: str, severity: str = 'info') -> Dict:
        """发送通知（通过评论）"""
        # GitLab CI主要通过Pipeline状态通知
        return {'success': True, 'message': 'Use pipeline status for notifications'}


class GitHubActionsIntegration:
    """GitHub Actions集成"""
    
    def __init__(self, config: Dict):
        self.token = config.get('token')
        self.repository = config.get('repository')
    
    def create_issue(self, vulnerability: Dict) -> Dict:
        """创建GitHub Issue"""
        url = f"https://api.github.com/repos/{self.repository}/issues"
        
        headers = {
            'Authorization': f'token {self.token}',
            'Accept': 'application/vnd.github.v3+json',
        }
        
        data = {
            'title': f"[SECURITY] {vulnerability['type']}",
            'body': self._format_issue_body(vulnerability),
            'labels': ['security', 'vulnerability', vulnerability.get('severity', 'medium')],
        }
        
        response = requests.post(url, headers=headers, json=data)
        
        return {
            'success': response.status_code == 201,
            'issue_number': response.json().get('number') if response.status_code == 201 else None,
        }
    
    def _format_issue_body(self, vuln: Dict) -> str:
        """格式化Issue内容"""
        return f"""
## Security Vulnerability Report

| Field | Value |
|-------|-------|
| Type | {vuln.get('type')} |
| Severity | {vuln.get('severity')} |
| Target | {vuln.get('target')} |

### Description
{vuln.get('description')}

### Recommendation
{vuln.get('recommendation')}
        """


class JiraIntegration:
    """Jira集成"""
    
    def __init__(self, config: Dict):
        self.url = config.get('url', '').rstrip('/')
        self.username = config.get('username')
        self.api_token = config.get('api_token')
        self.project_key = config.get('project_key', 'SEC')
    
    def create_issue(self, vulnerability: Dict) -> Dict:
        """在Jira中创建漏洞问题"""
        url = f"{self.url}/rest/api/2/issue"
        
        auth = (self.username, self.api_token)
        headers = {'Content-Type': 'application/json'}
        
        data = {
            'fields': {
                'project': {'key': self.project_key},
                'summary': f"[{vulnerability['severity'].upper()}] {vulnerability['type']}",
                'description': self._format_description(vulnerability),
                'issuetype': {'name': 'Bug'},
                'priority': {'name': self._map_severity(vulnerability['severity'])},
                'labels': ['security', 'vulnerability', vulnerability['type']],
            }
        }
        
        response = requests.post(url, auth=auth, headers=headers, json=data)
        
        if response.status_code == 201:
            result = response.json()
            return {
                'success': True,
                'issue_key': result['key'],
                'url': f"{self.url}/browse/{result['key']}",
            }
        else:
            return {
                'success': False,
                'error': response.text,
            }
    
    def _format_description(self, vuln: Dict) -> str:
        """格式化描述"""
        return f"""
h2. Vulnerability Details

*Type:* {vuln['type']}
*Severity:* {vuln['severity']}
*Target:* {vuln.get('target', 'N/A')}

h2. Description

{vuln.get('description', 'No description')}

h2. Recommendation

{vuln.get('recommendation', 'No recommendation')}
        """
    
    def _map_severity(self, severity: str) -> str:
        """映射严重程度到Jira优先级"""
        mapping = {
            'critical': 'Highest',
            'high': 'High',
            'medium': 'Medium',
            'low': 'Low',
            'info': 'Lowest',
        }
        return mapping.get(severity.lower(), 'Medium')


class SlackIntegration:
    """Slack集成"""
    
    def __init__(self, config: Dict):
        self.webhook_url = config.get('webhook_url')
    
    def send_notification(self, message: str, severity: str = 'info') -> Dict:
        """发送Slack通知"""
        colors = {
            'critical': '#ff0000',
            'high': '#ff6b6b',
            'medium': '#ffa500',
            'low': '#ffff00',
            'info': '#4287f5',
        }
        
        payload = {
            'attachments': [{
                'color': colors.get(severity, '#4287f5'),
                'title': f"Security Alert - {severity.upper()}",
                'text': message,
                'footer': 'WVS Security Scanner',
                'ts': int(__import__('time').time()),
            }]
        }
        
        response = requests.post(self.webhook_url, json=payload)
        
        return {
            'success': response.status_code == 200,
            'status_code': response.status_code,
        }
    
    def send_vulnerability_alert(self, vulnerability: Dict) -> Dict:
        """发送漏洞告警"""
        message = f"""
*Vulnerability Detected*

• Type: {vulnerability['type']}
• Severity: {vulnerability['severity'].upper()}
• Target: {vulnerability.get('target', 'N/A')}

{vulnerability.get('description', '')}
        """
        
        return self.send_notification(message, vulnerability.get('severity', 'info'))


class DingTalkIntegration:
    """钉钉集成"""
    
    def __init__(self, config: Dict):
        self.webhook_url = config.get('webhook_url')
        self.secret = config.get('secret')
    
    def _generate_signature(self) -> Dict:
        """生成钉钉签名"""
        import hmac
        import hashlib
        import base64
        import time
        
        if not self.secret:
            return None
        
        timestamp = str(round(time.time() * 1000))
        string_to_sign = f'{timestamp}\n{self.secret}'
        hmac_code = hmac.new(
            self.secret.encode('utf-8'),
            string_to_sign.encode('utf-8'),
            hashlib.sha256
        ).digest()
        sign = base64.b64encode(hmac_code).decode('utf-8')
        
        return {'timestamp': timestamp, 'sign': sign}
    
    def send_notification(self, message: str, severity: str = 'info') -> Dict:
        """发送钉钉通知"""
        signature = self._generate_signature()
        
        payload = {
            'msgtype': 'markdown',
            'markdown': {
                'title': f'安全告警 - {severity.upper()}',
                'text': message,
            },
        }
        
        url = self.webhook_url
        if signature:
            url = f"{url}&timestamp={signature['timestamp']}&sign={signature['sign']}"
        
        response = requests.post(url, json=payload)
        
        return {
            'success': response.status_code == 200,
            'status_code': response.status_code,
        }


class WebhookHandler:
    """Webhook处理器"""
    
    def __init__(self):
        self.handlers = {}
    
    def register_handler(self, event_type: str, handler):
        """注册处理器"""
        self.handlers[event_type] = handler
    
    def handle(self, event_type: str, payload: Dict) -> Dict:
        """处理Webhook"""
        if event_type not in self.handlers:
            return {'error': f'No handler for event: {event_type}'}
        
        return self.handlers[event_type](payload)


class IntegrationManager:
    """集成管理器"""
    
    def __init__(self):
        self.gateway = UnifiedAPIGateway()
        self.webhook_handler = WebhookHandler()
    
    def setup_default_handlers(self):
        """设置默认处理器"""
        # 扫描完成处理器
        self.webhook_handler.register_handler('scan_completed', self._handle_scan_completed)
        
        # 漏洞发现处理器
        self.webhook_handler.register_handler('vulnerability_found', self._handle_vulnerability_found)
    
    def _handle_scan_completed(self, payload: Dict) -> Dict:
        """处理扫描完成事件"""
        scan_id = payload.get('scan_id')
        vulnerabilities = payload.get('vulnerabilities', [])
        
        # 发送通知
        message = f"Scan completed. Found {len(vulnerabilities)} vulnerabilities."
        self.gateway.send_notification(message, ['slack', 'dingtalk'], 'info')
        
        return {'success': True}
    
    def _handle_vulnerability_found(self, payload: Dict) -> Dict:
        """处理漏洞发现事件"""
        vulnerability = payload.get('vulnerability', {})
        severity = vulnerability.get('severity', 'medium')
        
        # 高严重度漏洞转发到问题跟踪系统
        if severity in ['critical', 'high']:
            self.gateway.forward_vulnerability(vulnerability, 'jira')
        
        # 发送通知
        message = f"New {severity} vulnerability found: {vulnerability.get('type')}"
        self.gateway.send_notification(message, ['slack', 'dingtalk'], severity)
        
        return {'success': True}
