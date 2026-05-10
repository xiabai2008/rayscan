"""WVS v17.0 - 集成管理器

统一管理 CI/CD 集成和通知渠道
"""
import asyncio
import json
import aiohttp
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class IntegrationType(Enum):
    CI_CD = "ci_cd"
    NOTIFICATION = "notification"
    ISSUE_TRACKER = "issue_tracker"


@dataclass
class IntegrationConfig:
    name: str
    type: IntegrationType
    enabled: bool = True
    config: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    scan_id: str
    target: str
    vulns_found: int
    severity_breakdown: Dict[str, int]
    duration: float
    timestamp: datetime = field(default_factory=datetime.now)


class IntegrationManager:
    """集成管理器 - 统一管理所有外部集成"""
    
    def __init__(self):
        self.integrations: Dict[str, IntegrationConfig] = {}
        self._session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        self._session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30))
        return self
    
    async def __aexit__(self, *args):
        if self._session:
            await self._session.close()
    
    def register(self, integration: IntegrationConfig):
        """注册集成"""
        self.integrations[integration.name] = integration
        logger.info(f"注册集成: {integration.name} ({integration.type.value})")
    
    def unregister(self, name: str):
        """注销集成"""
        if name in self.integrations:
            del self.integrations[name]
            logger.info(f"注销集成: {name}")
    
    def get_enabled(self, type_filter: Optional[IntegrationType] = None) -> List[IntegrationConfig]:
        """获取启用的集成"""
        result = [i for i in self.integrations.values() if i.enabled]
        if type_filter:
            result = [i for i in result if i.type == type_filter]
        return result
    
    async def notify_all(self, result: ScanResult, event: str = "scan_complete"):
        """通知所有启用的通知渠道"""
        tasks = []
        for integration in self.get_enabled(IntegrationType.NOTIFICATION):
            tasks.append(self._send_notification(integration, result, event))
        
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for name, r in zip([i.name for i in self.get_enabled(IntegrationType.NOTIFICATION)], results):
                if isinstance(r, Exception):
                    logger.error(f"通知失败 [{name}]: {r}")
                else:
                    logger.info(f"通知成功 [{name}]")
    
    async def _send_notification(self, integration: IntegrationConfig, result: ScanResult, event: str):
        """发送通知到具体渠道"""
        config = integration.config
        
        if integration.name == "slack":
            return await self._notify_slack(config, result, event)
        elif integration.name == "dingtalk":
            return await self._notify_dingtalk(config, result, event)
        elif integration.name == "wecom":
            return await self._notify_wecom(config, result, event)
        elif integration.name == "webhook":
            return await self._notify_webhook(config, result, event)
        else:
            logger.warning(f"未知通知类型: {integration.name}")
    
    async def _notify_slack(self, config: Dict, result: ScanResult, event: str):
        """Slack 通知"""
        webhook_url = config.get("webhook_url")
        if not webhook_url:
            raise ValueError("Slack webhook_url 未配置")
        
        color = self._get_severity_color(result.severity_breakdown)
        payload = {
            "attachments": [{
                "color": color,
                "title": f"WVS 扫描完成 - {result.target}",
                "fields": [
                    {"title": "漏洞总数", "value": str(result.vulns_found), "short": True},
                    {"title": "扫描耗时", "value": f"{result.duration:.2f}s", "short": True},
                    {"title": "严重分布", "value": self._format_severity(result.severity_breakdown), "short": False}
                ],
                "footer": f"Scan ID: {result.scan_id}",
                "ts": int(result.timestamp.timestamp())
            }]
        }
        
        async with self._session.post(webhook_url, json=payload) as resp:
            if resp.status != 200:
                raise Exception(f"Slack API 返回 {resp.status}")
            return await resp.text()
    
    async def _notify_dingtalk(self, config: Dict, result: ScanResult, event: str):
        """钉钉机器人通知"""
        webhook_url = config.get("webhook_url")
        secret = config.get("secret")  # 加签密钥
        
        if not webhook_url:
            raise ValueError("钉钉 webhook_url 未配置")
        
        # 构建消息
        content = f"### WVS 扫描完成\n\n" \
                  f"- **目标**: {result.target}\n" \
                  f"- **漏洞数**: {result.vulns_found}\n" \
                  f"- **耗时**: {result.duration:.2f}s\n" \
                  f"- **严重分布**: {self._format_severity(result.severity_breakdown)}\n\n" \
                  f"> Scan ID: {result.scan_id}"
        
        payload = {
            "msgtype": "markdown",
            "markdown": {"title": "WVS 扫描完成", "text": content}
        }
        
        # 加签处理
        if secret:
            import hmac
            import hashlib
            import base64
            import time
            import urllib.parse
            
            timestamp = str(round(time.time() * 1000))
            string_to_sign = f"{timestamp}\n{secret}"
            hmac_code = hmac.new(secret.encode(), string_to_sign.encode(), hashlib.sha256).digest()
            sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
            webhook_url = f"{webhook_url}&timestamp={timestamp}&sign={sign}"
        
        async with self._session.post(webhook_url, json=payload) as resp:
            if resp.status != 200:
                raise Exception(f"钉钉 API 返回 {resp.status}")
            return await resp.text()
    
    async def _notify_wecom(self, config: Dict, result: ScanResult, event: str):
        """企业微信机器人通知"""
        webhook_url = config.get("webhook_url")
        if not webhook_url:
            raise ValueError("企业微信 webhook_url 未配置")
        
        content = f"# WVS 扫描完成\n" \
                  f"> 目标: {result.target}\n" \
                  f"> 漏洞数: {result.vulns_found}\n" \
                  f"> 耗时: {result.duration:.2f}s\n" \
                  f"> 严重分布: {self._format_severity(result.severity_breakdown)}\n" \
                  f"\nScan ID: {result.scan_id}"
        
        payload = {
            "msgtype": "markdown",
            "markdown": {"content": content}
        }
        
        async with self._session.post(webhook_url, json=payload) as resp:
            if resp.status != 200:
                raise Exception(f"企业微信 API 返回 {resp.status}")
            return await resp.text()
    
    async def _notify_webhook(self, config: Dict, result: ScanResult, event: str):
        """通用 Webhook 通知"""
        url = config.get("url")
        if not url:
            raise ValueError("Webhook URL 未配置")
        
        payload = {
            "event": event,
            "scan_id": result.scan_id,
            "target": result.target,
            "vulns_found": result.vulns_found,
            "severity_breakdown": result.severity_breakdown,
            "duration": result.duration,
            "timestamp": result.timestamp.isoformat()
        }
        
        headers = config.get("headers", {})
        
        async with self._session.post(url, json=payload, headers=headers) as resp:
            return await resp.text()
    
    async def trigger_ci_pipeline(self, pipeline: str, params: Dict[str, Any]):
        """触发 CI/CD 流水线"""
        for integration in self.get_enabled(IntegrationType.CI_CD):
            if integration.name == pipeline:
                return await self._trigger_pipeline(integration, params)
        raise ValueError(f"未找到 CI/CD 集成: {pipeline}")
    
    async def _trigger_pipeline(self, integration: IntegrationConfig, params: Dict):
        """触发具体流水线"""
        config = integration.config
        
        if integration.name == "gitlab_ci":
            return await self._trigger_gitlab(config, params)
        elif integration.name == "github_actions":
            return await self._trigger_github(config, params)
        else:
            raise ValueError(f"未知的 CI/CD 类型: {integration.name}")
    
    async def _trigger_gitlab(self, config: Dict, params: Dict):
        """触发 GitLab CI"""
        base_url = config.get("base_url", "https://gitlab.com")
        project_id = config.get("project_id")
        token = config.get("token")
        ref = params.get("ref", config.get("ref", "main"))
        
        if not project_id or not token:
            raise ValueError("GitLab project_id 或 token 未配置")
        
        url = f"{base_url}/api/v4/projects/{project_id}/pipeline"
        headers = {"PRIVATE-TOKEN": token}
        data = {"ref": ref}
        
        if params.get("variables"):
            data["variables"] = [{"key": k, "value": v} for k, v in params["variables"].items()]
        
        async with self._session.post(url, headers=headers, json=data) as resp:
            if resp.status not in [200, 201]:
                raise Exception(f"GitLab API 返回 {resp.status}")
            return await resp.json()
    
    async def _trigger_github(self, config: Dict, params: Dict):
        """触发 GitHub Actions"""
        owner = config.get("owner")
        repo = config.get("repo")
        workflow = config.get("workflow")
        token = config.get("token")
        ref = params.get("ref", config.get("ref", "main"))
        
        if not owner or not repo or not workflow or not token:
            raise ValueError("GitHub owner/repo/workflow/token 未配置")
        
        url = f"https://api.github.com/repos/{owner}/{repo}/actions/workflows/{workflow}/dispatches"
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json"
        }
        data = {"ref": ref, "inputs": params.get("inputs", {})}
        
        async with self._session.post(url, headers=headers, json=data) as resp:
            if resp.status not in [200, 204]:
                raise Exception(f"GitHub API 返回 {resp.status}")
            return {"status": "triggered"}
    
    async def create_issue(self, tracker: str, vuln_data: Dict):
        """在问题追踪器创建 Issue"""
        for integration in self.get_enabled(IntegrationType.ISSUE_TRACKER):
            if integration.name == tracker:
                return await self._create_issue(integration, vuln_data)
        raise ValueError(f"未找到问题追踪器: {tracker}")
    
    async def _create_issue(self, integration: IntegrationConfig, vuln_data: Dict):
        """创建具体 Issue"""
        config = integration.config
        
        if integration.name == "jira":
            return await self._create_jira_issue(config, vuln_data)
        elif integration.name == "github_issues":
            return await self._create_github_issue(config, vuln_data)
        else:
            raise ValueError(f"未知问题追踪器: {integration.name}")
    
    async def _create_jira_issue(self, config: Dict, vuln_data: Dict):
        """创建 Jira Issue"""
        base_url = config.get("base_url")
        email = config.get("email")
        api_token = config.get("api_token")
        project_key = config.get("project_key")
        
        if not all([base_url, email, api_token, project_key]):
            raise ValueError("Jira 配置不完整")
        
        import base64
        auth = base64.b64encode(f"{email}:{api_token}".encode()).decode()
        
        url = f"{base_url}/rest/api/3/issue"
        headers = {
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/json"
        }
        
        # Jira 字段映射
        severity_priority = {
            "critical": "Highest",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Lowest"
        }
        
        payload = {
            "fields": {
                "project": {"key": project_key},
                "summary": f"[WVS] {vuln_data.get('type', 'Vulnerability')} - {vuln_data.get('url', 'Unknown')}",
                "description": self._format_jira_description(vuln_data),
                "issuetype": {"name": "Bug"},
                "priority": {"name": severity_priority.get(vuln_data.get("severity", "medium"), "Medium")},
                "labels": ["security", "wvs-scan"]
            }
        }
        
        async with self._session.post(url, headers=headers, json=payload) as resp:
            if resp.status not in [200, 201]:
                raise Exception(f"Jira API 返回 {resp.status}")
            return await resp.json()
    
    async def _create_github_issue(self, config: Dict, vuln_data: Dict):
        """创建 GitHub Issue"""
        owner = config.get("owner")
        repo = config.get("repo")
        token = config.get("token")
        
        if not all([owner, repo, token]):
            raise ValueError("GitHub Issues 配置不完整")
        
        url = f"https://api.github.com/repos/{owner}/{repo}/issues"
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        severity_labels = {
            "critical": "severity:critical",
            "high": "severity:high",
            "medium": "severity:medium",
            "low": "severity:low"
        }
        
        payload = {
            "title": f"[WVS] {vuln_data.get('type', 'Vulnerability')} - {vuln_data.get('url', 'Unknown')}",
            "body": self._format_github_description(vuln_data),
            "labels": ["security", "vulnerability", severity_labels.get(vuln_data.get("severity", "medium"), "")]
        }
        
        async with self._session.post(url, headers=headers, json=payload) as resp:
            if resp.status not in [200, 201]:
                raise Exception(f"GitHub API 返回 {resp.status}")
            return await resp.json()
    
    def _get_severity_color(self, severity: Dict[str, int]) -> str:
        """根据严重程度返回颜色"""
        if severity.get("critical", 0) > 0:
            return "#ff0000"
        elif severity.get("high", 0) > 0:
            return "#ff6600"
        elif severity.get("medium", 0) > 0:
            return "#ffcc00"
        elif severity.get("low", 0) > 0:
            return "#36a64f"
        return "#cccccc"
    
    def _format_severity(self, severity: Dict[str, int]) -> str:
        """格式化严重程度分布"""
        parts = []
        for level in ["critical", "high", "medium", "low", "info"]:
            if level in severity:
                parts.append(f"{level}: {severity[level]}")
        return ", ".join(parts) if parts else "无漏洞"
    
    def _format_jira_description(self, vuln_data: Dict) -> str:
        """格式化 Jira 描述"""
        return f"h3. 漏洞详情\n\n" \
               f"||字段||值||\n" \
               f"|类型|{vuln_data.get('type', 'Unknown')}|\n" \
               f"|严重程度|{vuln_data.get('severity', 'Unknown')}|\n" \
               f"|URL|{vuln_data.get('url', 'Unknown')}|\n" \
               f"|参数|{vuln_data.get('parameter', 'N/A')}|\n" \
               f"|Payload|{{code}}{vuln_data.get('payload', 'N/A')}{{code}}|\n" \
               f"|置信度|{vuln_data.get('confidence', 0):.2%}|\n\n" \
               f"h3. 证据\n\n" \
               f"{{code}}{vuln_data.get('evidence', 'N/A')}{{code}}"
    
    def _format_github_description(self, vuln_data: Dict) -> str:
        """格式化 GitHub 描述"""
        return f"## 漏洞详情\n\n" \
               f"| 字段 | 值 |\n" \
               f"|------|----|\n" \
               f"| 类型 | {vuln_data.get('type', 'Unknown')} |\n" \
               f"| 严重程度 | {vuln_data.get('severity', 'Unknown')} |\n" \
               f"| URL | {vuln_data.get('url', 'Unknown')} |\n" \
               f"| 参数 | {vuln_data.get('parameter', 'N/A')} |\n" \
               f"| 置信度 | {vuln_data.get('confidence', 0):.2%} |\n\n" \
               f"### Payload\n\n```\n{vuln_data.get('payload', 'N/A')}\n```\n\n" \
               f"### 证据\n\n```\n{vuln_data.get('evidence', 'N/A')}\n```"
