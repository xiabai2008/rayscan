"""Webhook 通知模块 - 扫描结果推送"""
import asyncio
import json
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime

try:
    import aiohttp
except ImportError:
    aiohttp = None


@dataclass
class WebhookConfig:
    """Webhook 配置"""
    url: str
    method: str = "POST"
    headers: Dict = None
    timeout: float = 30.0
    retry_count: int = 3
    retry_delay: float = 1.0
    
    def __post_init__(self):
        if self.headers is None:
            self.headers = {"Content-Type": "application/json"}


class WebhookNotifier:
    """Webhook 通知器"""
    
    def __init__(self):
        self.webhooks: List[WebhookConfig] = []
        self.enabled = True
    
    def add_webhook(self, config: WebhookConfig):
        """添加 Webhook"""
        self.webhooks.append(config)
    
    def add_from_url(self, url: str, **kwargs):
        """从 URL 快速添加 Webhook"""
        config = WebhookConfig(url=url, **kwargs)
        self.add_webhook(config)
    
    async def notify_scan_started(self, scan_id: str, target: str):
        """扫描开始通知"""
        if not self.enabled or not self.webhooks:
            return
        
        payload = {
            "event": "scan_started",
            "scan_id": scan_id,
            "target": target,
            "timestamp": datetime.now().isoformat(),
        }
        
        await self._send_to_all(payload)
    
    async def notify_scan_completed(self, result: Dict):
        """扫描完成通知"""
        if not self.enabled or not self.webhooks:
            return
        
        payload = {
            "event": "scan_completed",
            "scan_id": result.get("scan_id"),
            "target": result.get("target"),
            "duration": result.get("duration"),
            "vulnerability_count": result.get("vulnerabilities"),
            "summary": self._generate_summary(result),
            "timestamp": datetime.now().isoformat(),
        }
        
        await self._send_to_all(payload)
    
    async def notify_vulnerability_found(self, scan_id: str, vuln: Dict):
        """发现高危漏洞实时通知"""
        if not self.enabled or not self.webhooks:
            return
        
        # 只通知高危及以上漏洞
        severity = vuln.get("severity", "")
        if severity not in ["CRITICAL", "HIGH", "严重", "高危"]:
            return
        
        payload = {
            "event": "vulnerability_found",
            "scan_id": scan_id,
            "vulnerability": {
                "name": vuln.get("name"),
                "severity": vuln.get("severity"),
                "url": vuln.get("url"),
                "confidence": vuln.get("confidence"),
            },
            "timestamp": datetime.now().isoformat(),
        }
        
        await self._send_to_all(payload)
    
    async def _send_to_all(self, payload: Dict):
        """发送到所有 Webhook"""
        tasks = [self._send(webhook, payload) for webhook in self.webhooks]
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _send(self, config: WebhookConfig, payload: Dict):
        """发送单个 Webhook 请求"""
        if aiohttp is None:
            return
        
        for attempt in range(config.retry_count):
            try:
                timeout = aiohttp.ClientTimeout(total=config.timeout)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.request(
                        method=config.method,
                        url=config.url,
                        headers=config.headers,
                        json=payload,
                    ) as resp:
                        if resp.status < 400:
                            return
                        else:
                            print(f"Webhook 请求失败: {resp.status}")
                            
            except Exception as e:
                print(f"Webhook 发送失败 (尝试 {attempt + 1}/{config.retry_count}): {e}")
                if attempt < config.retry_count - 1:
                    await asyncio.sleep(config.retry_delay)
    
    def _generate_summary(self, result: Dict) -> Dict:
        """生成扫描摘要"""
        vulns = result.get("details", [])
        severity_count = {}
        
        for vuln in vulns:
            sev = vuln.get("severity", "UNKNOWN")
            severity_count[sev] = severity_count.get(sev, 0) + 1
        
        return {
            "total": len(vulns),
            "critical": severity_count.get("CRITICAL", 0),
            "high": severity_count.get("HIGH", 0),
            "medium": severity_count.get("MEDIUM", 0),
            "low": severity_count.get("LOW", 0),
        }


class EmailNotifier:
    """邮件通知器"""
    
    def __init__(self, smtp_host: str, smtp_port: int = 587,
                 username: str = None, password: str = None,
                 use_tls: bool = True):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.use_tls = use_tls
        self.recipients: List[str] = []
    
    def add_recipient(self, email: str):
        """添加收件人"""
        self.recipients.append(email)
    
    async def send_scan_report(self, result: Dict, report_path: str = None):
        """发送扫描报告邮件"""
        if not self.recipients:
            return
        
        try:
            import aiosmtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            from email.mime.base import MIMEBase
            from email import encoders
            
            # 构建邮件
            msg = MIMEMultipart()
            msg["From"] = self.username
            msg["To"] = ", ".join(self.recipients)
            msg["Subject"] = f"[WVS] 扫描完成 - {result.get('target')}"
            
            # 邮件正文
            body = self._generate_email_body(result)
            msg.attach(MIMEText(body, "html", "utf-8"))
            
            # 添加附件
            if report_path:
                with open(report_path, "rb") as f:
                    attachment = MIMEBase("application", "octet-stream")
                    attachment.set_payload(f.read())
                    encoders.encode_base64(attachment)
                    attachment.add_header(
                        "Content-Disposition",
                        f"attachment; filename=scan_report.html"
                    )
                    msg.attach(attachment)
            
            # 发送邮件
            await aiosmtplib.send(
                msg,
                hostname=self.smtp_host,
                port=self.smtp_port,
                username=self.username,
                password=self.password,
                start_tls=self.use_tls,
            )
            
            print(f"邮件已发送至: {', '.join(self.recipients)}")
            
        except ImportError:
            print("邮件通知需要 aiosmtplib: pip install aiosmtplib")
        except Exception as e:
            print(f"邮件发送失败: {e}")
    
    def _generate_email_body(self, result: Dict) -> str:
        """生成邮件 HTML 正文"""
        vuln_count = result.get("vulnerabilities", 0)
        target = result.get("target", "")
        scan_id = result.get("scan_id", "")
        duration = result.get("duration", 0)
        
        color = "#e74c3c" if vuln_count > 0 else "#27ae60"
        
        return f"""
        <html>
        <body style="font-family: Arial, sans-serif;">
            <h2 style="color: {color};">WVS 扫描报告</h2>
            <table style="border-collapse: collapse; width: 100%;">
                <tr>
                    <td style="padding: 8px; border: 1px solid #ddd;"><strong>扫描目标</strong></td>
                    <td style="padding: 8px; border: 1px solid #ddd;">{target}</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border: 1px solid #ddd;"><strong>扫描 ID</strong></td>
                    <td style="padding: 8px; border: 1px solid #ddd;">{scan_id}</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border: 1px solid #ddd;"><strong>扫描耗时</strong></td>
                    <td style="padding: 8px; border: 1px solid #ddd;">{duration:.2f} 秒</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border: 1px solid #ddd;"><strong>漏洞数量</strong></td>
                    <td style="padding: 8px; border: 1px solid #ddd; color: {color}; font-weight: bold;">{vuln_count}</td>
                </tr>
            </table>
            <p>详细报告请查看附件。</p>
        </body>
        </html>
        """


# 全局通知器实例
webhook_notifier = WebhookNotifier()
email_notifier = None  # 需要配置后初始化
