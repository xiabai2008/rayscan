"""
OOB (Out-of-Band) 检测模块

提供统一的 OOB 回调验证机制，支持多种 OOB 服务提供商：
- Interactsh (推荐，免费开源)
- DNSLog.cn (国内备选)
- Burp Collaborator (商业)
"""

from .interactsh import InteractshClient
from .oob_manager import OOBManager, OOBCallback, OOBToken
from .dnslog import DNSLogClient, DNSLogManager, DNSLogRecord

__all__ = [
    "OOBManager",
    "OOBCallback",
    "OOBToken",
    "InteractshClient",
    "DNSLogClient",
    "DNSLogManager",
    "DNSLogRecord",
]
