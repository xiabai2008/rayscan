"""
OOB (Out-of-Band) Detection Module

Provides a unified OOB callback verification mechanism, supporting multiple OOB service providers:
- Interactsh (recommended, free and open source)
- DNSLog.cn (domestic alternative)
- Burp Collaborator (commercial)
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
