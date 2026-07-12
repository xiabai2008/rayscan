"""
OOB (Out-of-Band) Detection Module

Provides a unified OOB callback verification mechanism, supporting multiple OOB service providers:
- Interactsh (recommended, free and open source)
- DNSLog.cn (domestic alternative)
- Burp Collaborator (commercial)
"""

from .dnslog import DNSLogClient, DNSLogManager, DNSLogRecord
from .interactsh import InteractshClient
from .oob_manager import OOBCallback, OOBManager, OOBToken

__all__ = [
    "DNSLogClient",
    "DNSLogManager",
    "DNSLogRecord",
    "InteractshClient",
    "OOBCallback",
    "OOBManager",
    "OOBToken",
]
