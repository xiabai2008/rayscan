"""
敏感信息泄露检测模块
检测：源码泄露、配置文件泄露、备份文件、敏感目录
"""
from .detector import SensitiveDetector

__all__ = ["SensitiveDetector"]
