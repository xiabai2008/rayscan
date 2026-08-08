"""IDOR / 越权访问检测模块 (Phase 1: 业务逻辑检测)。"""

from .detector import IDORDetector

__all__ = ["IDORDetector"]
