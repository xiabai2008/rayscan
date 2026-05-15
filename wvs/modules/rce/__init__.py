"""
RCE (Remote Code Execution) Detection Module
Detection: code injection, deserialization RCE, file upload RCE
"""

from .detector import RCEDetector

__all__ = ["RCEDetector"]
