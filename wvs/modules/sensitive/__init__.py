"""
Sensitive Information Leakage Detection Module
Detection: source code leakage, configuration file leakage, backup files, sensitive directories
"""

from .detector import SensitiveDetector

__all__ = ["SensitiveDetector"]
