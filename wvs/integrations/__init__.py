#!/usr/bin/env python3
"""
RayScan 2.1.0 — External Tool Integration Module

Integrated tools:
- nuclei  : ProjectDiscovery template-based vulnerability scanning
- sqlmap  : automated SQL injection detection and exploitation
- ffuf    : directory/file brute-force and fuzzing
- wappalyzer : technology stack fingerprinting
"""

from .awvs_integration import AWVSInstance, AWVSIntegration, create_awvs_instance_config
from .ffuf_integration import FfufIntegration
from .msf_integration import MetasploitIntegration, MSFResult
from .nessus_integration import NessusInstance, NessusIntegration
from .nuclei_integration import NucleiIntegration
from .sqlmap_integration import SqlmapIntegration
from .wappalyzer_integration import WappalyzerIntegration

__all__ = [
    "AWVSInstance",
    "AWVSIntegration",
    "FfufIntegration",
    "MSFResult",
    "MetasploitIntegration",
    "NessusInstance",
    "NessusIntegration",
    "NucleiIntegration",
    "SqlmapIntegration",
    "WappalyzerIntegration",
    "create_awvs_instance_config",
]
