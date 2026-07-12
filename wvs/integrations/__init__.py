#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RayScan 1.0.2 — External Tool Integration Module

Integrated tools:
- nuclei  : ProjectDiscovery template-based vulnerability scanning
- sqlmap  : automated SQL injection detection and exploitation
- ffuf    : directory/file brute-force and fuzzing
- wappalyzer : technology stack fingerprinting
"""

from .nuclei_integration import NucleiIntegration
from .sqlmap_integration import SqlmapIntegration
from .ffuf_integration import FfufIntegration
from .wappalyzer_integration import WappalyzerIntegration
from .awvs_integration import AWVSIntegration, AWVSInstance, create_awvs_instance_config
from .nessus_integration import NessusIntegration, NessusInstance
from .msf_integration import MetasploitIntegration, MSFResult

__all__ = [
    "NucleiIntegration",
    "SqlmapIntegration",
    "FfufIntegration",
    "WappalyzerIntegration",
    "AWVSIntegration",
    "AWVSInstance",
    "create_awvs_instance_config",
    "NessusIntegration",
    "NessusInstance",
    "MetasploitIntegration",
    "MSFResult",
]
