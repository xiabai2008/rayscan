"""
RayScan Core — scanner, crawler, session management, rate limiting, and caching.
"""

from .crawler import DiscoveredEndpoint, WebCrawler
from .dedup import ResultDeduplicator, prioritize_endpoints
from .lab_profiles import (
    ALL_PROFILES,
    DVWA_PROFILE,
    METASPLOITABLE2_PROFILE,
    MUTILLIDAE_PROFILE,
    PIKACHU_PROFILE,
    LabEndpoint,
    LabProfile,
    detect_lab_profile,
    get_lab_endpoints,
)
from .nuclei_template_manager import (
    OA_FINGERPRINTS,
    POC_SOURCES,
    TECH_STACK_TAGS,
    NucleiTemplateManager,
    TemplateInfo,
    detect_oa_fingerprint,
    get_template_manager,
)
from .poc_source_manager import (
    DEFAULT_POC_CONFIG,
    PoCSourceInfo,
    PoCSourceManager,
    get_poc_source_manager,
)
from .rate_limiter import AdaptiveRateLimiter, IntelligentRateLimiter, RateLimiter, WAFEvasion
from .result_merger import (
    MergedVulnerability,
    ResultMerger,
    merge_and_display,
)
from .scanner import WAVScanner
from .session import HTTPPool

__all__ = [
    "HTTPPool",
    "WAVScanner",
    "WebCrawler",
    "DiscoveredEndpoint",
    "RateLimiter",
    "AdaptiveRateLimiter",
    "WAFEvasion",
    "IntelligentRateLimiter",
    "ResultDeduplicator",
    "prioritize_endpoints",
    "LabProfile",
    "LabEndpoint",
    "detect_lab_profile",
    "get_lab_endpoints",
    "DVWA_PROFILE",
    "MUTILLIDAE_PROFILE",
    "METASPLOITABLE2_PROFILE",
    "PIKACHU_PROFILE",
    "ALL_PROFILES",
    # Nuclei Template Manager
    "NucleiTemplateManager",
    "TemplateInfo",
    "get_template_manager",
    "detect_oa_fingerprint",
    "TECH_STACK_TAGS",
    "OA_FINGERPRINTS",
    "POC_SOURCES",
    # PoC Source Manager
    "PoCSourceManager",
    "PoCSourceInfo",
    "get_poc_source_manager",
    "DEFAULT_POC_CONFIG",
    # Result Merger
    "ResultMerger",
    "MergedVulnerability",
    "merge_and_display",
]
