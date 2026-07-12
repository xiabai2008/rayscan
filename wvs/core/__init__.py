"""
RayScan Core — scanner, crawler, session management, rate limiting, and caching.
"""

from .session import HTTPPool
from .scanner import WAVScanner
from .crawler import WebCrawler, DiscoveredEndpoint
from .cache import ScanCache, CacheManager, TargetFingerprinter, cache_scan, get_cached_scan
from .rate_limiter import RateLimiter, AdaptiveRateLimiter, WAFEvasion, IntelligentRateLimiter
from .scheduler import TaskScheduler, TaskPriority, PrioritizedTask
from .session_manager import SessionManager, SessionState

try:
    from .poc_generator import PoCGenerator, PoC
except ImportError:
    PoCGenerator = None
    PoC = None
from .nuclei_template_manager import (
    NucleiTemplateManager,
    TemplateInfo,
    get_template_manager,
    detect_oa_fingerprint,
    TECH_STACK_TAGS,
    OA_FINGERPRINTS,
    POC_SOURCES,
)
from .poc_source_manager import (
    PoCSourceManager,
    PoCSourceInfo,
    get_poc_source_manager,
    DEFAULT_POC_CONFIG,
)
from .result_merger import (
    ResultMerger,
    MergedVulnerability,
    merge_and_display,
)
from .lab_profiles import (
    LabProfile,
    LabEndpoint,
    detect_lab_profile,
    get_lab_endpoints,
    DVWA_PROFILE,
    MUTILLIDAE_PROFILE,
    METASPLOITABLE2_PROFILE,
    PIKACHU_PROFILE,
    ALL_PROFILES,
)

__all__ = [
    "HTTPPool",
    "WAVScanner",
    "WebCrawler",
    "DiscoveredEndpoint",
    "ScanCache",
    "CacheManager",
    "TargetFingerprinter",
    "cache_scan",
    "get_cached_scan",
    "RateLimiter",
    "AdaptiveRateLimiter",
    "WAFEvasion",
    "IntelligentRateLimiter",
    "TaskScheduler",
    "TaskPriority",
    "PrioritizedTask",
    "SessionManager",
    "SessionState",
    "PoCGenerator",
    "PoC",
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
    # PoC Source Manager
    "PoCSourceManager",
    "PoCSourceInfo",
    "get_poc_source_manager",
    "DEFAULT_POC_CONFIG",
]
