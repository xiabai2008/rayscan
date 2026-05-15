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
]
