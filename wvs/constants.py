"""
WVS unified constant definitions

Centralizes all hardcoded constants for maintainability and configuration.
"""

# ============================================================
# HTTP Settings
# ============================================================

DEFAULT_TIMEOUT = 30  # Default HTTP request timeout (seconds)
DEFAULT_TIMEOUT_LOCAL = 8  # Local target request timeout (seconds) — local network is much faster than remote
DEFAULT_CONNECT_TIMEOUT = 10  # Connection timeout (seconds)
DEFAULT_RETRY_COUNT = 1  # Default retry count (reduce duplicate requests)
DEFAULT_RETRY_DELAYS = [1.0, 2.0]  # Retry exponential backoff delays (seconds)

# ============================================================
# Security Settings
# ============================================================

DEFAULT_VERIFY_SSL = True  # Enable SSL certificate verification by default
COOKIE_STORAGE_PATH = "~/.wvs/sessions/cookies.enc"  # Encrypted cookie storage path
COOKIE_PLAINTEXT_PATH = "~/.wvs/sessions/cookies.json"  # Legacy plaintext cookie path (for migration)

# ============================================================
# Rate Limiting Settings
# ============================================================

DEFAULT_MAX_RPS = 10  # Default maximum requests per second
DEFAULT_MIN_RPS = 1  # Minimum RPS (adaptive lower bound)
DEFAULT_DELAY = 0.1  # Default request interval (seconds)

# ============================================================
# Time-based Detection Settings (upgraded with sqlmap statistical model)
# ============================================================

TIME_BASED_BASELINE_SAMPLES: int = (
    5  # Baseline sample count (sqlmap: minimum 30 for reliable model; we use 5 for speed)
)
TIME_BASED_MAX_BASELINE_STD: float = 0.5  # Baseline standard deviation threshold — if higher, network too jittery
TIME_BASED_MAX_BASELINE_AVG: float = (
    3.0  # Baseline average response time threshold (seconds), skip detection if exceeded
)
TIME_BASED_STDEV_COEFF: float = 7.0  # sqlmap: 99.9999% confidence — actual_delay >= avg + 7*stdev
TIME_BASED_MIN_VALID_DELAYED: float = 1.0  # sqlmap: minimum delay to be considered a valid delayed response
TIME_BASED_TEST_DELAYS: list = [3, 5]  # Test delay list (seconds)
TIME_BASED_DELAYS_LOCAL: list = [1, 2]  # Local network delay (seconds)
TIME_BASED_DELAYS_REMOTE: list = [3, 5]  # Remote network delay (seconds)
TIME_BASED_BATCH_TIMEOUT: float = 3.0  # Concurrent batch wait timeout (seconds)
TIME_BASED_VERIFICATION_ATTEMPTS: int = 3  # Verification attempts count

# ============================================================
# Response Analysis Settings
# ============================================================

RESPONSE_DIFF_THRESHOLD = 0.1  # Response difference threshold (ratio)
MAX_RESPONSE_TEXT_LENGTH = 10000  # Response text truncation length (characters)

# ============================================================
# Payload Limits
# ============================================================

MAX_ERROR_PAYLOADS_PER_DB = 8  # Number of error-based payloads to test per database
MAX_TIME_PAYLOADS = 4  # Number of time-based payloads
MAX_XSS_PRIORITY_PAYLOADS = 7  # Number of XSS priority test payloads
MAX_XSS_TEST_PAYLOADS = 15  # Number of XSS test payloads

# ============================================================
# Crawler Settings
# ============================================================

CRAWLER_MAX_DEPTH = 3  # Maximum crawler depth
CRAWLER_MAX_URLS = 200  # Maximum URLs per crawl
CRAWLER_REQUEST_TIMEOUT = 15  # Crawler request timeout (seconds)
CRAWLER_STABILITY_THRESHOLD = 3  # Stop after N consecutive crawls with no new URLs discovered

# ============================================================
# Report Settings
# ============================================================

REPORT_OUTPUT_FORMATS = ["json", "html", "markdown", "sarif", "csv"]

# ============================================================
# Log Truncation
# ============================================================

LOG_PAYLOAD_MAX_LENGTH = 50  # Maximum display length for payloads in logs
LOG_RESPONSE_MAX_LENGTH = 200  # Maximum display length for responses in logs
