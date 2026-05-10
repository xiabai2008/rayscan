"""
WVS 统一常量定义

集中管理所有硬编码常量，便于维护和配置。
"""

# ============================================================
# HTTP 设置
# ============================================================

DEFAULT_TIMEOUT = 30  # 默认 HTTP 请求超时（秒）
DEFAULT_TIMEOUT_LOCAL = 8  # 本地靶机请求超时（秒）— 本地网络远快于远程
DEFAULT_CONNECT_TIMEOUT = 10  # 连接超时（秒）
DEFAULT_RETRY_COUNT = 1  # 默认重试次数（减少重复请求）
DEFAULT_RETRY_DELAYS = [1.0, 2.0]  # 重试指数退避延迟（秒）

# ============================================================
# 安全设置
# ============================================================

DEFAULT_VERIFY_SSL = True  # 默认启用 SSL 证书验证
COOKIE_STORAGE_PATH = "~/.wvs/sessions/cookies.enc"  # 加密 Cookie 存储路径
COOKIE_PLAINTEXT_PATH = "~/.wvs/sessions/cookies.json"  # 旧明文 Cookie 路径（用于迁移）

# ============================================================
# 限流设置
# ============================================================

DEFAULT_MAX_RPS = 10  # 默认每秒最大请求数
DEFAULT_MIN_RPS = 1  # 最小 RPS（自适应下限）
DEFAULT_DELAY = 0.1  # 默认请求间隔（秒）

# ============================================================
# Time-based 检测设置
# ============================================================

TIME_BASED_BASELINE_SAMPLES = 3  # 基线采样次数（P8：从 2 恢复为 3，更准确的基线）
TIME_BASED_MAX_BASELINE_STD = 0.3  # 基线标准差阈值（P8：从 0.5 降为 0.3，减少网络抖动误报）
TIME_BASED_MAX_BASELINE_AVG = 2.0  # 基线平均响应时间阈值（秒），超过则跳过检测
TIME_BASED_THRESHOLD_FACTOR = 2.0  # 延迟阈值因子：actual > baseline_avg * factor + 1
TIME_BASED_MIN_DELAY_FACTOR = 0.7  # 最小延迟因子（P8：从 0.6 提升为 0.7，更严格）
TIME_BASED_TEST_DELAYS = [3, 5]  # 测试延迟列表（秒）
TIME_BASED_DELAYS_LOCAL = [1, 2]  # 本地网络延迟（秒）— 近零延迟，短 sleep 足够
TIME_BASED_DELAYS_REMOTE = [3, 5]  # 远端网络延迟（秒）
TIME_BASED_BATCH_TIMEOUT = 3.0  # 并发批次等待超时（秒）
TIME_BASED_VERIFICATION_ATTEMPTS = 3  # 二次验证次数（P8：从 2 提升为 3）

# ============================================================
# 响应分析设置
# ============================================================

RESPONSE_DIFF_THRESHOLD = 0.1  # 响应差异阈值（比例）
MAX_RESPONSE_TEXT_LENGTH = 10000  # 响应文本截断长度（字符）

# ============================================================
# Payload 限制
# ============================================================

MAX_ERROR_PAYLOADS_PER_DB = 8  # 每种数据库测试的 error-based payload 数量
MAX_TIME_PAYLOADS = 4  # time-based payload 数量
MAX_XSS_PRIORITY_PAYLOADS = 7  # XSS 优先测试 payload 数量
MAX_XSS_TEST_PAYLOADS = 15  # XSS 测试 payload 数量

# ============================================================
# 爬虫设置
# ============================================================

CRAWLER_MAX_DEPTH = 3  # 爬虫最大深度
CRAWLER_MAX_URLS = 200  # 每次爬取最大 URL 数
CRAWLER_REQUEST_TIMEOUT = 15  # 爬虫请求超时（秒）
CRAWLER_STABILITY_THRESHOLD = 3  # 连续 N 次无新 URL 发现即终止爬取

# ============================================================
# 报告设置
# ============================================================

REPORT_OUTPUT_FORMATS = ["json", "html", "markdown", "sarif", "csv"]

# ============================================================
# 日志截断
# ============================================================

LOG_PAYLOAD_MAX_LENGTH = 50  # 日志中 payload 最大显示长度
LOG_RESPONSE_MAX_LENGTH = 200  # 日志中响应最大显示长度
