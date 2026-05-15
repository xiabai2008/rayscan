"""
RayScan exception definitions — unified exception hierarchy.
"""

import logging
from contextlib import contextmanager
from functools import wraps
from typing import Optional

logger = logging.getLogger(__name__)


class WVSError(Exception):
    """Base WVS exception class"""

    pass


class ScanError(WVSError):
    """Scan-related errors"""

    pass


class ModuleError(WVSError):
    """Module-related errors"""

    pass


class ConfigurationError(WVSError):
    """Configuration-related errors"""

    pass


class NetworkError(WVSError):
    """Network-related errors"""

    pass


class RequestError(NetworkError):
    """HTTP request error"""

    def __init__(self, message: str, status_code: Optional[int] = None, url: Optional[str] = None):
        super().__init__(message)
        self.status_code = status_code
        self.url = url

    def __str__(self):
        parts = [super().__str__()]
        if self.status_code:
            parts.append(f"Status: {self.status_code}")
        if self.url:
            parts.append(f"URL: {self.url}")
        return " | ".join(parts)


class TimeoutError(NetworkError):
    """Request timeout error"""

    def __init__(self, message: str, timeout: Optional[float] = None, url: Optional[str] = None):
        super().__init__(message)
        self.timeout = timeout
        self.url = url


class ValidationError(WVSError):
    """Validation-related errors"""

    pass


class PayloadError(WVSError):
    """Payload-related errors"""

    pass


class ReportError(WVSError):
    """Report generation error"""

    pass


class PluginError(WVSError):
    """Plugin-related errors"""

    pass


class AuthenticationError(WVSError):
    """Authentication error"""

    pass


class RateLimitError(NetworkError):
    """Rate limit error"""

    def __init__(self, message: str, retry_after: Optional[int] = None):
        super().__init__(message)
        self.retry_after = retry_after


def handle_errors(default_return=None, log_level="error"):
    """
    Exception handling decorator

    Args:
        default_return: Default return value on exception
        log_level: Logging level
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except WVSError:
                # Known WVS exception, re-raise directly
                raise
            except Exception as e:
                log_func = getattr(logger, log_level, logger.error)
                log_func(f"{func.__name__} raised exception: {type(e).__name__}: {e}")

                if default_return is not None:
                    return default_return
                raise WVSError(f"{func.__name__} execution failed: {e}") from e

        return wrapper

    return decorator


@contextmanager
def exception_context(operation: str, reraise: bool = True):
    """
    Exception context manager

    Args:
        operation: Operation name
        reraise: Whether to re-raise the exception
    """
    try:
        yield
    except WVSError:
        raise
    except Exception as e:
        logger.error(f"{operation} failed: {type(e).__name__}: {e}")
        if reraise:
            raise WVSError(f"{operation} failed: {e}") from e


if __name__ == "__main__":
    # 测试异常
    print("测试异常类...")

    # 测试基础异常
    try:
        raise WVSError("基础错误")
    except WVSError as e:
        print(f"  WVSError: {e}")

    # 测试网络异常
    try:
        raise RequestError("请求失败", status_code=404, url="http://example.com")
    except RequestError as e:
        print(f"  RequestError: {e}")
        print(f"    - status_code: {e.status_code}")
        print(f"    - url: {e.url}")

    # 测试异常链
    try:
        raise NetworkError("网络错误")
    except WVSError as e:
        print(f"  异常链: {type(e).__name__} 是 WVSError 的子类: {isinstance(e, WVSError)}")

    print("测试完成！")
