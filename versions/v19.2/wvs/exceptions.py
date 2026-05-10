"""
WVS异常定义
统一的异常处理系统
"""


class WVSError(Exception):
    """WVS基础异常类"""
    pass


class ScanError(WVSError):
    """扫描相关错误"""
    pass


class ModuleError(WVSError):
    """模块相关错误"""
    pass


class ConfigurationError(WVSError):
    """配置相关错误"""
    pass


class NetworkError(WVSError):
    """网络相关错误"""
    pass


class RequestError(NetworkError):
    """HTTP请求错误"""
    def __init__(self, message: str, status_code: int = None, url: str = None):
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
    """请求超时错误"""
    def __init__(self, message: str, timeout: float = None, url: str = None):
        super().__init__(message)
        self.timeout = timeout
        self.url = url


class ValidationError(WVSError):
    """验证相关错误"""
    pass


class PayloadError(WVSError):
    """Payload相关错误"""
    pass


class ReportError(WVSError):
    """报告生成错误"""
    pass


class PluginError(WVSError):
    """插件相关错误"""
    pass


class AuthenticationError(WVSError):
    """认证错误"""
    pass


class RateLimitError(NetworkError):
    """速率限制错误"""
    def __init__(self, message: str, retry_after: int = None):
        super().__init__(message)
        self.retry_after = retry_after


# 异常处理装饰器
from functools import wraps
import logging

logger = logging.getLogger(__name__)


def handle_errors(default_return=None, log_level="error"):
    """
    异常处理装饰器
    
    Args:
        default_return: 异常时返回的默认值
        log_level: 日志级别
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except WVSError:
                # WVS已知异常，直接抛出
                raise
            except Exception as e:
                log_func = getattr(logger, log_level, logger.error)
                log_func(f"{func.__name__} 发生异常: {type(e).__name__}: {e}")
                
                if default_return is not None:
                    return default_return
                raise WVSError(f"{func.__name__} 执行失败: {e}") from e
        
        return wrapper
    return decorator


# 异常上下文管理器
from contextlib import contextmanager


@contextmanager
def exception_context(operation: str, reraise: bool = True):
    """
    异常上下文管理器
    
    Args:
        operation: 操作名称
        reraise: 是否重新抛出异常
    """
    try:
        yield
    except WVSError:
        raise
    except Exception as e:
        logger.error(f"{operation} 失败: {type(e).__name__}: {e}")
        if reraise:
            raise WVSError(f"{operation} 失败: {e}") from e


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