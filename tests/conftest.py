"""pytest 共享配置。

py<3.10 兼容：asyncio.Lock()/Event() 等构造在无当前 event loop 的主线程中
调用 events.get_event_loop() 会抛 RuntimeError（Python 3.10+ 才自动创建 loop）。

必须用 function scope：pytest-asyncio 在 function-scope loop 管理下会清理/重置
主线程 loop（session 级 fixture 无法覆盖测试间的清空）。
"""

import asyncio

import pytest


@pytest.fixture(autouse=True)
def _ensure_main_thread_event_loop():
    """确保 py<3.10 下主线程存在当前 event loop（每个测试前执行）。"""
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    yield
