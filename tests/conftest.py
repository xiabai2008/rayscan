"""pytest 共享配置。

py<3.10 兼容：asyncio.Lock()/Event() 等构造在无当前 event loop 的主线程中
调用 events.get_event_loop() 会抛 RuntimeError（Python 3.10+ 才自动创建 loop）。
测试（尤其是同步测试中构造 WAVScanner/HTTPPool/RateLimiter）依赖主线程 loop
存在——否则结果受测试收集顺序影响（先跑 async 测试则掩盖、先跑同步测试则崩溃）。

本 fixture 在 session 级保证主线程存在 event loop，消除顺序脆弱性。
"""

import asyncio

import pytest


@pytest.fixture(scope="session", autouse=True)
def _ensure_main_thread_event_loop():
    """确保 py<3.10 下主线程存在当前 event loop（asyncio.Lock/Event 构造需要）。"""
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    yield
