"""RayScan 被动扫描子系统 (Phase 1: --proxy)。

通过轻量 MITM 代理捕获经过的 HTTP 流量,将真实请求注入检测管线,
覆盖主动爬虫难以到达的"登录后业务深处"。

设计原则(见 docs/RayScan-升级改造路线方案.md Phase 1 亮点 B):
- 只做"流量 → 检测"单向,不做代理缓存/重放,避免过度工程
- 捕获到的请求复用各检测模块的 _scan_impl,不做二次爬取
- 结果标注 source="passive",可与主动扫描结果合并去重
"""

from .proxy import PassiveProxy, PassiveScanResult, run_passive_proxy

__all__ = ["PassiveProxy", "PassiveScanResult", "run_passive_proxy"]
