"""被动代理捕获队列 (v2.3 T3.1: passive→active 联动)。

被动代理捕获的端点/参数进入内存队列(按"方法 + 路径 + 参数名面"去重,
参数值不参与去重——浏览产生的值变化属同一参数面,首见值作为基线保留)。
代理停止时落盘为 JSON,`rayscan scan <url> --from-proxy <queue.json>`
读取队列做定向主动验证(不爬取,仅扫捕获面)。

域名过滤语义与代理 --target 完全一致(host_matches:主域/子域匹配、
www 前缀剥离、端口剥离),联动扫描沿用同一函数,保证只打授权域。
"""

from __future__ import annotations

import json
import logging
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

PROXY_QUEUE_SCHEMA = "rayscan-proxy-queue-v1"


def host_matches(host: str, target: str) -> bool:
    """判断请求 Host 是否属于目标域(支持子域;与被动代理 target 过滤同语义)。

    双侧剥离 www. 前缀与端口;target 支持域名或 IP。
    """
    target = (target or "").lower().split(":")[0].rstrip(".")
    if target.startswith("www."):
        target = target[4:]
    h = (host or "").lower().split(":")[0].rstrip(".")
    if h.startswith("www."):
        h = h[4:]
    return h == target or (bool(target) and h.endswith("." + target))


@dataclass
class _QueueItem:
    """队列条目:端点本体 + 捕获元数据。"""

    endpoint: Any  # DiscoveredEndpoint(懒导入避免爬虫依赖进热路径)
    first_seen: str = ""
    hits: int = 1


class ProxyCaptureQueue:
    """被动捕获端点的内存队列(去重),可落盘/恢复/按目标域过滤。"""

    def __init__(self, target_filter: Optional[str] = None):
        self._items: "OrderedDict[str, _QueueItem]" = OrderedDict()
        self.target_filter = target_filter

    # ─────────────────────────────────────────────────────────────
    # 入队与去重
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def dedup_key(endpoint: Any) -> str:
        """去重键:method + URL(去 query) + 排序后的"参数名:类型"面。

        参数值不参与——同一参数面的不同值视为同一端点(首见值留作基线)。
        """
        params = getattr(endpoint, "parameters", None) or {}
        ptypes = getattr(endpoint, "param_types", None) or {}
        sig = "&".join(f"{k}:{ptypes.get(k, 'query')}" for k in sorted(params))
        return f"{(getattr(endpoint, 'method', '') or 'GET').upper()}|{getattr(endpoint, 'url', '')}|{sig}"

    def enqueue(self, endpoint: Any) -> bool:
        """入队(去重)。返回 True 表示新端点,False 表示重复命中(hits+1)。"""
        key = self.dedup_key(endpoint)
        item = self._items.get(key)
        if item is not None:
            item.hits += 1
            return False
        self._items[key] = _QueueItem(endpoint=endpoint, first_seen=datetime.now().isoformat(timespec="seconds"))
        return True

    def __len__(self) -> int:
        return len(self._items)

    @property
    def endpoints(self) -> List[Any]:
        """队列中的端点(按首次捕获顺序)。"""
        return [item.endpoint for item in self._items.values()]

    def hits(self, endpoint: Any) -> int:
        """某端点被捕获的次数(0 表示不在队列)。"""
        return self._items.get(self.dedup_key(endpoint), _QueueItem(endpoint=None)).hits

    # ─────────────────────────────────────────────────────────────
    # 序列化
    # ─────────────────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": PROXY_QUEUE_SCHEMA,
            "saved_at": datetime.now().isoformat(timespec="seconds"),
            "target_filter": self.target_filter,
            "count": len(self._items),
            "endpoints": [
                {
                    "url": item.endpoint.url,
                    "method": (item.endpoint.method or "GET").upper(),
                    "parameters": dict(item.endpoint.parameters or {}),
                    "param_types": dict(item.endpoint.param_types or {}),
                    "source_url": item.endpoint.source_url,
                    "first_seen": item.first_seen,
                    "hits": item.hits,
                }
                for item in self._items.values()
            ],
        }

    def save(self, path: Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(self.to_dict(), indent=2, ensure_ascii=False))
        return path

    @classmethod
    def load(cls, path: Path) -> "ProxyCaptureQueue":
        """从落盘文件恢复队列;格式不符抛 ValueError。"""
        path = Path(path)
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("schema") != PROXY_QUEUE_SCHEMA:
            raise ValueError(f"不支持的代理队列文件(缺少 schema={PROXY_QUEUE_SCHEMA}): {path}")
        queue = cls(target_filter=data.get("target_filter"))
        from ..crawler import DiscoveredEndpoint

        for raw in data.get("endpoints") or []:
            if not isinstance(raw, dict) or not raw.get("url"):
                continue
            ep = DiscoveredEndpoint(
                url=str(raw["url"]).split("?")[0],
                method=str(raw.get("method") or "GET").upper(),
                source_url=raw.get("source_url"),
                is_api=True,
            )
            ep.parameters = {str(k): str(v) for k, v in (raw.get("parameters") or {}).items()}
            ep.param_types = {str(k): str(v) for k, v in (raw.get("param_types") or {}).items()}
            key = cls.dedup_key(ep)
            if key in queue._items:
                continue
            queue._items[key] = _QueueItem(
                endpoint=ep,
                first_seen=str(raw.get("first_seen") or ""),
                hits=int(raw.get("hits") or 1),
            )
        return queue

    # ─────────────────────────────────────────────────────────────
    # 目标域过滤(--target 语义延续到联动扫描)
    # ─────────────────────────────────────────────────────────────

    def filter_for_target(self, base_url: str) -> List[Any]:
        """按扫描目标 URL 的主机名过滤队列(子域匹配,与被动代理同语义)。"""
        parsed = urlparse(base_url)
        target = parsed.hostname or ""
        if not target:
            return list(self.endpoints)
        matched = []
        for ep in self.endpoints:
            ep_host = urlparse(getattr(ep, "url", "") or "").hostname or ""
            if host_matches(ep_host, target):
                matched.append(ep)
        return matched
