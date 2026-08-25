"""
LLM 客户端抽象（OpenAI 兼容 chat/completions）。

- 复用项目现有 httpx 依赖，不引入 openai SDK
- 官方 API 默认端点 https://api.openai.com/v1
- 无 api_key 时 available=False，调用方应静默跳过
- 所有请求失败均返回 None（fail-safe），不影响主扫描流程
"""

import json
import logging
import os
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_MODEL = "gpt-4o-mini"

# 环境变量约定（与 config ai 段互备，config 优先）
ENV_API_KEY = "LLM_API_KEY"
ENV_BASE_URL = "LLM_BASE_URL"
ENV_MODEL = "LLM_MODEL"


def truncate(text: Optional[str], limit: int = 500) -> str:
    """截断文本到 limit 字符（None -> ""），用于控制发往 LLM 的上下文大小。"""
    if not text:
        return ""
    text = str(text)
    return text[:limit] + ("..." if len(text) > limit else "")


def extract_json(content: str) -> Optional[Dict[str, Any]]:
    """宽松解析 LLM 输出中的 JSON 对象（容忍 markdown 代码块/前后缀文本）。"""
    if not content:
        return None
    start = content.find("{")
    end = content.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    try:
        parsed = json.loads(content[start : end + 1])
    except (json.JSONDecodeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


class LLMClient:
    """OpenAI 兼容 chat/completions 异步客户端（thin wrapper）。"""

    def __init__(
        self,
        config: Any = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: float = 30.0,
        transport: Any = None,
    ):
        """
        Args:
            config: ConfigManager（可选），ai 段配置优先于环境变量
            api_key: API key（显式传入最高优先级）
            base_url: 兼容端点（默认官方）
            model: 模型名
            timeout: 请求超时（秒）
            transport: httpx transport（测试注入用，如 httpx.MockTransport）
        """
        self._config = config

        # api_key 解析顺序：显式参数 > config ai.api_key > 环境变量
        self._api_key = api_key or self._get_config("api_key") or os.getenv(ENV_API_KEY) or ""
        self.base_url = (
            base_url or self._get_config("base_url") or os.getenv(ENV_BASE_URL) or DEFAULT_BASE_URL
        ).rstrip("/")
        self.model = model or self._get_config("model") or os.getenv(ENV_MODEL) or DEFAULT_MODEL
        self.timeout = timeout or float(self._get_config("timeout") or 30.0)
        self._transport = transport

        # 跟随主扫描器的 SSL 配置（verify_ssl 默认 False，见 constants）
        verify_ssl = False
        if config is not None:
            verify_ssl = bool(config.get("verify_ssl", False))
        self._verify_ssl = verify_ssl

    def _get_config(self, key: str) -> Any:
        if self._config is None:
            return None
        return self._config.get(f"ai.{key}")

    @property
    def available(self) -> bool:
        """是否具备调用条件（有 key 且配置了端点）。"""
        return bool(self._api_key) and bool(self.base_url)

    @property
    def provider_desc(self) -> str:
        """供告警/日志展示的提供方描述。"""
        host = self.base_url.split("//")[-1].split("/")[0]
        return f"{self.model} @ {host}"

    async def chat(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.0,
        max_tokens: Optional[int] = None,
    ) -> Optional[str]:
        """
        发送对话请求，返回 assistant 内容。

        Returns:
            content 字符串；请求失败/无 key 时返回 None
        """
        if not self.available:
            return None

        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
        }
        if max_tokens:
            payload["max_tokens"] = max_tokens

        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, verify=self._verify_ssl, transport=self._transport
            ) as client:
                resp = await client.post(
                    f"{self.base_url}/chat/completions",
                    json=payload,
                    headers=headers,
                )
                if resp.status_code != 200:
                    logger.warning(f"[AI] LLM 请求失败: HTTP {resp.status_code}: {truncate(resp.text, 200)}")
                    return None
                data = resp.json()
                choices = data.get("choices") or []
                if not choices:
                    return None
                message = choices[0].get("message") or {}
                content = message.get("content")
                return content if isinstance(content, str) else None
        except Exception as e:
            logger.debug(f"[AI] LLM 请求异常: {e}")
            return None

    async def chat_json(self, messages: List[Dict[str, str]], **kwargs) -> Optional[Dict[str, Any]]:
        """请求并要求输出 JSON，返回解析后的 dict（解析失败返回 None）。"""
        content = await self.chat(messages, **kwargs)
        if content is None:
            return None
        parsed = extract_json(content)
        if parsed is None:
            logger.debug("[AI] LLM 输出无法解析为 JSON，跳过本批")
        return parsed
