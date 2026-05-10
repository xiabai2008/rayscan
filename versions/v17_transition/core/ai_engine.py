"""WVS v17.0 - AI 辅助检测引擎

使用 LLM 增强 payload 选择、误报过滤、漏洞验证
"""
import asyncio
import json
import re
import hashlib
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class AIProvider(Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    LOCAL = "local"  # 本地模型
    CUSTOM = "custom"


@dataclass
class AIConfig:
    provider: AIProvider
    model: str
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    max_tokens: int = 2048
    temperature: float = 0.3
    timeout: int = 30


@dataclass
class PayloadSuggestion:
    payload: str
    technique: str
    confidence: float
    reason: str


@dataclass
class VulnerabilityAnalysis:
    is_vulnerable: bool
    confidence: float
    false_positive_probability: float
    severity: str
    explanation: str
    remediation: str


class AIEngine:
    """AI 辅助检测引擎"""
    
    def __init__(self, config: AIConfig):
        self.config = config
        self._client = None
        self._cache: Dict[str, Any] = {}
        self._prompt_templates = self._load_templates()
    
    async def __aenter__(self):
        await self._init_client()
        return self
    
    async def __aexit__(self, *args):
        pass
    
    async def _init_client(self):
        """初始化 AI 客户端"""
        try:
            import aiohttp
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.config.timeout)
            )
        except ImportError:
            raise RuntimeError("需要安装 aiohttp: pip install aiohttp")
    
    def _load_templates(self) -> Dict[str, str]:
        """加载提示词模板"""
        return {
            "sqli_payload": """你是一个 Web 安全专家。根据以下信息，生成最可能成功的 SQL 注入 payload。

目标信息:
- URL: {url}
- 参数: {param}
- 已测试的 payload: {tested_payloads}
- 响应特征: {response_features}
- WAF 检测: {waf_detected}

请返回一个 JSON 格式的建议:
{{
    "payload": "你的 payload",
    "technique": "使用的技术(error/union/boolean/time)",
    "confidence": 0.0-1.0,
    "reason": "选择原因"
}}""",
            
            "xss_payload": """你是一个 Web 安全专家。根据以下信息，生成最可能成功的 XSS payload。

目标信息:
- URL: {url}
- 参数: {param}
- 上下文位置: {context} (html/script/attribute/url)
- 过滤规则: {filters}
- 已测试的 payload: {tested_payloads}

请返回一个 JSON 格式的建议:
{{
    "payload": "你的 payload",
    "technique": "使用的技术(reflected/dom/stored)",
    "confidence": 0.0-1.0,
    "reason": "选择原因"
}}""",
            
            "analyze_response": """你是一个 Web 安全专家。分析以下 HTTP 响应，判断是否存在漏洞。

请求信息:
- URL: {url}
- 方法: {method}
- Payload: {payload}

响应信息:
- 状态码: {status}
- 响应体片段: {response_body}
- 响应头: {headers}

请返回 JSON 格式分析:
{{
    "is_vulnerable": true/false,
    "confidence": 0.0-1.0,
    "false_positive_probability": 0.0-1.0,
    "severity": "critical/high/medium/low/info",
    "explanation": "判断依据",
    "remediation": "修复建议"
}}""",
            
            "bypass_waf": """你是一个 Web 安全专家。以下 payload 被 WAF 拦截，请生成绕过方案。

原始 payload: {original_payload}
WAF 类型: {waf_type}
拦截规则猜测: {block_reason}

请返回绕过 payload 列表 (JSON 数组):
[
    {{"payload": "绕过方案1", "technique": "编码/分块/大小写/注释"}},
    ...
]""",
            
            "verify_vuln": """你是一个 Web 安全专家。验证以下疑似漏洞是否真实存在。

漏洞信息:
- 类型: {vuln_type}
- URL: {url}
- 参数: {param}
- 触发条件: {trigger}

已收集的证据:
{evidence}

请判断:
1. 是否为误报?
2. 实际风险等级?
3. 是否需要进一步验证?

返回 JSON:
{{
    "confirmed": true/false,
    "is_false_positive": true/false,
    "actual_severity": "critical/high/medium/low",
    "additional_tests_needed": ["test1", "test2"],
    "explanation": "判断依据"
}}"""
        }
    
    async def suggest_payload(
        self, 
        vuln_type: str, 
        url: str, 
        param: str,
        tested_payloads: List[str] = None,
        context: Dict[str, Any] = None
    ) -> PayloadSuggestion:
        """AI 建议 payload"""
        
        # 检查缓存
        cache_key = self._make_cache_key(vuln_type, url, param, tested_payloads)
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        # 选择模板
        if vuln_type.lower() in ["sqli", "sql_injection"]:
            prompt = self._prompt_templates["sqli_payload"].format(
                url=url,
                param=param,
                tested_payloads=tested_payloads or [],
                response_features=context.get("response_features", "未知") if context else "未知",
                waf_detected=context.get("waf_detected", "未检测到") if context else "未检测到"
            )
        elif vuln_type.lower() in ["xss", "cross_site_scripting"]:
            prompt = self._prompt_templates["xss_payload"].format(
                url=url,
                param=param,
                context=context.get("context", "html") if context else "html",
                filters=context.get("filters", []) if context else [],
                tested_payloads=tested_payloads or []
            )
        else:
            raise ValueError(f"不支持的漏洞类型: {vuln_type}")
        
        # 调用 AI
        response = await self._call_ai(prompt)
        
        # 解析响应
        try:
            data = json.loads(response)
            suggestion = PayloadSuggestion(
                payload=data["payload"],
                technique=data.get("technique", "unknown"),
                confidence=data.get("confidence", 0.5),
                reason=data.get("reason", "")
            )
        except (json.JSONDecodeError, KeyError) as e:
            logger.warning(f"AI 响应解析失败: {e}")
            # 返回基础建议
            suggestion = PayloadSuggestion(
                payload="' OR '1'='1" if "sqli" in vuln_type.lower() else "<script>alert(1)</script>",
                technique="basic",
                confidence=0.3,
                reason="AI 响应解析失败，使用基础 payload"
            )
        
        # 缓存结果
        self._cache[cache_key] = suggestion
        return suggestion
    
    async def analyze_response(
        self,
        url: str,
        method: str,
        payload: str,
        status: int,
        response_body: str,
        headers: Dict[str, str]
    ) -> VulnerabilityAnalysis:
        """AI 分析响应，判断是否漏洞"""
        
        prompt = self._prompt_templates["analyze_response"].format(
            url=url,
            method=method,
            payload=payload,
            status=status,
            response_body=response_body[:2000],  # 限制长度
            headers=headers
        )
        
        response = await self._call_ai(prompt)
        
        try:
            data = json.loads(response)
            return VulnerabilityAnalysis(
                is_vulnerable=data.get("is_vulnerable", False),
                confidence=data.get("confidence", 0.5),
                false_positive_probability=data.get("false_positive_probability", 0.5),
                severity=data.get("severity", "medium"),
                explanation=data.get("explanation", ""),
                remediation=data.get("remediation", "")
            )
        except (json.JSONDecodeError, KeyError) as e:
            logger.warning(f"AI 响应解析失败: {e}")
            return VulnerabilityAnalysis(
                is_vulnerable=False,
                confidence=0.0,
                false_positive_probability=1.0,
                severity="info",
                explanation="AI 分析失败",
                remediation=""
            )
    
    async def bypass_waf(
        self,
        original_payload: str,
        waf_type: str = "unknown",
        block_reason: str = "未知"
    ) -> List[Dict[str, str]]:
        """AI 生成 WAF 绕过 payload"""
        
        prompt = self._prompt_templates["bypass_waf"].format(
            original_payload=original_payload,
            waf_type=waf_type,
            block_reason=block_reason
        )
        
        response = await self._call_ai(prompt)
        
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            # 返回基础绕过技术
            return self._get_basic_bypasses(original_payload)
    
    def _get_basic_bypasses(self, payload: str) -> List[Dict[str, str]]:
        """基础 WAF 绕过技术"""
        bypasses = []
        
        # 大小写混淆
        mixed = ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(payload))
        bypasses.append({"payload": mixed, "technique": "大小写混淆"})
        
        # URL 编码
        import urllib.parse
        encoded = urllib.parse.quote(payload)
        bypasses.append({"payload": encoded, "technique": "URL编码"})
        
        # 双重编码
        double_encoded = urllib.parse.quote(encoded)
        bypasses.append({"payload": double_encoded, "technique": "双重URL编码"})
        
        # 注释混淆
        if "script" in payload.lower():
            commented = payload.replace("script", "scr/**/ipt")
            bypasses.append({"payload": commented, "technique": "注释混淆"})
        
        # Unicode 编码
        unicode_payload = ''.join(f"\\u{ord(c):04x}" if not c.isalnum() else c for c in payload)
        bypasses.append({"payload": unicode_payload, "technique": "Unicode编码"})
        
        return bypasses
    
    async def verify_vulnerability(
        self,
        vuln_type: str,
        url: str,
        param: str,
        trigger: str,
        evidence: List[str]
    ) -> Dict[str, Any]:
        """AI 验证漏洞真实性"""
        
        prompt = self._prompt_templates["verify_vuln"].format(
            vuln_type=vuln_type,
            url=url,
            param=param,
            trigger=trigger,
            evidence="\n".join(f"- {e}" for e in evidence)
        )
        
        response = await self._call_ai(prompt)
        
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return {
                "confirmed": False,
                "is_false_positive": True,
                "actual_severity": "info",
                "additional_tests_needed": [],
                "explanation": "AI 验证失败"
            }
    
    async def _call_ai(self, prompt: str) -> str:
        """调用 AI API"""
        
        if self.config.provider == AIProvider.OPENAI:
            return await self._call_openai(prompt)
        elif self.config.provider == AIProvider.ANTHROPIC:
            return await self._call_anthropic(prompt)
        elif self.config.provider == AIProvider.LOCAL:
            return await self._call_local(prompt)
        else:
            raise ValueError(f"不支持的 AI 提供商: {self.config.provider}")
    
    async def _call_openai(self, prompt: str) -> str:
        """调用 OpenAI API"""
        import aiohttp
        
        url = self.config.base_url or "https://api.openai.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": "你是一个专业的 Web 安全专家，擅长漏洞检测和分析。"},
                {"role": "user", "content": prompt}
            ],
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature
        }
        
        async with self._session.post(url, headers=headers, json=data) as resp:
            if resp.status != 200:
                error = await resp.text()
                raise Exception(f"OpenAI API 错误: {resp.status} - {error}")
            
            result = await resp.json()
            return result["choices"][0]["message"]["content"]
    
    async def _call_anthropic(self, prompt: str) -> str:
        """调用 Anthropic Claude API"""
        import aiohttp
        
        url = self.config.base_url or "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": self.config.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": self.config.model,
            "max_tokens": self.config.max_tokens,
            "messages": [
                {"role": "user", "content": prompt}
            ]
        }
        
        async with self._session.post(url, headers=headers, json=data) as resp:
            if resp.status != 200:
                error = await resp.text()
                raise Exception(f"Anthropic API 错误: {resp.status} - {error}")
            
            result = await resp.json()
            return result["content"][0]["text"]
    
    async def _call_local(self, prompt: str) -> str:
        """调用本地模型 (Ollama/vLLM 等)"""
        import aiohttp
        
        # 假设使用 Ollama
        url = self.config.base_url or "http://localhost:11434/api/generate"
        
        data = {
            "model": self.config.model,
            "prompt": prompt,
            "stream": False
        }
        
        async with self._session.post(url, json=data) as resp:
            if resp.status != 200:
                error = await resp.text()
                raise Exception(f"本地模型错误: {resp.status} - {error}")
            
            result = await resp.json()
            return result.get("response", "")
    
    def _make_cache_key(self, *args) -> str:
        """生成缓存键"""
        key_str = json.dumps(args, sort_keys=True, default=str)
        return hashlib.md5(key_str.encode()).hexdigest()
    
    def clear_cache(self):
        """清空缓存"""
        self._cache.clear()
